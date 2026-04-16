from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from models.schema.risk_model import RiskDriver, RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import ThreatRecord, ThreatReport


RISK_WEIGHTS: dict[str, float] = {
    "likelihood": 0.25,
    "impact": 0.20,
    "exposure": 0.15,
    "privilege_sensitivity": 0.15,
    "data_criticality": 0.15,
    "exploitability": 0.10,
}


SEVERITY_BASE: dict[str, float] = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 0.90,
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _stable_risk_id(threat_id: str) -> str:
    digest = hashlib.sha1(threat_id.encode("utf-8")).hexdigest()[:10]
    return f"RISK-{digest}"


def priority_from_score(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def _likelihood(threat: ThreatRecord) -> float:
    score = SEVERITY_BASE[threat.severity_hint]
    if threat.evidence.get("internet_exposed") is True:
        score += 0.15
    if threat.affected_workflows:
        score += min(0.10, 0.03 * len(threat.affected_workflows))
    if threat.rule_id == "TH-002":
        score += 0.10
    return _clamp(score)


def _impact(threat: ThreatRecord) -> float:
    score = SEVERITY_BASE[threat.severity_hint]
    target_boost = {
        "system": 0.15,
        "workflow": 0.12,
        "object": 0.10,
        "datastore": 0.08,
        "module": 0.05,
    }
    score += target_boost.get(threat.target_type, 0.0)
    if threat.affected_objects:
        score += min(0.10, 0.02 * len(threat.affected_objects))
    if threat.rule_id == "TH-005":
        score += 0.10
    return _clamp(score)


def _exposure(threat: ThreatRecord) -> float:
    score = 0.30
    if threat.evidence.get("internet_exposed") is True:
        score += 0.30
    if "trust_boundaries" in threat.evidence:
        boundaries = threat.evidence.get("trust_boundaries") or []
        score += min(0.20, 0.05 * len(boundaries))
    if threat.affected_workflows:
        score += min(0.20, 0.05 * len(threat.affected_workflows))
    hops = threat.evidence.get("hops")
    if isinstance(hops, (int, float)):
        score += min(0.10, float(hops) * 0.02)
    return _clamp(score)


def _privilege_sensitivity(threat: ThreatRecord) -> float:
    score = 0.20
    privilege_level = threat.evidence.get("privilege_level")
    if isinstance(privilege_level, (int, float)):
        score += min(0.60, float(privilege_level) / 3.0)
    if threat.rule_id in {"TH-003", "TH-006"}:
        score += 0.15
    return _clamp(score)


def _data_criticality(threat: ThreatRecord) -> float:
    score = 0.25
    if threat.target_type == "object":
        score += 0.25
    if threat.affected_objects:
        score += min(0.30, 0.08 * len(threat.affected_objects))
    if threat.rule_id in {"TH-002", "TH-005"}:
        score += 0.20
    return _clamp(score)


def _exploitability(threat: ThreatRecord) -> float:
    score = 0.30
    if threat.framework_mappings:
        score += min(0.20, 0.05 * len(threat.framework_mappings))

    tactics = {mapping.tactic.lower() for mapping in threat.framework_mappings}
    if "initial access" in tactics:
        score += 0.20
    if "lateral movement" in tactics:
        score += 0.15
    if "privilege escalation" in tactics:
        score += 0.10
    return _clamp(score)


def score_threat(threat: ThreatRecord, *, created_at: str | None = None) -> RiskRecord:
    factors = RiskFactors(
        likelihood=_likelihood(threat),
        impact=_impact(threat),
        exposure=_exposure(threat),
        privilege_sensitivity=_privilege_sensitivity(threat),
        data_criticality=_data_criticality(threat),
        exploitability=_exploitability(threat),
    )

    weighted = {
        key: getattr(factors, key) * weight
        for key, weight in RISK_WEIGHTS.items()
    }

    score = _clamp(sum(weighted.values()))
    score = round(score, 4)

    drivers = sorted(weighted.items(), key=lambda item: item[1], reverse=True)[:3]
    risk_drivers = [
        RiskDriver(
            factor=factor,  # type: ignore[arg-type]
            score=round(getattr(factors, factor), 4),
            weighted_contribution=round(contribution, 4),
        )
        for factor, contribution in drivers
    ]

    explanation = (
        f"Risk score {score:.2f} derived from top drivers: "
        f"{', '.join(f'{driver.factor}={driver.weighted_contribution:.2f}' for driver in risk_drivers)}."
    )

    return RiskRecord(
        risk_id=_stable_risk_id(threat.threat_id),
        model_id=threat.model_id,
        threat_id=threat.threat_id,
        rule_id=threat.rule_id,
        title=threat.title,
        target_id=threat.target_id,
        target_type=threat.target_type,
        risk_score=score,
        priority=priority_from_score(score),
        factors=factors,
        drivers=risk_drivers,
        explanation=explanation,
        evidence=threat.evidence,
        created_at=created_at or _now(),
    )


def build_risk_report(threat_report: ThreatReport, *, methodology_version: str = "0.1") -> RiskReport:
    created_at = _now()
    risks = [score_threat(threat, created_at=created_at) for threat in threat_report.threats]
    risks = sorted(risks, key=lambda risk: (-risk.risk_score, risk.risk_id))

    return RiskReport(
        model_id=threat_report.model_id,
        generated_at=created_at,
        methodology_version=methodology_version,
        risk_count=len(risks),
        risks=risks,
    )


def read_threat_report(path: str | Path) -> ThreatReport:
    payload = Path(path).read_text(encoding="utf-8")
    return ThreatReport.model_validate_json(payload)


def write_risk_report(report: RiskReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def generate_risk_report_from_file(
    threat_report_path: str | Path,
    output_path: str | Path | None = None,
) -> tuple[RiskReport, Path]:
    threat_report = read_threat_report(threat_report_path)
    report = build_risk_report(threat_report)

    if output_path is None:
        output_path = (
            Path("models")
            / "outputs"
            / "risks"
            / f"{threat_report.model_id}_risks.json"
        )

    written = write_risk_report(report, output_path)
    return report, written
