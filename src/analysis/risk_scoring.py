from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from models.schema.risk_model import RiskDriver, RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import ThreatRecord, ThreatReport

from .risk_factors import FACTOR_REGISTRY, RISK_WEIGHTS


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


def score_threat(threat: ThreatRecord, *, created_at: str | None = None) -> RiskRecord:
    computed = {name: fn(threat) for name, fn in FACTOR_REGISTRY.items()}

    factors = RiskFactors(**computed)

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
