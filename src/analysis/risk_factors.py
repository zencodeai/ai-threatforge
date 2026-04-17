from __future__ import annotations

from typing import Callable

from models.schema.threat_model import ThreatRecord


RiskFactorFn = Callable[[ThreatRecord], float]

SEVERITY_BASE: dict[str, float] = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 0.90,
}

RISK_WEIGHTS: dict[str, float] = {
    "likelihood": 0.25,
    "impact": 0.20,
    "exposure": 0.15,
    "privilege_sensitivity": 0.15,
    "data_criticality": 0.15,
    "exploitability": 0.10,
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


# ── Rule-specific adjustments ────────────────────────────────────
# Each dict maps rule_id -> additive bonus for that factor.

_LIKELIHOOD_RULE_BONUS: dict[str, float] = {
    "TH-002": 0.10,
}

_IMPACT_RULE_BONUS: dict[str, float] = {
    "TH-005": 0.10,
}

_PRIVILEGE_RULE_BONUS: dict[str, frozenset[str]] = {}
_PRIVILEGE_RULE_SET: frozenset[str] = frozenset({"TH-003", "TH-006"})

_DATA_CRIT_RULE_SET: frozenset[str] = frozenset({"TH-002", "TH-005"})


# ── Factor functions ─────────────────────────────────────────────

def likelihood(threat: ThreatRecord) -> float:
    score = SEVERITY_BASE[threat.severity_hint]
    if threat.evidence.get("internet_exposed") is True:
        score += 0.15
    if threat.affected_workflows:
        score += min(0.10, 0.03 * len(threat.affected_workflows))
    score += _LIKELIHOOD_RULE_BONUS.get(threat.rule_id, 0.0)
    return _clamp(score)


def impact(threat: ThreatRecord) -> float:
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
    score += _IMPACT_RULE_BONUS.get(threat.rule_id, 0.0)
    return _clamp(score)


def exposure(threat: ThreatRecord) -> float:
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


def privilege_sensitivity(threat: ThreatRecord) -> float:
    score = 0.20
    privilege_level = threat.evidence.get("privilege_level")
    if isinstance(privilege_level, (int, float)):
        score += min(0.60, float(privilege_level) / 3.0)
    if threat.rule_id in _PRIVILEGE_RULE_SET:
        score += 0.15
    return _clamp(score)


def data_criticality(threat: ThreatRecord) -> float:
    score = 0.25
    if threat.target_type == "object":
        score += 0.25
    if threat.affected_objects:
        score += min(0.30, 0.08 * len(threat.affected_objects))
    if threat.rule_id in _DATA_CRIT_RULE_SET:
        score += 0.20
    return _clamp(score)


def exploitability(threat: ThreatRecord) -> float:
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


# ── Factor registry ──────────────────────────────────────────────

FACTOR_REGISTRY: dict[str, RiskFactorFn] = {
    "likelihood": likelihood,
    "impact": impact,
    "exposure": exposure,
    "privilege_sensitivity": privilege_sensitivity,
    "data_criticality": data_criticality,
    "exploitability": exploitability,
}
