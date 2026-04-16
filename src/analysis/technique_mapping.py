from __future__ import annotations

from dataclasses import dataclass

from .threat_generation import THREAT_HEURISTICS


@dataclass(frozen=True)
class TechniqueMapping:
    rule_id: str
    framework: str
    technique_id: str
    technique_name: str
    tactic: str
    mapping_rationale: str


RULE_TECHNIQUE_MAPPINGS: tuple[TechniqueMapping, ...] = (
    TechniqueMapping(
        rule_id="TH-001",
        framework="ATTACK",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        mapping_rationale=(
            "Internet-exposed services handling sensitive data are prime targets for "
            "public-facing exploitation."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-001",
        framework="ATTACK",
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion",
        mapping_rationale=(
            "Sensitive internet-facing workflows often include credential attack surfaces "
            "that can enable valid account abuse."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-002",
        framework="ATTACK",
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="Lateral Movement",
        mapping_rationale=(
            "Dependency chains from low-trust zones indicate likely remote-service "
            "lateral movement paths to high-value assets."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-002",
        framework="ATTACK",
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        mapping_rationale=(
            "Path access to critical objects implies elevated impact potential on high-value data."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-003",
        framework="ATTACK",
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        mapping_rationale=(
            "Externally reachable privileged modules increase likelihood of exploit-driven "
            "privilege escalation."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-003",
        framework="ATTACK",
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Persistence",
        mapping_rationale=(
            "High-privilege reachable services are at risk of persistence through account abuse."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-004",
        framework="ATLAS",
        technique_id="AML.T0016",
        technique_name="Data Poisoning",
        tactic="ML Model Manipulation",
        mapping_rationale=(
            "AI-relevant module and feature pipeline dependencies create poisoning opportunities."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-004",
        framework="ATLAS",
        technique_id="AML.T0040",
        technique_name="Model Evasion",
        tactic="ML Model Inference Manipulation",
        mapping_rationale=(
            "Inference-facing AI dependencies can be abused via evasion-style inputs."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-004",
        framework="ATTACK",
        technique_id="T1565",
        technique_name="Data Manipulation",
        tactic="Impact",
        mapping_rationale=(
            "ML pipeline dependencies expose data manipulation opportunities across model inputs."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-005",
        framework="ATTACK",
        technique_id="T1530",
        technique_name="Data from Cloud Storage Object",
        tactic="Collection",
        mapping_rationale=(
            "Regulated objects concentrated in critical workflows are high-value collection targets."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-005",
        framework="ATTACK",
        technique_id="T1020",
        technique_name="Automated Exfiltration",
        tactic="Exfiltration",
        mapping_rationale=(
            "Critical workflows carrying regulated data increase exfiltration automation risk."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-006",
        framework="ATTACK",
        technique_id="T1570",
        technique_name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        mapping_rationale=(
            "Boundary crossing dependencies can support staged tool transfer into trusted zones."
        ),
    ),
    TechniqueMapping(
        rule_id="TH-006",
        framework="ATTACK",
        technique_id="T1550",
        technique_name="Use Alternate Authentication Material",
        tactic="Lateral Movement",
        mapping_rationale=(
            "Cross-boundary privileged dependencies can be abused through token/key-based movement."
        ),
    ),
)


def get_rule_technique_mappings(rule_id: str) -> tuple[TechniqueMapping, ...]:
    """Return all ATT&CK/ATLAS mappings for a specific threat rule."""

    return tuple(mapping for mapping in RULE_TECHNIQUE_MAPPINGS if mapping.rule_id == rule_id)


def map_rule_to_techniques(
    rule_id: str,
    context: dict | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Map a rule id to technique references.

    The `context` parameter is reserved for future conditional mappings.
    """

    _ = context
    return get_rule_technique_mappings(rule_id)


def get_all_technique_mappings() -> tuple[TechniqueMapping, ...]:
    """Return the full immutable mapping catalog."""

    return RULE_TECHNIQUE_MAPPINGS


def validate_mapping_coverage() -> tuple[bool, str]:
    """Check that every threat rule has at least one framework mapping."""

    rule_ids = {rule.rule_id for rule in THREAT_HEURISTICS}
    mapped_rule_ids = {mapping.rule_id for mapping in RULE_TECHNIQUE_MAPPINGS}

    missing = sorted(rule_ids - mapped_rule_ids)
    if missing:
        return False, f"Missing technique mappings for rules: {', '.join(missing)}"
    return True, "All rules have at least one technique mapping"
