from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueMapping:
    rule_id: str
    framework: str
    technique_id: str
    technique_name: str
    tactic: str
    mapping_rationale: str
    mapping_type: str = "curated"


# ── Legacy mappings (fallback when TOML not present) ─────────────

LEGACY_MAPPINGS: tuple[TechniqueMapping, ...] = (
    TechniqueMapping("TH-001", "ATTACK", "T1190", "Exploit Public-Facing Application", "initial-access",
                     "Internet-exposed services handling sensitive data are prime targets for public-facing exploitation."),
    TechniqueMapping("TH-001", "ATTACK", "T1078", "Valid Accounts", "defense-evasion",
                     "Sensitive internet-facing workflows often include credential attack surfaces that can enable valid account abuse."),
    TechniqueMapping("TH-002", "ATTACK", "T1021", "Remote Services", "lateral-movement",
                     "Dependency chains from low-trust zones indicate likely remote-service lateral movement paths to high-value assets."),
    TechniqueMapping("TH-002", "ATTACK", "T1485", "Data Destruction", "impact",
                     "Path access to critical objects implies elevated impact potential on high-value data."),
    TechniqueMapping("TH-003", "ATTACK", "T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
                     "Externally reachable privileged modules increase likelihood of exploit-driven privilege escalation."),
    TechniqueMapping("TH-003", "ATTACK", "T1078", "Valid Accounts", "persistence",
                     "High-privilege reachable services are at risk of persistence through account abuse."),
    TechniqueMapping("TH-004", "ATLAS", "AML.T0016", "Data Poisoning", "ml-attack-staging",
                     "AI-relevant module and feature pipeline dependencies create poisoning opportunities."),
    TechniqueMapping("TH-004", "ATLAS", "AML.T0040", "Model Evasion", "ml-attack-staging",
                     "Inference-facing AI dependencies can be abused via evasion-style inputs."),
    TechniqueMapping("TH-004", "ATTACK", "T1565", "Data Manipulation", "impact",
                     "ML pipeline dependencies expose data manipulation opportunities across model inputs."),
    TechniqueMapping("TH-005", "ATTACK", "T1530", "Data from Cloud Storage Object", "collection",
                     "Regulated objects concentrated in critical workflows are high-value collection targets."),
    TechniqueMapping("TH-005", "ATTACK", "T1020", "Automated Exfiltration", "exfiltration",
                     "Critical workflows carrying regulated data increase exfiltration automation risk."),
    TechniqueMapping("TH-006", "ATTACK", "T1570", "Lateral Tool Transfer", "lateral-movement",
                     "Boundary crossing dependencies can support staged tool transfer into trusted zones."),
    TechniqueMapping("TH-006", "ATTACK", "T1550", "Use Alternate Authentication Material", "lateral-movement",
                     "Cross-boundary privileged dependencies can be abused through token/key-based movement."),
)
