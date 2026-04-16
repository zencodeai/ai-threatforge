from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .threat_generation import THREAT_HEURISTICS

_MAPPING_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "mapping_rules.toml"
_MAPPING_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "mapping_config.toml"


@dataclass(frozen=True)
class TechniqueMapping:
    rule_id: str
    framework: str
    technique_id: str
    technique_name: str
    tactic: str
    mapping_rationale: str
    mapping_type: str = "curated"


def _load_curated_mappings(rule_id: str | None = None) -> tuple[TechniqueMapping, ...]:
    """Load curated mappings from TOML. Falls back to legacy tuple if file missing."""
    if not _MAPPING_RULES_PATH.exists():
        return _LEGACY_MAPPINGS if rule_id is None else tuple(
            m for m in _LEGACY_MAPPINGS if m.rule_id == rule_id
        )

    with open(_MAPPING_RULES_PATH, "rb") as f:
        data = tomllib.load(f)

    mappings = []
    for entry in data.get("mappings", []):
        if rule_id is not None and entry["rule_id"] != rule_id:
            continue
        # Resolve technique_name from the knowledge base if available
        name = _resolve_technique_name(entry["technique_id"])
        mappings.append(TechniqueMapping(
            rule_id=entry["rule_id"],
            framework=entry["framework"],
            technique_id=entry["technique_id"],
            technique_name=name,
            tactic=entry["tactic"],
            mapping_rationale=entry["rationale"],
            mapping_type="curated",
        ))
    return tuple(mappings)


def _resolve_technique_name(technique_id: str) -> str:
    """Resolve a technique name from the TechniqueIndex if available."""
    try:
        from knowledge.index import TechniqueIndex
        index = TechniqueIndex.get()
        tech = index.lookup(technique_id)
        if tech:
            return tech.name
    except Exception:
        pass
    # Fallback to legacy names
    for m in _LEGACY_MAPPINGS:
        if m.technique_id == technique_id:
            return m.technique_name
    return technique_id


def _load_expansion_config() -> dict:
    """Load expansion configuration from TOML."""
    if not _MAPPING_CONFIG_PATH.exists():
        return {"enabled": False}
    with open(_MAPPING_CONFIG_PATH, "rb") as f:
        data = tomllib.load(f)
    return data.get("expansion", {"enabled": False})


def _expand_by_tactic(rule_id: str, config: dict) -> tuple[TechniqueMapping, ...]:
    """Layer 2: expand a rule to all techniques in its target tactics."""
    if not config.get("enabled", False):
        return ()

    try:
        from knowledge.index import TechniqueIndex
        index = TechniqueIndex.get()
    except Exception:
        return ()

    if not index.is_populated():
        return ()

    heuristic = next((h for h in THREAT_HEURISTICS if h.rule_id == rule_id), None)
    if not heuristic:
        return ()

    # Gather curated technique IDs to avoid duplicates
    curated_ids = {m.technique_id for m in _load_curated_mappings(rule_id)}

    include_subtechniques = config.get("include_subtechniques", True)
    max_per_tactic = config.get("max_techniques_per_tactic", 20)
    allowed_domains = set(config.get("domains", ["enterprise"]))

    # Get the curated tactic shortnames for this rule
    curated = _load_curated_mappings(rule_id)
    target_tactics = {m.tactic for m in curated}

    expanded: list[TechniqueMapping] = []
    for tactic_shortname in target_tactics:
        techniques = index.techniques_for_tactic(tactic_shortname)
        count = 0
        for tech in techniques:
            if tech.technique_id in curated_ids:
                continue
            if tech.domain not in allowed_domains:
                continue
            if not include_subtechniques and tech.is_subtechnique:
                continue
            if count >= max_per_tactic:
                break
            expanded.append(TechniqueMapping(
                rule_id=rule_id,
                framework=tech.framework,
                technique_id=tech.technique_id,
                technique_name=tech.name,
                tactic=tactic_shortname,
                mapping_rationale=f"Tactic-expanded: {tech.name} shares tactic '{tactic_shortname}' with curated mapping.",
                mapping_type="tactic-expansion",
            ))
            count += 1

    return tuple(expanded)


def _filter_by_context(
    mappings: tuple[TechniqueMapping, ...],
    context: dict | None,
) -> tuple[TechniqueMapping, ...]:
    """Layer 3: filter expanded mappings by context (e.g., platform)."""
    if not context or not mappings:
        return mappings

    platforms = context.get("platforms")
    if not platforms:
        return mappings

    platform_set = {p.lower() for p in platforms}

    try:
        from knowledge.index import TechniqueIndex
        index = TechniqueIndex.get()
    except Exception:
        return mappings

    filtered = []
    for m in mappings:
        tech = index.lookup(m.technique_id)
        if tech is None or not tech.platforms:
            filtered.append(m)
            continue
        if any(p.lower() in platform_set for p in tech.platforms):
            filtered.append(m)

    return tuple(filtered)


# ── Legacy mappings (fallback when TOML not present) ─────────────

_LEGACY_MAPPINGS: tuple[TechniqueMapping, ...] = (
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


# ── Public API ────────────────────────────────────────────────────

def get_rule_technique_mappings(rule_id: str) -> tuple[TechniqueMapping, ...]:
    """Return all ATT&CK/ATLAS mappings for a specific threat rule."""
    return _load_curated_mappings(rule_id)


def map_rule_to_techniques(
    rule_id: str,
    context: dict | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Map a rule id to technique references using the layered mapping engine.

    Layer 1: Curated rules (always applied)
    Layer 2: Tactic-based expansion (opt-in via mapping_config.toml)
    Layer 3: Context-based filtering (when context provides platform info)
    """
    curated = _load_curated_mappings(rule_id)
    config = _load_expansion_config()
    expanded = _expand_by_tactic(rule_id, config)
    filtered = _filter_by_context(expanded, context)
    return curated + filtered


def get_all_technique_mappings() -> tuple[TechniqueMapping, ...]:
    """Return the full curated mapping catalog."""
    return _load_curated_mappings()


def validate_mapping_coverage() -> tuple[bool, str]:
    """Check that every threat rule has at least one framework mapping."""
    rule_ids = {rule.rule_id for rule in THREAT_HEURISTICS}
    mapped_rule_ids = {mapping.rule_id for mapping in get_all_technique_mappings()}

    missing = sorted(rule_ids - mapped_rule_ids)
    if missing:
        return False, f"Missing technique mappings for rules: {', '.join(missing)}"
    return True, "All rules have at least one technique mapping"
