from __future__ import annotations

from .mapping_loader import load_curated_mappings
from .mapping_types import TechniqueMapping
from .threat_generation import THREAT_HEURISTICS


def get_rule_technique_mappings(rule_id: str) -> tuple[TechniqueMapping, ...]:
    """Return all curated ATT&CK/ATLAS mappings for a specific threat rule."""
    return load_curated_mappings(rule_id)


def get_all_technique_mappings() -> tuple[TechniqueMapping, ...]:
    """Return the full curated mapping catalog."""
    return load_curated_mappings()


def validate_mapping_coverage() -> tuple[bool, str]:
    """Check that every threat rule has at least one framework mapping."""
    rule_ids = {rule.rule_id for rule in THREAT_HEURISTICS}
    mapped_rule_ids = {mapping.rule_id for mapping in get_all_technique_mappings()}

    missing = sorted(rule_ids - mapped_rule_ids)
    if missing:
        return False, f"Missing technique mappings for rules: {', '.join(missing)}"
    return True, "All rules have at least one technique mapping"


__all__ = [
    "TechniqueMapping",
    "get_rule_technique_mappings",
    "get_all_technique_mappings",
    "validate_mapping_coverage",
]
