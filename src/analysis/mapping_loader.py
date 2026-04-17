from __future__ import annotations

import tomllib
from pathlib import Path

from .mapping_types import LEGACY_MAPPINGS, TechniqueMapping

_MAPPING_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "mapping_rules.toml"
_MAPPING_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "mapping_config.toml"


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
    for m in LEGACY_MAPPINGS:
        if m.technique_id == technique_id:
            return m.technique_name
    return technique_id


def load_curated_mappings(
    rule_id: str | None = None,
    *,
    rules_path: Path = _MAPPING_RULES_PATH,
) -> tuple[TechniqueMapping, ...]:
    """Load curated mappings from TOML. Falls back to legacy tuple if file missing."""
    if not rules_path.exists():
        return LEGACY_MAPPINGS if rule_id is None else tuple(
            m for m in LEGACY_MAPPINGS if m.rule_id == rule_id
        )

    with open(rules_path, "rb") as f:
        data = tomllib.load(f)

    mappings = []
    for entry in data.get("mappings", []):
        if rule_id is not None and entry["rule_id"] != rule_id:
            continue
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


def load_expansion_config(
    *,
    config_path: Path = _MAPPING_CONFIG_PATH,
) -> dict:
    """Load expansion configuration from TOML."""
    if not config_path.exists():
        return {"enabled": False}
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("expansion", {"enabled": False})
