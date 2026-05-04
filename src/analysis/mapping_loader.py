from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from project_paths import ProjectPaths

from .mapping_types import LEGACY_MAPPINGS, TechniqueMapping

if TYPE_CHECKING:
    from knowledge.index import TechniqueIndex

_DEFAULT_PATHS = ProjectPaths.default()
_log = logging.getLogger(__name__)


def _resolve_technique_name(
    technique_id: str,
    *,
    index: TechniqueIndex | None = None,
) -> str:
    """Resolve a technique name from an injected TechniqueIndex, falling back to legacy."""
    if index is not None:
        tech = index.lookup(technique_id)
        if tech:
            return tech.name
    for m in LEGACY_MAPPINGS:
        if m.technique_id == technique_id:
            return m.technique_name
    return technique_id


def load_curated_mappings(
    rule_id: str | None = None,
    *,
    rules_path: Path | None = None,
    index: TechniqueIndex | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Load curated mappings from TOML. Falls back to legacy tuple if file missing."""
    rules_path = rules_path or _DEFAULT_PATHS.mapping_rules
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
        name = _resolve_technique_name(entry["technique_id"], index=index)
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
    config_path: Path | None = None,
) -> dict:
    """Load expansion configuration from TOML."""
    config_path = config_path or _DEFAULT_PATHS.mapping_config
    if not config_path.exists():
        return {"enabled": False}
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("expansion", {"enabled": False})


def load_suggestions_config(
    *,
    config_path: Path | None = None,
) -> dict:
    """Load suggestions configuration from TOML."""
    config_path = config_path or _DEFAULT_PATHS.mapping_config
    if not config_path.exists():
        return {"include_suggested": False}
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("suggestions", {"include_suggested": False})


def load_graphrag_config(
    *,
    config_path: Path | None = None,
) -> dict:
    """Load GraphRAG scorer configuration from TOML."""
    config_path = config_path or _DEFAULT_PATHS.mapping_config
    if not config_path.exists():
        return {}
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("graphrag", {})


def load_suggested_mappings(
    rule_id: str | None = None,
    *,
    suggestions_path: Path | None = None,
    index: TechniqueIndex | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Load auto-generated suggested mappings from TOML.

    Returns an empty tuple if the file does not exist.
    """
    if suggestions_path is None:
        cfg = load_suggestions_config()
        rel = cfg.get("suggestions_path", "data/threat_intel/mapping_suggestions.toml")
        suggestions_path = _DEFAULT_PATHS.root / rel
    if not suggestions_path.exists():
        return ()

    with open(suggestions_path, "rb") as f:
        data = tomllib.load(f)

    mappings = []
    for entry in data.get("mappings", []):
        if rule_id is not None and entry["rule_id"] != rule_id:
            continue
        name = _resolve_technique_name(entry["technique_id"], index=index)
        mappings.append(TechniqueMapping(
            rule_id=entry["rule_id"],
            framework=entry["framework"],
            technique_id=entry["technique_id"],
            technique_name=name,
            tactic=entry["tactic"],
            mapping_rationale=entry.get("rationale", ""),
            mapping_type=entry.get("mapping_type", "suggested"),
        ))
    return tuple(mappings)
