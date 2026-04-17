from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .mapping_loader import load_curated_mappings, load_expansion_config
from .mapping_types import TechniqueMapping
from .threat_generation import THREAT_HEURISTICS

if TYPE_CHECKING:
    from knowledge.index import TechniqueIndex


def _expand_by_tactic(
    rule_id: str,
    config: dict,
    *,
    index: TechniqueIndex | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Layer 2: expand a rule to all techniques in its target tactics."""
    if not config.get("enabled", False):
        return ()

    if index is None or not index.is_populated():
        return ()

    heuristic = next((h for h in THREAT_HEURISTICS if h.rule_id == rule_id), None)
    if not heuristic:
        return ()

    curated_ids = {m.technique_id for m in load_curated_mappings(rule_id)}

    include_subtechniques = config.get("include_subtechniques", True)
    max_per_tactic = config.get("max_techniques_per_tactic", 20)
    allowed_domains = set(config.get("domains", ["enterprise"]))

    curated = load_curated_mappings(rule_id)
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
    *,
    index: TechniqueIndex | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Layer 3: filter expanded mappings by context (e.g., platform)."""
    if not context or not mappings:
        return mappings

    platforms = context.get("platforms")
    if not platforms:
        return mappings

    if index is None:
        return mappings

    platform_set = {p.lower() for p in platforms}

    filtered = []
    for m in mappings:
        tech = index.lookup(m.technique_id)
        if tech is None or not tech.platforms:
            filtered.append(m)
            continue
        if any(p.lower() in platform_set for p in tech.platforms):
            filtered.append(m)

    return tuple(filtered)


def _get_default_index() -> TechniqueIndex | None:
    """Try to get the global TechniqueIndex singleton; return None if unavailable."""
    try:
        from knowledge.index import TechniqueIndex
        return TechniqueIndex.get()
    except Exception:
        logging.getLogger(__name__).debug(
            "TechniqueIndex singleton unavailable", exc_info=True,
        )
        return None


def map_rule_to_techniques(
    rule_id: str,
    context: dict | None = None,
    *,
    index: TechniqueIndex | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Map a rule id to technique references using the layered mapping engine.

    Layer 1: Curated rules (always applied)
    Layer 2: Tactic-based expansion (opt-in via mapping_config.toml)
    Layer 3: Context-based filtering (when context provides platform info)
    """
    if index is None:
        index = _get_default_index()
    curated = load_curated_mappings(rule_id, index=index)
    config = load_expansion_config()
    expanded = _expand_by_tactic(rule_id, config, index=index)
    filtered = _filter_by_context(expanded, context, index=index)
    return curated + filtered
