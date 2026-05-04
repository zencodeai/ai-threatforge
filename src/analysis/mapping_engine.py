from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from knowledge.provider import KnowledgeProvider
from project_paths import ProjectPaths

from .mapping_loader import (
    load_curated_mappings,
    load_expansion_config,
    load_graphrag_config,
    load_suggested_mappings,
    load_suggestions_config,
)
from .mapping_types import TechniqueMapping
from .threat_heuristics import THREAT_HEURISTICS

if TYPE_CHECKING:
    from graph.neo4j_client import Neo4jClient
    from knowledge.embedder import TextEmbedder
    from knowledge.index import TechniqueIndex

    from .graphrag_scorer import GraphRAGSuggestion


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


def _get_default_index(
    *,
    knowledge_provider: KnowledgeProvider | None = None,
) -> TechniqueIndex | None:
    """Resolve the default knowledge index without using the legacy singleton path."""
    try:
        provider = knowledge_provider or KnowledgeProvider.from_paths(ProjectPaths.default())
        return provider.maybe_get_index()
    except Exception:
        logging.getLogger(__name__).debug(
            "Knowledge index unavailable", exc_info=True,
        )
        return None


def map_rule_to_techniques(
    rule_id: str,
    context: dict | None = None,
    *,
    index: TechniqueIndex | None = None,
    knowledge_provider: KnowledgeProvider | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Map a rule id to technique references using the layered mapping engine.

    Layer 1: Curated rules (always applied)
    Layer 2: Tactic-based expansion (opt-in via mapping_config.toml)
    Layer 3: Context-based filtering (when context provides platform info)
    """
    if index is None:
        index = _get_default_index(knowledge_provider=knowledge_provider)
    curated = load_curated_mappings(rule_id, index=index)
    suggestions_cfg = load_suggestions_config()
    suggested = (
        load_suggested_mappings(rule_id, index=index)
        if suggestions_cfg.get("include_suggested", False)
        else ()
    )
    config = load_expansion_config()
    expanded = _expand_by_tactic(rule_id, config, index=index)
    filtered = _filter_by_context(expanded, context, index=index)
    seen = {mapping.technique_id for mapping in curated}
    ordered_suggested = tuple(
        mapping for mapping in suggested
        if mapping.technique_id not in seen
    )
    seen.update(mapping.technique_id for mapping in ordered_suggested)
    ordered_filtered = tuple(
        mapping for mapping in filtered
        if mapping.technique_id not in seen
    )
    return curated + ordered_suggested + ordered_filtered


def graphrag_score_suggestions(
    rule_id: str,
    heuristic_text: str,
    *,
    neo4j_client: Neo4jClient,
    embedder: TextEmbedder,
    curated_mappings: tuple[TechniqueMapping, ...] = (),
    target_frameworks: tuple[str, ...] = (),
    module_controls: list[str] | None = None,
    top_k: int = 15,
    threshold: float = 0.0,
) -> list[GraphRAGSuggestion]:
    """Run the GraphRAG-enhanced Layer 0 scorer.

    This is the graph-aware alternative to :func:`suggestion_scorer.score_suggestions`.
    Requires a live Neo4j connection with MITRE knowledge graph and TextChunk
    vector index populated (via ``threatforge sync --neo4j``).

    Returns a list of :class:`~analysis.graphrag_scorer.GraphRAGSuggestion`.
    """
    from knowledge.graph_vector_search import GraphVectorSearch

    from .graphrag_scorer import GraphRAGScorer, GraphRAGScoringWeights

    cfg = load_graphrag_config()
    weights = GraphRAGScoringWeights(
        vector=cfg.get("weight_vector", 0.45),
        tactic=cfg.get("weight_tactic", 0.15),
        framework=cfg.get("weight_framework", 0.10),
        mitigation_gap=cfg.get("weight_mitigation_gap", 0.20),
        subtechnique=cfg.get("weight_subtechnique", 0.10),
    )

    graph_search = GraphVectorSearch(neo4j_client)
    scorer = GraphRAGScorer(neo4j_client, graph_search)

    return scorer.score(
        rule_id,
        heuristic_text,
        embedder=embedder,
        curated_mappings=curated_mappings,
        target_frameworks=target_frameworks,
        module_controls=module_controls,
        weights=weights,
        top_k=top_k,
        threshold=threshold,
    )
