"""GraphRAG-enhanced technique suggestion scorer (Layer 0 replacement).

Combines Neo4j vector search over TextChunk nodes with graph traversal
signals (mitigation gaps, sub-technique relevance, tactic overlap) to
produce higher-quality technique suggestions than the flat composite
scorer in :mod:`suggestion_scorer`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from graph.neo4j_client import Neo4jClient
    from knowledge.embedder import TextEmbedder
    from knowledge.graph_vector_search import GraphVectorSearch, VectorSearchResult

    from .mapping_types import TechniqueMapping

__all__ = [
    "GraphRAGScorer",
    "GraphRAGScoringWeights",
    "GraphRAGSuggestion",
]

_log = logging.getLogger(__name__)


# ── Data classes ────────────────────────────────────────────────


@dataclass(frozen=True)
class GraphRAGScoringWeights:
    """Weight configuration for the GraphRAG composite scorer."""

    vector: float = 0.45
    tactic: float = 0.15
    framework: float = 0.10
    mitigation_gap: float = 0.20
    subtechnique: float = 0.10


@dataclass(frozen=True)
class GraphRAGSuggestion:
    """A single scored technique suggestion from the GraphRAG scorer."""

    technique_id: str
    technique_name: str
    framework: str
    tactic: str
    vector_score: float
    tactic_bonus: float
    framework_bonus: float
    mitigation_gap_score: float
    subtechnique_bonus: float
    composite_score: float
    explanation: str
    mitigations: list[str] = field(default_factory=list)


# ── Scorer ──────────────────────────────────────────────────────


class GraphRAGScorer:
    """Graph-aware technique suggestion scorer.

    Uses :class:`~knowledge.graph_vector_search.GraphVectorSearch` for
    semantic retrieval, then re-ranks candidates using graph-structural
    signals from the MITRE knowledge sub-graph.
    """

    def __init__(
        self,
        client: Neo4jClient,
        graph_search: GraphVectorSearch,
    ) -> None:
        self.client = client
        self.graph_search = graph_search

    def score(
        self,
        rule_id: str,
        heuristic_text: str,
        *,
        embedder: TextEmbedder,
        curated_mappings: Sequence[TechniqueMapping] = (),
        target_frameworks: tuple[str, ...] = (),
        module_controls: list[str] | None = None,
        weights: GraphRAGScoringWeights = GraphRAGScoringWeights(),
        top_k: int = 15,
        threshold: float = 0.0,
    ) -> list[GraphRAGSuggestion]:
        """Score and rank technique suggestions for a heuristic.

        Parameters
        ----------
        rule_id:
            The heuristic rule ID (e.g. ``"TH-007"``).
        heuristic_text:
            Heuristic name + description used as the query.
        embedder:
            Text embedder (must match the model used at chunk time).
        curated_mappings:
            Existing curated mappings for this rule (excluded from results).
        target_frameworks:
            Frameworks declared by the heuristic.
        module_controls:
            Control functions of the target module (for mitigation-gap scoring).
            When ``None``, mitigation gap defaults to 1.0 (full gap).
        weights:
            Scoring weight configuration.
        top_k:
            Maximum number of suggestions to return.
        threshold:
            Minimum composite score for inclusion.
        """
        import numpy as np

        # Encode query
        query_vector: np.ndarray = embedder.encode([heuristic_text])[0]

        # Exclude curated technique IDs
        curated_ids = {m.technique_id for m in curated_mappings}
        curated_tactics = {m.tactic for m in curated_mappings}
        curated_parents = self._resolve_parent_ids(curated_ids)
        fw_set = {fw.upper() for fw in target_frameworks}

        # Vector search with graph expansion
        search_results = self.graph_search.search(
            query_vector.tolist(),
            top_k=top_k * 3,
            exclude=curated_ids,
        )

        # Fetch mitigation IDs for gap scoring
        mitigation_ids_by_technique = self._fetch_mitigation_ids(
            [r.technique_id for r in search_results]
        )

        controls = set(module_controls) if module_controls else set()

        # Score each candidate
        suggestions: list[GraphRAGSuggestion] = []
        for result in search_results:
            # Tactic overlap
            overlapping_tactics = [t for t in result.tactics if t in curated_tactics]
            display_tactic = (
                overlapping_tactics[0]
                if overlapping_tactics
                else (result.tactics[0] if result.tactics else "unknown")
            )
            tactic_bonus = 1.0 if overlapping_tactics else 0.0

            # Framework match
            framework_bonus = (
                1.0 if (fw_set and result.framework.upper() in fw_set) else 0.0
            )

            # Mitigation gap
            mit_ids = mitigation_ids_by_technique.get(result.technique_id, [])
            mitigation_gap = _compute_mitigation_gap(mit_ids, controls)

            # Sub-technique bonus
            subtechnique_bonus = _compute_subtechnique_bonus(
                result.technique_id, curated_parents,
            )

            # Composite
            composite = (
                weights.vector * result.score
                + weights.tactic * tactic_bonus
                + weights.framework * framework_bonus
                + weights.mitigation_gap * mitigation_gap
                + weights.subtechnique * subtechnique_bonus
            )

            if composite < threshold:
                continue

            # Explanation
            parts = [f"vector={result.score:.3f}"]
            if tactic_bonus:
                parts.append(f"tactic-overlap={display_tactic}")
            if framework_bonus:
                parts.append(f"framework-match={result.framework}")
            if mitigation_gap > 0:
                parts.append(f"mit-gap={mitigation_gap:.2f}")
            if subtechnique_bonus:
                parts.append("subtechnique-match")
            explanation = f"GraphRAG {composite:.3f}: {', '.join(parts)}"

            suggestions.append(GraphRAGSuggestion(
                technique_id=result.technique_id,
                technique_name=result.technique_name,
                framework=result.framework,
                tactic=display_tactic,
                vector_score=result.score,
                tactic_bonus=tactic_bonus,
                framework_bonus=framework_bonus,
                mitigation_gap_score=mitigation_gap,
                subtechnique_bonus=subtechnique_bonus,
                composite_score=composite,
                explanation=explanation,
                mitigations=result.mitigations,
            ))

        suggestions.sort(key=lambda s: -s.composite_score)
        return suggestions[:top_k]

    def _resolve_parent_ids(self, technique_ids: set[str]) -> set[str]:
        """Extract parent technique IDs from a set of curated technique IDs.

        For example, if curated has ``T1059``, returns ``{"T1059"}`` so that
        sub-techniques like ``T1059.001`` get a bonus.
        """
        parents: set[str] = set()
        for tid in technique_ids:
            if "." not in tid:
                parents.add(tid)
            else:
                parents.add(tid.rsplit(".", 1)[0])
        return parents

    def _fetch_mitigation_ids(
        self,
        technique_ids: list[str],
    ) -> dict[str, list[str]]:
        """Fetch mitigation IDs for each technique from the graph."""
        if not technique_ids:
            return {}

        rows = self.client.run_query(
            """
            UNWIND $technique_ids AS tid
            MATCH (tech:Technique {technique_id: tid})-[:MITIGATED_BY]->(mit:Mitigation)
            RETURN tech.technique_id AS technique_id,
                   collect(mit.mitigation_id) AS mitigation_ids
            """,
            {"technique_ids": technique_ids},
        )
        return {
            row["technique_id"]: row["mitigation_ids"]
            for row in rows
        }


# ── Scoring helpers ─────────────────────────────────────────────


def _compute_mitigation_gap(
    technique_mitigation_ids: list[str],
    module_controls: set[str],
) -> float:
    """Compute mitigation gap score (0.0 = fully mitigated, 1.0 = fully unmitigated).

    ``gap = 1.0 - (implemented / total)``

    If the technique has no known mitigations or no module controls are
    provided, the gap defaults to 1.0 (assume full gap).
    """
    if not technique_mitigation_ids or not module_controls:
        return 1.0

    implemented = sum(
        1 for mid in technique_mitigation_ids if mid in module_controls
    )
    return 1.0 - (implemented / len(technique_mitigation_ids))


def _compute_subtechnique_bonus(
    technique_id: str,
    curated_parent_ids: set[str],
) -> float:
    """Return 1.0 if the technique is a sub-technique of a curated parent.

    A technique like ``T1059.001`` gets a bonus if ``T1059`` is in the
    curated parent set, indicating the scorer has found a more specific
    variant of an already-mapped technique.
    """
    if "." not in technique_id:
        return 0.0
    parent = technique_id.rsplit(".", 1)[0]
    return 1.0 if parent in curated_parent_ids else 0.0
