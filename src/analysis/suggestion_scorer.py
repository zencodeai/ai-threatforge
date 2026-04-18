"""Composite scoring for vector-based technique suggestions (Layer 0).

Blends dense-vector cosine similarity with structured metadata signals
(tactic overlap, framework match) to rank candidate technique bindings
for a given heuristic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Sequence

import numpy as np

if TYPE_CHECKING:
    from knowledge.index import TechniqueIndex
    from knowledge.vector_index import VectorIndex

    from .mapping_types import TechniqueMapping
    from .threat_generation import ThreatHeuristic

    from knowledge.embedder import TextEmbedder

__all__ = [
    "ScoredSuggestion",
    "ScoringWeights",
    "score_suggestions",
]


@dataclass(frozen=True)
class ScoredSuggestion:
    technique_id: str
    technique_name: str
    framework: str
    tactic: str
    vector_score: float
    tactic_bonus: float
    framework_bonus: float
    composite_score: float
    explanation: str


@dataclass(frozen=True)
class ScoringWeights:
    vector: float = 0.60
    tactic: float = 0.25
    framework: float = 0.15


_TACTIC_BONUS = 0.15
_FRAMEWORK_BONUS = 0.10


def score_suggestions(
    rule_id: str,
    heuristic_text: str,
    *,
    embedder: TextEmbedder,
    vector_index: VectorIndex,
    technique_index: TechniqueIndex,
    curated_mappings: Sequence[TechniqueMapping] = (),
    target_frameworks: tuple[str, ...] = (),
    weights: ScoringWeights = ScoringWeights(),
    top_k: int = 15,
) -> list[ScoredSuggestion]:
    """Score and rank technique suggestions for a heuristic.

    Parameters
    ----------
    rule_id:
        The heuristic rule ID (e.g. ``"TH-007"``).
    heuristic_text:
        The heuristic name + description, used as the query.
    embedder:
        Text embedder (must match the model used at sync time).
    vector_index:
        Pre-loaded vector index of technique embeddings.
    technique_index:
        The structured technique index for metadata lookups.
    curated_mappings:
        Existing curated mappings for this rule (excluded from results).
    target_frameworks:
        Frameworks declared by the heuristic (e.g. ``("ATLAS",)``).
    weights:
        Scoring weight configuration.
    top_k:
        Maximum number of suggestions to return.
    """
    if not vector_index.is_populated:
        return []

    curated_ids = {m.technique_id for m in curated_mappings}
    curated_tactics = {m.tactic for m in curated_mappings}
    fw_set = {fw.upper() for fw in target_frameworks}

    query_vector: np.ndarray = embedder.encode([heuristic_text])[0]

    # Over-fetch to allow re-ranking after bonuses
    candidates = vector_index.search(
        query_vector,
        top_k=top_k * 3,
        exclude=curated_ids,
    )

    results: list[ScoredSuggestion] = []
    for technique_id, vec_score in candidates:
        tech = technique_index.lookup(technique_id)
        if tech is None:
            continue

        # Pick the best tactic for display (prefer one that overlaps with curated)
        tech_tactics = list(tech.tactics)
        overlapping = [t for t in tech_tactics if t in curated_tactics]
        display_tactic = overlapping[0] if overlapping else (tech_tactics[0] if tech_tactics else "unknown")

        tactic_bonus = _TACTIC_BONUS if overlapping else 0.0
        framework_bonus = _FRAMEWORK_BONUS if (fw_set and tech.framework.upper() in fw_set) else 0.0

        composite = (
            weights.vector * vec_score
            + weights.tactic * tactic_bonus
            + weights.framework * framework_bonus
        )

        parts: list[str] = [f"vector={vec_score:.3f}"]
        if tactic_bonus:
            parts.append(f"tactic-overlap={display_tactic}")
        if framework_bonus:
            parts.append(f"framework-match={tech.framework}")
        explanation = f"Composite {composite:.3f}: {', '.join(parts)}"

        results.append(ScoredSuggestion(
            technique_id=technique_id,
            technique_name=tech.name,
            framework=tech.framework,
            tactic=display_tactic,
            vector_score=vec_score,
            tactic_bonus=tactic_bonus,
            framework_bonus=framework_bonus,
            composite_score=composite,
            explanation=explanation,
        ))

    results.sort(key=lambda s: -s.composite_score)
    return results[:top_k]
