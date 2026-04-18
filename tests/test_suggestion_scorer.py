"""Tests for analysis.suggestion_scorer — composite scoring logic."""

from __future__ import annotations

from typing import Sequence

import numpy as np
import pytest

from knowledge.models import Tactic, Technique
from knowledge.store import TechniqueStore


# ── Helpers ──────────────────────────────────────────────────────

class FixedEmbedder:
    """Embedder that returns a predetermined vector for the query."""

    _model_name = "fixed-test-model"
    _dimensions = 4

    def __init__(self, fixed_query: np.ndarray) -> None:
        self._fixed = fixed_query

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        return np.tile(self._fixed, (len(texts), 1))


def _norm(v: list[float]) -> np.ndarray:
    a = np.array(v, dtype=np.float32)
    return a / np.linalg.norm(a)


def _make_techniques() -> list[Technique]:
    return [
        Technique("T1190", "Exploit Public-Facing Application", "ATTACK", "enterprise",
                  "Exploit internet-facing software.",
                  False, None, ("Linux",), ("initial-access",), False, ""),
        Technique("T1021", "Remote Services", "ATTACK", "enterprise",
                  "Use remote services for lateral movement.",
                  False, None, ("Linux",), ("lateral-movement",), False, ""),
        Technique("T1485", "Data Destruction", "ATTACK", "enterprise",
                  "Destroy data to disrupt availability.",
                  False, None, ("Linux",), ("impact",), False, ""),
        Technique("AML.T0016", "Data Poisoning", "ATLAS", "atlas",
                  "Adversaries may poison training data.",
                  False, None, (), ("ml-attack-staging",), False, ""),
    ]


def _make_store_and_indices(tmp_path, query_vec: np.ndarray, tech_vecs: dict[str, np.ndarray]):
    """Build store, vector index, and technique index with predetermined vectors."""
    from knowledge.index import TechniqueIndex
    from knowledge.vector_index import VectorIndex

    techniques = _make_techniques()
    tactics = [
        Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0),
        Tactic("TA0008", "Lateral Movement", "ATTACK", "enterprise", "lateral-movement", 7),
        Tactic("TA0040", "Impact", "ATTACK", "enterprise", "impact", 12),
        Tactic("AML.TA0002", "ML Attack Staging", "ATLAS", "atlas", "ml-attack-staging", 1),
    ]

    db = tmp_path / "scorer_test.db"
    store = TechniqueStore(db)
    store.replace_all(tactics=tactics, techniques=techniques, mitigations=[])

    # Insert predetermined embeddings for each technique
    ids = list(tech_vecs.keys())
    vecs = np.stack([tech_vecs[tid] for tid in ids])
    hashes = [f"h_{tid}" for tid in ids]
    store.upsert_embeddings(
        entity_ids=ids,
        entity_type="technique",
        model_name="fixed-test-model",
        vectors=vecs,
        text_hashes=hashes,
    )

    vec_idx = VectorIndex(store, "fixed-test-model")
    tech_idx = TechniqueIndex(store)
    return store, vec_idx, tech_idx


# ── Tests ────────────────────────────────────────────────────────

def test_score_suggestions_basic_ranking(tmp_path):
    from analysis.suggestion_scorer import score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),   # high similarity
        "T1021": _norm([0.3, 0.7, 0.1, 0.0]),   # medium
        "T1485": _norm([0.0, 0.0, 0.1, 0.9]),   # low
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),  # medium-high
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
    )

    assert len(results) > 0
    # Results should be sorted by composite score descending
    scores = [r.composite_score for r in results]
    assert scores == sorted(scores, reverse=True)
    store.close()


def test_score_suggestions_excludes_curated(tmp_path):
    from analysis.mapping_types import TechniqueMapping
    from analysis.suggestion_scorer import score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
        "T1021": _norm([0.3, 0.7, 0.1, 0.0]),
        "T1485": _norm([0.0, 0.0, 0.1, 0.9]),
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    curated = [
        TechniqueMapping("TH-TEST", "ATTACK", "T1190", "Exploit", "initial-access", "test", "curated"),
    ]

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        curated_mappings=curated,
    )

    result_ids = {r.technique_id for r in results}
    assert "T1190" not in result_ids
    store.close()


def test_tactic_bonus_applied(tmp_path):
    from analysis.mapping_types import TechniqueMapping
    from analysis.suggestion_scorer import ScoringWeights, score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    # Make T1021 and T1485 have identical vector scores
    shared = _norm([0.6, 0.6, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
        "T1021": shared.copy(),
        "T1485": shared.copy(),
        "AML.T0016": _norm([0.0, 0.0, 0.0, 1.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    # Curated mapping targets lateral-movement tactic
    curated = [
        TechniqueMapping("TH-TEST", "ATTACK", "T1190", "Exploit", "lateral-movement", "test", "curated"),
    ]

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        curated_mappings=curated,
    )

    # T1021 has tactic lateral-movement matching curated, T1485 has impact (no match)
    t1021 = next(r for r in results if r.technique_id == "T1021")
    t1485 = next(r for r in results if r.technique_id == "T1485")
    assert t1021.tactic_bonus > 0
    assert t1485.tactic_bonus == 0
    assert t1021.composite_score > t1485.composite_score
    store.close()


def test_framework_bonus_applied(tmp_path):
    from analysis.suggestion_scorer import score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.5, 0.5, 0.0, 0.0]),
        "T1021": _norm([0.5, 0.5, 0.0, 0.0]),
        "T1485": _norm([0.5, 0.5, 0.0, 0.0]),
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        target_frameworks=("ATLAS",),
    )

    atlas_result = next(r for r in results if r.technique_id == "AML.T0016")
    attack_result = next(r for r in results if r.technique_id == "T1190")
    assert atlas_result.framework_bonus > 0
    assert attack_result.framework_bonus == 0
    assert atlas_result.composite_score > attack_result.composite_score
    store.close()


def test_empty_vector_index_returns_empty(tmp_path):
    from knowledge.index import TechniqueIndex
    from knowledge.vector_index import VectorIndex
    from analysis.suggestion_scorer import score_suggestions

    store = TechniqueStore(tmp_path / "empty.db")
    store.replace_all(tactics=[], techniques=[], mitigations=[])
    vec_idx = VectorIndex(store, "fixed-test-model")
    tech_idx = TechniqueIndex(store)

    query = _norm([1.0, 0.0, 0.0, 0.0])
    embedder = FixedEmbedder(query)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
    )
    assert results == []
    store.close()


def test_top_k_limits_results(tmp_path):
    from analysis.suggestion_scorer import score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
        "T1021": _norm([0.3, 0.7, 0.1, 0.0]),
        "T1485": _norm([0.0, 0.0, 0.1, 0.9]),
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        top_k=2,
    )
    assert len(results) <= 2
    store.close()


def test_suggestion_has_explanation(tmp_path):
    from analysis.suggestion_scorer import score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
        "T1021": _norm([0.3, 0.7, 0.1, 0.0]),
        "T1485": _norm([0.0, 0.0, 0.1, 0.9]),
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
    )

    for r in results:
        assert r.explanation
        assert "Composite" in r.explanation
        assert "vector=" in r.explanation
    store.close()


def test_scoring_weights_custom(tmp_path):
    from analysis.suggestion_scorer import ScoringWeights, score_suggestions

    query = _norm([1.0, 0.0, 0.0, 0.0])
    tech_vecs = {
        "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
        "T1021": _norm([0.3, 0.7, 0.1, 0.0]),
        "T1485": _norm([0.0, 0.0, 0.1, 0.9]),
        "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
    }

    store, vec_idx, tech_idx = _make_store_and_indices(tmp_path, query, tech_vecs)
    embedder = FixedEmbedder(query)

    # All weight on vector, none on bonuses
    weights = ScoringWeights(vector=1.0, tactic=0.0, framework=0.0)

    results = score_suggestions(
        rule_id="TH-TEST",
        heuristic_text="Test heuristic",
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        weights=weights,
    )

    for r in results:
        assert r.composite_score == pytest.approx(r.vector_score, abs=1e-5)
    store.close()
