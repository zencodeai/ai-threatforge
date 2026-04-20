"""Tests for the GraphRAG-enhanced technique suggestion scorer."""

from __future__ import annotations

import pytest

from analysis.graphrag_scorer import (
    GraphRAGScorer,
    GraphRAGScoringWeights,
    GraphRAGSuggestion,
    _compute_mitigation_gap,
    _compute_subtechnique_bonus,
)
from analysis.mapping_types import TechniqueMapping


# ── Fake collaborators ────────────────────────────────────────────


class FakeNeo4jClient:
    """Fake Neo4j client that returns predetermined mitigation data."""

    def __init__(self, mitigation_rows: list[dict] | None = None) -> None:
        self.calls: list[tuple[str, dict | None]] = []
        self._mitigation_rows = mitigation_rows or []

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        return self._mitigation_rows


class FakeGraphVectorSearch:
    """Fake vector search returning predetermined VectorSearchResult-like objects."""

    def __init__(self, results: list | None = None) -> None:
        self._results = results or []

    def search(
        self,
        query_vector: list[float],
        *,
        top_k: int = 20,
        exclude: set[str] | None = None,
    ) -> list:
        exclude = exclude or set()
        return [r for r in self._results if r.technique_id not in exclude]


class FakeEmbedder:
    """Fake embedder returning a fixed vector."""

    model_name = "test-model"
    dimensions = 384

    def encode(self, texts: list[str]):
        import numpy as np

        return np.ones((len(texts), 384), dtype="float32") * 0.1


class FakeVectorResult:
    """Mimics VectorSearchResult for testing."""

    def __init__(
        self,
        technique_id: str,
        technique_name: str,
        framework: str,
        score: float,
        tactics: list[str] | None = None,
        mitigations: list[str] | None = None,
        subtechniques: list[str] | None = None,
    ) -> None:
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.framework = framework
        self.score = score
        self.tactics = tactics or []
        self.mitigations = mitigations or []
        self.subtechniques = subtechniques or []


# ── Sample data ───────────────────────────────────────────────────


SAMPLE_VECTOR_RESULTS = [
    FakeVectorResult(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        framework="ATTACK",
        score=0.92,
        tactics=["initial-access"],
        mitigations=["Exploit Protection"],
    ),
    FakeVectorResult(
        technique_id="T1059.001",
        technique_name="PowerShell",
        framework="ATTACK",
        score=0.85,
        tactics=["execution"],
        mitigations=[],
        subtechniques=[],
    ),
    FakeVectorResult(
        technique_id="T1078",
        technique_name="Valid Accounts",
        framework="ATTACK",
        score=0.78,
        tactics=["initial-access", "defense-evasion"],
        mitigations=["Account Use Policies", "Multi-factor Authentication"],
    ),
]

SAMPLE_CURATED = (
    TechniqueMapping(
        rule_id="TH-007",
        framework="ATTACK",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        mapping_rationale="Curated mapping",
        mapping_type="curated",
    ),
)


# ── Mitigation gap tests ─────────────────────────────────────────


class TestComputeMitigationGap:

    def test_no_mitigations_returns_full_gap(self) -> None:
        assert _compute_mitigation_gap([], set()) == 1.0

    def test_no_controls_returns_full_gap(self) -> None:
        assert _compute_mitigation_gap(["M1050"], set()) == 1.0

    def test_fully_mitigated(self) -> None:
        assert _compute_mitigation_gap(["M1050", "M1036"], {"M1050", "M1036"}) == 0.0

    def test_partially_mitigated(self) -> None:
        gap = _compute_mitigation_gap(["M1050", "M1036"], {"M1050"})
        assert gap == pytest.approx(0.5)

    def test_no_overlap(self) -> None:
        gap = _compute_mitigation_gap(["M1050"], {"M9999"})
        assert gap == 1.0


# ── Sub-technique bonus tests ────────────────────────────────────


class TestComputeSubtechniqueBonus:

    def test_subtechnique_of_curated_parent(self) -> None:
        assert _compute_subtechnique_bonus("T1059.001", {"T1059"}) == 1.0

    def test_subtechnique_no_parent_match(self) -> None:
        assert _compute_subtechnique_bonus("T1059.001", {"T1190"}) == 0.0

    def test_parent_technique_no_bonus(self) -> None:
        assert _compute_subtechnique_bonus("T1059", {"T1059"}) == 0.0

    def test_empty_parents(self) -> None:
        assert _compute_subtechnique_bonus("T1059.001", set()) == 0.0


# ── GraphRAGScorer integration tests ─────────────────────────────


class TestGraphRAGScorer:

    def _make_scorer(
        self,
        vector_results: list | None = None,
        mitigation_rows: list[dict] | None = None,
    ) -> GraphRAGScorer:
        client = FakeNeo4jClient(mitigation_rows or [])
        search = FakeGraphVectorSearch(
            SAMPLE_VECTOR_RESULTS if vector_results is None else vector_results,
        )
        return GraphRAGScorer(client, search)  # type: ignore[arg-type]

    def test_returns_suggestions(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Command injection via scripting interpreters",
            embedder=FakeEmbedder(),
        )
        assert len(results) > 0
        assert all(isinstance(r, GraphRAGSuggestion) for r in results)

    def test_excludes_curated_techniques(self) -> None:
        # T1059 is curated; results should not include it
        # (but T1059.001 is a sub-technique and should still appear)
        curated = (
            TechniqueMapping(
                rule_id="TH-007",
                framework="ATTACK",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="initial-access",
                mapping_rationale="Curated",
                mapping_type="curated",
            ),
        )
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Exploit detection",
            embedder=FakeEmbedder(),
            curated_mappings=curated,
        )
        ids = [r.technique_id for r in results]
        assert "T1190" not in ids

    def test_results_sorted_by_composite_score(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Command injection",
            embedder=FakeEmbedder(),
        )
        scores = [r.composite_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_subtechnique_bonus_applied(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Command injection",
            embedder=FakeEmbedder(),
            curated_mappings=SAMPLE_CURATED,
        )
        sub = next((r for r in results if r.technique_id == "T1059.001"), None)
        assert sub is not None
        assert sub.subtechnique_bonus == 1.0

    def test_tactic_overlap_bonus(self) -> None:
        curated_with_tactic = (
            TechniqueMapping(
                rule_id="TH-007",
                framework="ATTACK",
                technique_id="T9999",
                technique_name="Dummy",
                tactic="initial-access",
                mapping_rationale="Curated",
                mapping_type="curated",
            ),
        )
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Access exploitation",
            embedder=FakeEmbedder(),
            curated_mappings=curated_with_tactic,
        )
        ia_result = next((r for r in results if "initial-access" in r.tactic), None)
        assert ia_result is not None
        assert ia_result.tactic_bonus == 1.0

    def test_framework_bonus_applied(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "MITRE ATT&CK technique",
            embedder=FakeEmbedder(),
            target_frameworks=("ATTACK",),
        )
        for r in results:
            assert r.framework_bonus == 1.0

    def test_threshold_filters_low_scores(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Test query",
            embedder=FakeEmbedder(),
            threshold=0.99,
        )
        # With threshold=0.99, most or all results should be filtered
        for r in results:
            assert r.composite_score >= 0.99

    def test_top_k_limits_output(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Test query",
            embedder=FakeEmbedder(),
            top_k=1,
        )
        assert len(results) <= 1

    def test_mitigation_gap_with_controls(self) -> None:
        mitigation_rows = [
            {
                "technique_id": "T1190",
                "mitigation_ids": ["M1050", "M1036"],
            },
        ]
        scorer = self._make_scorer(mitigation_rows=mitigation_rows)
        results = scorer.score(
            "TH-007",
            "Exploit detection",
            embedder=FakeEmbedder(),
            module_controls=["M1050"],
        )
        t1190 = next((r for r in results if r.technique_id == "T1190"), None)
        assert t1190 is not None
        # 1 of 2 mitigations implemented → gap = 0.5
        assert t1190.mitigation_gap_score == pytest.approx(0.5)

    def test_explanation_contains_vector_score(self) -> None:
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Test",
            embedder=FakeEmbedder(),
        )
        for r in results:
            assert "GraphRAG" in r.explanation
            assert "vector=" in r.explanation

    def test_custom_weights(self) -> None:
        weights = GraphRAGScoringWeights(
            vector=1.0, tactic=0.0, framework=0.0,
            mitigation_gap=0.0, subtechnique=0.0,
        )
        scorer = self._make_scorer()
        results = scorer.score(
            "TH-007",
            "Test",
            embedder=FakeEmbedder(),
            weights=weights,
        )
        for r in results:
            # With only vector weight=1.0, composite should equal vector_score
            assert r.composite_score == pytest.approx(r.vector_score)

    def test_empty_vector_results(self) -> None:
        scorer = self._make_scorer(vector_results=[])
        results = scorer.score(
            "TH-007",
            "No results expected",
            embedder=FakeEmbedder(),
        )
        assert results == []


# ── GraphRAGScoringWeights tests ──────────────────────────────────


class TestGraphRAGScoringWeights:

    def test_defaults_sum_to_one(self) -> None:
        w = GraphRAGScoringWeights()
        total = w.vector + w.tactic + w.framework + w.mitigation_gap + w.subtechnique
        assert total == pytest.approx(1.0)

    def test_custom_weights(self) -> None:
        w = GraphRAGScoringWeights(vector=0.50, tactic=0.20, framework=0.10, mitigation_gap=0.10, subtechnique=0.10)
        assert w.vector == 0.50
        assert w.tactic == 0.20

    def test_invalid_weights_rejected(self) -> None:
        with pytest.raises(ValueError, match="sum to"):
            GraphRAGScoringWeights(vector=0.9, tactic=0.9)
