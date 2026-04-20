"""Tests for GraphVectorSearch — Cypher-based vector query against Neo4j."""

from __future__ import annotations

import pytest

from knowledge.graph_vector_search import GraphVectorSearch, VectorSearchResult


# ── Fake Neo4j client ───────────────────────────────────────────


class FakeVectorClient:
    """Fake client that returns predetermined vector search results."""

    def __init__(self, results: list[dict] | None = None) -> None:
        self.calls: list[tuple[str, dict | None]] = []
        self._results = results or []

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        return self._results

    def execute_write(self, query: str, parameters: dict | None = None) -> None:
        self.calls.append((query.strip(), parameters))


# ── Sample search results ──────────────────────────────────────


SAMPLE_TECHNIQUE_RESULTS = [
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "framework": "ATTACK",
        "score": 0.92,
        "tactics": ["initial-access"],
        "mitigations": ["Exploit Protection"],
        "subtechniques": ["T1190.001"],
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "framework": "ATTACK",
        "score": 0.85,
        "tactics": ["initial-access", "defense-evasion"],
        "mitigations": ["Account Use Policies", "Multi-factor Authentication"],
        "subtechniques": [],
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "framework": "ATTACK",
        "score": 0.78,
        "tactics": ["execution"],
        "mitigations": [],
        "subtechniques": ["T1059.001", "T1059.003"],
    },
]

SAMPLE_MITIGATION_RESULTS = [
    {
        "mitigation_id": "M1050",
        "name": "Exploit Protection",
        "score": 0.88,
        "techniques": ["T1190", "T1189"],
    },
    {
        "mitigation_id": "M1036",
        "name": "Account Use Policies",
        "score": 0.75,
        "techniques": ["T1078"],
    },
]


# ── Technique search tests ─────────────────────────────────────


class TestGraphVectorSearchTechniques:

    def test_search_returns_results(self) -> None:
        fake = FakeVectorClient(SAMPLE_TECHNIQUE_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384, top_k=10)
        assert len(results) == 3
        assert all(isinstance(r, VectorSearchResult) for r in results)

    def test_results_ordered_by_score(self) -> None:
        fake = FakeVectorClient(SAMPLE_TECHNIQUE_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384)
        assert results[0].score >= results[1].score >= results[2].score

    def test_result_fields_populated(self) -> None:
        fake = FakeVectorClient(SAMPLE_TECHNIQUE_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384)
        r = results[0]
        assert r.technique_id == "T1190"
        assert r.technique_name == "Exploit Public-Facing Application"
        assert r.framework == "ATTACK"
        assert r.score == 0.92
        assert "initial-access" in r.tactics
        assert "Exploit Protection" in r.mitigations
        assert "T1190.001" in r.subtechniques

    def test_exclude_filters_techniques(self) -> None:
        fake = FakeVectorClient(SAMPLE_TECHNIQUE_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384, exclude={"T1190"})
        ids = [r.technique_id for r in results]
        assert "T1190" not in ids
        assert "T1078" in ids

    def test_top_k_limits_results(self) -> None:
        fake = FakeVectorClient(SAMPLE_TECHNIQUE_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384, top_k=1)
        assert len(results) == 1
        assert results[0].technique_id == "T1190"

    def test_empty_results(self) -> None:
        fake = FakeVectorClient([])
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search([0.1] * 384)
        assert results == []

    def test_cypher_query_uses_vector_index(self) -> None:
        fake = FakeVectorClient([])
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        search.search([0.1] * 384, top_k=5, threshold=0.5)
        assert len(fake.calls) == 1
        query, params = fake.calls[0]
        assert "db.index.vector.queryNodes" in query
        assert "CHUNK_OF" in query
        assert params["index_name"] == "textchunk_embedding"
        assert params["fetch_k"] == 15  # 5 * 3
        assert params["threshold"] == 0.5

    def test_cypher_traverses_graph_context(self) -> None:
        fake = FakeVectorClient([])
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        search.search([0.1] * 384)
        query = fake.calls[0][0]
        assert "IN_TACTIC" in query
        assert "MITIGATED_BY" in query
        assert "IS_SUBTECHNIQUE_OF" in query


# ── Mitigation search tests ────────────────────────────────────


class TestGraphVectorSearchMitigations:

    def test_search_mitigations_returns_results(self) -> None:
        fake = FakeVectorClient(SAMPLE_MITIGATION_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search_mitigations([0.1] * 384)
        assert len(results) == 2
        assert results[0]["mitigation_id"] == "M1050"
        assert results[0]["score"] == 0.88

    def test_mitigation_results_include_techniques(self) -> None:
        fake = FakeVectorClient(SAMPLE_MITIGATION_RESULTS)
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search_mitigations([0.1] * 384)
        assert "T1190" in results[0]["techniques"]

    def test_mitigation_query_filters_entity_type(self) -> None:
        fake = FakeVectorClient([])
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        search.search_mitigations([0.1] * 384, top_k=5, threshold=0.3)
        query = fake.calls[0][0]
        assert "entity_type = 'mitigation'" in query

    def test_empty_mitigation_results(self) -> None:
        fake = FakeVectorClient([])
        search = GraphVectorSearch(fake)  # type: ignore[arg-type]
        results = search.search_mitigations([0.1] * 384)
        assert results == []
