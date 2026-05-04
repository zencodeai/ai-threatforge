from __future__ import annotations

from pathlib import Path

from graph.graph_queries import AGENT_GRAPH_QUERY_IDS, GraphQueries, load_sample_queries


ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __init__(self) -> None:
        self.last_query: str | None = None
        self.last_parameters: dict | None = None

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.last_query = query
        self.last_parameters = parameters
        return [{"ok": True}]


def test_load_sample_queries_returns_expected_count() -> None:
    queries = load_sample_queries(ROOT / "src" / "graph" / "cypher" / "sample_queries.cypher")
    assert len(queries) == 10


def test_internet_exposed_modules_query_executes() -> None:
    client = FakeClient()
    service = GraphQueries(client)  # type: ignore[arg-type]

    result = service.internet_exposed_modules()

    assert result == [{"ok": True}]
    assert client.last_query is not None
    assert "MATCH (m:Module)" in client.last_query


def test_high_privilege_query_passes_parameter() -> None:
    client = FakeClient()
    service = GraphQueries(client)  # type: ignore[arg-type]

    service.high_privilege_externally_reachable_modules(min_level=3)

    assert client.last_parameters == {"min_level": 3}


def test_attack_paths_query_passes_parameter() -> None:
    client = FakeClient()
    service = GraphQueries(client)  # type: ignore[arg-type]

    service.low_to_high_trust_attack_paths(max_depth=7)

    assert client.last_parameters == {"max_depth": 7}


def test_execute_dispatches_named_agent_query() -> None:
    client = FakeClient()
    service = GraphQueries(client)  # type: ignore[arg-type]

    result = service.execute(AGENT_GRAPH_QUERY_IDS["dependencies"])

    assert result == [{"ok": True}]
    assert client.last_query is not None
    assert "MATCH (s:Module)-[r:DEPENDS_ON]->(t)" in client.last_query
