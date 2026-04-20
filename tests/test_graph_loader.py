from __future__ import annotations

import os
from pathlib import Path

import pytest

from graph.graph_loader import GraphLoader, load_model_into_graph
from graph.neo4j_client import Neo4jClient, Neo4jConfig
from models.schema.canonical_model import load_canonical_model


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def execute_write(self, query: str, parameters: dict | None = None) -> None:
        self.calls.append((query.strip(), parameters))

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        return [{"node_count": 1, "rel_count": 1}]


def test_apply_schema_reads_constraints_and_indexes() -> None:
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]

    loader.apply_schema(ROOT / "src" / "graph")

    executed_queries = [query for query, _ in fake.calls]
    assert any("CREATE CONSTRAINT system_id_unique" in q for q in executed_queries)
    assert any("CREATE INDEX module_internet_exposed_idx" in q for q in executed_queries)


def test_load_model_runs_core_merges() -> None:
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)

    stats = loader.load_model(model)

    executed_queries = [query for query, _ in fake.calls]
    assert any("MERGE (s:System {id: $id})" in q for q in executed_queries)
    assert any("MERGE (m)-[:IN_DOMAIN]->(d)" in q for q in executed_queries)
    assert any("MERGE (source)-[r:DEPENDS_ON" in q for q in executed_queries)
    assert stats.nodes_created == 1
    assert stats.relationships_created == 1


def test_module_enrichment_properties_in_cypher() -> None:
    """Verify new Module properties appear in the MERGE SET clause."""
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)
    loader.load_model(model)

    module_queries = [q for q, _ in fake.calls if "MERGE (m:Module" in q]
    assert module_queries, "No Module MERGE query found"
    q = module_queries[0]
    for prop in (
        "authentication_required", "input_validation", "rate_limiting",
        "logging_enabled", "api_endpoints", "deployment_context",
    ):
        assert f"m.{prop}" in q, f"Missing {prop} in Module MERGE"


def test_dependency_enrichment_properties_in_cypher() -> None:
    """Verify new Dependency properties appear in the DEPENDS_ON SET clause."""
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)
    loader.load_model(model)

    dep_queries = [q for q, _ in fake.calls if "MERGE (source)-[r:DEPENDS_ON" in q]
    assert dep_queries, "No DEPENDS_ON MERGE query found"
    q = dep_queries[0]
    assert "r.encryption_in_transit" in q
    assert "r.data_flow_direction" in q


def test_module_enrichment_batch_data() -> None:
    """Verify batch data includes enrichment values from the model."""
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)
    loader.load_model(model)

    module_calls = [
        (q, p) for q, p in fake.calls
        if "MERGE (m:Module" in q and p and "batch" in p
    ]
    assert module_calls
    batch = module_calls[0][1]["batch"]
    gateway = next(m for m in batch if m["id"] == "api_gateway")
    assert gateway["authentication_required"] is True
    assert gateway["rate_limiting"] is True
    assert len(gateway["api_endpoints"]) > 0


# ── Phase 4 control-gap detection tests ─────────────────────────


def test_control_functions_in_cypher() -> None:
    """Verify control_functions appears in the Module MERGE SET clause."""
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)
    loader.load_model(model)

    module_queries = [q for q, _ in fake.calls if "MERGE (m:Module" in q]
    assert module_queries
    assert "m.control_functions" in module_queries[0]


def test_control_functions_batch_data() -> None:
    """Verify batch data includes control_functions from the model."""
    fake = FakeClient()
    loader = GraphLoader(fake)  # type: ignore[arg-type]
    model = load_canonical_model(EXAMPLE_MODEL)
    loader.load_model(model)

    module_calls = [
        (q, p) for q, p in fake.calls
        if "MERGE (m:Module" in q and p and "batch" in p
    ]
    assert module_calls
    batch = module_calls[0][1]["batch"]
    gateway = next(m for m in batch if m["id"] == "api_gateway")
    assert "AC-4" in gateway["control_functions"]
    assert "SC-7" in gateway["control_functions"]


@pytest.mark.integration
def test_load_model_into_graph_integration() -> None:
    required = ["NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"]
    if not all(os.getenv(key) for key in required):
        pytest.skip("Neo4j environment variables not set for integration test")

    stats = load_model_into_graph(EXAMPLE_MODEL, clear_graph=True)

    assert stats.nodes_created > 0
    assert stats.relationships_created > 0


@pytest.mark.integration
def test_loader_is_idempotent_integration() -> None:
    required = ["NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"]
    if not all(os.getenv(key) for key in required):
        pytest.skip("Neo4j environment variables not set for integration test")

    cfg = Neo4jConfig.from_env()
    with Neo4jClient(cfg) as client:
        loader = GraphLoader(client)
        model = load_canonical_model(EXAMPLE_MODEL)

        loader.apply_schema()
        loader.clear_graph()
        first = loader.load_model(model)
        second = loader.load_model(model)

    assert first.nodes_created == second.nodes_created
    assert first.relationships_created == second.relationships_created
