from __future__ import annotations

from agents.router import QueryRouter


def test_router_emits_named_graph_query_for_dependencies() -> None:
    actions = QueryRouter().route("What dependencies exist between modules?")

    query_graph = next(action for action in actions if action.tool_name == "query_graph")

    assert query_graph.tool_input["graph_intent"] == "dependencies"
    assert query_graph.tool_input["query_id"] == "dependency_edges"


def test_router_emits_named_graph_query_for_trust_boundaries() -> None:
    actions = QueryRouter().route("Which trust boundary crossings are present?")

    query_graph = next(action for action in actions if action.tool_name == "query_graph")

    assert query_graph.tool_input["graph_intent"] == "trust_boundaries"
    assert query_graph.tool_input["query_id"] == "trust_boundary_crossings"
