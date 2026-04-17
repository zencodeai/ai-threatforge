from __future__ import annotations

import re
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RoutedAction:
    name: str
    tool_name: str
    tool_input: dict[str, Any]


class QueryRouter:
    """Route analyst questions to tool actions via deterministic keyword matching."""

    _TECHNIQUE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?|AML\.T\d{4})\b", re.IGNORECASE)

    def route(self, question: str) -> list[RoutedAction]:
        q = question.lower()
        actions: list[RoutedAction] = []

        technique_match = self._TECHNIQUE_PATTERN.search(question)
        if technique_match:
            actions.append(
                RoutedAction(
                    name="lookup_technique",
                    tool_name="lookup_technique",
                    tool_input={"technique_id": technique_match.group(1).upper()},
                )
            )

        if any(token in q for token in ("risk", "risks", "priority", "highest")):
            actions.append(
                RoutedAction(
                    name="get_risks",
                    tool_name="get_risks",
                    tool_input={"top_n": 5},
                )
            )

        if any(token in q for token in ("threat", "threats", "rule", "rules")):
            filter_by: dict[str, Any] = {}
            module = self._extract_module_hint(question)
            if module:
                filter_by["target_id"] = module
            actions.append(
                RoutedAction(
                    name="get_threats",
                    tool_name="get_threats",
                    tool_input={"filter_by": filter_by or None, "top_n": 5},
                )
            )

        if any(token in q for token in ("graph", "dependency", "dependencies", "trust boundary", "internet exposed")):
            cypher = self._graph_query_for_question(q)
            actions.append(
                RoutedAction(
                    name="query_graph",
                    tool_name="query_graph",
                    tool_input={"query": cypher, "params": None},
                )
            )

        if any(token in q for token in ("why", "explain", "how", "atlas", "attack", "mitre")):
            actions.append(
                RoutedAction(
                    name="search_knowledge",
                    tool_name="search_knowledge",
                    tool_input={"query": question, "top_k": 5},
                )
            )

        # Preserve deterministic order while removing duplicates.
        unique_actions: list[RoutedAction] = []
        seen: set[str] = set()
        for action in actions:
            key = _action_key(action)
            if key not in seen:
                seen.add(key)
                unique_actions.append(action)
        return unique_actions

    @staticmethod
    def _extract_module_hint(question: str) -> str | None:
        match = re.search(r"\b(?:module|about|for)\s+([a-z][a-z0-9_\-]+)\b", question, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _graph_query_for_question(question_lower: str) -> str:
        if "trust boundary" in question_lower:
            return (
                "MATCH (tb:TrustBoundary)-[:CROSSES_FROM]->(from:SecurityDomain), "
                "(tb)-[:CROSSES_TO]->(to:SecurityDomain) "
                "RETURN tb.id AS trust_boundary, from.id AS from_domain, to.id AS to_domain "
                "ORDER BY trust_boundary"
            )

        if "dependency" in question_lower:
            return (
                "MATCH (s:Module)-[r:DEPENDS_ON]->(t) "
                "RETURN s.id AS source, t.id AS target, r.relationship AS relationship "
                "ORDER BY source, target"
            )

        return (
            "MATCH (m:Module) "
            "WHERE m.internet_exposed = true "
            "RETURN m.id AS module_id, m.name AS module_name, m.module_type AS module_type "
            "ORDER BY m.id"
        )


def _action_key(action: RoutedAction) -> str:
    return f"{action.tool_name}:{json.dumps(action.tool_input, sort_keys=True, default=str)}"
