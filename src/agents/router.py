from __future__ import annotations

import re
import json
from dataclasses import dataclass
from typing import Any

from graph.graph_queries import AGENT_GRAPH_QUERY_IDS


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

        if self._contains_any(q, ("risk", "risks", "priority", "highest")):
            actions.append(
                RoutedAction(
                    name="get_risks",
                    tool_name="get_risks",
                    tool_input={"top_n": 5},
                )
            )

        if self._contains_any(q, ("threat", "threats", "rule", "rules")):
            filter_by: dict[str, Any] = {}
            module = self._extract_module_hint(question)
            if module:
                filter_by["target_id"] = module
            if "atlas" in q or "ai" in q:
                filter_by["framework"] = "ATLAS"
            actions.append(
                RoutedAction(
                    name="get_threats",
                    tool_name="get_threats",
                    tool_input={"filter_by": filter_by or None, "top_n": 5},
                )
            )

        graph_intent = self._graph_intent_for_question(q)
        if graph_intent is not None:
            actions.append(
                RoutedAction(
                    name="query_graph",
                    tool_name="query_graph",
                    tool_input={
                        "query_id": AGENT_GRAPH_QUERY_IDS[graph_intent],
                        "params": None,
                        "graph_intent": graph_intent,
                    },
                )
            )

        if self._contains_any(q, ("why", "explain", "how", "atlas", "attack", "mitre")):
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
        match = re.search(r"\bfor\s+module\s+([a-z][a-z0-9_\-]+)\b", question, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r"\bmodule\s+([a-z][a-z0-9_\-]+)\b", question, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r"\b(?:about|for)\s+([a-z][a-z0-9_\-]+)\b", question, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _graph_intent_for_question(question_lower: str) -> str | None:
        if "trust boundary" in question_lower:
            return "trust_boundaries"

        if "dependency" in question_lower or "dependencies" in question_lower:
            return "dependencies"

        if "graph" in question_lower or "internet exposed" in question_lower:
            return "internet_exposure"

        return None

    @staticmethod
    def _contains_any(question_lower: str, terms: tuple[str, ...]) -> bool:
        return any(
            re.search(rf"\b{re.escape(term)}\b", question_lower)
            for term in terms
        )

def _action_key(action: RoutedAction) -> str:
    return f"{action.tool_name}:{json.dumps(action.tool_input, sort_keys=True, default=str)}"
