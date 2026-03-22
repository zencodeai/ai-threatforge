from __future__ import annotations

import re
import json
from dataclasses import dataclass
from typing import Any

from .observability import TraceRecorder, create_trace_recorder, new_run_id
from .state import AgentAnswer, AgentState, ToolCallRecord
from .tools import AgentTools


@dataclass(frozen=True)
class RoutedAction:
    name: str
    tool_name: str
    tool_input: dict[str, Any]


class QueryWorkflow:
    """Deterministic query workflow that routes analyst questions to tools."""

    _TECHNIQUE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?|AML\.T\d{4})\b", re.IGNORECASE)

    def __init__(self, tools: AgentTools | None = None, tracer: TraceRecorder | None = None):
        self.tools = tools or AgentTools()
        self.tracer = tracer or create_trace_recorder()

    def answer(self, question: str) -> tuple[AgentAnswer, AgentState]:
        run_id = new_run_id()
        state = AgentState(question=question)
        actions = self._route(question)

        if not actions:
            actions = [
                RoutedAction(
                    name="knowledge_search",
                    tool_name="search_knowledge",
                    tool_input={"query": question, "top_k": 5},
                )
            ]

        self.tracer.on_workflow_start(run_id, question, [action.tool_name for action in actions])

        for action in actions:
            response = self._run_action(action)
            state.tool_calls.append(
                ToolCallRecord(name=action.tool_name, tool_input=action.tool_input, response=response)
            )
            self.tracer.on_tool_result(run_id, action.tool_name, action.tool_input, response)

        answer = self._compose_answer(state)
        self.tracer.on_workflow_end(run_id, answer)
        return answer, state

    def _route(self, question: str) -> list[RoutedAction]:
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
        seen = set()
        for action in actions:
            key = self._action_key(action)
            if key not in seen:
                seen.add(key)
                unique_actions.append(action)
        return unique_actions

    @staticmethod
    def _action_key(action: RoutedAction) -> str:
        return f"{action.tool_name}:{json.dumps(action.tool_input, sort_keys=True, default=str)}"

    def _run_action(self, action: RoutedAction):
        if action.tool_name == "lookup_technique":
            return self.tools.lookup_technique(action.tool_input["technique_id"])
        if action.tool_name == "get_risks":
            return self.tools.get_risks(top_n=action.tool_input.get("top_n", 5))
        if action.tool_name == "get_threats":
            return self.tools.get_threats(
                filter_by=action.tool_input.get("filter_by"),
                top_n=action.tool_input.get("top_n", 5),
            )
        if action.tool_name == "query_graph":
            return self.tools.query_graph(
                action.tool_input["query"],
                action.tool_input.get("params"),
            )
        if action.tool_name == "search_knowledge":
            return self.tools.search_knowledge(
                action.tool_input["query"],
                top_k=action.tool_input.get("top_k", 5),
            )
        raise ValueError(f"Unsupported tool name: {action.tool_name}")

    def _compose_answer(self, state: AgentState) -> AgentAnswer:
        lines: list[str] = []
        evidence_refs: list[str] = []
        limitations: list[str] = []

        for call in state.tool_calls:
            response = call.response

            if not response.ok:
                if response.error:
                    limitations.append(
                        f"{call.name}: {response.error.code} - {response.error.message}"
                    )
                continue

            if not response.evidence:
                limitations.append(f"{call.name}: no evidence found")
                continue

            if call.name == "get_risks":
                top = response.evidence[0]
                lines.append(
                    "Top risk: "
                    f"{top.get('title')} on {top.get('target_id')} "
                    f"(score={top.get('risk_score')}, priority={top.get('priority')})."
                )
                for row in response.evidence[:3]:
                    risk_id = row.get("risk_id")
                    if risk_id:
                        evidence_refs.append(f"risk:{risk_id}")

            elif call.name == "get_threats":
                top = response.evidence[0]
                lines.append(
                    "Relevant threat: "
                    f"{top.get('rule_id')} targeting {top.get('target_id')} "
                    f"({top.get('title')})."
                )
                for row in response.evidence[:3]:
                    threat_id = row.get("threat_id")
                    if threat_id:
                        evidence_refs.append(f"threat:{threat_id}")

            elif call.name == "lookup_technique":
                first = response.evidence[0]
                lines.append(
                    "Technique mapping: "
                    f"{first.get('technique_id')} ({first.get('technique_name')}) "
                    f"under {first.get('framework')} / {first.get('tactic')}."
                )
                for row in response.evidence[:3]:
                    technique_id = row.get("technique_id")
                    if technique_id:
                        evidence_refs.append(f"technique:{technique_id}")

            elif call.name == "query_graph":
                lines.append(
                    f"Graph evidence returned {len(response.evidence)} row(s) for the routed query."
                )
                for idx, _row in enumerate(response.evidence[:3], start=1):
                    evidence_refs.append(f"graph:row-{idx}")

            elif call.name == "search_knowledge":
                lines.append(
                    f"Knowledge retrieval matched {len(response.evidence)} reference item(s)."
                )
                for row in response.evidence[:3]:
                    item_id = row.get("id")
                    if item_id:
                        evidence_refs.append(f"knowledge:{item_id}")

        if not lines:
            lines.append(
                "I could not gather grounded evidence for this question from available tools."
            )
            if not limitations:
                limitations.append("No tool returned usable evidence")

        answer_text = " ".join(lines)
        dedup_refs = list(dict.fromkeys(evidence_refs))
        dedup_limits = list(dict.fromkeys(limitations))
        return AgentAnswer(answer=answer_text, evidence_refs=dedup_refs, limitations=dedup_limits)

    @staticmethod
    def _extract_module_hint(question: str) -> str | None:
        # Accept module hints in forms like "for module api_gateway" or "about mobile_app".
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
