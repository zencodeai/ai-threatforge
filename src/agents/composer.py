from __future__ import annotations

from .workflow_models import AgentAnswer, AgentState


class AnswerComposer:
    """Compose a grounded answer from tool call results."""

    def compose(self, state: AgentState) -> AgentAnswer:
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
                graph_intent = call.tool_input.get("graph_intent")
                lines.append(self._compose_graph_summary(graph_intent, response.evidence))
                for row in response.evidence[:3]:
                    evidence_refs.append(self._graph_evidence_ref(graph_intent, row))

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
    def _compose_graph_summary(graph_intent: str | None, evidence: list[dict]) -> str:
        shown = evidence[:3]
        extra = len(evidence) - len(shown)

        if graph_intent == "trust_boundaries":
            details = [
                f"{row.get('trust_boundary')}: {row.get('from_domain')} -> {row.get('to_domain')}"
                for row in shown
            ]
            suffix = f" and {extra} more." if extra > 0 else "."
            return "Trust boundary crossings: " + "; ".join(details) + suffix

        if graph_intent == "dependencies":
            details = [
                f"{row.get('source')} -> {row.get('target')} ({row.get('relationship')})"
                for row in shown
            ]
            suffix = f" and {extra} more." if extra > 0 else "."
            return "Dependency edges: " + "; ".join(details) + suffix

        if graph_intent == "internet_exposure":
            details = [
                f"{row.get('module_id')} ({row.get('module_type')})"
                for row in shown
            ]
            suffix = f" and {extra} more." if extra > 0 else "."
            return "Internet-exposed modules: " + "; ".join(details) + suffix

        return f"Graph evidence returned {len(evidence)} row(s)."

    @staticmethod
    def _graph_evidence_ref(graph_intent: str | None, row: dict) -> str:
        if graph_intent == "trust_boundaries":
            return f"graph:trust_boundary:{row.get('trust_boundary')}"
        if graph_intent == "dependencies":
            return f"graph:dependency:{row.get('source')}->{row.get('target')}"
        if graph_intent == "internet_exposure":
            return f"graph:module:{row.get('module_id')}"
        return "graph:row"
