from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from analysis.mapping_catalog import get_all_technique_mappings
from analysis.threat_generation import THREAT_HEURISTICS
from artifact_locator import ArtifactLocator
from graph.graph_queries import GraphQueries
from graph.neo4j_client import Neo4jClient, Neo4jConfig
from knowledge.provider import KnowledgeProvider
from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatReport
from report_repository import FileReportRepository, ReportRepository
from project_paths import ProjectPaths

from .state import ToolError, ToolResponse
from .tool_protocol import Tool, ToolRegistry

GraphRunner = Callable[[str, dict[str, Any] | None], list[dict[str, Any]]]


class _QueryGraphTool:
    name = "query_graph"

    def __init__(self, agent_tools: AgentTools) -> None:
        self._tools = agent_tools

    def run(self, tool_input: dict[str, Any]) -> ToolResponse:
        return self._tools.query_graph(
            tool_input["query_id"],
            tool_input.get("params"),
        )


class _GetThreatsTool:
    name = "get_threats"

    def __init__(self, agent_tools: AgentTools) -> None:
        self._tools = agent_tools

    def run(self, tool_input: dict[str, Any]) -> ToolResponse:
        return self._tools.get_threats(
            filter_by=tool_input.get("filter_by"),
            top_n=tool_input.get("top_n", 5),
        )


class _GetRisksTool:
    name = "get_risks"

    def __init__(self, agent_tools: AgentTools) -> None:
        self._tools = agent_tools

    def run(self, tool_input: dict[str, Any]) -> ToolResponse:
        return self._tools.get_risks(top_n=tool_input.get("top_n", 5))


class _LookupTechniqueTool:
    name = "lookup_technique"

    def __init__(self, agent_tools: AgentTools) -> None:
        self._tools = agent_tools

    def run(self, tool_input: dict[str, Any]) -> ToolResponse:
        return self._tools.lookup_technique(tool_input["technique_id"])


class _SearchKnowledgeTool:
    name = "search_knowledge"

    def __init__(self, agent_tools: AgentTools) -> None:
        self._tools = agent_tools

    def run(self, tool_input: dict[str, Any]) -> ToolResponse:
        return self._tools.search_knowledge(
            tool_input["query"],
            top_k=tool_input.get("top_k", 5),
        )


class AgentTools:
    def __init__(
        self,
        *,
        base_dir: str | Path = ".",
        graph_runner: GraphRunner | None = None,
        report_repo: ReportRepository | None = None,
        knowledge_provider: KnowledgeProvider | None = None,
    ):
        self.base_dir = Path(base_dir)
        self._graph_runner = graph_runner
        self._locator = ArtifactLocator(self.base_dir)
        self._repo = report_repo or FileReportRepository(self.base_dir)
        self._knowledge_provider = knowledge_provider or KnowledgeProvider.from_paths(
            ProjectPaths.from_root(self.base_dir.resolve()),
        )

    def _ok(
        self,
        source: str,
        evidence: list[dict[str, Any]],
        *,
        confidence: float,
        meta: dict[str, Any] | None = None,
    ) -> ToolResponse:
        return ToolResponse(
            ok=True,
            source=source,
            evidence=evidence,
            confidence=confidence,
            meta=meta or {},
        )

    def _error(
        self,
        source: str,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> ToolResponse:
        return ToolResponse(
            ok=False,
            source=source,
            confidence=0.0,
            error=ToolError(code=code, message=message, details=details or {}),
        )

    def _latest_artifact(self, folder: str, suffix: str) -> Path | None:
        return self._locator.latest(folder, suffix)

    def _default_graph_runner(self, query_id: str, params: dict[str, Any] | None) -> list[dict[str, Any]]:
        config = Neo4jConfig.from_env()
        with Neo4jClient(config) as client:
            client.verify_connectivity()
            return GraphQueries(client).execute(query_id, params)

    def query_graph(self, query_id: str, params: dict[str, Any] | None = None) -> ToolResponse:
        runner = self._graph_runner or self._default_graph_runner
        try:
            rows = runner(query_id, params)
        except Exception as exc:  # pragma: no cover - defensive pass-through
            return self._error(
                "neo4j",
                "GRAPH_QUERY_FAILED",
                "Failed to execute graph query",
                details={"exception": str(exc), "query_id": query_id},
            )

        confidence = 0.9 if rows else 0.4
        return self._ok(
            "neo4j",
            rows,
            confidence=confidence,
            meta={"rows": len(rows), "query_id": query_id},
        )

    def get_threats(
        self,
        *,
        filter_by: dict[str, Any] | None = None,
        top_n: int | None = 10,
        path: str | Path | None = None,
    ) -> ToolResponse:
        report, threat_path = self._repo.load_threat_report(path)
        if report is None or threat_path is None:
            return self._error(
                "threat-artifacts",
                "THREATS_NOT_FOUND",
                "No threat artifact found",
                details={"search_path": "models/outputs/threats/*_threats.json"},
            )

        rows = [threat.model_dump() for threat in report.threats]

        if filter_by:
            rows = [
                row
                for row in rows
                if self._matches_threat_filter(row, filter_by)
            ]

        if top_n is not None:
            rows = rows[: max(0, top_n)]

        confidence = 0.95 if rows else 0.4
        return self._ok(
            "threat-artifacts",
            rows,
            confidence=confidence,
            meta={"path": str(threat_path), "count": len(rows)},
        )

    @staticmethod
    def _matches_threat_filter(row: dict[str, Any], filter_by: dict[str, Any]) -> bool:
        for key, value in filter_by.items():
            if key == "framework":
                frameworks = {
                    mapping.get("framework")
                    for mapping in row.get("framework_mappings", [])
                    if mapping.get("framework")
                }
                if value not in frameworks:
                    return False
                continue

            if row.get(key) != value:
                return False

        return True

    def get_risks(
        self,
        *,
        filter_by: dict[str, Any] | None = None,
        top_n: int | None = 10,
        path: str | Path | None = None,
    ) -> ToolResponse:
        report, risk_path = self._repo.load_risk_report(path)
        if report is None or risk_path is None:
            return self._error(
                "risk-artifacts",
                "RISKS_NOT_FOUND",
                "No risk artifact found",
                details={"search_path": "models/outputs/risks/*_risks.json"},
            )

        rows = [risk.model_dump() for risk in report.risks]

        if filter_by:
            rows = [
                row
                for row in rows
                if all(row.get(key) == value for key, value in filter_by.items())
            ]

        if top_n is not None:
            rows = rows[: max(0, top_n)]

        confidence = 0.95 if rows else 0.4
        return self._ok(
            "risk-artifacts",
            rows,
            confidence=confidence,
            meta={"path": str(risk_path), "count": len(rows)},
        )

    def lookup_technique(self, technique_id: str) -> ToolResponse:
        technique_id_upper = technique_id.upper()

        # Try the knowledge base first
        try:
            index = self._knowledge_provider.maybe_get_index()
            if index is not None:
                tech = index.lookup(technique_id)
                if tech:
                    matches = [{
                        "framework": tech.framework,
                        "technique_id": tech.technique_id,
                        "technique_name": tech.name,
                        "tactic": ", ".join(tech.tactics),
                        "description": tech.description[:500],
                        "platforms": list(tech.platforms),
                        "is_subtechnique": tech.is_subtechnique,
                        "parent_id": tech.parent_id,
                        "url": tech.url,
                        "mitigations": [
                            {"id": m.mitigation_id, "name": m.name}
                            for m in index.mitigations_for(tech.technique_id)
                        ],
                    }]
                    return self._ok(
                        "knowledge-base",
                        matches,
                        confidence=0.95,
                        meta={"query": technique_id, "count": 1, "source": "knowledge-base"},
                    )
        except Exception:
            logging.getLogger(__name__).debug(
                "Knowledge index unavailable for technique lookup", exc_info=True,
            )

        # Fallback to curated mappings
        matches = [
            {
                "rule_id": mapping.rule_id,
                "framework": mapping.framework,
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "tactic": mapping.tactic,
                "mapping_rationale": mapping.mapping_rationale,
            }
            for mapping in get_all_technique_mappings()
            if mapping.technique_id.upper() == technique_id_upper
        ]

        confidence = 0.9 if matches else 0.2
        return self._ok(
            "technique-mappings",
            matches,
            confidence=confidence,
            meta={"query": technique_id, "count": len(matches)},
        )

    def search_knowledge(self, query: str, *, top_k: int = 5) -> ToolResponse:
        terms = {token.lower() for token in query.split() if token.strip()}
        corpus: list[dict[str, Any]] = []

        for heuristic in THREAT_HEURISTICS:
            corpus.append(
                {
                    "source": "heuristics",
                    "id": heuristic.rule_id,
                    "title": heuristic.name,
                    "text": f"{heuristic.description} {heuristic.graph_pattern}",
                }
            )

        # Use knowledge base if available, otherwise fall back to curated mappings
        try:
            index = self._knowledge_provider.maybe_get_index()
            if index is not None:
                kb_results = index.search(query, top_k=top_k)
                for tech in kb_results:
                    corpus.append(
                        {
                            "source": "knowledge-base",
                            "id": tech.technique_id,
                            "title": tech.name,
                            "text": f"{tech.framework} {tech.technique_id} {' '.join(tech.tactics)} {tech.description[:300]}",
                        }
                    )
        except Exception:
            logging.getLogger(__name__).debug(
                "Knowledge index unavailable for knowledge search", exc_info=True,
            )

        if not any(entry["source"] == "knowledge-base" for entry in corpus):
            for mapping in get_all_technique_mappings():
                corpus.append(
                    {
                        "source": "technique-mappings",
                        "id": f"{mapping.rule_id}:{mapping.technique_id}",
                        "title": mapping.technique_name,
                        "text": f"{mapping.framework} {mapping.technique_id} {mapping.tactic} {mapping.mapping_rationale}",
                    }
                )

        scored: list[tuple[int, dict[str, Any]]] = []
        for entry in corpus:
            text = entry["text"].lower()
            score = sum(1 for term in terms if term in text)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda item: (-item[0], item[1]["id"]))
        evidence = [
            {
                "source": item["source"],
                "id": item["id"],
                "title": item["title"],
                "snippet": item["text"][:240],
                "match_score": score,
            }
            for score, item in scored[: max(1, top_k)]
        ]

        source_label = "knowledge-base" if any(e["source"] == "knowledge-base" for e in evidence) else "knowledge-stub"
        confidence = 0.85 if evidence else 0.25
        return self._ok(
            source_label,
            evidence,
            confidence=confidence,
            meta={"query": query, "count": len(evidence)},
        )

    def tool_registry(self) -> ToolRegistry:
        """Return a name→Tool mapping for all available tools."""
        tools: list[Tool] = [
            _QueryGraphTool(self),
            _GetThreatsTool(self),
            _GetRisksTool(self),
            _LookupTechniqueTool(self),
            _SearchKnowledgeTool(self),
        ]
        return {tool.name: tool for tool in tools}
