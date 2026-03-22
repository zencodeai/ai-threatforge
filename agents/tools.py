from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from analysis.technique_mapping import get_all_technique_mappings
from analysis.threat_generation import THREAT_HEURISTICS
from graph.neo4j_client import Neo4jClient, Neo4jConfig
from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatReport

from .state import ToolError, ToolResponse

GraphRunner = Callable[[str, dict[str, Any] | None], list[dict[str, Any]]]


class AgentTools:
    def __init__(
        self,
        *,
        base_dir: str | Path = ".",
        graph_runner: GraphRunner | None = None,
    ):
        self.base_dir = Path(base_dir)
        self._graph_runner = graph_runner

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
        path = self.base_dir / folder
        candidates = sorted(path.glob(f"*{suffix}")) if path.exists() else []
        return candidates[-1] if candidates else None

    def _default_graph_runner(self, query: str, params: dict[str, Any] | None) -> list[dict[str, Any]]:
        config = Neo4jConfig.from_env()
        with Neo4jClient(config) as client:
            client.verify_connectivity()
            return client.run_query(query, params)

    def query_graph(self, query: str, params: dict[str, Any] | None = None) -> ToolResponse:
        runner = self._graph_runner or self._default_graph_runner
        try:
            rows = runner(query, params)
        except Exception as exc:  # pragma: no cover - defensive pass-through
            return self._error(
                "neo4j",
                "GRAPH_QUERY_FAILED",
                "Failed to execute graph query",
                details={"exception": str(exc)},
            )

        confidence = 0.9 if rows else 0.4
        return self._ok(
            "neo4j",
            rows,
            confidence=confidence,
            meta={"rows": len(rows)},
        )

    def get_threats(
        self,
        *,
        filter_by: dict[str, Any] | None = None,
        top_n: int | None = 10,
        path: str | Path | None = None,
    ) -> ToolResponse:
        threat_path = Path(path) if path else self._latest_artifact("models/outputs/threats", "_threats.json")
        if threat_path is None or not threat_path.exists():
            return self._error(
                "threat-artifacts",
                "THREATS_NOT_FOUND",
                "No threat artifact found",
                details={"search_path": "models/outputs/threats/*_threats.json"},
            )

        report = ThreatReport.model_validate_json(threat_path.read_text(encoding="utf-8"))
        rows = [threat.model_dump() for threat in report.threats]

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
            "threat-artifacts",
            rows,
            confidence=confidence,
            meta={"path": str(threat_path), "count": len(rows)},
        )

    def get_risks(
        self,
        *,
        filter_by: dict[str, Any] | None = None,
        top_n: int | None = 10,
        path: str | Path | None = None,
    ) -> ToolResponse:
        risk_path = Path(path) if path else self._latest_artifact("models/outputs/risks", "_risks.json")
        if risk_path is None or not risk_path.exists():
            return self._error(
                "risk-artifacts",
                "RISKS_NOT_FOUND",
                "No risk artifact found",
                details={"search_path": "models/outputs/risks/*_risks.json"},
            )

        report = RiskReport.model_validate_json(risk_path.read_text(encoding="utf-8"))
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

        confidence = 0.85 if evidence else 0.25
        return self._ok(
            "knowledge-stub",
            evidence,
            confidence=confidence,
            meta={"query": query, "count": len(evidence)},
        )
