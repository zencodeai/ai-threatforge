from __future__ import annotations

from pathlib import Path

from agents.tools import AgentTools
from models.schema.risk_model import RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport


def _write_threat_report(path: Path) -> None:
    report = ThreatReport(
        model_id="fintech-ai-demo",
        generated_at="2026-03-22T00:00:00+00:00",
        threat_count=1,
        threats=[
            ThreatRecord(
                threat_id="TH-001-a",
                model_id="fintech-ai-demo",
                rule_id="TH-001",
                title="Internet exposed module handling sensitive workflow data",
                description="desc",
                target_id="api_gateway",
                target_type="module",
                severity_hint="high",
                framework_mappings=[
                    TechniqueReference(
                        framework="ATTACK",
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application",
                        tactic="Initial Access",
                        mapping_rationale="rationale",
                    )
                ],
                rationale="Because exposed",
                evidence={"internet_exposed": True},
                affected_workflows=["payment_execution"],
                affected_objects=["payment_instruction"],
                created_at="2026-03-22T00:00:00+00:00",
            )
        ],
    )
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _write_risk_report(path: Path) -> None:
    report = RiskReport(
        model_id="fintech-ai-demo",
        generated_at="2026-03-22T00:00:00+00:00",
        methodology_version="0.1",
        risk_count=1,
        risks=[
            RiskRecord(
                risk_id="RISK-TH-001-a",
                model_id="fintech-ai-demo",
                threat_id="TH-001-a",
                rule_id="TH-001",
                title="Internet exposed module handling sensitive workflow data",
                target_id="api_gateway",
                target_type="module",
                risk_score=0.87,
                priority="critical",
                factors=RiskFactors(
                    likelihood=0.9,
                    impact=0.85,
                    exposure=0.95,
                    privilege_sensitivity=0.5,
                    data_criticality=0.9,
                    exploitability=0.8,
                ),
                drivers=[],
                explanation="Risk score is high due to exposure",
                evidence={"internet_exposed": True},
                created_at="2026-03-22T00:00:00+00:00",
            )
        ],
    )
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def test_query_graph_tool_can_run_independently() -> None:
    tools = AgentTools(graph_runner=lambda _qid, _p: [{"module_id": "api_gateway"}])

    response = tools.query_graph("internet_exposed_modules")

    assert response.ok is True
    assert response.source == "neo4j"
    assert response.evidence == [{"module_id": "api_gateway"}]
    assert response.error is None
    assert response.confidence > 0
    assert response.meta["query_id"] == "internet_exposed_modules"


def test_query_graph_tool_returns_structured_error() -> None:
    def _raise(_qid: str, _p: dict | None) -> list[dict]:
        raise RuntimeError("boom")

    tools = AgentTools(graph_runner=_raise)
    response = tools.query_graph("internet_exposed_modules")

    assert response.ok is False
    assert response.source == "neo4j"
    assert response.error is not None
    assert response.error.code == "GRAPH_QUERY_FAILED"
    assert "boom" in response.error.details["exception"]
    assert response.error.details["query_id"] == "internet_exposed_modules"
    assert response.confidence == 0.0


def test_get_threats_filters_and_shapes_response(tmp_path: Path) -> None:
    threat_path = tmp_path / "demo_threats.json"
    _write_threat_report(threat_path)

    tools = AgentTools()
    response = tools.get_threats(path=threat_path, filter_by={"rule_id": "TH-001"}, top_n=5)

    assert response.ok is True
    assert response.source == "threat-artifacts"
    assert response.error is None
    assert response.meta["count"] == 1
    assert response.evidence[0]["rule_id"] == "TH-001"


def test_get_risks_missing_artifact_returns_structured_error() -> None:
    tools = AgentTools()
    response = tools.get_risks(path="/does/not/exist.json")

    assert response.ok is False
    assert response.source == "risk-artifacts"
    assert response.error is not None
    assert response.error.code == "RISKS_NOT_FOUND"
    assert "search_path" in response.error.details


def test_lookup_technique_returns_matches() -> None:
    tools = AgentTools()
    response = tools.lookup_technique("T1190")

    assert response.ok is True
    assert response.source in {"knowledge-base", "technique-mappings"}
    assert response.error is None
    assert response.evidence
    assert all(item["technique_id"] == "T1190" for item in response.evidence)


def test_search_knowledge_returns_ranked_items() -> None:
    tools = AgentTools()
    response = tools.search_knowledge("internet exposed sensitive", top_k=3)

    assert response.ok is True
    assert response.source in {"knowledge-base", "knowledge-stub"}
    assert response.error is None
    assert len(response.evidence) <= 3
    if response.evidence:
        scores = [item["match_score"] for item in response.evidence]
        assert scores == sorted(scores, reverse=True)
