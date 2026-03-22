from __future__ import annotations

import json
from pathlib import Path

from agents.observability import JsonlTraceRecorder
from agents.tools import AgentTools
from agents.workflow import QueryWorkflow
from models.schema.risk_model import RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport


def _write_artifacts(base_dir: Path) -> None:
    threat_dir = base_dir / "models" / "outputs" / "threats"
    risk_dir = base_dir / "models" / "outputs" / "risks"
    threat_dir.mkdir(parents=True, exist_ok=True)
    risk_dir.mkdir(parents=True, exist_ok=True)

    threat_report = ThreatReport(
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

    risk_report = RiskReport(
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

    (threat_dir / "fintech-ai-demo_threats.json").write_text(
        threat_report.model_dump_json(indent=2), encoding="utf-8"
    )
    (risk_dir / "fintech-ai-demo_risks.json").write_text(
        risk_report.model_dump_json(indent=2), encoding="utf-8"
    )


def test_workflow_observability_writes_jsonl_trace(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    trace_file = tmp_path / "models" / "outputs" / "traces" / "agent_runs.jsonl"
    tracer = JsonlTraceRecorder(trace_file)

    tools = AgentTools(
        base_dir=tmp_path,
        graph_runner=lambda _q, _p: [{"module_id": "api_gateway", "module_name": "API Gateway"}],
    )
    workflow = QueryWorkflow(tools=tools, tracer=tracer)

    answer, state = workflow.answer("What are the highest risks and related threats?")

    assert answer.answer
    assert state.tool_calls
    assert trace_file.exists()

    rows = [json.loads(line) for line in trace_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    event_types = [row["event"] for row in rows]

    assert event_types[0] == "workflow_start"
    assert event_types[-1] == "workflow_end"
    assert "tool_result" in event_types

    run_ids = {row["run_id"] for row in rows}
    assert len(run_ids) == 1

    tool_events = [row for row in rows if row["event"] == "tool_result"]
    assert tool_events
    assert any(event["tool_name"] == "get_risks" for event in tool_events)
