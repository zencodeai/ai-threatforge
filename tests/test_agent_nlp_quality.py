from __future__ import annotations

from pathlib import Path

from agents.observability import NullTraceRecorder
from agents.tools import AgentTools
from agents.workflow import QueryWorkflow
from models.schema.risk_model import RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport

from nlp_quality_fixtures import load_golden_fixture


def _write_artifacts(base_dir: Path) -> None:
    threat_dir = base_dir / "models" / "outputs" / "threats"
    risk_dir = base_dir / "models" / "outputs" / "risks"
    threat_dir.mkdir(parents=True, exist_ok=True)
    risk_dir.mkdir(parents=True, exist_ok=True)

    threat_report = ThreatReport(
        model_id="fintech-ai-demo",
        generated_at="2026-03-22T00:00:00+00:00",
        threat_count=2,
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
            ),
            ThreatRecord(
                threat_id="TH-004-b",
                model_id="fintech-ai-demo",
                rule_id="TH-004",
                title="AI-relevant module dependency and model service exposure",
                description="desc",
                target_id="fraud_model_service",
                target_type="module",
                severity_hint="high",
                framework_mappings=[
                    TechniqueReference(
                        framework="ATLAS",
                        technique_id="AML.T0040",
                        technique_name="Model Evasion",
                        tactic="ML Model Inference Manipulation",
                        mapping_rationale="rationale",
                    )
                ],
                rationale="AI service dependency",
                evidence={"ai_relevant": True},
                affected_workflows=["payment_execution"],
                affected_objects=["fraud_features"],
                created_at="2026-03-22T00:00:00+00:00",
            ),
        ],
    )

    risk_report = RiskReport(
        model_id="fintech-ai-demo",
        generated_at="2026-03-22T00:00:00+00:00",
        methodology_version="0.1",
        risk_count=2,
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
            ),
            RiskRecord(
                risk_id="RISK-TH-004-b",
                model_id="fintech-ai-demo",
                threat_id="TH-004-b",
                rule_id="TH-004",
                title="AI-relevant module dependency and model service exposure",
                target_id="fraud_model_service",
                target_type="module",
                risk_score=0.72,
                priority="high",
                factors=RiskFactors(
                    likelihood=0.82,
                    impact=0.8,
                    exposure=0.7,
                    privilege_sensitivity=0.55,
                    data_criticality=0.9,
                    exploitability=0.7,
                ),
                drivers=[],
                explanation="Risk score driven by AI-service exposure",
                evidence={"ai_relevant": True},
                created_at="2026-03-22T00:00:00+00:00",
            ),
        ],
    )

    (threat_dir / "fintech-ai-demo_threats.json").write_text(
        threat_report.model_dump_json(indent=2), encoding="utf-8",
    )
    (risk_dir / "fintech-ai-demo_risks.json").write_text(
        risk_report.model_dump_json(indent=2), encoding="utf-8",
    )


def _workflow(base_dir: Path) -> QueryWorkflow:
    def _graph_runner(query: str, _params: dict | None) -> list[dict]:
        if "TrustBoundary" in query:
            return [{"trust_boundary": "internet_boundary", "from_domain": "client", "to_domain": "edge"}]
        if "DEPENDS_ON" in query:
            return [{"source": "api_gateway", "target": "payment_service", "relationship": "calls"}]
        return [{"module_id": "api_gateway", "module_name": "API Gateway", "module_type": "gateway"}]

    tools = AgentTools(base_dir=base_dir, graph_runner=_graph_runner)
    return QueryWorkflow(tools, tracer=NullTraceRecorder())


def test_query_workflow_quality_metrics(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    workflow = _workflow(tmp_path)

    cases, thresholds = load_golden_fixture("synthetic_golden.json")

    total = len(cases)
    answer_hits = 0
    tool_hits = 0
    evidence_hits = 0
    phrase_hits = 0
    clean_hits = 0
    failures: list[str] = []

    for case in cases:
        answer, state = workflow.answer(case.question)
        tool_names = {call.name for call in state.tool_calls}

        has_answer = bool(answer.answer.strip())
        has_tools = set(case.expected_tools).issubset(tool_names)
        has_refs = all(
            any(ref.startswith(prefix) for ref in answer.evidence_refs)
            for prefix in case.required_ref_prefixes
        )
        has_phrases = all(phrase in answer.answer for phrase in case.required_answer_phrases)
        is_clean = case.allow_limitations or not answer.limitations

        answer_hits += int(has_answer)
        tool_hits += int(has_tools)
        evidence_hits += int(has_refs)
        phrase_hits += int(has_phrases)
        clean_hits += int(is_clean)

        if not all((has_answer, has_tools, has_refs, has_phrases, is_clean)):
            failures.append(
                f"{case.question!r}: "
                f"answer={has_answer} tools={has_tools} refs={has_refs} "
                f"phrases={has_phrases} clean={is_clean} "
                f"tool_names={sorted(tool_names)} refs={answer.evidence_refs} "
                f"limitations={answer.limitations} answer_text={answer.answer!r}"
            )

    metrics = {
        "answer_nonempty_rate": answer_hits / total,
        "expected_tool_coverage_rate": tool_hits / total,
        "grounded_reference_rate": evidence_hits / total,
        "required_phrase_rate": phrase_hits / total,
        "clean_answer_rate": clean_hits / total,
    }

    metric_failures = [
        f"{name}={metrics[name]:.2f} < {minimum:.2f}"
        for name, minimum in thresholds.items()
        if metrics[name] < minimum
    ]

    assert not metric_failures, (
        "NLP query quality regression: "
        + ", ".join(metric_failures)
        + "\nCase failures:\n"
        + "\n".join(failures)
    )
