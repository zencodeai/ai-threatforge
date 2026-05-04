from __future__ import annotations

from pathlib import Path

from models.schema.risk_model import RiskFactors, RiskRecord, RiskReport
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport
from project_paths import ProjectPaths
from session_store import SessionStore
from analysis_manifest import AnalysisManifestStore
from ui.data_access import (
    build_model_overview,
    latest_artifact,
    list_example_models,
    load_active_session,
    load_model,
    load_risk_report,
    load_threat_report,
    risk_rows,
    threat_rows,
)


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


def test_list_example_models_contains_fintech_example() -> None:
    models = list_example_models()
    assert any(path.name == "fintech_ai_platform.toml" for path in models)


def test_model_overview_contains_expected_counts() -> None:
    model = load_model(Path("examples/fintech_ai_platform.toml"))
    overview = build_model_overview(model)

    assert overview["model_id"] == "fintech-ai-demo"
    assert overview["counts"]["modules"] > 0
    assert overview["counts"]["workflows"] > 0


def test_load_latest_artifacts_and_rows(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    latest_threat = latest_artifact(tmp_path, "models/outputs/threats", "_threats.json")
    latest_risk = latest_artifact(tmp_path, "models/outputs/risks", "_risks.json")
    assert latest_threat is not None
    assert latest_risk is not None

    threat_report, _ = load_threat_report(base_dir=tmp_path)
    risk_report, _ = load_risk_report(base_dir=tmp_path)

    assert threat_report is not None
    assert risk_report is not None

    t_rows = threat_rows(threat_report)
    r_rows = risk_rows(risk_report)

    assert t_rows[0]["threat_id"] == "TH-001-a"
    assert r_rows[0]["risk_id"] == "RISK-TH-001-a"


def test_load_artifacts_prefers_session_paths(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    older_threat = tmp_path / "models" / "outputs" / "threats" / "aaa_threats.json"
    older_threat.write_text(
        ThreatReport(
            model_id="older-demo",
            generated_at="2026-03-21T00:00:00+00:00",
            threat_count=0,
            threats=[],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    older_risk = tmp_path / "models" / "outputs" / "risks" / "aaa_risks.json"
    older_risk.write_text(
        RiskReport(
            model_id="older-demo",
            generated_at="2026-03-21T00:00:00+00:00",
            methodology_version="0.1",
            risk_count=0,
            risks=[],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)
    store.set_threat_report(older_threat)
    store.set_risk_report(older_risk)

    threat_report, threat_path = load_threat_report(base_dir=tmp_path)
    risk_report, risk_path = load_risk_report(base_dir=tmp_path)
    session = load_active_session(paths=paths)

    assert threat_report is not None
    assert risk_report is not None
    assert threat_path == older_threat
    assert risk_path == older_risk
    assert session["threat_report_path"] == "models/outputs/threats/aaa_threats.json"
    assert session["risk_report_path"] == "models/outputs/risks/aaa_risks.json"


def test_load_artifacts_fall_back_to_active_manifest(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    paths = ProjectPaths.from_root(tmp_path)
    session = SessionStore(paths)
    manifest_store = AnalysisManifestStore(paths, session_store=session)

    threat_path = tmp_path / "models" / "outputs" / "threats" / "fintech-ai-demo_threats.json"
    risk_path = tmp_path / "models" / "outputs" / "risks" / "fintech-ai-demo_risks.json"

    manifest_store.create(
        model_path=tmp_path / "examples" / "fintech_ai_platform.toml",
        model_id="fintech-ai-demo",
        threat_report_path=threat_path,
        risk_report_path=risk_path,
    )

    threat_report, resolved_threat_path = load_threat_report(base_dir=tmp_path)
    risk_report, resolved_risk_path = load_risk_report(base_dir=tmp_path)

    assert threat_report is not None
    assert risk_report is not None
    assert resolved_threat_path == threat_path
    assert resolved_risk_path == risk_path
