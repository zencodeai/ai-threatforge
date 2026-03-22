from __future__ import annotations

import json
from pathlib import Path

from analysis.risk_scoring import (
    build_risk_report,
    generate_risk_report_from_file,
    priority_from_score,
    score_threat,
    write_risk_report,
)
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport


def _threat_report_fixture() -> ThreatReport:
    created = "2026-03-22T00:00:00+00:00"

    return ThreatReport(
        model_id="fintech-ai-demo",
        generated_at=created,
        threat_count=3,
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
                        mapping_rationale="r1",
                    )
                ],
                rationale="r",
                evidence={"internet_exposed": True},
                affected_workflows=["payment_execution"],
                affected_objects=["payment_instruction"],
                created_at=created,
            ),
            ThreatRecord(
                threat_id="TH-002-b",
                model_id="fintech-ai-demo",
                rule_id="TH-002",
                title="Low-trust to high-value object dependency path",
                description="desc",
                target_id="payment_instruction",
                target_type="object",
                severity_hint="critical",
                framework_mappings=[
                    TechniqueReference(
                        framework="ATTACK",
                        technique_id="T1021",
                        technique_name="Remote Services",
                        tactic="Lateral Movement",
                        mapping_rationale="r2",
                    )
                ],
                rationale="r",
                evidence={"hops": 4},
                affected_workflows=[],
                affected_objects=["payment_instruction"],
                created_at=created,
            ),
            ThreatRecord(
                threat_id="TH-006-c",
                model_id="fintech-ai-demo",
                rule_id="TH-006",
                title="Trust boundary crossing with privileged dependency",
                description="desc",
                target_id="api_gateway",
                target_type="module",
                severity_hint="medium",
                framework_mappings=[
                    TechniqueReference(
                        framework="ATTACK",
                        technique_id="T1570",
                        technique_name="Lateral Tool Transfer",
                        tactic="Lateral Movement",
                        mapping_rationale="r3",
                    )
                ],
                rationale="r",
                evidence={"trust_boundaries": ["internet_boundary"]},
                affected_workflows=[],
                affected_objects=[],
                created_at=created,
            ),
        ],
    )


def test_priority_from_score_bands() -> None:
    assert priority_from_score(0.90) == "critical"
    assert priority_from_score(0.80) == "high"
    assert priority_from_score(0.50) == "medium"
    assert priority_from_score(0.20) == "low"


def test_score_threat_is_bounded_and_explained() -> None:
    threat = _threat_report_fixture().threats[0]
    risk = score_threat(threat, created_at="2026-03-22T00:00:00+00:00")

    assert 0.0 <= risk.risk_score <= 1.0
    assert risk.priority in {"low", "medium", "high", "critical"}
    assert risk.drivers
    assert "Risk score" in risk.explanation


def test_build_risk_report_deterministic_ordering() -> None:
    report = _threat_report_fixture()

    first = build_risk_report(report, methodology_version="0.1")
    second = build_risk_report(report, methodology_version="0.1")

    first_pairs = [(risk.threat_id, risk.risk_score, risk.priority) for risk in first.risks]
    second_pairs = [(risk.threat_id, risk.risk_score, risk.priority) for risk in second.risks]
    assert first_pairs == second_pairs
    assert first.risk_count == 3


def test_write_and_generate_risk_report_from_file(tmp_path: Path) -> None:
    threat_report = _threat_report_fixture()
    threat_path = tmp_path / "threats.json"
    threat_path.write_text(threat_report.model_dump_json(indent=2), encoding="utf-8")

    generated_path = tmp_path / "generated_risks.json"
    report, output_path = generate_risk_report_from_file(threat_path, generated_path)

    assert report.risk_count == len(report.risks)
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["model_id"] == "fintech-ai-demo"
    assert payload["risk_count"] == 3

    target = tmp_path / "custom_risks.json"
    write_risk_report(report, target)
    assert target.exists()
