from __future__ import annotations

import pytest

from models.schema.risk_model import RiskDriver, RiskFactors, RiskRecord, RiskReport


def _risk_record() -> RiskRecord:
    return RiskRecord(
        risk_id="RISK-001",
        model_id="fintech-ai-demo",
        threat_id="TH-001-abcd1234",
        rule_id="TH-001",
        title="Internet exposed module handling sensitive workflow data",
        target_id="api_gateway",
        target_type="module",
        risk_score=0.82,
        priority="high",
        factors=RiskFactors(
            likelihood=0.9,
            impact=0.8,
            exposure=0.75,
            privilege_sensitivity=0.6,
            data_criticality=0.85,
            exploitability=0.7,
        ),
        drivers=[
            RiskDriver(
                factor="likelihood",
                score=0.9,
                weighted_contribution=0.225,
            ),
            RiskDriver(
                factor="impact",
                score=0.8,
                weighted_contribution=0.16,
            ),
        ],
        explanation="Internet-facing module intersects with sensitive workflow context and high data criticality.",
        evidence={"module_name": "API Gateway"},
        created_at="2026-03-22T00:00:00+00:00",
    )


def test_risk_record_schema_valid() -> None:
    record = _risk_record()
    assert record.priority == "high"
    assert record.factors.likelihood == 0.9


def test_risk_report_count_validation() -> None:
    report = RiskReport(
        model_id="fintech-ai-demo",
        generated_at="2026-03-22T00:00:00+00:00",
        risk_count=1,
        risks=[_risk_record()],
    )
    assert report.risk_count == 1


def test_risk_report_count_mismatch_fails() -> None:
    with pytest.raises(ValueError, match="risk_count"):
        RiskReport(
            model_id="fintech-ai-demo",
            generated_at="2026-03-22T00:00:00+00:00",
            risk_count=2,
            risks=[_risk_record()],
        )


def test_factor_bounds_enforced() -> None:
    with pytest.raises(ValueError):
        RiskFactors(
            likelihood=1.1,
            impact=0.8,
            exposure=0.75,
            privilege_sensitivity=0.6,
            data_criticality=0.85,
            exploitability=0.7,
        )
