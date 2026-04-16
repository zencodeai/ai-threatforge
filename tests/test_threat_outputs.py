from __future__ import annotations

import json
from pathlib import Path

from analysis.threat_outputs import build_threat_report_from_snapshot, write_threat_report
from models.schema.canonical_model import load_canonical_model


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


def _snapshot() -> dict:
    return {
        "internet_modules": [
            {"module_id": "api_gateway", "module_name": "API Gateway", "module_type": "gateway"}
        ],
        "sensitive_workflows": [
            {"workflow_id": "payment_execution", "sensitive_objects": ["payment_instruction", "fraud_features"]}
        ],
        "attack_paths": [
            {"entry_module": "mobile_app", "target_object": "payment_instruction", "hops": 3}
        ],
        "high_priv_modules": [
            {
                "module_id": "api_gateway",
                "privilege_id": "service",
                "privilege_level": 2,
                "internet_exposed": True,
            }
        ],
        "ai_dependencies": [
            {"module_id": "payment_service", "ai_module_id": "fraud_model_service"}
        ],
        "critical_workflows": [
            {
                "workflow_id": "payment_execution",
                "involved_modules": ["payment_service", "fraud_model_service"],
                "system_criticality": "high",
            }
        ],
        "regulated_data": [
            {
                "regulated_object": "payment_instruction",
                "workflows": ["payment_execution"],
                "modules": ["payment_service"],
            }
        ],
        "dependency_edges": [
            {"source": "api_gateway", "target": "payment_service", "relationship": "calls"}
        ],
        "trust_boundaries": [
            {"trust_boundary": "internet_boundary", "from_domain": "client", "to_domain": "edge"}
        ],
        "boundary_objects": [
            {
                "trust_boundary": "internet_boundary",
                "object_id": "payment_instruction",
                "classification": "confidential",
                "regulated": True,
                "workflow_id": "payment_execution",
            }
        ],
    }


def test_build_threat_report_from_snapshot_produces_structured_output() -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    report = build_threat_report_from_snapshot(model, _snapshot())

    assert report.model_id == "fintech-ai-demo"
    assert report.threat_count >= 6
    assert len(report.threats) == report.threat_count

    rule_ids = {threat.rule_id for threat in report.threats}
    assert {"TH-001", "TH-002", "TH-003", "TH-004", "TH-005", "TH-006"}.issubset(rule_ids)

    for threat in report.threats:
        assert threat.framework_mappings
        assert threat.threat_id.startswith(threat.rule_id)


def test_write_threat_report_writes_json(tmp_path: Path) -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    report = build_threat_report_from_snapshot(model, _snapshot())

    output = tmp_path / "threats.json"
    write_threat_report(report, output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["model_id"] == "fintech-ai-demo"
    assert payload["threat_count"] == len(payload["threats"])
