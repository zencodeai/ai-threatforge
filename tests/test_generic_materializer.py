"""Tests for the config-driven GenericMaterializer and TOML discovery.

Each TOML rule (TH-001 through TH-006) is loaded independently and compared
against the hand-coded Python materializer to verify identical output.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from analysis.heuristics import _RULES_DIR, _heuristic_from_toml, _load_toml, _materializer_from_toml
from analysis.heuristics.generic_materializer import GenericMaterializer
from analysis.threat_generation import ThreatHeuristic
from models.schema.canonical_model import load_canonical_model
from models.schema.threat_model import ThreatRecord

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


# ── Shared test fixtures ────────────────────────────────────────


def _snapshot() -> dict[str, list[dict[str, Any]]]:
    return {
        "internet_modules": [
            {"module_id": "api_gateway", "module_name": "API Gateway", "module_type": "gateway"},
        ],
        "sensitive_workflows": [
            {"workflow_id": "payment_execution", "sensitive_objects": ["payment_instruction", "fraud_features"]},
        ],
        "attack_paths": [
            {"entry_module": "mobile_app", "target_object": "payment_instruction", "hops": 3},
        ],
        "high_priv_modules": [
            {
                "module_id": "api_gateway",
                "privilege_id": "service",
                "privilege_level": 2,
                "internet_exposed": True,
            },
        ],
        "ai_dependencies": [
            {"module_id": "payment_service", "ai_module_id": "fraud_model_service"},
        ],
        "critical_workflows": [
            {
                "workflow_id": "payment_execution",
                "involved_modules": ["payment_service", "fraud_model_service"],
                "system_criticality": "high",
            },
        ],
        "regulated_data": [
            {
                "regulated_object": "payment_instruction",
                "workflows": ["payment_execution"],
                "modules": ["payment_service"],
            },
        ],
        "dependency_edges": [
            {"source": "api_gateway", "target": "payment_service", "relationship": "calls"},
        ],
        "trust_boundaries": [
            {"trust_boundary": "internet_boundary", "from_domain": "client", "to_domain": "edge"},
        ],
        "boundary_objects": [
            {
                "trust_boundary": "internet_boundary",
                "object_id": "payment_instruction",
                "classification": "confidential",
                "regulated": True,
                "workflow_id": "payment_execution",
            },
        ],
    }


def _technique_refs(rule_id: str) -> list:
    return []


def _stable_id(rule_id: str, *parts: str) -> str:
    import hashlib
    payload = "|".join([rule_id, *parts]).encode()
    digest = hashlib.sha1(payload).hexdigest()[:10]
    return f"{rule_id}-{digest}"


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


NOW = "2026-01-01T00:00:00+00:00"


# ── Helper to run a materializer ────────────────────────────────


def _run_materializer(
    materializer: Any,
    rule: ThreatHeuristic,
    snapshot: dict[str, list[dict[str, Any]]],
) -> list[ThreatRecord]:
    model = load_canonical_model(EXAMPLE_MODEL)
    return materializer.materialize(
        rule,
        model,
        snapshot,
        now=NOW,
        technique_refs_fn=_technique_refs,
        stable_id_fn=_stable_id,
        sorted_unique_fn=_sorted_unique,
    )


# ── Helper to load TOML rule ───────────────────────────────────


def _load_rule(rule_file: str) -> tuple[ThreatHeuristic, GenericMaterializer]:
    path = _RULES_DIR / rule_file
    data = _load_toml(path)
    heuristic = _heuristic_from_toml(data)
    materializer = _materializer_from_toml(heuristic.rule_id, data)
    return heuristic, materializer


# ── Helper to import Python materializer ────────────────────────


def _python_materializer(module_name: str):
    import importlib
    mod = importlib.import_module(f"analysis.heuristics.{module_name}")
    for attr in vars(mod).values():
        if isinstance(attr, type) and hasattr(attr, "rule_id") and hasattr(attr, "materialize"):
            return mod.HEURISTIC, attr()
    raise RuntimeError(f"No materializer found in {module_name}")


# ── Tests ───────────────────────────────────────────────────────


class TestGenericMaterializerProtocol:
    """Verify GenericMaterializer satisfies the ThreatMaterializer protocol."""

    def test_has_rule_id_and_materialize(self) -> None:
        _, mat = _load_rule("th_003.toml")
        assert hasattr(mat, "rule_id")
        assert hasattr(mat, "materialize")
        assert callable(mat.materialize)

    def test_rule_id_matches_config(self) -> None:
        _, mat = _load_rule("th_003.toml")
        assert mat.rule_id == "TH-003"


class TestTOMLHeuristicParsing:
    """Verify heuristic definitions round-trip from TOML."""

    @pytest.mark.parametrize(
        "toml_file,expected_id",
        [
            ("th_001.toml", "TH-001"),
            ("th_002.toml", "TH-002"),
            ("th_003.toml", "TH-003"),
            ("th_004.toml", "TH-004"),
            ("th_005.toml", "TH-005"),
            ("th_006.toml", "TH-006"),
        ],
    )
    def test_heuristic_parses_from_toml(self, toml_file: str, expected_id: str) -> None:
        h, _ = _load_rule(toml_file)
        assert h.rule_id == expected_id
        assert h.name
        assert h.description
        assert h.target_type in {"module", "workflow", "object", "datastore", "system"}
        assert h.severity_hint in {"low", "medium", "high", "critical"}
        assert len(h.frameworks) >= 1


class TestGenericMaterializerParity:
    """Verify TOML-driven materializers produce identical output to Python ones."""

    @pytest.mark.parametrize(
        "toml_file,python_module",
        [
            ("th_001.toml", "th_001"),
            ("th_002.toml", "th_002"),
            ("th_003.toml", "th_003"),
            ("th_004.toml", "th_004"),
            ("th_005.toml", "th_005"),
            ("th_006.toml", "th_006"),
        ],
    )
    def test_toml_matches_python_output(self, toml_file: str, python_module: str) -> None:
        snapshot = _snapshot()

        # Python materializer
        py_rule, py_mat = _python_materializer(python_module)
        py_threats = _run_materializer(py_mat, py_rule, snapshot)

        # TOML materializer
        toml_rule, toml_mat = _load_rule(toml_file)
        toml_threats = _run_materializer(toml_mat, toml_rule, snapshot)

        assert len(toml_threats) == len(py_threats), (
            f"{toml_file}: expected {len(py_threats)} threats, got {len(toml_threats)}"
        )

        for py_t, toml_t in zip(py_threats, toml_threats):
            assert toml_t.threat_id == py_t.threat_id
            assert toml_t.rule_id == py_t.rule_id
            assert toml_t.target_id == py_t.target_id
            assert toml_t.target_type == py_t.target_type
            assert toml_t.severity_hint == py_t.severity_hint
            assert toml_t.rationale == py_t.rationale
            assert toml_t.evidence == py_t.evidence
            assert toml_t.affected_workflows == py_t.affected_workflows
            assert toml_t.affected_objects == py_t.affected_objects


class TestGenericMaterializerEdgeCases:
    """Edge cases for the generic materializer engine."""

    def test_empty_primary_produces_no_threats(self) -> None:
        _, mat = _load_rule("th_003.toml")
        h, _ = _load_rule("th_003.toml")
        snapshot = _snapshot()
        snapshot["high_priv_modules"] = []
        threats = _run_materializer(mat, h, snapshot)
        assert threats == []

    def test_skip_if_empty_filters_blank_ids(self) -> None:
        _, mat = _load_rule("th_003.toml")
        h, _ = _load_rule("th_003.toml")
        snapshot = _snapshot()
        snapshot["high_priv_modules"] = [
            {"module_id": "", "privilege_level": 2, "internet_exposed": True},
        ]
        threats = _run_materializer(mat, h, snapshot)
        assert threats == []

    def test_filter_excludes_non_matching_rows(self) -> None:
        _, mat = _load_rule("th_006.toml")
        h, _ = _load_rule("th_006.toml")
        snapshot = _snapshot()
        snapshot["dependency_edges"] = [
            {"source": "a", "target": "b", "relationship": "inherits"},
        ]
        threats = _run_materializer(mat, h, snapshot)
        assert threats == []

    def test_multiple_primary_rows(self) -> None:
        _, mat = _load_rule("th_003.toml")
        h, _ = _load_rule("th_003.toml")
        snapshot = _snapshot()
        snapshot["high_priv_modules"] = [
            {"module_id": "mod_b", "privilege_level": 3, "internet_exposed": True},
            {"module_id": "mod_a", "privilege_level": 2, "internet_exposed": False},
        ]
        threats = _run_materializer(mat, h, snapshot)
        assert len(threats) == 2
        assert threats[0].target_id == "mod_a"
        assert threats[1].target_id == "mod_b"


class TestDiscoveryIntegration:
    """Verify the discovery engine finds and deduplicates Python + TOML rules."""

    def test_discovered_heuristics_include_all_six(self) -> None:
        from analysis.heuristics import discovered_heuristics
        ids = {h.rule_id for h in discovered_heuristics()}
        assert {"TH-001", "TH-002", "TH-003", "TH-004", "TH-005", "TH-006"}.issubset(ids)

    def test_discovered_materializers_include_all_six(self) -> None:
        from analysis.heuristics import discovered_materializers
        ids = {m.rule_id for m in discovered_materializers()}
        assert {"TH-001", "TH-002", "TH-003", "TH-004", "TH-005", "TH-006"}.issubset(ids)

    def test_python_overrides_toml_for_same_rule_id(self) -> None:
        """Python materializers should take precedence over TOML ones."""
        from analysis.heuristics import discovered_materializers
        mats = {m.rule_id: m for m in discovered_materializers()}
        # TH-003 has both Python and TOML; the Python class should win
        assert not isinstance(mats["TH-003"], GenericMaterializer)
