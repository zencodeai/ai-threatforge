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


# ── CAPEC Phase 2 heuristics (TH-015 – TH-024) ──────────────────


def _capec_snapshot() -> dict[str, list[dict[str, Any]]]:
    """Snapshot data covering all Phase 2 CAPEC heuristic queries."""
    return {
        "transitive_priv_escalation": [
            {
                "source_module": "mobile_app",
                "source_privilege": 1,
                "intermediate_module": "api_gateway",
                "intermediate_privilege": 2,
                "target_module": "payment_service",
                "target_privilege": 3,
                "total_privilege_gap": 2,
            },
        ],
        "actor_privileged_modules": [
            {
                "actor_id": "customer",
                "actor_name": "Customer",
                "actor_type": "end_user",
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "module_id": "payment_service",
                "module_name": "Payment Service",
                "privilege_level": 2,
            },
        ],
        "cross_trust_writes": [
            {
                "module_id": "edge_writer",
                "module_name": "Edge Writer",
                "module_trust": "low",
                "datastore_id": "txn_db",
                "datastore_name": "Transaction Database",
                "datastore_trust": "high",
                "relationship": "writes",
            },
        ],
        "credential_low_trust": [
            {
                "object_id": "user_credentials",
                "object_name": "User Credentials",
                "workflow_id": "user_login",
                "workflow_name": "User Login",
                "module_id": "mobile_app",
                "module_name": "Mobile App",
                "domain_id": "client",
            },
        ],
        "high_fan_in": [
            {
                "target_id": "api_gateway",
                "target_name": "API Gateway",
                "target_label": "Module",
                "fan_in": 3,
                "dependent_modules": ["mobile_app", "admin_panel", "monitoring"],
            },
        ],
        "workflow_trust_span": [
            {
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "trust_levels": ["low", "medium", "high"],
                "domains": ["client", "edge", "backend"],
            },
        ],
        "actor_regulated_access": [
            {
                "actor_id": "customer",
                "actor_name": "Customer",
                "actor_type": "end_user",
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "object_id": "payment_instruction",
                "object_name": "Payment Instruction",
            },
        ],
        "untrusted_ai_store": [
            {
                "module_id": "data_collector",
                "module_name": "Data Collector",
                "module_trust": "low",
                "datastore_id": "feature_store",
                "datastore_name": "Feature Store",
            },
        ],
        "multi_domain_chain": [
            {
                "source_module": "mobile_app",
                "source_domain": "client",
                "intermediate": "api_gateway",
                "intermediate_domain": "edge",
                "target": "payment_service",
                "target_domain": "backend",
            },
        ],
        "exposed_transitive_stores": [
            {
                "exposed_module": "api_gateway",
                "exposed_name": "API Gateway",
                "datastore_id": "txn_db",
                "datastore_name": "Transaction Database",
                "sensitive_objects": ["payment_instruction"],
            },
        ],
    }


class TestCAPECHeuristicParsing:
    """Verify all Phase 2 CAPEC TOML rules parse correctly."""

    @pytest.mark.parametrize(
        "toml_file,expected_id",
        [
            ("th_015.toml", "TH-015"),
            ("th_016.toml", "TH-016"),
            ("th_017.toml", "TH-017"),
            ("th_018.toml", "TH-018"),
            ("th_019.toml", "TH-019"),
            ("th_020.toml", "TH-020"),
            ("th_021.toml", "TH-021"),
            ("th_022.toml", "TH-022"),
            ("th_023.toml", "TH-023"),
            ("th_024.toml", "TH-024"),
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


class TestCAPECMaterializerOutput:
    """Verify Phase 2 TOML materializers produce correct threat records."""

    @pytest.mark.parametrize(
        "toml_file,snapshot_key,expected_count",
        [
            ("th_015.toml", "transitive_priv_escalation", 1),
            ("th_016.toml", "actor_privileged_modules", 1),
            ("th_017.toml", "cross_trust_writes", 1),
            ("th_018.toml", "credential_low_trust", 1),
            ("th_019.toml", "high_fan_in", 1),
            ("th_020.toml", "workflow_trust_span", 1),
            ("th_021.toml", "actor_regulated_access", 1),
            ("th_022.toml", "untrusted_ai_store", 1),
            ("th_023.toml", "multi_domain_chain", 1),
            ("th_024.toml", "exposed_transitive_stores", 1),
        ],
    )
    def test_produces_expected_threat_count(
        self, toml_file: str, snapshot_key: str, expected_count: int,
    ) -> None:
        h, mat = _load_rule(toml_file)
        snapshot = _capec_snapshot()
        threats = _run_materializer(mat, h, snapshot)
        assert len(threats) == expected_count, (
            f"{toml_file}: expected {expected_count} threats, got {len(threats)}"
        )

    def test_th_015_transitive_escalation_fields(self) -> None:
        h, mat = _load_rule("th_015.toml")
        threats = _run_materializer(mat, h, _capec_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-015"
        assert t.target_id == "payment_service"
        assert t.severity_hint == "critical"
        assert t.evidence["source_module"] == "mobile_app"
        assert t.evidence["intermediate_module"] == "api_gateway"
        assert t.evidence["total_privilege_gap"] == 2

    def test_th_016_actor_privileged_module_fields(self) -> None:
        h, mat = _load_rule("th_016.toml")
        threats = _run_materializer(mat, h, _capec_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-016"
        assert t.target_id == "payment_service"
        assert t.evidence["actor_id"] == "customer"
        assert t.evidence["privilege_level"] == 2
        assert t.affected_workflows == ["payment_execution"]

    def test_th_018_credential_exposure_fields(self) -> None:
        h, mat = _load_rule("th_018.toml")
        threats = _run_materializer(mat, h, _capec_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-018"
        assert t.target_id == "user_credentials"
        assert t.severity_hint == "critical"
        assert t.affected_workflows == ["user_login"]
        assert t.affected_objects == ["user_credentials"]

    def test_th_020_trust_span_fields(self) -> None:
        h, mat = _load_rule("th_020.toml")
        threats = _run_materializer(mat, h, _capec_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-020"
        assert t.target_id == "payment_execution"
        assert t.target_type == "workflow"
        assert t.evidence["trust_levels"] == ["low", "medium", "high"]

    def test_th_021_regulated_access_fields(self) -> None:
        h, mat = _load_rule("th_021.toml")
        threats = _run_materializer(mat, h, _capec_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-021"
        assert t.target_id == "payment_execution"
        assert t.evidence["object_id"] == "payment_instruction"
        assert t.affected_objects == ["payment_instruction"]

    def test_empty_snapshot_produces_no_threats(self) -> None:
        """All CAPEC heuristics should produce 0 threats from empty snapshot."""
        for i in range(15, 25):
            toml_file = f"th_{i:03d}.toml"
            h, mat = _load_rule(toml_file)
            threats = _run_materializer(mat, h, {})
            assert threats == [], f"{toml_file} produced threats from empty snapshot"


class TestCAPECDiscoveryIntegration:
    """Verify Phase 2 heuristics are discovered and registered."""

    def test_discovered_heuristics_include_capec_set(self) -> None:
        from analysis.heuristics import discovered_heuristics
        ids = {h.rule_id for h in discovered_heuristics()}
        expected = {f"TH-{i:03d}" for i in range(15, 25)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_discovered_materializers_include_capec_set(self) -> None:
        from analysis.heuristics import discovered_materializers
        ids = {m.rule_id for m in discovered_materializers()}
        expected = {f"TH-{i:03d}" for i in range(15, 25)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_heuristic_count_phase2(self) -> None:
        from analysis.heuristics import discovered_heuristics
        # Phase 0: TH-001–TH-006, Phase 1: TH-007–TH-014, Phase 2: TH-015–TH-024
        # Phase 3 adds TH-025–TH-034 (tested separately)
        assert len(discovered_heuristics()) >= 24


# ── Schema Enrichment Phase 3 heuristics (TH-025 – TH-034) ──────


def _enrichment_snapshot() -> dict[str, list[dict[str, Any]]]:
    """Snapshot data covering all Phase 3 schema enrichment heuristic queries."""
    return {
        "unauth_actor_modules": [
            {
                "actor_id": "customer",
                "actor_name": "Customer",
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "module_id": "fraud_model_service",
                "module_name": "Fraud Model Service",
            },
        ],
        "unencrypted_boundary": [
            {
                "source_module": "payment_service",
                "source_name": "Payment Service",
                "target_id": "fraud_model_service",
                "target_name": "Fraud Model Service",
                "trust_boundary": "backend_ml_boundary",
                "relationship": "calls",
            },
        ],
        "exposed_no_validation": [
            {
                "module_id": "mobile_app",
                "module_name": "Mobile App",
                "module_type": "client_application",
            },
        ],
        "exposed_no_rate_limit": [
            {
                "module_id": "mobile_app",
                "module_name": "Mobile App",
                "downstream_count": 1,
                "downstream_ids": ["api_gateway"],
            },
        ],
        "critical_unlogged": [
            {
                "module_id": "fraud_model_service",
                "module_name": "Fraud Model Service",
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "system_criticality": "high",
            },
        ],
        "unencrypted_sensitive_store": [
            {
                "module_id": "payment_service",
                "module_name": "Payment Service",
                "datastore_id": "txn_db",
                "datastore_name": "Transaction Database",
                "relationship": "writes",
                "sensitive_objects": ["payment_instruction"],
            },
        ],
        "bidirectional_boundary": [
            {
                "source_module": "payment_service",
                "source_name": "Payment Service",
                "target_id": "fraud_model_service",
                "target_name": "Fraud Model Service",
                "trust_boundary": "backend_ml_boundary",
                "relationship": "calls",
            },
        ],
        "api_across_boundary": [
            {
                "module_id": "auth_service",
                "module_name": "Auth Service",
                "api_endpoints": ["/internal/auth/verify", "/internal/auth/token"],
                "domain_id": "backend",
                "trust_boundary": "backend_ml_boundary",
            },
        ],
        "unauth_chain_privileged": [
            {
                "source_module": "mobile_app",
                "source_name": "Mobile App",
                "target_module": "fraud_model_service",
                "target_name": "Fraud Model Service",
                "privilege_level": 2,
            },
        ],
        "mobile_edge_regulated": [
            {
                "module_id": "mobile_app",
                "module_name": "Mobile App",
                "deployment_context": "mobile",
                "workflow_id": "user_login",
                "workflow_name": "User Login",
                "object_id": "user_credentials",
                "object_name": "User Credentials",
            },
        ],
    }


class TestEnrichmentHeuristicParsing:
    """Verify all Phase 3 enrichment TOML rules parse correctly."""

    @pytest.mark.parametrize(
        "toml_file,expected_id",
        [
            ("th_025.toml", "TH-025"),
            ("th_026.toml", "TH-026"),
            ("th_027.toml", "TH-027"),
            ("th_028.toml", "TH-028"),
            ("th_029.toml", "TH-029"),
            ("th_030.toml", "TH-030"),
            ("th_031.toml", "TH-031"),
            ("th_032.toml", "TH-032"),
            ("th_033.toml", "TH-033"),
            ("th_034.toml", "TH-034"),
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


class TestEnrichmentMaterializerOutput:
    """Verify Phase 3 TOML materializers produce correct threat records."""

    @pytest.mark.parametrize(
        "toml_file,snapshot_key,expected_count",
        [
            ("th_025.toml", "unauth_actor_modules", 1),
            ("th_026.toml", "unencrypted_boundary", 1),
            ("th_027.toml", "exposed_no_validation", 1),
            ("th_028.toml", "exposed_no_rate_limit", 1),
            ("th_029.toml", "critical_unlogged", 1),
            ("th_030.toml", "unencrypted_sensitive_store", 1),
            ("th_031.toml", "bidirectional_boundary", 1),
            ("th_032.toml", "api_across_boundary", 1),
            ("th_033.toml", "unauth_chain_privileged", 1),
            ("th_034.toml", "mobile_edge_regulated", 1),
        ],
    )
    def test_produces_expected_threat_count(
        self, toml_file: str, snapshot_key: str, expected_count: int,
    ) -> None:
        h, mat = _load_rule(toml_file)
        snapshot = _enrichment_snapshot()
        threats = _run_materializer(mat, h, snapshot)
        assert len(threats) == expected_count, (
            f"{toml_file}: expected {expected_count} threats, got {len(threats)}"
        )

    def test_th_025_unauthenticated_actor_fields(self) -> None:
        h, mat = _load_rule("th_025.toml")
        threats = _run_materializer(mat, h, _enrichment_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-025"
        assert t.target_id == "fraud_model_service"
        assert t.evidence["actor_id"] == "customer"
        assert t.affected_workflows == ["payment_execution"]

    def test_th_027_no_input_validation_fields(self) -> None:
        h, mat = _load_rule("th_027.toml")
        threats = _run_materializer(mat, h, _enrichment_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-027"
        assert t.target_id == "mobile_app"
        assert t.severity_hint == "high"
        assert t.evidence["module_type"] == "client_application"

    def test_th_029_unlogged_critical_fields(self) -> None:
        h, mat = _load_rule("th_029.toml")
        threats = _run_materializer(mat, h, _enrichment_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-029"
        assert t.target_id == "fraud_model_service"
        assert t.evidence["system_criticality"] == "high"
        assert t.affected_workflows == ["payment_execution"]

    def test_th_033_unauth_chain_privileged_fields(self) -> None:
        h, mat = _load_rule("th_033.toml")
        threats = _run_materializer(mat, h, _enrichment_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-033"
        assert t.target_id == "fraud_model_service"
        assert t.severity_hint == "critical"
        assert t.evidence["privilege_level"] == 2

    def test_th_034_mobile_regulated_fields(self) -> None:
        h, mat = _load_rule("th_034.toml")
        threats = _run_materializer(mat, h, _enrichment_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-034"
        assert t.target_id == "mobile_app"
        assert t.evidence["deployment_context"] == "mobile"
        assert t.affected_workflows == ["user_login"]
        assert t.affected_objects == ["user_credentials"]

    def test_empty_snapshot_produces_no_threats(self) -> None:
        """All enrichment heuristics should produce 0 threats from empty snapshot."""
        for i in range(25, 35):
            toml_file = f"th_{i:03d}.toml"
            h, mat = _load_rule(toml_file)
            threats = _run_materializer(mat, h, {})
            assert threats == [], f"{toml_file} produced threats from empty snapshot"


class TestEnrichmentDiscoveryIntegration:
    """Verify Phase 3 heuristics are discovered and registered."""

    def test_discovered_heuristics_include_enrichment_set(self) -> None:
        from analysis.heuristics import discovered_heuristics
        ids = {h.rule_id for h in discovered_heuristics()}
        expected = {f"TH-{i:03d}" for i in range(25, 35)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_discovered_materializers_include_enrichment_set(self) -> None:
        from analysis.heuristics import discovered_materializers
        ids = {m.rule_id for m in discovered_materializers()}
        expected = {f"TH-{i:03d}" for i in range(25, 35)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_heuristic_count(self) -> None:
        from analysis.heuristics import discovered_heuristics
        # Phase 0–3: TH-001–TH-034
        assert len(discovered_heuristics()) >= 34


# ── Control-Gap Detection Phase 4 heuristics (TH-035 – TH-044) ──


def _control_gap_snapshot() -> dict[str, list[dict[str, Any]]]:
    """Snapshot data covering all Phase 4 control-gap heuristic queries."""
    return {
        "no_flow_enforcement": [
            {
                "source_module": "mobile_app",
                "source_name": "Mobile App",
                "target_id": "api_gateway",
                "target_name": "API Gateway",
                "trust_boundary": "internet_boundary",
                "unprotected_domain": "edge",
            },
        ],
        "no_access_control": [
            {
                "actor_id": "customer",
                "actor_name": "Customer",
                "actor_type": "end_user",
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
            },
        ],
        "no_boundary_protection": [
            {
                "trust_boundary": "internet_boundary",
                "boundary_name": "Internet Boundary",
                "from_domain": "client",
                "to_domain": "edge",
            },
        ],
        "no_encryption_service": [
            {
                "module_id": "payment_service",
                "module_name": "Payment Service",
                "datastore_id": "txn_db",
                "datastore_name": "Transaction Database",
                "sensitive_objects": ["payment_instruction"],
            },
        ],
        "no_auth_service": [
            {
                "actor_id": "customer",
                "actor_name": "Customer",
                "module_id": "fraud_model_service",
                "module_name": "Fraud Model Service",
                "workflow_id": "payment_execution",
            },
        ],
        "no_validation_service": [
            {
                "exposed_module": "mobile_app",
                "exposed_name": "Mobile App",
                "downstream_module": "api_gateway",
                "downstream_name": "API Gateway",
            },
        ],
        "no_audit_module": [
            {
                "workflow_id": "payment_execution",
                "workflow_name": "Payment Execution",
                "system_criticality": "high",
            },
        ],
        "no_encryption_at_rest": [
            {
                "datastore_id": "txn_db",
                "datastore_name": "Transaction Database",
                "classified_objects": ["payment_instruction"],
            },
        ],
        "no_change_control": [
            {
                "module_id": "payment_service",
                "module_name": "Payment Service",
                "privilege_level": 3,
            },
        ],
        "spof_no_contingency": [
            {
                "module_id": "api_gateway",
                "module_name": "API Gateway",
                "workflow_count": 3,
                "workflows": ["payment_execution", "user_login", "fraud_check"],
            },
        ],
    }


class TestControlGapHeuristicParsing:
    """Verify all Phase 4 control-gap TOML rules parse correctly."""

    @pytest.mark.parametrize(
        "toml_file,expected_id",
        [
            ("th_035.toml", "TH-035"),
            ("th_036.toml", "TH-036"),
            ("th_037.toml", "TH-037"),
            ("th_038.toml", "TH-038"),
            ("th_039.toml", "TH-039"),
            ("th_040.toml", "TH-040"),
            ("th_041.toml", "TH-041"),
            ("th_042.toml", "TH-042"),
            ("th_043.toml", "TH-043"),
            ("th_044.toml", "TH-044"),
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


class TestControlGapMaterializerOutput:
    """Verify Phase 4 TOML materializers produce correct threat records."""

    @pytest.mark.parametrize(
        "toml_file,snapshot_key,expected_count",
        [
            ("th_035.toml", "no_flow_enforcement", 1),
            ("th_036.toml", "no_access_control", 1),
            ("th_037.toml", "no_boundary_protection", 1),
            ("th_038.toml", "no_encryption_service", 1),
            ("th_039.toml", "no_auth_service", 1),
            ("th_040.toml", "no_validation_service", 1),
            ("th_041.toml", "no_audit_module", 1),
            ("th_042.toml", "no_encryption_at_rest", 1),
            ("th_043.toml", "no_change_control", 1),
            ("th_044.toml", "spof_no_contingency", 1),
        ],
    )
    def test_produces_expected_threat_count(
        self, toml_file: str, snapshot_key: str, expected_count: int,
    ) -> None:
        h, mat = _load_rule(toml_file)
        snapshot = _control_gap_snapshot()
        threats = _run_materializer(mat, h, snapshot)
        assert len(threats) == expected_count, (
            f"{toml_file}: expected {expected_count} threats, got {len(threats)}"
        )

    def test_th_035_no_flow_enforcement_fields(self) -> None:
        h, mat = _load_rule("th_035.toml")
        threats = _run_materializer(mat, h, _control_gap_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-035"
        assert t.target_id == "mobile_app"
        assert t.severity_hint == "high"
        assert t.evidence["trust_boundary"] == "internet_boundary"
        assert t.evidence["unprotected_domain"] == "edge"

    def test_th_036_no_access_control_fields(self) -> None:
        h, mat = _load_rule("th_036.toml")
        threats = _run_materializer(mat, h, _control_gap_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-036"
        assert t.target_id == "payment_execution"
        assert t.evidence["actor_id"] == "customer"
        assert t.affected_workflows == ["payment_execution"]

    def test_th_039_no_auth_service_fields(self) -> None:
        h, mat = _load_rule("th_039.toml")
        threats = _run_materializer(mat, h, _control_gap_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-039"
        assert t.target_id == "payment_execution"
        assert t.evidence["actor_id"] == "customer"
        assert t.affected_workflows == ["payment_execution"]

    def test_th_041_no_audit_module_fields(self) -> None:
        h, mat = _load_rule("th_041.toml")
        threats = _run_materializer(mat, h, _control_gap_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-041"
        assert t.target_id == "payment_execution"
        assert t.target_type == "workflow"
        assert t.evidence["system_criticality"] == "high"
        assert t.affected_workflows == ["payment_execution"]

    def test_th_044_spof_no_contingency_fields(self) -> None:
        h, mat = _load_rule("th_044.toml")
        threats = _run_materializer(mat, h, _control_gap_snapshot())
        t = threats[0]
        assert t.rule_id == "TH-044"
        assert t.target_id == "api_gateway"
        assert t.severity_hint == "high"
        assert t.evidence["workflow_count"] == 3

    def test_empty_snapshot_produces_no_threats(self) -> None:
        """All control-gap heuristics should produce 0 threats from empty snapshot."""
        for i in range(35, 45):
            toml_file = f"th_{i:03d}.toml"
            h, mat = _load_rule(toml_file)
            threats = _run_materializer(mat, h, {})
            assert threats == [], f"{toml_file} produced threats from empty snapshot"


class TestControlGapDiscoveryIntegration:
    """Verify Phase 4 heuristics are discovered and registered."""

    def test_discovered_heuristics_include_control_gap_set(self) -> None:
        from analysis.heuristics import discovered_heuristics
        ids = {h.rule_id for h in discovered_heuristics()}
        expected = {f"TH-{i:03d}" for i in range(35, 45)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_discovered_materializers_include_control_gap_set(self) -> None:
        from analysis.heuristics import discovered_materializers
        ids = {m.rule_id for m in discovered_materializers()}
        expected = {f"TH-{i:03d}" for i in range(35, 45)}
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_heuristic_count_phase4(self) -> None:
        from analysis.heuristics import discovered_heuristics
        # Phase 0–4: TH-001–TH-044
        assert len(discovered_heuristics()) == 44
