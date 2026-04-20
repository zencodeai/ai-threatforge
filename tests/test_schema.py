from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from models.schema.canonical_model import CanonicalModel, load_canonical_model


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


def load_example_payload() -> dict[str, Any]:
    import tomllib

    with EXAMPLE_MODEL.open("rb") as handle:
        return tomllib.load(handle)


def test_valid_example_model_loads() -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    assert model.meta.model_id == "fintech-ai-demo"
    assert len(model.modules) == 5


def test_invalid_module_domain_fails() -> None:
    payload = load_example_payload()
    payload["modules"][0]["domain"] = "unknown_domain"

    with pytest.raises(ValueError, match="unknown domain"):
        CanonicalModel.model_validate(payload)


def test_invalid_workflow_object_reference_fails() -> None:
    payload = load_example_payload()
    payload["workflows"][0]["objects"].append("does_not_exist")

    with pytest.raises(ValueError, match="unknown objects"):
        CanonicalModel.model_validate(payload)


def test_invalid_dependency_target_fails() -> None:
    payload = load_example_payload()
    payload["dependencies"][0]["target"] = "not_a_component"

    with pytest.raises(ValueError, match="known module or datastore"):
        CanonicalModel.model_validate(payload)


def test_duplicate_module_ids_fail() -> None:
    payload = load_example_payload()
    duplicate = dict(payload["modules"][0])
    payload["modules"].append(duplicate)

    with pytest.raises(ValueError, match="Duplicate module ids"):
        CanonicalModel.model_validate(payload)


def test_invalid_datastore_contains_fails() -> None:
    payload = load_example_payload()
    payload["datastores"][0]["contains"] = ["unknown_object"]

    with pytest.raises(ValueError, match="contains unknown objects"):
        CanonicalModel.model_validate(payload)


# ── Phase 3 schema enrichment tests ──────────────────────────────


def test_module_enrichment_fields_parse() -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    gateway = next(m for m in model.modules if m.id == "api_gateway")
    assert gateway.authentication_required is True
    assert gateway.input_validation is True
    assert gateway.rate_limiting is True
    assert gateway.logging_enabled is True
    assert "/api/v1/payments" in gateway.api_endpoints
    assert gateway.deployment_context == "cloud"


def test_module_enrichment_defaults() -> None:
    """Omitting enrichment fields should produce backward-compatible defaults."""
    payload = load_example_payload()
    # Strip all enrichment fields from first module
    for key in (
        "authentication_required", "input_validation", "rate_limiting",
        "logging_enabled", "api_endpoints", "deployment_context",
    ):
        payload["modules"][0].pop(key, None)
    model = CanonicalModel.model_validate(payload)
    m = model.modules[0]
    assert m.authentication_required is False
    assert m.input_validation is False
    assert m.rate_limiting is False
    assert m.logging_enabled is False
    assert m.api_endpoints == []
    assert m.deployment_context is None


def test_dependency_enrichment_fields_parse() -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    encrypted_dep = next(
        d for d in model.dependencies
        if d.source == "mobile_app" and d.target == "api_gateway"
    )
    assert encrypted_dep.encryption_in_transit is True
    assert encrypted_dep.data_flow_direction == "outbound"


def test_dependency_enrichment_defaults() -> None:
    """Omitting dependency enrichment fields should produce defaults."""
    payload = load_example_payload()
    for key in ("encryption_in_transit", "data_flow_direction"):
        payload["dependencies"][0].pop(key, None)
    model = CanonicalModel.model_validate(payload)
    d = model.dependencies[0]
    assert d.encryption_in_transit is False
    assert d.data_flow_direction is None


# ── Phase 4 control-gap detection tests ─────────────────────────


def test_module_control_functions_parse() -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    gateway = next(m for m in model.modules if m.id == "api_gateway")
    assert "AC-4" in gateway.control_functions
    assert "SC-7" in gateway.control_functions
    assert "SI-10" in gateway.control_functions
    assert "AU-2" in gateway.control_functions


def test_module_control_functions_default() -> None:
    """Omitting control_functions should default to empty list."""
    payload = load_example_payload()
    payload["modules"][0].pop("control_functions", None)
    model = CanonicalModel.model_validate(payload)
    m = model.modules[0]
    assert m.control_functions == []
