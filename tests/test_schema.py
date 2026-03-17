from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from models.schema.canonical_model import CanonicalModel, load_canonical_model


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "models" / "examples" / "fintech_ai_platform.toml"


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
