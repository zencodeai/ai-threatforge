from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator


class Meta(BaseModel):
    schema_version: str
    model_id: str
    last_updated: str
    author: str


class System(BaseModel):
    name: str
    description: str
    criticality: Literal["low", "medium", "high", "critical"]
    industry: str


class SecurityDomain(BaseModel):
    id: str
    name: str
    trust_level: Literal["low", "medium", "high"]


class PrivilegeLevel(BaseModel):
    id: str
    level: int = Field(ge=0)
    description: str


class Module(BaseModel):
    id: str
    name: str
    module_type: str
    domain: str
    privilege: str
    internet_exposed: bool = False
    processes_sensitive_data: bool = False
    ai_relevant: bool = False
    description: str | None = None
    authentication_required: bool = False
    input_validation: bool = False
    rate_limiting: bool = False
    logging_enabled: bool = False
    api_endpoints: list[str] = Field(default_factory=list)
    deployment_context: str | None = None


class ObjectModel(BaseModel):
    id: str
    name: str
    object_type: str
    classification: Literal["public", "internal", "confidential", "secret"]
    regulated: bool = False
    ai_relevant: bool = False


class DataStore(BaseModel):
    id: str
    name: str
    store_type: str
    domain: str
    contains: list[str] = Field(default_factory=list)
    ai_relevant: bool = False


class ExternalActor(BaseModel):
    id: str
    name: str
    actor_type: str


class Workflow(BaseModel):
    id: str
    name: str
    description: str
    steps: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    objects: list[str] = Field(default_factory=list)


class TrustBoundary(BaseModel):
    id: str
    name: str
    from_domain: str
    to_domain: str


class Dependency(BaseModel):
    source: str
    target: str
    relationship: str
    encryption_in_transit: bool = False
    data_flow_direction: str | None = None


class CanonicalModel(BaseModel):
    meta: Meta
    system: System
    security_domains: list[SecurityDomain] = Field(default_factory=list)
    privilege_levels: list[PrivilegeLevel] = Field(default_factory=list)
    modules: list[Module] = Field(default_factory=list)
    objects: list[ObjectModel] = Field(default_factory=list)
    datastores: list[DataStore] = Field(default_factory=list)
    external_actors: list[ExternalActor] = Field(default_factory=list)
    workflows: list[Workflow] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references(self) -> "CanonicalModel":
        errors: list[str] = []

        def duplicate_ids(values: list[str], label: str) -> None:
            counts = Counter(values)
            dupes = [item for item, count in counts.items() if count > 1]
            if dupes:
                errors.append(f"Duplicate {label} ids: {', '.join(sorted(dupes))}")

        domain_ids = [d.id for d in self.security_domains]
        privilege_ids = [p.id for p in self.privilege_levels]
        module_ids = [m.id for m in self.modules]
        object_ids = [o.id for o in self.objects]
        datastore_ids = [d.id for d in self.datastores]

        duplicate_ids(domain_ids, "security_domain")
        duplicate_ids(privilege_ids, "privilege_level")
        duplicate_ids(module_ids, "module")
        duplicate_ids(object_ids, "object")
        duplicate_ids(datastore_ids, "datastore")

        domain_set = set(domain_ids)
        privilege_set = set(privilege_ids)
        module_set = set(module_ids)
        object_set = set(object_ids)
        target_set = module_set | set(datastore_ids)

        for module in self.modules:
            if module.domain not in domain_set:
                errors.append(f"Module '{module.id}' references unknown domain '{module.domain}'")
            if module.privilege not in privilege_set:
                errors.append(
                    f"Module '{module.id}' references unknown privilege '{module.privilege}'"
                )

        for datastore in self.datastores:
            if datastore.domain not in domain_set:
                errors.append(
                    f"Datastore '{datastore.id}' references unknown domain '{datastore.domain}'"
                )
            unknown_contains = sorted(set(datastore.contains) - object_set)
            if unknown_contains:
                errors.append(
                    f"Datastore '{datastore.id}' contains unknown objects: {', '.join(unknown_contains)}"
                )

        for workflow in self.workflows:
            unknown_modules = sorted(set(workflow.modules) - module_set)
            if unknown_modules:
                errors.append(
                    f"Workflow '{workflow.id}' references unknown modules: {', '.join(unknown_modules)}"
                )
            unknown_objects = sorted(set(workflow.objects) - object_set)
            if unknown_objects:
                errors.append(
                    f"Workflow '{workflow.id}' references unknown objects: {', '.join(unknown_objects)}"
                )

        for boundary in self.trust_boundaries:
            if boundary.from_domain not in domain_set:
                errors.append(
                    f"Trust boundary '{boundary.id}' has unknown from_domain '{boundary.from_domain}'"
                )
            if boundary.to_domain not in domain_set:
                errors.append(
                    f"Trust boundary '{boundary.id}' has unknown to_domain '{boundary.to_domain}'"
                )

        for dependency in self.dependencies:
            if dependency.source not in module_set:
                errors.append(
                    f"Dependency source '{dependency.source}' is not a known module"
                )
            if dependency.target not in target_set:
                errors.append(
                    f"Dependency target '{dependency.target}' is not a known module or datastore"
                )

        if errors:
            raise ValueError("; ".join(errors))

        return self


def load_canonical_model(path: str | Path) -> CanonicalModel:
    import tomllib

    path = Path(path)
    with path.open("rb") as handle:
        payload: dict[str, Any] = tomllib.load(handle)
    return CanonicalModel.model_validate(payload)


def validate_canonical_model(path: str | Path) -> tuple[bool, str]:
    try:
        load_canonical_model(path)
    except ValidationError as exc:
        return False, exc.json(indent=2)
    except ValueError as exc:
        return False, str(exc)
    return True, "Model is valid"
