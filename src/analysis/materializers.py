from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from .threat_generation import ThreatHeuristic


class TH001Materializer:
    rule_id = "TH-001"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        sensitive_workflow_ids = sorted_unique_fn(
            [row.get("workflow_id", "") for row in snapshot["sensitive_workflows"]]
        )
        sensitive_objects = sorted_unique_fn(
            [
                obj
                for row in snapshot["sensitive_workflows"]
                for obj in row.get("sensitive_objects", [])
            ]
        )
        threats: list[ThreatRecord] = []
        for row in sorted(snapshot["internet_modules"], key=lambda x: x.get("module_id", "")):
            module_id = row.get("module_id", "")
            if not module_id:
                continue
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, module_id),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=module_id,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="Internet-exposed module intersects with sensitive workflow context.",
                    evidence={
                        "module_name": row.get("module_name"),
                        "module_type": row.get("module_type"),
                        "sensitive_workflow_count": len(sensitive_workflow_ids),
                    },
                    affected_workflows=sensitive_workflow_ids,
                    affected_objects=sensitive_objects,
                    created_at=now,
                )
            )
        return threats


class TH002Materializer:
    rule_id = "TH-002"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        threats: list[ThreatRecord] = []
        for row in sorted(
            snapshot["attack_paths"], key=lambda x: (x.get("entry_module", ""), x.get("target_object", ""))
        ):
            target_object = row.get("target_object", "")
            entry_module = row.get("entry_module", "")
            if not target_object:
                continue
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, target_object, entry_module),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=target_object,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="Low-trust dependency path reaches high-value object.",
                    evidence={
                        "entry_module": entry_module,
                        "hops": row.get("hops"),
                    },
                    affected_workflows=[],
                    affected_objects=[target_object],
                    created_at=now,
                )
            )
        return threats


class TH003Materializer:
    rule_id = "TH-003"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        threats: list[ThreatRecord] = []
        for row in sorted(snapshot["high_priv_modules"], key=lambda x: x.get("module_id", "")):
            module_id = row.get("module_id", "")
            if not module_id:
                continue
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, module_id),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=module_id,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="High-privilege module is externally reachable.",
                    evidence={
                        "privilege_level": row.get("privilege_level"),
                        "internet_exposed": row.get("internet_exposed"),
                    },
                    affected_workflows=[],
                    affected_objects=[],
                    created_at=now,
                )
            )
        return threats


class TH004Materializer:
    rule_id = "TH-004"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        threats: list[ThreatRecord] = []
        for row in sorted(snapshot["ai_dependencies"], key=lambda x: (x.get("module_id", ""), x.get("ai_module_id", ""))):
            ai_module_id = row.get("ai_module_id", "")
            module_id = row.get("module_id", "")
            if not ai_module_id:
                continue
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, ai_module_id, module_id),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=ai_module_id,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="Module dependency exposes AI-relevant service surface.",
                    evidence={"dependent_module": module_id},
                    affected_workflows=[],
                    affected_objects=[],
                    created_at=now,
                )
            )
        return threats


class TH005Materializer:
    rule_id = "TH-005"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        regulated_objects = {
            row.get("regulated_object", ""): row for row in snapshot["regulated_data"] if row.get("regulated_object")
        }
        threats: list[ThreatRecord] = []
        for row in sorted(snapshot["critical_workflows"], key=lambda x: x.get("workflow_id", "")):
            workflow_id = row.get("workflow_id", "")
            if not workflow_id:
                continue
            related_regulated = sorted_unique_fn(
                [
                    object_id
                    for object_id, detail in regulated_objects.items()
                    if workflow_id in detail.get("workflows", [])
                ]
            )
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, workflow_id),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=workflow_id,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="Critical workflow aggregates regulated data and privileged modules.",
                    evidence={"system_criticality": row.get("system_criticality")},
                    affected_workflows=[workflow_id],
                    affected_objects=related_regulated,
                    created_at=now,
                )
            )
        return threats


class TH006Materializer:
    rule_id = "TH-006"

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]:
        boundaries = sorted_unique_fn([row.get("trust_boundary", "") for row in snapshot["trust_boundaries"]])
        threats: list[ThreatRecord] = []
        for row in sorted(snapshot["dependency_edges"], key=lambda x: (x.get("source", ""), x.get("target", ""))):
            source = row.get("source", "")
            if not source:
                continue
            relationship = row.get("relationship", "")
            if relationship not in {"calls", "reads_writes", "writes"}:
                continue
            threats.append(
                ThreatRecord(
                    threat_id=stable_id_fn(rule.rule_id, source, row.get("target", "")),
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=source,
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale="Dependency can cross trust boundary into privileged/sensitive zone.",
                    evidence={
                        "dependency_target": row.get("target"),
                        "dependency_relationship": relationship,
                        "trust_boundaries": boundaries,
                    },
                    affected_workflows=[],
                    affected_objects=[],
                    created_at=now,
                )
            )
        return threats
