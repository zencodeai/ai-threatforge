from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_generation import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-005",
    name="Regulated object concentration in critical workflows",
    description=(
        "Highlight workflows in high or critical systems that involve multiple "
        "regulated objects and privileged modules."
    ),
    graph_pattern=(
        "(s:System {criticality in ['high','critical']})-[:HAS_WORKFLOW]->(w)-"
        "[:INVOLVES_OBJECT]->(o:Object {regulated:true}) and workflow privileged modules"
    ),
    target_type="workflow",
    severity_hint="high",
    frameworks=("ATTACK",),
    output_field_mapping=(
        "target_id <- workflow.id",
        "affected_objects <- regulated object ids",
        "affected_modules <- privileged module ids",
        "system_criticality <- system.criticality",
        "rationale <- regulated data in critical workflow",
    ),
)


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
