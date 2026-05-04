from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_heuristics import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-001",
    name="Internet exposed module handling sensitive workflow data",
    description=(
        "Detect modules reachable from the internet that participate in workflows "
        "handling confidential, secret, or regulated objects."
    ),
    graph_pattern=(
        "(m:Module {internet_exposed:true})<-[:INVOLVES_MODULE]-(w:Workflow)-"
        "[:INVOLVES_OBJECT]->(o:Object) WHERE o.classification IN ['confidential','secret'] "
        "OR o.regulated=true"
    ),
    target_type="module",
    severity_hint="high",
    frameworks=("ATTACK",),
    output_field_mapping=(
        "target_id <- module.id",
        "target_type <- 'module'",
        "affected_workflows <- workflow.id",
        "affected_objects <- object.id",
        "rationale <- internet exposure + sensitive data handling",
    ),
)


class TH001Materializer:
    rule_id = "TH-001"
    required_snapshot_keys = ("internet_modules", "sensitive_workflows")

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
