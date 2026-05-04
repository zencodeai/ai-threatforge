from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_generation import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-004",
    name="AI-relevant module dependency and model service exposure",
    description=(
        "Detect modules that depend on AI-relevant services and can influence model "
        "inputs, feature stores, or inference surfaces."
    ),
    graph_pattern=(
        "(m:Module)-[:DEPENDS_ON]->(ai:Module {ai_relevant:true}) OR "
        "workflow path to ai_relevant datastore/object"
    ),
    target_type="module",
    severity_hint="high",
    frameworks=("ATLAS", "ATTACK"),
    output_field_mapping=(
        "target_id <- ai module.id",
        "target_type <- 'module'",
        "ai_surface <- model/feature data path",
        "rationale <- AI service dependency with potential manipulation",
    ),
)


class TH004Materializer:
    rule_id = "TH-004"
    required_snapshot_keys = ("ai_dependencies",)

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
