from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_heuristics import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-003",
    name="High-privilege module externally reachable",
    description=(
        "Flag modules with service/admin privilege that are internet-exposed or "
        "reachable through workflows involving external actors."
    ),
    graph_pattern=(
        "(m:Module)-[:HAS_PRIVILEGE]->(p:PrivilegeLevel {level>=2}) AND "
        "(m.internet_exposed=true OR EXISTS external actor workflow path)"
    ),
    target_type="module",
    severity_hint="high",
    frameworks=("ATTACK",),
    output_field_mapping=(
        "target_id <- module.id",
        "privilege_level <- privilege.level",
        "external_reachability <- internet_exposed|workflow_actor_path",
        "rationale <- privilege + exposure combination",
    ),
)


class TH003Materializer:
    rule_id = "TH-003"
    required_snapshot_keys = ("high_priv_modules",)

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
