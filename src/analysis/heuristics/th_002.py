from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_generation import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-002",
    name="Low-trust to high-value object dependency path",
    description=(
        "Identify dependency chains beginning in low-trust domains and ending at "
        "confidential, secret, or regulated objects through datastores."
    ),
    graph_pattern=(
        "(src:Module)-[:IN_DOMAIN]->(:SecurityDomain {trust_level:'low'}), "
        "path via [:DEPENDS_ON*] to (:DataStore)-[:STORES]->(o:Object high-value)"
    ),
    target_type="object",
    severity_hint="critical",
    frameworks=("ATTACK",),
    output_field_mapping=(
        "target_id <- object.id",
        "target_type <- 'object'",
        "exposure_path <- dependency path",
        "affected_modules <- entry and pivot modules",
        "rationale <- low-trust reachability to high-value data",
    ),
)


class TH002Materializer:
    rule_id = "TH-002"
    required_snapshot_keys = ("attack_paths",)

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
