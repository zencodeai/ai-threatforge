from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_generation import ThreatHeuristic

HEURISTIC = ThreatHeuristic(
    rule_id="TH-006",
    name="Trust boundary crossing with privileged dependency",
    description=(
        "Detect dependencies that traverse defined trust boundaries and terminate "
        "in privileged backend or datastore components."
    ),
    graph_pattern=(
        "(tb:TrustBoundary)-[:CROSSES_FROM]->(from), (tb)-[:CROSSES_TO]->(to), "
        "(src)-[:IN_DOMAIN]->(from), (src)-[:DEPENDS_ON]->(dst)-[:IN_DOMAIN]->(to), "
        "dst privilege >= service or datastore with sensitive objects"
    ),
    target_type="module",
    severity_hint="medium",
    frameworks=("ATTACK",),
    output_field_mapping=(
        "target_id <- destination module/datastore id",
        "trust_boundary <- trust boundary id",
        "dependency_relationship <- DEPENDS_ON.relationship",
        "rationale <- boundary crossing into privileged/sensitive zone",
    ),
)


class TH006Materializer:
    rule_id = "TH-006"
    required_snapshot_keys = ("trust_boundaries", "dependency_edges")

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
