from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from graph.graph_queries import GraphQueries
from graph.neo4j_client import Neo4jClient, Neo4jConfig
from models.schema.canonical_model import CanonicalModel, load_canonical_model
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport

from .technique_mapping import map_rule_to_techniques
from .threat_generation import THREAT_HEURISTICS


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _stable_threat_id(rule_id: str, target_id: str, suffix: str = "") -> str:
    payload = f"{rule_id}|{target_id}|{suffix}".encode("utf-8")
    digest = hashlib.sha1(payload).hexdigest()[:10]
    return f"{rule_id}-{digest}"


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _build_snapshot(queries: GraphQueries) -> dict[str, list[dict[str, Any]]]:
    return {
        "internet_modules": queries.internet_exposed_modules(),
        "sensitive_workflows": queries.workflows_involving_sensitive_data(),
        "attack_paths": queries.low_to_high_trust_attack_paths(),
        "high_priv_modules": queries.high_privilege_externally_reachable_modules(),
        "ai_dependencies": queries.modules_depending_on_ai_services(),
        "critical_workflows": queries.risks_targeting_critical_workflows_view(),
        "regulated_data": queries.threats_affecting_regulated_data_view(),
        "dependency_edges": queries.dependency_edges(),
        "trust_boundaries": queries.trust_boundary_crossings(),
        "boundary_objects": queries.high_value_objects_crossing_boundaries(),
    }


def _technique_refs(rule_id: str) -> list[TechniqueReference]:
    return [
        TechniqueReference(**{
            "framework": mapping.framework,
            "technique_id": mapping.technique_id,
            "technique_name": mapping.technique_name,
            "tactic": mapping.tactic,
            "mapping_rationale": mapping.mapping_rationale,
            "mapping_type": mapping.mapping_type,
        })
        for mapping in map_rule_to_techniques(rule_id)
    ]


def _heuristic(rule_id: str):
    return next(rule for rule in THREAT_HEURISTICS if rule.rule_id == rule_id)


def build_threat_report_from_snapshot(
    model: CanonicalModel,
    snapshot: dict[str, list[dict[str, Any]]],
) -> ThreatReport:
    now = _timestamp()
    threats: list[ThreatRecord] = []

    sensitive_workflow_ids = _sorted_unique(
        [row.get("workflow_id", "") for row in snapshot["sensitive_workflows"]]
    )
    sensitive_objects = _sorted_unique(
        [
            obj
            for row in snapshot["sensitive_workflows"]
            for obj in row.get("sensitive_objects", [])
        ]
    )

    # TH-001
    rule = _heuristic("TH-001")
    for row in sorted(snapshot["internet_modules"], key=lambda x: x.get("module_id", "")):
        module_id = row.get("module_id", "")
        if not module_id:
            continue
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, module_id),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=module_id,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
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

    # TH-002
    rule = _heuristic("TH-002")
    for row in sorted(
        snapshot["attack_paths"], key=lambda x: (x.get("entry_module", ""), x.get("target_object", ""))
    ):
        target_object = row.get("target_object", "")
        entry_module = row.get("entry_module", "")
        if not target_object:
            continue
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, target_object, entry_module),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=target_object,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
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

    # TH-003
    rule = _heuristic("TH-003")
    for row in sorted(snapshot["high_priv_modules"], key=lambda x: x.get("module_id", "")):
        module_id = row.get("module_id", "")
        if not module_id:
            continue
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, module_id),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=module_id,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
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

    # TH-004
    rule = _heuristic("TH-004")
    for row in sorted(snapshot["ai_dependencies"], key=lambda x: (x.get("module_id", ""), x.get("ai_module_id", ""))):
        ai_module_id = row.get("ai_module_id", "")
        module_id = row.get("module_id", "")
        if not ai_module_id:
            continue
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, ai_module_id, module_id),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=ai_module_id,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
                rationale="Module dependency exposes AI-relevant service surface.",
                evidence={"dependent_module": module_id},
                affected_workflows=[],
                affected_objects=[],
                created_at=now,
            )
        )

    # TH-005
    rule = _heuristic("TH-005")
    regulated_objects = {
        row.get("regulated_object", ""): row for row in snapshot["regulated_data"] if row.get("regulated_object")
    }
    for row in sorted(snapshot["critical_workflows"], key=lambda x: x.get("workflow_id", "")):
        workflow_id = row.get("workflow_id", "")
        if not workflow_id:
            continue
        related_regulated = _sorted_unique(
            [
                object_id
                for object_id, detail in regulated_objects.items()
                if workflow_id in detail.get("workflows", [])
            ]
        )
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, workflow_id),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=workflow_id,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
                rationale="Critical workflow aggregates regulated data and privileged modules.",
                evidence={"system_criticality": row.get("system_criticality")},
                affected_workflows=[workflow_id],
                affected_objects=related_regulated,
                created_at=now,
            )
        )

    # TH-006
    rule = _heuristic("TH-006")
    boundaries = _sorted_unique([row.get("trust_boundary", "") for row in snapshot["trust_boundaries"]])
    for row in sorted(snapshot["dependency_edges"], key=lambda x: (x.get("source", ""), x.get("target", ""))):
        source = row.get("source", "")
        if not source:
            continue
        relationship = row.get("relationship", "")
        if relationship not in {"calls", "reads_writes", "writes"}:
            continue
        threats.append(
            ThreatRecord(
                threat_id=_stable_threat_id(rule.rule_id, source, row.get("target", "")),
                model_id=model.meta.model_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                target_id=source,
                target_type=rule.target_type,
                severity_hint=rule.severity_hint,
                framework_mappings=_technique_refs(rule.rule_id),
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

    # Deduplicate by threat_id for deterministic output.
    unique = {threat.threat_id: threat for threat in threats}
    ordered = sorted(unique.values(), key=lambda t: (t.rule_id, t.target_id, t.threat_id))

    return ThreatReport(
        model_id=model.meta.model_id,
        generated_at=now,
        threat_count=len(ordered),
        threats=ordered,
    )


def write_threat_report(report: ThreatReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def generate_threat_report(
    model_path: str | Path,
    output_path: str | Path | None = None,
) -> tuple[ThreatReport, Path]:
    model = load_canonical_model(model_path)

    config = Neo4jConfig.from_env()
    with Neo4jClient(config) as client:
        client.verify_connectivity()
        queries = GraphQueries(client)
        snapshot = _build_snapshot(queries)

    report = build_threat_report_from_snapshot(model, snapshot)

    if output_path is None:
        output_path = (
            Path("models")
            / "outputs"
            / "threats"
            / f"{model.meta.model_id}_threats.json"
        )

    written_path = write_threat_report(report, output_path)
    return report, written_path
