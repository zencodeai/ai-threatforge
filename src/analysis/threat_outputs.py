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

from .materializer_registry import all_materializers, auto_discover
from .technique_mapping import map_rule_to_techniques
from .threat_generation import THREAT_HEURISTICS

# ── Auto-discover and register heuristic plugins ─────────────────

auto_discover()


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
        # STRIDE expansion queries
        "unverified_actor_workflows": queries.unverified_actor_workflows(),
        "sensitive_writes": queries.module_writes_to_sensitive_datastore(),
        "exposed_fan_out": queries.exposed_module_fan_out(),
        "privilege_escalation": queries.privilege_escalation_dependencies(),
        "cross_domain_stores": queries.cross_domain_datastore_access(),
        "workflow_module_concentration": queries.workflow_module_concentration(),
        "regulated_ai_data": queries.regulated_ai_data(),
        # CAPEC expansion queries (Phase 2)
        "transitive_priv_escalation": queries.transitive_privilege_escalation(),
        "actor_privileged_modules": queries.actor_to_privileged_module(),
        "cross_trust_writes": queries.cross_trust_write_access(),
        "credential_low_trust": queries.credential_in_low_trust_workflow(),
        "high_fan_in": queries.high_fan_in_targets(),
        "workflow_trust_span": queries.workflow_trust_span(),
        "actor_regulated_access": queries.actor_regulated_data_access(),
        "untrusted_ai_store": queries.untrusted_ai_datastore_access(),
        "multi_domain_chain": queries.multi_domain_dependency_chain(),
        "exposed_transitive_stores": queries.exposed_transitive_datastore_access(),
        # Schema enrichment queries (Phase 3)
        "unauth_actor_modules": queries.unauthenticated_actor_modules(),
        "unencrypted_boundary": queries.unencrypted_boundary_flows(),
        "exposed_no_validation": queries.exposed_without_input_validation(),
        "exposed_no_rate_limit": queries.exposed_without_rate_limiting(),
        "critical_unlogged": queries.critical_workflow_unlogged_modules(),
        "unencrypted_sensitive_store": queries.unencrypted_sensitive_datastore_flow(),
        "bidirectional_boundary": queries.bidirectional_boundary_flows(),
        "api_across_boundary": queries.api_endpoints_across_boundary(),
        "unauth_chain_privileged": queries.unauthenticated_chain_to_privileged(),
        "mobile_edge_regulated": queries.mobile_edge_regulated_data(),
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

    for materializer in all_materializers():
        rule = _heuristic(materializer.rule_id)
        threats.extend(
            materializer.materialize(
                rule,
                model,
                snapshot,
                now=now,
                technique_refs_fn=_technique_refs,
                stable_id_fn=_stable_threat_id,
                sorted_unique_fn=_sorted_unique,
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
