from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from graph.graph_queries import GraphQueries
from graph.neo4j_client import Neo4jClient, Neo4jConfig
from models.schema.canonical_model import CanonicalModel, load_canonical_model
from models.schema.threat_model import TechniqueReference, ThreatRecord, ThreatReport

from .materializer_registry import all_materializers, auto_discover
from .snapshot_resolver import ThreatSnapshotResolver
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
    snapshot: Mapping[str, list[dict[str, Any]]],
    *,
    neo4j_client: Neo4jClient | None = None,
) -> ThreatReport:
    now = _timestamp()
    threats: list[ThreatRecord] = []

    for materializer in all_materializers():
        required_keys = getattr(materializer, "required_snapshot_keys", ())
        if hasattr(snapshot, "preload"):
            snapshot.preload(required_keys)  # type: ignore[union-attr]
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

    # GraphRAG enrichment (opt-in when Neo4j client is provided)
    if neo4j_client is not None:
        try:
            from .threat_enricher import ThreatEnricher

            enricher = ThreatEnricher(neo4j_client)
            enricher.enrich(ordered, model)
        except Exception:
            logging.getLogger(__name__).warning(
                "GraphRAG enrichment failed; returning unenriched report.",
                exc_info=True,
            )

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
    *,
    enrich: bool = False,
) -> tuple[ThreatReport, Path]:
    model = load_canonical_model(model_path)

    config = Neo4jConfig.from_env()
    with Neo4jClient(config) as client:
        client.verify_connectivity()
        queries = GraphQueries(client)
        snapshot = ThreatSnapshotResolver(queries)

        report = build_threat_report_from_snapshot(
            model, snapshot, neo4j_client=client if enrich else None,
        )

    if output_path is None:
        output_path = (
            Path("models")
            / "outputs"
            / "threats"
            / f"{model.meta.model_id}_threats.json"
        )

    written_path = write_threat_report(report, output_path)
    return report, written_path
