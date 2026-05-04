from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .index import TechniqueIndex
from .models import Mitigation, Tactic, Technique
from .store import DEFAULT_DB_PATH, TechniqueStore
from .sync_attack import (
    ATTACK_DOMAINS,
    fetch_attack_bundle,
    load_attack_bundle_from_file,
    parse_attack_bundle,
)
from .sync_atlas import (
    fetch_atlas_data,
    load_atlas_data_from_file,
    parse_atlas_data,
)


def _dedup_tactics(tactics: list[Tactic]) -> list[Tactic]:
    """Keep the first occurrence of each tactic_id."""
    seen: dict[str, Tactic] = {}
    for t in tactics:
        if t.tactic_id not in seen:
            seen[t.tactic_id] = t
    return list(seen.values())


def _dedup_techniques(techniques: list[Technique]) -> list[Technique]:
    """Merge techniques that share an ID across domains (union platforms/tactics)."""
    seen: dict[str, Technique] = {}
    for t in techniques:
        if t.technique_id not in seen:
            seen[t.technique_id] = t
        else:
            existing = seen[t.technique_id]
            merged_platforms = tuple(dict.fromkeys(existing.platforms + t.platforms))
            merged_tactics = tuple(dict.fromkeys(existing.tactics + t.tactics))
            seen[t.technique_id] = Technique(
                technique_id=existing.technique_id,
                name=existing.name,
                framework=existing.framework,
                domain=existing.domain,
                description=existing.description,
                is_subtechnique=existing.is_subtechnique,
                parent_id=existing.parent_id,
                platforms=merged_platforms,
                tactics=merged_tactics,
                deprecated=existing.deprecated,
                url=existing.url,
            )
    return list(seen.values())


def _dedup_mitigations(mitigations: list[Mitigation]) -> list[Mitigation]:
    """Merge mitigations that share an ID across domains (union technique_ids)."""
    seen: dict[str, Mitigation] = {}
    for m in mitigations:
        if m.mitigation_id not in seen:
            seen[m.mitigation_id] = m
        else:
            existing = seen[m.mitigation_id]
            merged_ids = tuple(dict.fromkeys(existing.technique_ids + m.technique_ids))
            seen[m.mitigation_id] = Mitigation(
                mitigation_id=existing.mitigation_id,
                name=existing.name,
                framework=existing.framework,
                domain=existing.domain,
                description=existing.description,
                technique_ids=merged_ids,
            )
    return list(seen.values())


def _sync_to_neo4j(
    tactics: list[Tactic],
    techniques: list[Technique],
    mitigations: list[Mitigation],
    *,
    embed_chunks: bool = True,
) -> Any:
    """Load MITRE data into Neo4j and create bridge relationships.

    When *embed_chunks* is True (default), also runs the chunking pipeline
    to split descriptions, embed them, and write TextChunk nodes with a
    Neo4j native vector index.
    """
    from graph.knowledge_loader import KnowledgeGraphLoader, KnowledgeLoadStats
    from graph.neo4j_client import Neo4jClient, Neo4jConfig

    config = Neo4jConfig.from_env()
    with Neo4jClient(config) as client:
        client.verify_connectivity()
        loader = KnowledgeGraphLoader(client)
        loader.apply_schema()

        stats = loader.load_mitre_data(
            tactics=tactics,
            techniques=techniques,
            mitigations=mitigations,
        )

        # Build heuristic rule nodes and MAPS_TO edges from curated TOML
        heuristic_rules, curated_mappings = _load_heuristic_bridge_data()
        rules_count, maps_count = loader.load_heuristic_bridges(
            heuristic_rules=heuristic_rules,
            curated_mappings=curated_mappings,
        )
        stats.heuristic_rules = rules_count
        stats.maps_to_edges = maps_count

        # Create IMPLEMENTS_CONTROL bridges (Module -> Mitigation)
        stats.implements_control_edges = loader.sync_control_bridges()

        # Chunk descriptions and write TextChunk nodes with embeddings
        if embed_chunks:
            from .chunking import ChunkingPipeline
            from .embedder import SentenceTransformerEmbedder

            embedder = SentenceTransformerEmbedder()
            pipeline = ChunkingPipeline(client, embedder)
            chunk_stats = pipeline.process(
                techniques=techniques,
                mitigations=mitigations,
            )
            stats.text_chunks = chunk_stats.total_embedded

    return stats


def _load_heuristic_bridge_data() -> tuple[list[dict], list[dict]]:
    """Load heuristic definitions and curated mappings for Neo4j bridge creation."""
    import tomllib

    from project_paths import ProjectPaths

    paths = ProjectPaths.default()

    # Load heuristic rules from discovered heuristics
    from analysis.heuristics import discovered_heuristics

    heuristic_rules = [
        {
            "rule_id": h.rule_id,
            "name": h.name,
            "severity_hint": h.severity_hint,
            "target_type": h.target_type,
        }
        for h in discovered_heuristics()
    ]

    # Load curated mappings from TOML
    curated_mappings: list[dict] = []
    if paths.mapping_rules.exists():
        with open(paths.mapping_rules, "rb") as f:
            data = tomllib.load(f)
        for entry in data.get("mappings", []):
            curated_mappings.append({
                "rule_id": entry["rule_id"],
                "technique_id": entry["technique_id"],
                "tactic": entry["tactic"],
                "rationale": entry["rationale"],
                "mapping_type": "curated",
            })

    return heuristic_rules, curated_mappings


def sync(
    *,
    attack_version: str = "latest",
    atlas_version: str = "latest",
    offline_dir: str | Path | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
    attack_domains: tuple[str, ...] = ATTACK_DOMAINS,
    embed: bool = False,
    neo4j: bool = False,
    map_heuristics: bool = False,
    map_threshold: float = 0.40,
    map_top_k: int = 10,
    map_output: Path | None = None,
) -> dict[str, Any]:
    all_tactics: list[Tactic] = []
    all_techniques: list[Technique] = []
    all_mitigations: list[Mitigation] = []

    # ── ATT&CK ───────────────────────────────────────────────────
    for domain in attack_domains:
        if offline_dir:
            path = Path(offline_dir) / f"{domain}.json"
            bundle = load_attack_bundle_from_file(str(path))
        else:
            bundle = fetch_attack_bundle(domain, version=attack_version)

        tactics, techniques, mitigations = parse_attack_bundle(bundle, domain)
        all_tactics.extend(tactics)
        all_techniques.extend(techniques)
        all_mitigations.extend(mitigations)

    # ── ATLAS ────────────────────────────────────────────────────
    if offline_dir:
        atlas_path = Path(offline_dir) / "ATLAS.yaml"
        if atlas_path.exists():
            atlas_data = load_atlas_data_from_file(str(atlas_path))
        else:
            atlas_data = {"matrices": []}
    else:
        atlas_data = fetch_atlas_data(version=atlas_version)

    tactics, techniques, mitigations = parse_atlas_data(atlas_data)
    all_tactics.extend(tactics)
    all_techniques.extend(techniques)
    all_mitigations.extend(mitigations)

    # ── Store ────────────────────────────────────────────────────
    deduped_tactics = _dedup_tactics(all_tactics)
    deduped_techniques = _dedup_techniques(all_techniques)
    deduped_mitigations = _dedup_mitigations(all_mitigations)

    with TechniqueStore(db_path) as store:
        counts = store.replace_all(
            tactics=deduped_tactics,
            techniques=deduped_techniques,
            mitigations=deduped_mitigations,
        )
        store.set_meta("attack_version", attack_version)
        store.set_meta("atlas_version", atlas_version)
        store.set_meta("last_sync_utc", datetime.now(UTC).isoformat())
        store.set_meta("technique_count", str(counts["techniques"]))

        use_neo4j = neo4j or embed or map_heuristics

        # ── Neo4j knowledge graph ────────────────────────────────
        if use_neo4j:
            neo4j_counts = _sync_to_neo4j(
                deduped_tactics, deduped_techniques, deduped_mitigations,
            )
            counts["neo4j_techniques"] = neo4j_counts.techniques
            counts["neo4j_tactics"] = neo4j_counts.tactics
            counts["neo4j_mitigations"] = neo4j_counts.mitigations
            counts["neo4j_heuristic_rules"] = neo4j_counts.heuristic_rules
            counts["neo4j_maps_to"] = neo4j_counts.maps_to_edges
            counts["neo4j_implements_control"] = neo4j_counts.implements_control_edges
            counts["neo4j_text_chunks"] = neo4j_counts.text_chunks
            store.set_meta("text_chunk_count", str(neo4j_counts.text_chunks))

        if map_heuristics:
            from analysis.mapping_writer import generate_mapping_suggestions

            suggestion_counts = generate_mapping_suggestions(
                store,
                threshold=map_threshold,
                top_k=map_top_k,
                output_path=map_output,
            )
            counts["suggestions"] = suggestion_counts["_total"]
            counts["suggestion_counts"] = suggestion_counts

    TechniqueIndex.reset()
    return counts


def sync_status(db_path: Path | str = DEFAULT_DB_PATH) -> dict[str, str]:
    path = Path(db_path)
    if not path.exists():
        return {"status": "not synced", "db_path": str(path)}

    from project_paths import ProjectPaths

    defaults = ProjectPaths.default()
    suggestions_path = defaults.data_dir / "mapping_suggestions.toml"
    suggestion_count = 0
    if suggestions_path.exists():
        import tomllib

        with open(suggestions_path, "rb") as f:
            data = tomllib.load(f)
        suggestion_count = len(data.get("mappings", []))

    with TechniqueStore(path) as store:
        return {
            "status": "synced" if store.is_populated() else "empty",
            "attack_version": store.get_meta("attack_version", "unknown"),
            "atlas_version": store.get_meta("atlas_version", "unknown"),
            "last_sync_utc": store.get_meta("last_sync_utc", "never"),
            "technique_count": store.get_meta("technique_count", "0"),
            "text_chunk_count": store.get_meta("text_chunk_count", "0"),
            "suggestion_count": str(suggestion_count),
            "db_path": str(path),
        }
