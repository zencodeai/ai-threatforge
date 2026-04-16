from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def sync(
    *,
    attack_version: str = "latest",
    atlas_version: str = "latest",
    offline_dir: str | Path | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
    attack_domains: tuple[str, ...] = ATTACK_DOMAINS,
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

    return counts


def sync_status(db_path: Path | str = DEFAULT_DB_PATH) -> dict[str, str]:
    path = Path(db_path)
    if not path.exists():
        return {"status": "not synced", "db_path": str(path)}

    with TechniqueStore(path) as store:
        return {
            "status": "synced" if store.is_populated() else "empty",
            "attack_version": store.get_meta("attack_version", "unknown"),
            "atlas_version": store.get_meta("atlas_version", "unknown"),
            "last_sync_utc": store.get_meta("last_sync_utc", "never"),
            "technique_count": store.get_meta("technique_count", "0"),
            "db_path": str(path),
        }
