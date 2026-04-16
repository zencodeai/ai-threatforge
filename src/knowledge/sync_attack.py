from __future__ import annotations

import json
from typing import Any

from .models import Mitigation, Tactic, Technique

ATTACK_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")

_KILL_CHAIN_PREFIXES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")


def _domain_label(domain: str) -> str:
    return domain.replace("-attack", "")


def _extract_external_id(obj: dict[str, Any], source_name: str) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref["external_id"]
    return ""


def _extract_url(obj: dict[str, Any], source_name: str) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("url", "")
    return ""


def parse_attack_bundle(bundle: dict[str, Any], domain: str) -> tuple[
    list[Tactic], list[Technique], list[Mitigation],
]:
    objects = bundle.get("objects", [])
    domain_label = _domain_label(domain)

    source_name = "mitre-attack"
    if domain == "mobile-attack":
        source_name = "mitre-mobile-attack"
    elif domain == "ics-attack":
        source_name = "mitre-ics-attack"

    # Parse tactics from x-mitre-tactic objects
    tactics: list[Tactic] = []
    tactic_id_to_shortname: dict[str, str] = {}

    # Determine tactic order from matrix
    tactic_ref_order: dict[str, int] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-matrix":
            for idx, ref in enumerate(obj.get("tactic_refs", [])):
                tactic_ref_order[ref] = idx

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue
        tactic_id = _extract_external_id(obj, source_name)
        if not tactic_id:
            # Fallback: some domains use "mitre-attack" as source_name for tactics
            tactic_id = _extract_external_id(obj, "mitre-attack")
        if not tactic_id:
            continue
        shortname = obj.get("x_mitre_shortname", "")
        stix_id = obj.get("id", "")
        order = tactic_ref_order.get(stix_id, 999)
        tactic_id_to_shortname[stix_id] = shortname
        tactics.append(Tactic(
            tactic_id=tactic_id,
            name=obj["name"],
            framework="ATTACK",
            domain=domain_label,
            shortname=shortname,
            order=order,
        ))

    # Parse relationships for subtechnique-of and mitigates
    subtechnique_parents: dict[str, str] = {}  # child stix_id -> parent stix_id
    mitigation_links: dict[str, list[str]] = {}  # mitigation stix_id -> [technique stix_id]

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked", False):
            continue
        rel_type = obj.get("relationship_type", "")
        if rel_type == "subtechnique-of":
            subtechnique_parents[obj["source_ref"]] = obj["target_ref"]
        elif rel_type == "mitigates":
            mitigation_links.setdefault(obj["source_ref"], []).append(obj["target_ref"])

    # Build stix_id -> technique_id mapping (need two passes)
    stix_to_attack_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            attack_id = _extract_external_id(obj, source_name)
            if not attack_id:
                attack_id = _extract_external_id(obj, "mitre-attack")
            if attack_id:
                stix_to_attack_id[obj["id"]] = attack_id

    # Parse techniques
    techniques: list[Technique] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _extract_external_id(obj, source_name)
        if not technique_id:
            technique_id = _extract_external_id(obj, "mitre-attack")
        if not technique_id:
            continue

        is_sub = obj.get("x_mitre_is_subtechnique", False)
        parent_stix_id = subtechnique_parents.get(obj["id"])
        parent_id = stix_to_attack_id.get(parent_stix_id, "") if parent_stix_id else None

        tactic_shortnames = tuple(
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if any(phase.get("kill_chain_name", "").startswith(p) for p in _KILL_CHAIN_PREFIXES)
        )

        url = _extract_url(obj, source_name)
        if not url:
            url = _extract_url(obj, "mitre-attack")

        techniques.append(Technique(
            technique_id=technique_id,
            name=obj["name"],
            framework="ATTACK",
            domain=domain_label,
            description=obj.get("description", ""),
            is_subtechnique=is_sub,
            parent_id=parent_id,
            platforms=tuple(obj.get("x_mitre_platforms", [])),
            tactics=tactic_shortnames,
            deprecated=obj.get("x_mitre_deprecated", False) or obj.get("revoked", False),
            url=url,
        ))

    # Parse mitigations
    mitigations: list[Mitigation] = []
    for obj in objects:
        if obj.get("type") != "course-of-action":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue
        mit_id = _extract_external_id(obj, source_name)
        if not mit_id:
            mit_id = _extract_external_id(obj, "mitre-attack")
        if not mit_id:
            continue

        linked_stix_ids = mitigation_links.get(obj["id"], [])
        linked_technique_ids = tuple(
            stix_to_attack_id[sid] for sid in linked_stix_ids if sid in stix_to_attack_id
        )

        mitigations.append(Mitigation(
            mitigation_id=mit_id,
            name=obj["name"],
            framework="ATTACK",
            domain=domain_label,
            description=obj.get("description", ""),
            technique_ids=linked_technique_ids,
        ))

    return tactics, techniques, mitigations


def fetch_attack_bundle(domain: str, *, version: str = "latest") -> dict[str, Any]:
    import httpx

    if version == "latest":
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
    else:
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}-{version}.json"

    response = httpx.get(url, timeout=60.0, follow_redirects=True)
    response.raise_for_status()
    return response.json()


def load_attack_bundle_from_file(path: str | __builtins__) -> dict[str, Any]:
    from pathlib import Path as _Path

    return json.loads(_Path(path).read_text(encoding="utf-8"))
