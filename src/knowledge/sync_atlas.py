from __future__ import annotations

from typing import Any

from .models import Mitigation, Tactic, Technique


def parse_atlas_data(data: dict[str, Any]) -> tuple[
    list[Tactic], list[Technique], list[Mitigation],
]:
    matrices = data.get("matrices", [])
    if not matrices:
        return [], [], []

    matrix = matrices[0]

    # Parse tactics
    tactics: list[Tactic] = []
    tactic_id_to_shortname: dict[str, str] = {}
    for idx, tac in enumerate(matrix.get("tactics", [])):
        tactic_id = tac["id"]
        # ATLAS tactic shortnames: derive from id (AML.TA0001 -> ml-model-access)
        # or use the name lowercased with hyphens
        shortname = tac.get("shortname", tac["name"].lower().replace(" ", "-"))
        tactic_id_to_shortname[tactic_id] = shortname
        tactics.append(Tactic(
            tactic_id=tactic_id,
            name=tac["name"],
            framework="ATLAS",
            domain="atlas",
            shortname=shortname,
            order=idx,
        ))

    # Parse techniques
    techniques: list[Technique] = []
    for tech in matrix.get("techniques", []):
        tech_id = tech["id"]
        # Subtechnique detection: AML.T0016.001 has more than one dot
        parts = tech_id.split(".")
        is_sub = len(parts) > 2
        parent_id = ".".join(parts[:2]) if is_sub else None

        # Tactics are stored as list of tactic IDs (or dicts) in ATLAS
        raw_tactics = tech.get("tactics", [])
        tactic_ids = [
            t["id"] if isinstance(t, dict) else t
            for t in raw_tactics
        ]
        tactic_shortnames = tuple(
            tactic_id_to_shortname.get(tid, tid)
            for tid in tactic_ids
        )

        techniques.append(Technique(
            technique_id=tech_id,
            name=tech["name"],
            framework="ATLAS",
            domain="atlas",
            description=tech.get("description", ""),
            is_subtechnique=is_sub,
            parent_id=parent_id,
            platforms=(),
            tactics=tactic_shortnames,
            deprecated=tech.get("deprecated", False),
            url=f"https://atlas.mitre.org/techniques/{tech_id}",
        ))

    # Parse mitigations
    mitigations: list[Mitigation] = []
    for mit in matrix.get("mitigations", []):
        raw_techniques = mit.get("techniques", [])
        technique_ids = tuple(
            t["id"] if isinstance(t, dict) else t
            for t in raw_techniques
        )
        mitigations.append(Mitigation(
            mitigation_id=mit["id"],
            name=mit["name"],
            framework="ATLAS",
            domain="atlas",
            description=mit.get("description", ""),
            technique_ids=technique_ids,
        ))

    return tactics, techniques, mitigations


def fetch_atlas_data(*, version: str = "latest") -> dict[str, Any]:
    import httpx
    import yaml

    if version == "latest":
        url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
    else:
        url = f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/refs/tags/v{version}/dist/ATLAS.yaml"

    response = httpx.get(url, timeout=60.0, follow_redirects=True)
    response.raise_for_status()
    return yaml.safe_load(response.text)


def load_atlas_data_from_file(path: str) -> dict[str, Any]:
    import yaml
    from pathlib import Path as _Path

    text = _Path(path).read_text(encoding="utf-8")
    return yaml.safe_load(text)
