from __future__ import annotations
"""Read and write helpers for mapping-focused UI screens."""

import tomllib
from pathlib import Path

from app import KnowledgeService
from project_paths import ProjectPaths
from toml_utils import toml_array, toml_scalar, toml_string


def _default_paths() -> ProjectPaths:
    return ProjectPaths.default()


def _resolve_paths(paths: ProjectPaths | None) -> ProjectPaths:
    return paths or _default_paths()


def load_sync_status(
    *,
    paths: ProjectPaths | None = None,
) -> dict[str, str]:
    """Return current knowledge-sync status for the mappings page."""
    return KnowledgeService(paths=_resolve_paths(paths)).status()


def curated_mapping_rows(
    rule_id: str | None = None,
    *,
    rules_path: Path | None = None,
) -> list[dict[str, str]]:
    """Load curated mappings as simple rows for table rendering."""
    rules_path = rules_path or _default_paths().mapping_rules
    if not rules_path.exists():
        return []
    with open(rules_path, "rb") as f:
        data = tomllib.load(f)
    rows: list[dict[str, str]] = []
    for entry in data.get("mappings", []):
        if rule_id is not None and entry["rule_id"] != rule_id:
            continue
        rows.append({
            "rule_id": entry["rule_id"],
            "technique_id": entry["technique_id"],
            "framework": entry["framework"],
            "tactic": entry["tactic"],
            "rationale": entry.get("rationale", ""),
        })
    return rows


def suggested_mapping_rows(
    rule_id: str | None = None,
    *,
    suggestions_path: Path | None = None,
) -> list[dict[str, object]]:
    """Load suggested mappings as simple rows for table rendering."""
    suggestions_path = suggestions_path or _default_paths().mapping_suggestions
    if not suggestions_path.exists():
        return []
    with open(suggestions_path, "rb") as f:
        data = tomllib.load(f)
    rows: list[dict[str, object]] = []
    for entry in data.get("mappings", []):
        if rule_id is not None and entry["rule_id"] != rule_id:
            continue
        rows.append({
            "rule_id": entry["rule_id"],
            "technique_id": entry["technique_id"],
            "framework": entry["framework"],
            "tactic": entry["tactic"],
            "rationale": entry.get("rationale", ""),
            "mapping_type": entry.get("mapping_type", "suggested"),
            "composite_score": entry.get("composite_score", 0.0),
        })
    return rows


def heuristic_rows() -> list[dict[str, str]]:
    """Return discovered heuristics in a compact UI-friendly form."""
    from analysis.heuristics import discovered_heuristics

    rows: list[dict[str, str]] = []
    for h in discovered_heuristics():
        rows.append({
            "rule_id": h.rule_id,
            "name": h.name,
            "description": h.description,
            "frameworks": ", ".join(h.frameworks),
            "severity": h.severity_hint,
            "target_type": h.target_type,
        })
    return rows


def load_mapping_config(
    *,
    config_path: Path | None = None,
) -> dict[str, object]:
    """Load mapping configuration with defaults for missing config files."""
    config_path = config_path or _default_paths().mapping_config
    if not config_path.exists():
        return {
            "expansion": {"enabled": False},
            "suggestions": {"include_suggested": False},
            "graphrag": {},
        }
    with open(config_path, "rb") as f:
        return tomllib.load(f)


def save_mapping_config(
    config: dict[str, object],
    *,
    config_path: Path | None = None,
) -> None:
    """Persist mapping configuration edited through the UI."""
    config_path = config_path or _default_paths().mapping_config
    expansion = config.get("expansion", {})
    suggestions = config.get("suggestions", {})
    graphrag = config.get("graphrag", {})

    lines = [
        "# Technique mapping expansion configuration.",
        "#",
        "# Controls how threat heuristics are expanded beyond curated mappings.",
        "",
        "[expansion]",
        "# Enable tactic-based expansion (Layer 2).",
        "# When true, heuristics are auto-expanded to all techniques in their target tactics.",
        f"enabled = {str(expansion.get('enabled', False)).lower()}",
        "",
        "# Include sub-techniques in expansion results.",
        f"include_subtechniques = {str(expansion.get('include_subtechniques', True)).lower()}",
        "",
        "# Maximum techniques per tactic to include (prevents output bloat).",
        f"max_techniques_per_tactic = {expansion.get('max_techniques_per_tactic', 20)}",
        "",
        '# ATT&CK domains to include in expansion.',
        '# Options: "enterprise", "mobile", "ics"',
        f"domains = {toml_array(expansion.get('domains', ['enterprise']))}",
        "",
        "[suggestions]",
        "# Include auto-suggested mappings alongside curated ones at analysis time.",
        f"include_suggested = {str(suggestions.get('include_suggested', False)).lower()}",
        "",
        "# Path to the auto-generated suggestions file (relative to project root).",
        f"suggestions_path = {toml_string(suggestions.get('suggestions_path', 'data/threat_intel/mapping_suggestions.toml'))}",
        "",
        "[graphrag]",
        "# Weights for the graph-aware suggestion scorer.",
        f"weight_vector = {toml_scalar(graphrag.get('weight_vector', 0.45))}",
        f"weight_tactic = {toml_scalar(graphrag.get('weight_tactic', 0.15))}",
        f"weight_framework = {toml_scalar(graphrag.get('weight_framework', 0.10))}",
        f"weight_mitigation_gap = {toml_scalar(graphrag.get('weight_mitigation_gap', 0.20))}",
        f"weight_subtechnique = {toml_scalar(graphrag.get('weight_subtechnique', 0.10))}",
    ]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def promote_suggestion(
    rule_id: str,
    technique_id: str,
    *,
    rules_path: Path | None = None,
    suggestions_path: Path | None = None,
) -> bool:
    """Promote one suggested mapping into the curated rules file."""
    defaults = _default_paths()
    rules_path = rules_path or defaults.mapping_rules
    suggestions_path = suggestions_path or defaults.mapping_suggestions

    if not suggestions_path.exists():
        return False
    with open(suggestions_path, "rb") as f:
        data = tomllib.load(f)
    mappings = data.get("mappings", [])
    target = None
    remaining: list[dict] = []
    for entry in mappings:
        if entry["rule_id"] == rule_id and entry["technique_id"] == technique_id:
            target = entry
        else:
            remaining.append(entry)
    if target is None:
        return False

    header_lines = [
        "# Auto-generated by: threatforge sync --map-heuristics",
        "# Modified by promote action",
        "",
    ]
    suggestion_lines = list(header_lines)
    for entry in remaining:
        suggestion_lines.append("[[mappings]]")
        suggestion_lines.append(f"rule_id = {toml_string(entry['rule_id'])}")
        suggestion_lines.append(f"technique_id = {toml_string(entry['technique_id'])}")
        suggestion_lines.append(f"framework = {toml_string(entry['framework'])}")
        suggestion_lines.append(f"tactic = {toml_string(entry['tactic'])}")
        suggestion_lines.append(f"rationale = {toml_string(entry.get('rationale', ''))}")
        suggestion_lines.append(f"mapping_type = {toml_string(entry.get('mapping_type', 'suggested'))}")
        if "composite_score" in entry:
            suggestion_lines.append(f"composite_score = {toml_scalar(round(entry['composite_score'], 4))}")
        suggestion_lines.append("")
    suggestions_path.write_text("\n".join(suggestion_lines), encoding="utf-8")

    block = "\n".join([
        "",
        "[[mappings]]",
        f"rule_id = {toml_string(target['rule_id'])}",
        f"technique_id = {toml_string(target['technique_id'])}",
        f"framework = {toml_string(target['framework'])}",
        f"tactic = {toml_string(target['tactic'])}",
        f"rationale = {toml_string(target.get('rationale', 'Promoted from suggested mappings.'))}",
        "",
    ])
    with open(rules_path, "a", encoding="utf-8") as f:
        f.write(block)
    return True


__all__ = [
    "curated_mapping_rows",
    "heuristic_rows",
    "load_mapping_config",
    "load_sync_status",
    "promote_suggestion",
    "save_mapping_config",
    "suggested_mapping_rows",
]
