from __future__ import annotations

import tomllib
from pathlib import Path

from artifact_locator import ArtifactLocator
from project_paths import ProjectPaths
from models.schema.canonical_model import CanonicalModel, load_canonical_model
from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatRecord, ThreatReport
from report_repository import FileReportRepository, ReportRepository
from toml_utils import toml_array, toml_scalar, toml_string

_DEFAULT_PATHS = ProjectPaths.default()
ROOT = _DEFAULT_PATHS.root
_DEFAULT_REPO = FileReportRepository(ROOT)


def list_example_models(base_dir: Path = ROOT) -> list[Path]:
    examples_dir = base_dir / "examples"
    if not examples_dir.exists():
        return []
    return sorted(examples_dir.glob("*.toml"))


def load_model(model_path: str | Path) -> CanonicalModel:
    return load_canonical_model(model_path)


def build_model_overview(model: CanonicalModel) -> dict[str, object]:
    return {
        "model_id": model.meta.model_id,
        "schema_version": model.meta.schema_version,
        "system": model.system.name,
        "criticality": model.system.criticality,
        "industry": model.system.industry,
        "counts": {
            "domains": len(model.security_domains),
            "modules": len(model.modules),
            "objects": len(model.objects),
            "datastores": len(model.datastores),
            "workflows": len(model.workflows),
            "trust_boundaries": len(model.trust_boundaries),
            "dependencies": len(model.dependencies),
        },
    }


def latest_artifact(base_dir: Path, folder: str, suffix: str) -> Path | None:
    return ArtifactLocator(base_dir).latest(folder, suffix)


def load_threat_report(
    path: str | Path | None = None,
    *,
    base_dir: Path = ROOT,
    repo: ReportRepository | None = None,
) -> tuple[ThreatReport | None, Path | None]:
    r = repo or (FileReportRepository(base_dir) if base_dir != ROOT else _DEFAULT_REPO)
    return r.load_threat_report(path)


def load_risk_report(
    path: str | Path | None = None,
    *,
    base_dir: Path = ROOT,
    repo: ReportRepository | None = None,
) -> tuple[RiskReport | None, Path | None]:
    r = repo or (FileReportRepository(base_dir) if base_dir != ROOT else _DEFAULT_REPO)
    return r.load_risk_report(path)


def threat_rows(report: ThreatReport, limit: int | None = None) -> list[dict[str, object]]:
    rows = [
        {
            "threat_id": threat.threat_id,
            "rule_id": threat.rule_id,
            "title": threat.title,
            "target_id": threat.target_id,
            "target_type": threat.target_type,
            "severity_hint": threat.severity_hint,
            "frameworks": ", ".join(sorted({m.framework for m in threat.framework_mappings})),
            "techniques": ", ".join(sorted({m.technique_id for m in threat.framework_mappings})),
            "mitigations": len(threat.suggested_mitigations),
            "related": len(threat.related_techniques),
        }
        for threat in report.threats
    ]
    if limit is None:
        return rows
    return rows[: max(0, limit)]


def mitigation_rows(threat: ThreatRecord) -> list[dict[str, str]]:
    """Extract suggested mitigations from a ThreatRecord as flat dicts."""
    return [
        {
            "mitigation_id": m.mitigation_id,
            "name": m.name,
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "rationale": m.rationale,
        }
        for m in threat.suggested_mitigations
    ]


def related_technique_rows(threat: ThreatRecord) -> list[dict[str, object]]:
    """Extract related techniques from a ThreatRecord as flat dicts."""
    return [
        {
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "framework": r.framework,
            "relationship": r.relationship,
            "shared_mitigations": r.shared_mitigations,
        }
        for r in threat.related_techniques
    ]


def risk_rows(report: RiskReport, limit: int | None = None) -> list[dict[str, object]]:
    rows = [
        {
            "risk_id": risk.risk_id,
            "threat_id": risk.threat_id,
            "rule_id": risk.rule_id,
            "title": risk.title,
            "target_id": risk.target_id,
            "priority": risk.priority,
            "risk_score": risk.risk_score,
            "top_driver": risk.drivers[0].factor if risk.drivers else "n/a",
        }
        for risk in report.risks
    ]
    if limit is None:
        return rows
    return rows[: max(0, limit)]


# ── Mapping / Sync helpers ───────────────────────────────────────


def load_sync_status(
    *,
    paths: ProjectPaths | None = None,
) -> dict[str, str]:
    """Return knowledge-base sync status as a flat dict for the sidebar."""
    from knowledge.sync import sync_status

    p = paths or _DEFAULT_PATHS
    return sync_status(db_path=p.knowledge_db)


def curated_mapping_rows(
    rule_id: str | None = None,
    *,
    rules_path: Path | None = None,
) -> list[dict[str, str]]:
    """Load curated mappings from ``mapping_rules.toml`` as flat dicts."""
    rules_path = rules_path or _DEFAULT_PATHS.mapping_rules
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
    """Load suggested mappings from ``mapping_suggestions.toml`` as flat dicts."""
    if suggestions_path is None:
        suggestions_path = _DEFAULT_PATHS.mapping_suggestions
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
    """Return discovered heuristics as flat dicts for display."""
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
    """Load ``mapping_config.toml`` as a dict."""
    config_path = config_path or _DEFAULT_PATHS.mapping_config
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
    """Write ``mapping_config.toml`` from a config dict."""
    config_path = config_path or _DEFAULT_PATHS.mapping_config
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
    """Move a suggested mapping to the curated rules file.

    Returns True on success, False if the suggestion was not found.
    """
    rules_path = rules_path or _DEFAULT_PATHS.mapping_rules
    suggestions_path = suggestions_path or _DEFAULT_PATHS.mapping_suggestions

    # ── Find and remove from suggestions ─────────────────────────
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

    # Rewrite suggestions file without the promoted entry
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

    # ── Append to curated rules ──────────────────────────────────
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
