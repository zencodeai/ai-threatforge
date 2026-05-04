from __future__ import annotations
"""Read-only helpers for report, model, and session data used by the UI."""

import logging
from pathlib import Path

from analysis_manifest import AnalysisManifestError
from artifact_locator import ArtifactLocator
from models.schema.canonical_model import CanonicalModel, load_canonical_model
from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatRecord, ThreatReport
from project_paths import ProjectPaths
from report_repository import ArtifactLoadError, FileReportRepository, ReportRepository
from session_store import SessionStore


def _default_paths() -> ProjectPaths:
    return ProjectPaths.default()


def _resolve_paths(paths: ProjectPaths | None) -> ProjectPaths:
    return paths or _default_paths()


def _build_repo(base_dir: Path) -> FileReportRepository:
    paths = ProjectPaths.from_root(base_dir)
    return FileReportRepository(base_dir, session_store=SessionStore(paths))


def list_example_models(base_dir: Path | None = None) -> list[Path]:
    """Return bundled example models available for selection in the UI."""
    base_dir = base_dir or _default_paths().root
    examples_dir = base_dir / "examples"
    if not examples_dir.exists():
        return []
    return sorted(examples_dir.glob("*.toml"))


def load_model(model_path: str | Path) -> CanonicalModel:
    """Load and validate a canonical model for display."""
    return load_canonical_model(model_path)


def load_active_session(
    *,
    paths: ProjectPaths | None = None,
) -> dict[str, str | None]:
    """Return the active shared-session state as a simple display dictionary."""
    store = SessionStore(_resolve_paths(paths))
    try:
        state = store.load()
    except Exception:
        logging.getLogger(__name__).exception("Failed to load active session")
        return {
            "session_id": "default",
            "model_path": None,
            "model_id": None,
            "manifest_path": None,
            "threat_report_path": None,
            "risk_report_path": None,
            "last_updated": None,
        }
    return {
        "session_id": state.session_id,
        "model_path": state.model_path,
        "model_id": state.model_id,
        "manifest_path": state.manifest_path,
        "threat_report_path": state.threat_report_path,
        "risk_report_path": state.risk_report_path,
        "last_updated": state.last_updated,
    }


def build_model_overview(model: CanonicalModel) -> dict[str, object]:
    """Project a full model into a compact summary for the overview page."""
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
    """Return the latest artifact when manifest-backed resolution is not used."""
    return ArtifactLocator(base_dir).latest(folder, suffix)


def load_threat_report(
    path: str | Path | None = None,
    *,
    base_dir: Path | None = None,
    repo: ReportRepository | None = None,
) -> tuple[ThreatReport | None, Path | None]:
    """Load the active or explicit threat report for UI display.

    UI callers receive ``(None, None)`` on load failure so pages can render an
    empty state rather than raising.
    """
    resolved_base_dir = base_dir or _default_paths().root
    r = repo or _build_repo(resolved_base_dir)
    try:
        return r.load_threat_report(path)
    except (ArtifactLoadError, AnalysisManifestError):
        logging.getLogger(__name__).exception("Failed to load threat report")
        return None, None


def load_risk_report(
    path: str | Path | None = None,
    *,
    base_dir: Path | None = None,
    repo: ReportRepository | None = None,
) -> tuple[RiskReport | None, Path | None]:
    """Load the active or explicit risk report for UI display."""
    resolved_base_dir = base_dir or _default_paths().root
    r = repo or _build_repo(resolved_base_dir)
    try:
        return r.load_risk_report(path)
    except (ArtifactLoadError, AnalysisManifestError):
        logging.getLogger(__name__).exception("Failed to load risk report")
        return None, None


def threat_rows(report: ThreatReport, limit: int | None = None) -> list[dict[str, object]]:
    """Flatten a threat report into table-friendly rows."""
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
    """Flatten mitigation enrichment for a single threat detail view."""
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
    """Flatten related-technique enrichment for a single threat detail view."""
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
    """Flatten a risk report into table-friendly rows."""
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


__all__ = [
    "build_model_overview",
    "latest_artifact",
    "list_example_models",
    "load_active_session",
    "load_model",
    "load_risk_report",
    "load_threat_report",
    "mitigation_rows",
    "related_technique_rows",
    "risk_rows",
    "threat_rows",
]
