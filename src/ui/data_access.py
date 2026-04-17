from __future__ import annotations

from pathlib import Path

from artifact_locator import ArtifactLocator
from project_paths import ProjectPaths
from models.schema.canonical_model import CanonicalModel, load_canonical_model
from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatReport
from report_repository import FileReportRepository, ReportRepository

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
        }
        for threat in report.threats
    ]
    if limit is None:
        return rows
    return rows[: max(0, limit)]


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
