from __future__ import annotations

from pathlib import Path
from typing import Protocol

from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatReport
from project_paths import ProjectPaths
from session_store import SessionStore

from artifact_locator import ArtifactLocator


class ReportRepository(Protocol):
    """Protocol for reading and writing threat/risk report artifacts."""

    def load_threat_report(
        self, path: str | Path | None = None,
    ) -> tuple[ThreatReport | None, Path | None]: ...

    def load_risk_report(
        self, path: str | Path | None = None,
    ) -> tuple[RiskReport | None, Path | None]: ...

    def save_threat_report(
        self, report: ThreatReport, path: str | Path,
    ) -> Path: ...

    def save_risk_report(
        self, report: RiskReport, path: str | Path,
    ) -> Path: ...


class FileReportRepository:
    """File-system backed implementation of :class:`ReportRepository`."""

    def __init__(self, base_dir: Path, *, session_store: SessionStore | None = None) -> None:
        self._base = Path(base_dir)
        self._locator = ArtifactLocator(self._base)
        self._session_store = session_store or SessionStore(ProjectPaths.from_root(self._base))

    def load_threat_report(
        self, path: str | Path | None = None,
    ) -> tuple[ThreatReport | None, Path | None]:
        threat_path = (
            Path(path)
            if path
            else self._session_store.resolve_threat_report_path() or self._locator.latest_threats()
        )
        if threat_path is None or not threat_path.exists():
            return None, None
        report = ThreatReport.model_validate_json(
            threat_path.read_text(encoding="utf-8"),
        )
        return report, threat_path

    def load_risk_report(
        self, path: str | Path | None = None,
    ) -> tuple[RiskReport | None, Path | None]:
        risk_path = (
            Path(path)
            if path
            else self._session_store.resolve_risk_report_path() or self._locator.latest_risks()
        )
        if risk_path is None or not risk_path.exists():
            return None, None
        report = RiskReport.model_validate_json(
            risk_path.read_text(encoding="utf-8"),
        )
        return report, risk_path

    def save_threat_report(
        self, report: ThreatReport, path: str | Path,
    ) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        self._session_store.set_threat_report(out)
        return out

    def save_risk_report(
        self, report: RiskReport, path: str | Path,
    ) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        self._session_store.set_risk_report(out)
        return out
