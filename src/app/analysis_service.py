from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analysis_manifest import AnalysisManifestStore
from knowledge.provider import KnowledgeProvider
from project_paths import ProjectPaths
from session_store import SessionStore


@dataclass(frozen=True)
class ServiceResult:
    ok: bool
    stdout: str
    stderr: str = ""
    returncode: int = 0
    data: dict[str, Any] = field(default_factory=dict)


class AnalysisService:
    """Shared analysis orchestration used by both CLI and UI."""

    def __init__(
        self,
        *,
        paths: ProjectPaths | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        self.paths = paths or ProjectPaths.default()
        self.session_store = session_store or SessionStore(self.paths)
        self.knowledge_provider = KnowledgeProvider.from_paths(self.paths)
        self.manifest_store = AnalysisManifestStore(self.paths, session_store=self.session_store)

    def validate_model(self, model_path: str | Path | None = None) -> ServiceResult:
        from models.schema.canonical_model import validate_canonical_model

        try:
            resolved = self.resolve_model_path(model_path)
        except Exception as exc:
            return self._error(str(exc))

        ok, message = validate_canonical_model(resolved)
        if ok:
            self.record_model_session(resolved)
            return self._ok(f"VALID: {resolved}", model_path=str(resolved))
        return self._error(
            f"INVALID: {resolved}\n{message}",
            model_path=str(resolved),
        )

    def load_graph(
        self,
        model_path: str | Path | None = None,
        *,
        clear_graph: bool = True,
    ) -> ServiceResult:
        from graph.graph_loader import load_model_into_graph

        try:
            resolved = self.resolve_model_path(model_path)
            stats = load_model_into_graph(resolved, clear_graph=clear_graph)
        except Exception as exc:
            return self._error(str(exc))

        self.record_model_session(resolved)
        return self._ok(
            f"LOADED: nodes={stats.nodes_created} relationships={stats.relationships_created}",
            model_path=str(resolved),
            nodes_created=stats.nodes_created,
            relationships_created=stats.relationships_created,
        )

    def generate_threats(
        self,
        model_path: str | Path | None = None,
        *,
        output_path: str | Path | None = None,
        enrich: bool = False,
    ) -> ServiceResult:
        from analysis.threat_outputs import generate_threat_report

        try:
            resolved = self.resolve_model_path(model_path)
            report, written = generate_threat_report(
                resolved,
                output_path,
                enrich=enrich,
                knowledge_provider=self.knowledge_provider,
            )
        except Exception as exc:
            return self._error(str(exc))

        self.session_store.set_model(resolved, model_id=report.model_id)
        self.session_store.set_threat_report(written)
        self.manifest_store.create(
            model_path=resolved,
            model_id=report.model_id,
            threat_report_path=written,
        )
        return self._ok(
            f"GENERATED: {report.threat_count} threats\nOUTPUT: {written}",
            model_path=str(resolved),
            output_path=str(written),
            model_id=report.model_id,
            threat_count=report.threat_count,
        )

    def score_risks(
        self,
        *,
        threat_path: str | Path | None = None,
        output_path: str | Path | None = None,
    ) -> ServiceResult:
        from analysis.risk_scoring import generate_risk_report_from_file

        try:
            resolved = Path(threat_path) if threat_path is not None else self.default_threat_path()
            report, written = generate_risk_report_from_file(resolved, output_path)
        except Exception as exc:
            return self._error(str(exc))

        self.session_store.set_threat_report(resolved)
        self.session_store.set_risk_report(written)
        current_manifest_path = self.session_store.resolve_manifest_path()
        if current_manifest_path is not None and current_manifest_path.exists():
            self.manifest_store.update(
                current_manifest_path,
                model_id=report.model_id,
                threat_report_path=resolved,
                risk_report_path=written,
            )
        else:
            self.manifest_store.create(
                model_path=self.session_store.resolve_model_path(),
                model_id=report.model_id,
                threat_report_path=resolved,
                risk_report_path=written,
            )

        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for risk in report.risks:
            priority_counts[risk.priority] += 1

        lines = [
            f"THREATS INPUT: {resolved}",
            f"GENERATED: {report.risk_count} risks",
            "PRIORITIES:",
            f"  critical: {priority_counts['critical']}",
            f"  high: {priority_counts['high']}",
            f"  medium: {priority_counts['medium']}",
            f"  low: {priority_counts['low']}",
            "TOP RISKS:",
        ]
        for risk in report.risks[:5]:
            top_driver = risk.drivers[0].factor if risk.drivers else "n/a"
            lines.append(
                f"  {risk.risk_id} | score={risk.risk_score:.2f} | "
                f"priority={risk.priority} | target={risk.target_id} | driver={top_driver}"
            )
        lines.append(f"OUTPUT: {written}")

        return self._ok(
            "\n".join(lines),
            threat_path=str(resolved),
            output_path=str(written),
            risk_count=report.risk_count,
            model_id=report.model_id,
        )

    def rebuild_analysis(
        self,
        model_path: str | Path | None = None,
        *,
        clear_graph: bool = True,
        enrich: bool = False,
    ) -> list[tuple[str, ServiceResult]]:
        steps: list[tuple[str, ServiceResult]] = []

        result = self.validate_model(model_path)
        steps.append(("validate_model", result))
        if not result.ok:
            return steps

        result = self.load_graph(model_path, clear_graph=clear_graph)
        steps.append(("load_graph", result))
        if not result.ok:
            return steps

        result = self.generate_threats(model_path, enrich=enrich)
        steps.append(("generate_threats", result))
        if not result.ok:
            return steps

        threat_path = result.data.get("output_path")
        result = self.score_risks(threat_path=threat_path)
        steps.append(("score_risks", result))
        return steps

    def resolve_model_path(self, model: str | Path | None) -> Path:
        if model is not None:
            return Path(model)
        session_model = self.session_store.resolve_model_path()
        if session_model is not None:
            return session_model
        raise FileNotFoundError(
            "No model provided and no session model is set. "
            "Pass --model or set one with 'threatforge session --model <path>'."
        )

    def record_model_session(self, model_path: str | Path) -> None:
        from models.schema.canonical_model import load_canonical_model

        resolved = Path(model_path)
        try:
            model = load_canonical_model(resolved)
            self.session_store.set_model(resolved, model_id=model.meta.model_id)
        except Exception:
            self.session_store.set_model(resolved)

    def default_threat_path(self) -> Path:
        from artifact_locator import ArtifactLocator

        session_path = self.session_store.resolve_threat_report_path()
        if session_path is not None:
            return session_path

        manifest_path = self.manifest_store.current_threat_report_path()
        if manifest_path is not None:
            return manifest_path

        path = ArtifactLocator(self.paths.root).latest_threats()
        if path is None:
            raise FileNotFoundError(
                "No threat artifacts found in session or models/outputs/threats/. "
                "Run 'threatforge generate-threats' first, pass --threats, "
                "or set a session with 'threatforge session --model <path>'."
            )
        return path

    @staticmethod
    def _ok(stdout: str, **data: Any) -> ServiceResult:
        return ServiceResult(ok=True, stdout=stdout, returncode=0, data=data)

    @staticmethod
    def _error(message: str, **data: Any) -> ServiceResult:
        return ServiceResult(ok=False, stdout="", stderr=f"FAILED: {message}", returncode=1, data=data)
