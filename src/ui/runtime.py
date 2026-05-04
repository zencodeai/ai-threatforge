from __future__ import annotations
"""Construction of the shared runtime object graph for the Streamlit UI."""

from dataclasses import dataclass

from app import AnalysisService, KnowledgeService
from project_paths import ProjectPaths
from report_repository import FileReportRepository
from session_store import SessionStore


@dataclass(frozen=True)
class UiRuntime:
    """Explicit runtime dependencies for one UI process."""

    paths: ProjectPaths
    session_store: SessionStore
    report_repo: FileReportRepository
    analysis_service: AnalysisService
    knowledge_service: KnowledgeService


def build_ui_runtime(
    *,
    paths: ProjectPaths | None = None,
    session_store: SessionStore | None = None,
) -> UiRuntime:
    """Build the shared services and repositories used by the UI shell and pages."""
    resolved_paths = paths or ProjectPaths.default()
    resolved_session = session_store or SessionStore(resolved_paths)
    report_repo = FileReportRepository(resolved_paths.root, session_store=resolved_session)
    return UiRuntime(
        paths=resolved_paths,
        session_store=resolved_session,
        report_repo=report_repo,
        analysis_service=AnalysisService(paths=resolved_paths, session_store=resolved_session),
        knowledge_service=KnowledgeService(paths=resolved_paths),
    )


__all__ = ["UiRuntime", "build_ui_runtime"]
