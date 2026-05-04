from __future__ import annotations

from pathlib import Path

from analysis_manifest import AnalysisManifestStore
from project_paths import ProjectPaths
from session_store import SessionStore


def test_manifest_store_creates_and_updates_current_manifest(tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    session = SessionStore(paths)
    store = AnalysisManifestStore(paths, session_store=session)

    manifest, manifest_path = store.create(
        model_path=tmp_path / "examples" / "demo.toml",
        model_id="demo",
        threat_report_path=tmp_path / "models" / "outputs" / "threats" / "demo_threats.json",
    )

    updated, updated_path = store.update(
        manifest_path,
        risk_report_path=tmp_path / "models" / "outputs" / "risks" / "demo_risks.json",
    )

    assert manifest.run_id == updated.run_id
    assert manifest_path == updated_path
    assert session.resolve_manifest_path() == manifest_path
    assert updated.risk_report_path == "models/outputs/risks/demo_risks.json"
