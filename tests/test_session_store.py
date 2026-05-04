from __future__ import annotations

from pathlib import Path

from project_paths import ProjectPaths
from session_store import SessionStore


def test_session_store_persists_model_and_artifact_paths(tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)

    model_path = tmp_path / "examples" / "demo.toml"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text("title = 'demo'\n", encoding="utf-8")

    threat_path = tmp_path / "models" / "outputs" / "threats" / "demo_threats.json"
    threat_path.parent.mkdir(parents=True, exist_ok=True)
    threat_path.write_text("{}", encoding="utf-8")

    risk_path = tmp_path / "models" / "outputs" / "risks" / "demo_risks.json"
    risk_path.parent.mkdir(parents=True, exist_ok=True)
    risk_path.write_text("{}", encoding="utf-8")

    manifest_path = tmp_path / "models" / "outputs" / "manifests" / "analysis-demo.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("{}", encoding="utf-8")

    store.set_model(model_path, model_id="demo")
    store.set_manifest(manifest_path)
    store.set_threat_report(threat_path)
    store.set_risk_report(risk_path)

    loaded = store.load()
    assert loaded.model_id == "demo"
    assert loaded.model_path == "examples/demo.toml"
    assert loaded.manifest_path == "models/outputs/manifests/analysis-demo.json"
    assert loaded.threat_report_path == "models/outputs/threats/demo_threats.json"
    assert loaded.risk_report_path == "models/outputs/risks/demo_risks.json"
    assert store.resolve_model_path() == model_path
    assert store.resolve_manifest_path() == manifest_path
    assert store.resolve_threat_report_path() == threat_path
    assert store.resolve_risk_report_path() == risk_path


def test_session_store_persists_uploaded_model_copy(tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)

    saved = store.set_uploaded_model("upload.toml", b"[meta]\nmodel_id='demo'\n")

    assert saved.exists()
    assert saved.parent == paths.session_models_dir
    assert saved.read_text(encoding="utf-8").startswith("[meta]")


def test_session_store_quarantines_corrupt_state(tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)
    paths.current_session_file.parent.mkdir(parents=True, exist_ok=True)
    paths.current_session_file.write_text("{not-json", encoding="utf-8")

    state = store.load()

    assert state.model_path is None
    assert not paths.current_session_file.exists()
    quarantined = list(paths.current_session_file.parent.glob(f"{paths.current_session_file.name}.invalid*"))
    assert quarantined
