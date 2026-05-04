from __future__ import annotations

import importlib
from pathlib import Path

from app.analysis_service import AnalysisService
from app.knowledge_service import KnowledgeService
from analysis_manifest import AnalysisManifestStore
from knowledge.index import get_index, set_index
from project_paths import ProjectPaths
from session_store import SessionStore


def test_analysis_service_rebuild_uses_generated_threat_output(monkeypatch, tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)
    service = AnalysisService(paths=paths, session_store=store)

    monkeypatch.setattr(service, "validate_model", lambda _model=None: service._ok("VALID"))
    monkeypatch.setattr(service, "load_graph", lambda _model=None, clear_graph=True: service._ok("LOADED"))
    monkeypatch.setattr(
        service,
        "generate_threats",
        lambda _model=None, output_path=None, enrich=False: service._ok(
            "GENERATED",
            output_path="models/outputs/threats/demo_threats.json",
        ),
    )

    captured: dict[str, str | Path | None] = {}

    def fake_score(*, threat_path=None, output_path=None):
        captured["threat_path"] = threat_path
        return service._ok("SCORED")

    monkeypatch.setattr(service, "score_risks", fake_score)

    steps = service.rebuild_analysis(Path("examples/fintech_ai_platform.toml"))

    assert [name for name, _ in steps] == [
        "validate_model", "load_graph", "generate_threats", "score_risks",
    ]
    assert captured["threat_path"] == "models/outputs/threats/demo_threats.json"


def test_knowledge_service_status_uses_injected_paths(monkeypatch, tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    service = KnowledgeService(paths=paths)

    sync_module = importlib.import_module("knowledge.sync")

    captured: dict[str, Path | str] = {}

    def fake_status(*, db_path):
        captured["db_path"] = db_path
        return {"status": "synced", "db_path": str(db_path)}

    monkeypatch.setattr(sync_module, "sync_status", fake_status)

    status = service.status()

    assert status["status"] == "synced"
    assert captured["db_path"] == paths.knowledge_db


def test_knowledge_service_sync_invalidates_provider_and_legacy_index(monkeypatch, tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    service = KnowledgeService(paths=paths)

    class SentinelIndex:
        pass

    set_index(SentinelIndex())

    invalidated = {"provider": False}

    monkeypatch.setattr(service.knowledge_provider, "invalidate", lambda: invalidated.__setitem__("provider", True))

    import importlib

    sync_module = importlib.import_module("knowledge.sync")

    def fake_sync(**kwargs):
        return {"tactics": 1, "techniques": 1, "mitigations": 1}

    monkeypatch.setattr(sync_module, "sync", fake_sync)

    result = service.sync()

    assert result.ok is True
    assert invalidated["provider"] is True
    assert get_index() is None


def test_analysis_service_creates_and_updates_manifest(monkeypatch, tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    session = SessionStore(paths)
    service = AnalysisService(paths=paths, session_store=session)
    manifest_store = AnalysisManifestStore(paths, session_store=session)

    model_path = tmp_path / "examples" / "demo.toml"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text("[meta]\nmodel_id='demo'\n", encoding="utf-8")

    threat_path = tmp_path / "models" / "outputs" / "threats" / "demo_threats.json"
    threat_path.parent.mkdir(parents=True, exist_ok=True)
    threat_path.write_text("{}", encoding="utf-8")

    risk_path = tmp_path / "models" / "outputs" / "risks" / "demo_risks.json"
    risk_path.parent.mkdir(parents=True, exist_ok=True)
    risk_path.write_text("{}", encoding="utf-8")

    import analysis.threat_outputs as threat_outputs
    import analysis.risk_scoring as risk_scoring
    from models.schema.risk_model import RiskReport
    from models.schema.threat_model import ThreatReport

    monkeypatch.setattr(
        threat_outputs,
        "generate_threat_report",
        lambda *args, **kwargs: (
            ThreatReport(model_id="demo", generated_at="2026-01-01T00:00:00+00:00", threat_count=0, threats=[]),
            threat_path,
        ),
    )
    monkeypatch.setattr(
        risk_scoring,
        "generate_risk_report_from_file",
        lambda *args, **kwargs: (
            RiskReport(model_id="demo", generated_at="2026-01-01T00:00:00+00:00", methodology_version="0.1", risk_count=0, risks=[]),
            risk_path,
        ),
    )

    gen = service.generate_threats(model_path)
    score = service.score_risks()
    manifest, manifest_path = manifest_store.current()

    assert gen.ok is True
    assert score.ok is True
    assert manifest is not None
    assert manifest_path is not None
    assert manifest.model_id == "demo"
    assert manifest.threat_report_path == "models/outputs/threats/demo_threats.json"
    assert manifest.risk_report_path == "models/outputs/risks/demo_risks.json"
