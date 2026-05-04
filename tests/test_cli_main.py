from __future__ import annotations

import importlib
from pathlib import Path

from models.schema.risk_model import RiskReport
from models.schema.threat_model import ThreatReport
from project_paths import ProjectPaths
from session_store import SessionStore

cli_main = importlib.import_module("cli.main")


def test_session_command_sets_active_model(monkeypatch, tmp_path: Path, capsys) -> None:
    store = SessionStore(ProjectPaths.from_root(tmp_path))
    monkeypatch.setattr(cli_main, "_session_store", lambda: store)

    rc = cli_main.main(["session", "--model", "examples/fintech_ai_platform.toml"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "examples/fintech_ai_platform.toml" in out
    assert store.load().model_id == "fintech-ai-demo"


def test_generate_threats_uses_session_model_when_flag_is_omitted(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    store = SessionStore(ProjectPaths.from_root(tmp_path))
    store.set_model(Path("examples/fintech_ai_platform.toml"), model_id="fintech-ai-demo")
    monkeypatch.setattr(cli_main, "_session_store", lambda: store)

    called: dict[str, Path] = {}

    def fake_generate(model_path: str | Path, output_path=None, *, enrich: bool = False):
        called["model_path"] = Path(model_path)
        report = ThreatReport(model_id="fintech-ai-demo", generated_at="2026-01-01T00:00:00+00:00", threat_count=0, threats=[])
        return report, Path("models/outputs/threats/fintech-ai-demo_threats.json")

    import analysis.threat_outputs as threat_outputs

    monkeypatch.setattr(threat_outputs, "generate_threat_report", fake_generate)

    rc = cli_main.main(["generate-threats"])

    out = capsys.readouterr().out
    assert rc == 0
    assert called["model_path"].name == "fintech_ai_platform.toml"
    assert "GENERATED: 0 threats" in out
    assert store.load().threat_report_path.endswith("models/outputs/threats/fintech-ai-demo_threats.json")


def test_score_risks_prefers_session_threat_artifact(monkeypatch, tmp_path: Path) -> None:
    store = SessionStore(ProjectPaths.from_root(tmp_path))
    threat_path = tmp_path / "models" / "outputs" / "threats" / "demo_threats.json"
    threat_path.parent.mkdir(parents=True, exist_ok=True)
    threat_path.write_text("{}", encoding="utf-8")
    store.set_threat_report(threat_path)
    monkeypatch.setattr(cli_main, "_session_store", lambda: store)

    called: dict[str, Path] = {}

    def fake_score(threat_report_path: str | Path, output_path=None):
        called["threat_report_path"] = Path(threat_report_path)
        report = RiskReport(
            model_id="demo",
            generated_at="2026-01-01T00:00:00+00:00",
            methodology_version="0.1",
            risk_count=0,
            risks=[],
        )
        return report, Path("models/outputs/risks/demo_risks.json")

    import analysis.risk_scoring as risk_scoring

    monkeypatch.setattr(risk_scoring, "generate_risk_report_from_file", fake_score)

    rc = cli_main.main(["score-risks"])

    assert rc == 0
    assert called["threat_report_path"] == threat_path
    assert store.load().risk_report_path.endswith("models/outputs/risks/demo_risks.json")
