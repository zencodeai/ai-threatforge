from __future__ import annotations

from pathlib import Path

from ui.ui_actions import ActionResult, rebuild_analysis, run_command, score_risks


def test_run_command_uses_executor() -> None:
    calls: list[tuple[list[str], Path]] = []

    def fake_executor(command, cwd):
        calls.append((list(command), cwd))
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    result = run_command(["validate", "--model", "model.toml"], executor=fake_executor)

    assert result.ok is True
    assert calls
    assert "validate" in calls[0][0]


def test_rebuild_analysis_stops_on_first_failure() -> None:
    invocations: list[str] = []

    def fake_executor(command, _cwd):
        subcommand = command[3]  # python -m cli.main <subcommand>
        invocations.append(subcommand)
        if subcommand == "load-graph":
            return ActionResult(ok=False, command=" ".join(command), returncode=1, stdout="", stderr="failed")
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    steps = rebuild_analysis(Path("examples/fintech_ai_platform.toml"), executor=fake_executor)

    assert [name for name, _ in steps] == ["validate_model", "load_graph"]
    assert invocations == ["validate", "load-graph"]
    assert steps[-1][1].ok is False


def test_rebuild_analysis_scores_generated_threat_artifact() -> None:
    calls: list[list[str]] = []

    def fake_executor(command, _cwd):
        cmd = list(command)
        calls.append(cmd)
        subcommand = cmd[3]
        stdout = "ok"
        if subcommand == "generate-threats":
            stdout = "GENERATED: 1 threats\nOUTPUT: models/outputs/threats/demo_threats.json"
        return ActionResult(ok=True, command=" ".join(cmd), returncode=0, stdout=stdout, stderr="")

    steps = rebuild_analysis(Path("examples/fintech_ai_platform.toml"), executor=fake_executor)

    assert [name for name, _ in steps] == [
        "validate_model", "load_graph", "generate_threats", "score_risks",
    ]
    assert calls[-1][-2:] == ["--threats", "models/outputs/threats/demo_threats.json"]


def test_score_risks_accepts_explicit_threat_path() -> None:
    calls: list[list[str]] = []

    def fake_executor(command, _cwd):
        cmd = list(command)
        calls.append(cmd)
        return ActionResult(ok=True, command=" ".join(cmd), returncode=0, stdout="ok", stderr="")

    score_risks(threat_path=Path("models/outputs/threats/demo_threats.json"), executor=fake_executor)

    assert calls[0][-2:] == ["--threats", "models/outputs/threats/demo_threats.json"]


def test_rebuild_analysis_without_executor_uses_service_results(monkeypatch) -> None:
    import ui.ui_actions as actions
    from app import ServiceResult

    class FakeAnalysisService:
        def rebuild_analysis(self, model_path, *, clear_graph=True, enrich=False):
            return [
                ("validate_model", ServiceResult(ok=True, stdout="VALID", returncode=0)),
                ("load_graph", ServiceResult(ok=True, stdout="LOADED", returncode=0)),
            ]

    monkeypatch.setattr(actions, "AnalysisService", FakeAnalysisService)

    steps = rebuild_analysis(Path("examples/fintech_ai_platform.toml"))

    assert [name for name, _ in steps] == ["validate_model", "load_graph"]
    assert steps[0][1].stdout == "VALID"
    assert steps[1][1].stdout == "LOADED"
