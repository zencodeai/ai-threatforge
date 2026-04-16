from __future__ import annotations

from pathlib import Path

from ui.actions import ActionResult, rebuild_analysis, run_script


def test_run_script_uses_executor() -> None:
    calls: list[tuple[list[str], Path]] = []

    def fake_executor(command, cwd):
        calls.append((list(command), cwd))
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    result = run_script("scripts/validate_model.py", ["--model", "model.toml"], executor=fake_executor)

    assert result.ok is True
    assert calls
    assert calls[0][0][1] == "scripts/validate_model.py"


def test_rebuild_analysis_stops_on_first_failure() -> None:
    invocations: list[str] = []

    def fake_executor(command, _cwd):
        script = command[1]
        invocations.append(script)
        if script == "scripts/load_graph.py":
            return ActionResult(ok=False, command=" ".join(command), returncode=1, stdout="", stderr="failed")
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    steps = rebuild_analysis(Path("examples/fintech_ai_platform.toml"), executor=fake_executor)

    assert [name for name, _ in steps] == ["validate_model", "load_graph"]
    assert invocations == ["scripts/validate_model.py", "scripts/load_graph.py"]
    assert steps[-1][1].ok is False
