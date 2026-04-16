from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    command: str
    returncode: int
    stdout: str
    stderr: str


Executor = Callable[[Sequence[str], Path], ActionResult]


def _default_executor(command: Sequence[str], cwd: Path) -> ActionResult:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    return ActionResult(
        ok=completed.returncode == 0,
        command=" ".join(command),
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def run_script(script_rel_path: str, args: Sequence[str], *, executor: Executor | None = None) -> ActionResult:
    command = [sys.executable, script_rel_path, *args]
    runner = executor or _default_executor
    return runner(command, ROOT)


def validate_model(model_path: Path, *, executor: Executor | None = None) -> ActionResult:
    return run_script("scripts/validate_model.py", ["--model", str(model_path)], executor=executor)


def load_graph(model_path: Path, *, clear_graph: bool = True, executor: Executor | None = None) -> ActionResult:
    args = ["--model", str(model_path)]
    if clear_graph:
        args.append("--clear")
    return run_script("scripts/load_graph.py", args, executor=executor)


def generate_threats(model_path: Path, *, executor: Executor | None = None) -> ActionResult:
    return run_script("scripts/generate_threats.py", ["--model", str(model_path)], executor=executor)


def score_risks(*, executor: Executor | None = None) -> ActionResult:
    return run_script("scripts/score_risks.py", [], executor=executor)


def rebuild_analysis(
    model_path: Path,
    *,
    clear_graph: bool = True,
    executor: Executor | None = None,
) -> list[tuple[str, ActionResult]]:
    steps: list[tuple[str, ActionResult]] = []

    pipeline = [
        ("validate_model", lambda: validate_model(model_path, executor=executor)),
        ("load_graph", lambda: load_graph(model_path, clear_graph=clear_graph, executor=executor)),
        ("generate_threats", lambda: generate_threats(model_path, executor=executor)),
        ("score_risks", lambda: score_risks(executor=executor)),
    ]

    for step_name, run_step in pipeline:
        result = run_step()
        steps.append((step_name, result))
        if not result.ok:
            break

    return steps
