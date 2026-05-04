from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from project_paths import ProjectPaths

ROOT = ProjectPaths.default().root


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


def run_command(cli_args: list[str], *, executor: Executor | None = None) -> ActionResult:
    command = [sys.executable, "-m", "cli.main", *cli_args]
    runner = executor or _default_executor
    return runner(command, ROOT)


def validate_model(model_path: Path, *, executor: Executor | None = None) -> ActionResult:
    return run_command(["validate", "--model", str(model_path)], executor=executor)


def load_graph(model_path: Path, *, clear_graph: bool = True, executor: Executor | None = None) -> ActionResult:
    args = ["load-graph", "--model", str(model_path)]
    if clear_graph:
        args.append("--clear")
    return run_command(args, executor=executor)


def generate_threats(
    model_path: Path,
    *,
    enrich: bool = False,
    executor: Executor | None = None,
) -> ActionResult:
    args = ["generate-threats", "--model", str(model_path)]
    if enrich:
        args.append("--enrich")
    return run_command(args, executor=executor)


def score_risks(
    *,
    threat_path: Path | None = None,
    executor: Executor | None = None,
) -> ActionResult:
    args = ["score-risks"]
    if threat_path is not None:
        args.extend(["--threats", str(threat_path)])
    return run_command(args, executor=executor)


def _extract_output_path(result: ActionResult) -> Path | None:
    for line in result.stdout.splitlines():
        if line.startswith("OUTPUT: "):
            return Path(line.removeprefix("OUTPUT: ").strip())
    return None


def rebuild_analysis(
    model_path: Path,
    *,
    clear_graph: bool = True,
    enrich: bool = False,
    executor: Executor | None = None,
) -> list[tuple[str, ActionResult]]:
    steps: list[tuple[str, ActionResult]] = []

    result = validate_model(model_path, executor=executor)
    steps.append(("validate_model", result))
    if not result.ok:
        return steps

    result = load_graph(model_path, clear_graph=clear_graph, executor=executor)
    steps.append(("load_graph", result))
    if not result.ok:
        return steps

    result = generate_threats(model_path, enrich=enrich, executor=executor)
    steps.append(("generate_threats", result))
    if not result.ok:
        return steps

    threat_path = _extract_output_path(result)
    result = score_risks(threat_path=threat_path, executor=executor)
    steps.append(("score_risks", result))

    return steps


def sync_knowledge(
    *,
    attack_version: str = "latest",
    atlas_version: str = "latest",
    embed: bool = False,
    map_heuristics: bool = False,
    map_threshold: float = 0.40,
    map_top_k: int = 10,
    executor: Executor | None = None,
) -> ActionResult:
    """Run ``threatforge sync`` with the given options."""
    args = [
        "sync",
        "--attack-version", attack_version,
        "--atlas-version", atlas_version,
    ]
    if embed or map_heuristics:
        args.append("--embed")
    if map_heuristics:
        args.extend([
            "--map-heuristics",
            "--map-threshold", str(map_threshold),
            "--map-top-k", str(map_top_k),
        ])
    return run_command(args, executor=executor)


def get_sync_status(*, executor: Executor | None = None) -> ActionResult:
    """Run ``threatforge sync --status``."""
    return run_command(["sync", "--status"], executor=executor)
