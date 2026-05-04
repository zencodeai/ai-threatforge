from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from app import AnalysisService, KnowledgeService, ServiceResult
from project_paths import ProjectPaths


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


def _action_from_service(command: str, result: ServiceResult) -> ActionResult:
    return ActionResult(
        ok=result.ok,
        command=command,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def run_command(
    cli_args: list[str],
    *,
    executor: Executor | None = None,
    cwd: Path | None = None,
) -> ActionResult:
    command = [sys.executable, "-m", "cli.main", *cli_args]
    runner = executor or _default_executor
    return runner(command, cwd or ProjectPaths.default().root)

def validate_model(
    model_path: Path,
    *,
    executor: Executor | None = None,
    analysis_service: AnalysisService | None = None,
) -> ActionResult:
    if executor is not None:
        return run_command(["validate", "--model", str(model_path)], executor=executor)
    result = (analysis_service or AnalysisService()).validate_model(model_path)
    return _action_from_service(f"validate --model {model_path}", result)

def load_graph(
    model_path: Path,
    *,
    clear_graph: bool = True,
    executor: Executor | None = None,
    analysis_service: AnalysisService | None = None,
) -> ActionResult:
    if executor is not None:
        args = ["load-graph", "--model", str(model_path)]
        if clear_graph:
            args.append("--clear")
        return run_command(args, executor=executor)
    result = (analysis_service or AnalysisService()).load_graph(model_path, clear_graph=clear_graph)
    suffix = " --clear" if clear_graph else ""
    return _action_from_service(f"load-graph --model {model_path}{suffix}", result)


def generate_threats(
    model_path: Path,
    *,
    enrich: bool = False,
    executor: Executor | None = None,
    analysis_service: AnalysisService | None = None,
) -> ActionResult:
    if executor is not None:
        args = ["generate-threats", "--model", str(model_path)]
        if enrich:
            args.append("--enrich")
        return run_command(args, executor=executor)
    result = (analysis_service or AnalysisService()).generate_threats(model_path, enrich=enrich)
    suffix = " --enrich" if enrich else ""
    return _action_from_service(f"generate-threats --model {model_path}{suffix}", result)


def score_risks(
    *,
    threat_path: Path | None = None,
    executor: Executor | None = None,
    analysis_service: AnalysisService | None = None,
) -> ActionResult:
    if executor is not None:
        args = ["score-risks"]
        if threat_path is not None:
            args.extend(["--threats", str(threat_path)])
        return run_command(args, executor=executor)
    result = (analysis_service or AnalysisService()).score_risks(threat_path=threat_path)
    command = "score-risks"
    if threat_path is not None:
        command += f" --threats {threat_path}"
    return _action_from_service(command, result)


def rebuild_analysis(
    model_path: Path,
    *,
    clear_graph: bool = True,
    enrich: bool = False,
    executor: Executor | None = None,
    analysis_service: AnalysisService | None = None,
) -> list[tuple[str, ActionResult]]:
    if executor is not None:
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

        threat_path = None
        for line in result.stdout.splitlines():
            if line.startswith("OUTPUT: "):
                threat_path = Path(line.removeprefix("OUTPUT: ").strip())
                break

        result = score_risks(threat_path=threat_path, executor=executor)
        steps.append(("score_risks", result))
        return steps

    service = analysis_service or AnalysisService()
    results = service.rebuild_analysis(model_path, clear_graph=clear_graph, enrich=enrich)
    return [
        (
            step_name,
            _action_from_service(
                step_name,
                step_result,
            ),
        )
        for step_name, step_result in results
    ]


def sync_knowledge(
    *,
    attack_version: str = "latest",
    atlas_version: str = "latest",
    embed: bool = False,
    map_heuristics: bool = False,
    map_threshold: float = 0.40,
    map_top_k: int = 10,
    executor: Executor | None = None,
    knowledge_service: KnowledgeService | None = None,
) -> ActionResult:
    if executor is not None:
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

    result = (knowledge_service or KnowledgeService()).sync(
        attack_version=attack_version,
        atlas_version=atlas_version,
        embed=embed or map_heuristics,
        map_heuristics=map_heuristics,
        map_threshold=map_threshold,
        map_top_k=map_top_k,
    )
    return _action_from_service("sync", result)


def get_sync_status(*, executor: Executor | None = None) -> ActionResult:
    if executor is not None:
        return run_command(["sync", "--status"], executor=executor)

    status = KnowledgeService().status()
    lines = [f"  {key}: {value}" for key, value in status.items()]
    return ActionResult(
        ok=True,
        command="sync --status",
        returncode=0,
        stdout="\n".join(lines),
        stderr="",
    )
