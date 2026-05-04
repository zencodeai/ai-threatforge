from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from analysis_manifest import AnalysisManifestStore
from project_paths import ProjectPaths
from session_store import SessionStore

from .state import AgentAnswer, ToolResponse


class TraceRecorder(Protocol):
    def on_workflow_start(self, run_id: str, question: str, actions: list[str]) -> None: ...

    def on_tool_result(
        self,
        run_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        response: ToolResponse,
    ) -> None: ...

    def on_workflow_end(self, run_id: str, answer: AgentAnswer) -> None: ...

    def on_workflow_error(
        self,
        run_id: str,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None: ...


class NullTraceRecorder:
    def on_workflow_start(self, run_id: str, question: str, actions: list[str]) -> None:
        _ = (run_id, question, actions)

    def on_tool_result(
        self,
        run_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        response: ToolResponse,
    ) -> None:
        _ = (run_id, tool_name, tool_input, response)

    def on_workflow_end(self, run_id: str, answer: AgentAnswer) -> None:
        _ = (run_id, answer)

    def on_workflow_error(
        self,
        run_id: str,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        _ = (run_id, error_type, message, details)


class JsonlTraceRecorder:
    """Writes workflow traces as JSONL events for local observability."""

    def __init__(self, trace_file: str | Path, *, manifest_store: AnalysisManifestStore | None = None):
        self.trace_file = Path(trace_file)
        self.trace_file.parent.mkdir(parents=True, exist_ok=True)
        self._manifest_store = manifest_store

    def on_workflow_start(self, run_id: str, question: str, actions: list[str]) -> None:
        self._append(
            {
                "event": "workflow_start",
                "run_id": run_id,
                "question": question,
                "actions": actions,
            }
        )

    def on_tool_result(
        self,
        run_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        response: ToolResponse,
    ) -> None:
        self._append(
            {
                "event": "tool_result",
                "run_id": run_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "response": response.model_dump(),
            }
        )

    def on_workflow_end(self, run_id: str, answer: AgentAnswer) -> None:
        self._append(
            {
                "event": "workflow_end",
                "run_id": run_id,
                "answer": answer.model_dump(),
            }
        )

    def on_workflow_error(
        self,
        run_id: str,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._append(
            {
                "event": "workflow_error",
                "run_id": run_id,
                "error_type": error_type,
                "message": message,
                "details": details or {},
            }
        )

    def _append(self, payload: dict[str, Any]) -> None:
        payload["ts"] = datetime.now(timezone.utc).isoformat()
        if self._manifest_store is not None:
            manifest = self._manifest_store.current_metadata()
            if manifest is not None:
                payload["analysis_manifest"] = manifest
        with self.trace_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True))
            fh.write("\n")


class LangSmithTraceRecorder:
    """Best-effort LangSmith instrumentation with graceful local fallback."""

    def __init__(self, project: str = "threat-forge-ai"):
        from langsmith import Client  # type: ignore

        self._client = Client()
        self._project = project

    def on_workflow_start(self, run_id: str, question: str, actions: list[str]) -> None:
        self._client.create_run(
            id=run_id,
            project_name=self._project,
            name="query_workflow",
            run_type="chain",
            inputs={"question": question, "actions": actions},
        )

    def on_tool_result(
        self,
        run_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        response: ToolResponse,
    ) -> None:
        self._client.create_run(
            project_name=self._project,
            name=tool_name,
            run_type="tool",
            inputs=tool_input,
            outputs=response.model_dump(),
            parent_run_id=run_id,
        )

    def on_workflow_end(self, run_id: str, answer: AgentAnswer) -> None:
        self._client.update_run(
            run_id,
            outputs=answer.model_dump(),
            end_time=datetime.now(timezone.utc),
        )

    def on_workflow_error(
        self,
        run_id: str,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._client.update_run(
            run_id,
            outputs={
                "error_type": error_type,
                "message": message,
                "details": details or {},
            },
            end_time=datetime.now(timezone.utc),
        )


class CompositeTraceRecorder:
    def __init__(self, recorders: list[TraceRecorder]):
        self._recorders = recorders

    def on_workflow_start(self, run_id: str, question: str, actions: list[str]) -> None:
        for recorder in self._recorders:
            recorder.on_workflow_start(run_id, question, actions)

    def on_tool_result(
        self,
        run_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        response: ToolResponse,
    ) -> None:
        for recorder in self._recorders:
            recorder.on_tool_result(run_id, tool_name, tool_input, response)

    def on_workflow_end(self, run_id: str, answer: AgentAnswer) -> None:
        for recorder in self._recorders:
            recorder.on_workflow_end(run_id, answer)

    def on_workflow_error(
        self,
        run_id: str,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        for recorder in self._recorders:
            recorder.on_workflow_error(run_id, error_type, message, details)


def create_trace_recorder(base_dir: str | Path = ".") -> TraceRecorder:
    """Create local tracing and optional LangSmith tracing from environment."""

    base = Path(base_dir)
    paths = ProjectPaths.from_root(base.resolve())
    manifest_store = AnalysisManifestStore(paths, session_store=SessionStore(paths))
    local = JsonlTraceRecorder(
        base / "models" / "outputs" / "traces" / "agent_runs.jsonl",
        manifest_store=manifest_store,
    )

    use_langsmith = os.getenv("LANGSMITH_TRACING", "").lower() in {"1", "true", "yes"}
    if not use_langsmith:
        return local

    try:
        project = os.getenv("LANGSMITH_PROJECT", "threat-forge-ai")
        langsmith_recorder = LangSmithTraceRecorder(project=project)
    except (ImportError, ValueError, RuntimeError):
        logging.getLogger(__name__).warning(
            "LangSmith recorder unavailable; using local tracing only", exc_info=True,
        )
        return local

    return CompositeTraceRecorder([local, langsmith_recorder])


def new_run_id() -> str:
    return f"run-{uuid4().hex[:12]}"


__all__ = [
    "TraceRecorder",
    "NullTraceRecorder",
    "JsonlTraceRecorder",
    "LangSmithTraceRecorder",
    "CompositeTraceRecorder",
    "create_trace_recorder",
    "new_run_id",
]
