from __future__ import annotations
"""Deterministic analyst-query workflow orchestration."""

from .composer import AnswerComposer
from .executor import ActionExecutor
from .observability import TraceRecorder, create_trace_recorder, new_run_id
from .router import QueryRouter, RoutedAction
from .workflow_models import AgentAnswer, AgentState, ToolCallRecord
from .tools import AgentTools


class QueryWorkflow:
    """Deterministic query workflow that routes analyst questions to tools."""

    def __init__(self, tools: AgentTools | None = None, tracer: TraceRecorder | None = None):
        self.tools = tools or AgentTools()
        self.tracer = tracer or create_trace_recorder()
        self._router = QueryRouter()
        self._executor = ActionExecutor(self.tools)
        self._composer = AnswerComposer()

    def answer(self, question: str) -> tuple[AgentAnswer, AgentState]:
        """Answer a question and return both the answer and full tool-call state."""
        run_id = new_run_id()
        state = AgentState(question=question)
        try:
            actions = self._router.route(question)

            if not actions:
                actions = [
                    RoutedAction(
                        name="knowledge_search",
                        tool_name="search_knowledge",
                        tool_input={"query": question, "top_k": 5},
                    )
                ]

            self.tracer.on_workflow_start(run_id, question, [action.tool_name for action in actions])

            for action in actions:
                response = self._executor.run(action)
                state.tool_calls.append(
                    ToolCallRecord(name=action.tool_name, tool_input=action.tool_input, response=response)
                )
                self.tracer.on_tool_result(run_id, action.tool_name, action.tool_input, response)

            answer = self._composer.compose(state)
            self.tracer.on_workflow_end(run_id, answer)
            return answer, state
        except Exception as exc:
            self.tracer.on_workflow_error(
                run_id,
                type(exc).__name__,
                str(exc),
                {"tool_calls": len(state.tool_calls)},
            )
            answer = AgentAnswer(
                answer="The workflow failed before it could produce a grounded answer.",
                limitations=[f"WORKFLOW_FAILED: {type(exc).__name__} - {exc}"],
            )
            return answer, state
