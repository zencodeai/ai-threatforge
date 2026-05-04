from __future__ import annotations

from .router import RoutedAction
from .state import ToolError, ToolResponse
from .tool_protocol import ToolRegistry
from .tools import AgentTools


class ActionExecutor:
    """Execute a routed action against the tool registry."""

    def __init__(self, tools: AgentTools):
        self._registry: ToolRegistry = tools.tool_registry()

    def run(self, action: RoutedAction) -> ToolResponse:
        tool = self._registry.get(action.tool_name)
        if tool is None:
            return ToolResponse(
                ok=False,
                source="workflow",
                confidence=0.0,
                error=ToolError(
                    code="UNSUPPORTED_TOOL",
                    message=f"Unsupported tool name: {action.tool_name}",
                    details={"tool_name": action.tool_name},
                ),
            )
        try:
            return tool.run(action.tool_input)
        except Exception as exc:
            return ToolResponse(
                ok=False,
                source="workflow",
                confidence=0.0,
                error=ToolError(
                    code="TOOL_EXECUTION_FAILED",
                    message=str(exc),
                    details={
                        "tool_name": action.tool_name,
                        "exception_type": type(exc).__name__,
                    },
                ),
            )
