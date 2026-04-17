from __future__ import annotations

from .router import RoutedAction
from .state import ToolResponse
from .tool_protocol import ToolRegistry
from .tools import AgentTools


class ActionExecutor:
    """Execute a routed action against the tool registry."""

    def __init__(self, tools: AgentTools):
        self._registry: ToolRegistry = tools.tool_registry()

    def run(self, action: RoutedAction) -> ToolResponse:
        tool = self._registry.get(action.tool_name)
        if tool is None:
            raise ValueError(f"Unsupported tool name: {action.tool_name}")
        return tool.run(action.tool_input)
