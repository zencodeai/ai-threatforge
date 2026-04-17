from __future__ import annotations

from .router import RoutedAction
from .state import ToolResponse
from .tools import AgentTools


class ActionExecutor:
    """Execute a routed action against the tool layer."""

    def __init__(self, tools: AgentTools):
        self.tools = tools

    def run(self, action: RoutedAction) -> ToolResponse:
        if action.tool_name == "lookup_technique":
            return self.tools.lookup_technique(action.tool_input["technique_id"])
        if action.tool_name == "get_risks":
            return self.tools.get_risks(top_n=action.tool_input.get("top_n", 5))
        if action.tool_name == "get_threats":
            return self.tools.get_threats(
                filter_by=action.tool_input.get("filter_by"),
                top_n=action.tool_input.get("top_n", 5),
            )
        if action.tool_name == "query_graph":
            return self.tools.query_graph(
                action.tool_input["query"],
                action.tool_input.get("params"),
            )
        if action.tool_name == "search_knowledge":
            return self.tools.search_knowledge(
                action.tool_input["query"],
                top_k=action.tool_input.get("top_k", 5),
            )
        raise ValueError(f"Unsupported tool name: {action.tool_name}")
