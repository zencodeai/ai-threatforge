from __future__ import annotations

from typing import Any, Protocol

from .state import ToolResponse


class Tool(Protocol):
    """Protocol for a named tool that can be executed by the agent."""

    @property
    def name(self) -> str: ...

    def run(self, tool_input: dict[str, Any]) -> ToolResponse: ...


ToolRegistry = dict[str, Tool]
