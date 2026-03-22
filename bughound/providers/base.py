"""Abstract AI provider interface for BugHound agent mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """A tool call requested by the AI."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class AIResponse:
    """Response from an AI provider."""
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class AIProvider:
    """Abstract base for AI providers."""

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AIResponse:
        raise NotImplementedError

    def format_tool_result(
        self,
        tool_call_id: str,
        result: str,
    ) -> dict[str, Any]:
        """Format a tool result message for the conversation."""
        raise NotImplementedError

    def format_assistant_tool_calls(
        self,
        response: AIResponse,
    ) -> dict[str, Any]:
        """Format the assistant's tool call message for the conversation."""
        raise NotImplementedError
