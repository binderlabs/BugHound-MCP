"""Native Anthropic provider — best tool_use support for Claude models."""

from __future__ import annotations

import json
from typing import Any

from bughound.providers.base import AIProvider, AIResponse, ToolCall


class AnthropicProvider(AIProvider):
    """Provider using native Anthropic SDK."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
    ) -> None:
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            raise RuntimeError(
                "anthropic package required. Install: pip install anthropic"
            )

        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model or "claude-sonnet-4-6"

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AIResponse:
        # Anthropic separates system from messages
        system_msg = ""
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                chat_messages.append(msg)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": chat_messages,
            "max_tokens": 4096,
        }
        if system_msg:
            kwargs["system"] = system_msg
        if tools:
            kwargs["tools"] = self._convert_tools(tools)

        response = await self.client.messages.create(**kwargs)

        content = ""
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                content += block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                ))

        usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }

        return AIResponse(content=content, tool_calls=tool_calls, usage=usage)

    def format_tool_result(self, tool_call_id: str, result: str) -> dict[str, Any]:
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": tool_call_id,
                    "content": result,
                }
            ],
        }

    def format_assistant_tool_calls(self, response: AIResponse) -> dict[str, Any]:
        content: list[dict[str, Any]] = []
        if response.content:
            content.append({"type": "text", "text": response.content})
        for tc in response.tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })
        return {"role": "assistant", "content": content}

    @staticmethod
    def _convert_tools(openai_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI function-calling format to Anthropic tool format."""
        anthropic_tools = []
        for tool in openai_tools:
            if tool.get("type") == "function":
                func = tool["function"]
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
                })
        return anthropic_tools
