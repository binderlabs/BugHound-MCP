"""OpenAI-compatible provider — covers OpenAI, Grok (xAI), and OpenRouter.

All three use the same API format with different base_url:
  - OpenAI:     https://api.openai.com/v1
  - Grok:       https://api.x.ai/v1
  - OpenRouter:  https://openrouter.ai/api/v1
"""

from __future__ import annotations

import json
from typing import Any

from bughound.providers.base import AIProvider, AIResponse, ToolCall

PROVIDER_URLS = {
    "openai": "https://api.openai.com/v1",
    "grok": "https://api.x.ai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}

DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "grok": "grok-3",
    "openrouter": "anthropic/claude-sonnet-4.5",
}


class OpenAICompatProvider(AIProvider):
    """Provider using OpenAI-compatible chat completions API."""

    def __init__(
        self,
        provider_name: str,
        api_key: str,
        model: str | None = None,
    ) -> None:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise RuntimeError(
                "openai package required. Install: pip install openai"
            )

        base_url = PROVIDER_URLS.get(provider_name)
        if not base_url:
            raise ValueError(f"Unknown provider: {provider_name}")

        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self.model = model or DEFAULT_MODELS.get(provider_name, "gpt-4o")
        self.provider_name = provider_name

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AIResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = await self.client.chat.completions.create(**kwargs)

        if not response.choices:
            return AIResponse(content="No response from model", tool_calls=[], usage={})
        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls: list[ToolCall] = []

        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args,
                ))

        usage = {}
        if response.usage:
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }

        return AIResponse(content=content, tool_calls=tool_calls, usage=usage)

    def format_tool_result(self, tool_call_id: str, result: str) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        }

    def format_assistant_tool_calls(self, response: AIResponse) -> dict[str, Any]:
        return {
            "role": "assistant",
            "content": response.content or None,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in response.tool_calls
            ],
        }
