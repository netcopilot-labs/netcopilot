"""Anthropic Claude provider.

Translation helpers are module-level and import-free (testable without the SDK);
the SDK is imported lazily inside ``run_turn``.
"""

from __future__ import annotations

import os

from .base import LLMProvider, LLMResult, ToolCall


def to_anthropic_tools(tools: list[dict]) -> list[dict]:
    return [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t["parameters"],
        }
        for t in tools
    ]


def to_anthropic_messages(history: list[dict]) -> list[dict]:
    """Normalized history -> Anthropic messages.

    Anthropic requires tool results inside a *user* message; consecutive normalized
    ``tool`` items are coalesced into one user message of ``tool_result`` blocks.
    """
    messages: list[dict] = []
    pending: list[dict] = []

    def flush() -> None:
        nonlocal pending
        if pending:
            messages.append({"role": "user", "content": pending})
            pending = []

    for item in history:
        role = item["role"]
        if role == "tool":
            pending.append(
                {
                    "type": "tool_result",
                    "tool_use_id": item["tool_call_id"],
                    "content": item["content"],
                }
            )
            continue
        flush()
        if role == "user":
            messages.append({"role": "user", "content": item["content"]})
        elif role == "assistant":
            content: list[dict] = []
            if item.get("content"):
                content.append({"type": "text", "text": item["content"]})
            for tc in item.get("tool_calls", []):
                content.append(
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments}
                )
            messages.append({"role": "assistant", "content": content})
    flush()
    return messages


def parse_anthropic(response) -> LLMResult:
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in response.content:
        if block.type == "text":
            text_parts.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
    usage = None
    if getattr(response, "usage", None):
        usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
    return LLMResult(text="".join(text_parts) or None, tool_calls=tool_calls, usage=usage)


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = (
            api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        )
        self.model = model or os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
        if not self.api_key:
            raise ValueError("ClaudeProvider requires ANTHROPIC_API_KEY (or CLAUDE_API_KEY).")

    async def run_turn(self, *, system, history, tools, max_tokens=4096) -> LLMResult:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self.api_key)
        response = await client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=to_anthropic_messages(history),
            tools=to_anthropic_tools(tools),
            tool_choice={"type": "auto"},
        )
        return parse_anthropic(response)
