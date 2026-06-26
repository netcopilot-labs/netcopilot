"""Ollama provider via its OpenAI-compatible API (``/v1/chat/completions``).

Same wire format as any OpenAI-style endpoint. Translation helpers are module-level
and import-free (testable without httpx); httpx is imported lazily in ``run_turn``.
"""

from __future__ import annotations

import json
import os

from .base import LLMProvider, LLMResult, ToolCall


def to_openai_tools(tools: list[dict]) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t["parameters"],
            },
        }
        for t in tools
    ]


def to_openai_messages(system: str, history: list[dict]) -> list[dict]:
    messages: list[dict] = [{"role": "system", "content": system}]
    for item in history:
        role = item["role"]
        if role == "user":
            messages.append({"role": "user", "content": item["content"]})
        elif role == "assistant":
            msg: dict = {"role": "assistant", "content": item.get("content") or ""}
            if item.get("tool_calls"):
                msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in item["tool_calls"]
                ]
            messages.append(msg)
        elif role == "tool":
            messages.append(
                {"role": "tool", "tool_call_id": item["tool_call_id"], "content": item["content"]}
            )
    return messages


def parse_openai(data: dict) -> LLMResult:
    msg = data["choices"][0]["message"]
    tool_calls: list[ToolCall] = []
    for tc in msg.get("tool_calls") or []:
        raw = tc["function"].get("arguments") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            args = {}
        tool_calls.append(ToolCall(id=tc.get("id", ""), name=tc["function"]["name"], arguments=args))
    usage = None
    u = data.get("usage")
    if u:
        usage = {
            "input_tokens": u.get("prompt_tokens", 0),
            "output_tokens": u.get("completion_tokens", 0),
        }
    return LLMResult(text=msg.get("content") or None, tool_calls=tool_calls, usage=usage)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        ).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3.1")
        # Optional bearer token — required for commercial OpenAI-compatible APIs
        # (OpenAI, Gemini, Groq, …); omitted for keyless local servers.
        self.api_key = api_key
        self.timeout = timeout

    async def run_turn(self, *, system, history, tools, max_tokens=4096) -> LLMResult:
        import httpx

        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": to_openai_messages(system, history),
                    "tools": to_openai_tools(tools),
                    "tool_choice": "auto",
                    "max_tokens": max_tokens,
                    "temperature": 0.1,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            return parse_openai(resp.json())
