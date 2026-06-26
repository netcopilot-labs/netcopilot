"""LLM provider abstraction.

The orchestrator is provider-agnostic: it works with a *normalized* conversation and
*normalized* tool schemas, and a provider translates to/from each LLM's native format.

Normalized history items (plain dicts):
    {"role": "user", "content": str}
    {"role": "assistant", "content": str | None, "tool_calls": list[ToolCall]}
    {"role": "tool", "tool_call_id": str, "content": str}

Normalized tool schema (dict):
    {"name": str, "description": str, "parameters": <JSON Schema>}
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict


@dataclass(frozen=True)
class LLMResult:
    """The outcome of one turn: assistant text and/or tool calls."""

    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict | None = None  # {"input_tokens": int, "output_tokens": int} when the provider reports it

    @property
    def is_final(self) -> bool:
        """True when the model returned an answer with no tool calls."""
        return not self.tool_calls


class LLMProvider(ABC):
    """One tool-calling turn against an LLM, expressed in normalized terms."""

    name: str

    @abstractmethod
    async def run_turn(
        self,
        *,
        system: str,
        history: list[dict],
        tools: list[dict],
        max_tokens: int = 4096,
    ) -> LLMResult:
        """Send (system, normalized history, normalized tools); return text + tool calls."""
        raise NotImplementedError
