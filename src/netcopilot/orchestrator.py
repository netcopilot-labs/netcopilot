"""Client-agnostic agent loop: an LLM provider drives the MCP tools to a grounded answer.

The same loop powers any client (CLI, the dashboard SSE stream, the Telegram bot,
another agent). It depends only on the LLM abstraction (``provider.run_turn``) and
the tool registry (``TOOL_SCHEMAS`` + ``dispatch``) — no provider-specific transport
lives here.

``run_tool_loop`` is the streaming core: it yields structured event dicts a client
renders as it sees fit:

    {"type": "tool_status", "data": "Querying get_findings..."}
    {"type": "tool_call",   "data": {"name": "get_findings", "arguments": {...}}}
    {"type": "tool_result", "data": {"name": "get_findings", "content": "..."}}
    {"type": "content",     "data": "There are 5 devices..."}
    {"type": "highlight",   "data": {"device": "core-rtr-01"}}
    {"type": "usage",       "data": {"model": ..., "input_tokens": ..., ...}}
    {"type": "done",        "data": None}
    {"type": "error",       "data": "AI service unavailable: ..."}

``answer`` is a thin wrapper that consumes the stream and returns the final text.

When an ``anonymizer`` is supplied (the cloud-LLM path), the conversation history
is kept anonymized: the model only ever sees scrubbed identifiers, while tool
dispatch and the events streamed to the local client use real data. The caller is
responsible for anonymizing the initial history; the loop deanonymizes tool-call
arguments before dispatch and anonymizes tool results before feeding them back.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncGenerator

from .llm import LLMProvider, get_provider
from .mcp.registry import MAX_RESULT_CHARS, TOOL_SCHEMAS, dispatch
from .prompts import load_system_prompt

log = logging.getLogger(__name__)

# The full tool-routing contract, shipped as package data. Loaded once (cached).
SYSTEM_PROMPT = load_system_prompt()

# Tools whose results drive topology-map highlighting in graphical clients.
_HIGHLIGHT_TOOLS = {"blast_radius", "trace_path", "get_device_detail"}

# ── Deterministic LaTeX → Unicode output normalizer ──────────────────────────
# Some models intermittently emit LaTeX math ($\rightarrow$, $\le 1$) despite a
# prompt rule forbidding it. A prompt rule is non-deterministic — the model
# ignores it. This post-processor enforces plain Unicode deterministically at
# the output boundary, for every client and provider.
_LATEX_UNICODE = {
    "longrightarrow": "→", "rightarrow": "→", "Rightarrow": "⇒",
    "longleftarrow": "←", "leftrightarrow": "↔", "leftarrow": "←",
    "Leftarrow": "⇐", "implies": "⇒", "to": "→",
    "leq": "≤", "le": "≤", "geq": "≥", "ge": "≥",
    "neq": "≠", "ne": "≠", "approx": "≈", "equiv": "≡",
    "times": "×", "cdot": "·", "pm": "±", "div": "÷",
    "ldots": "…", "dots": "…",
}
# Longest-first alternation so \leq matches before \le, \geq before \ge; the
# trailing (?![a-zA-Z]) stops \le from eating \leftarrow / \leq.
_LATEX_CMD_RE = re.compile(
    r"\\(" + "|".join(sorted(_LATEX_UNICODE, key=len, reverse=True)) + r")(?![a-zA-Z])"
)
# Strip $…$ delimiters only around spans containing a LaTeX command, so plain
# text with a bare '$' (e.g. a dollar figure) is left untouched.
_INLINE_MATH_RE = re.compile(r"\$([^$\n]*?\\[a-zA-Z][^$\n]*?)\$")


def sanitize_math(text: str) -> str:
    """Deterministically convert LaTeX math the model emits to plain Unicode.

    Unwraps $…$ around LaTeX commands, maps \\rightarrow→→, \\le→≤, etc.
    Idempotent; no-op on text without a backslash.
    """
    if not text or "\\" not in text:
        return text
    text = _INLINE_MATH_RE.sub(r"\1", text)
    text = _LATEX_CMD_RE.sub(lambda m: _LATEX_UNICODE[m.group(1)], text)
    return text


# A tool can emit a trailing `__highlight__:<json>` marker to trigger a client-
# side effect (e.g. switching a panel to report view). The loop strips the
# marker from the visible result — the model never sees it — and emits it as a
# highlight event.
_INLINE_HIGHLIGHT_RE = re.compile(r"\n*__highlight__:(\{.*?\})\s*$", re.DOTALL)


def _strip_inline_highlight(tool_result: str) -> tuple[str, dict | None]:
    """Strip a trailing ``__highlight__:<json>`` marker from a tool result.

    Returns (cleaned_result, parsed_highlight_or_none). If the marker is absent
    or malformed, returns (tool_result, None) unchanged.
    """
    match = _INLINE_HIGHLIGHT_RE.search(tool_result)
    if not match:
        return tool_result, None
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return tool_result, None
    return tool_result[: match.start()].rstrip(), payload


def extract_highlight(tool_name: str, tool_args: dict, tool_result: str) -> dict | None:
    """Extract topology-highlight data from a spatial tool's result.

    Returns a dict with the device name (and optional ``failedMember`` for
    cluster analysis), or a ``devices`` list for path tracing. Only fires for
    tools in ``_HIGHLIGHT_TOOLS``.
    """
    if tool_name not in _HIGHLIGHT_TOOLS:
        return None

    device = tool_args.get("device") or tool_args.get("source_device") or ""

    # Resolve shorthand device names from the tool result (canonical name).
    if device and tool_name == "get_device_detail" and "Device: " in tool_result:
        for line in tool_result.split("\n"):
            if line.startswith("Device: "):
                device = line.split("Device: ", 1)[1].strip()
                break

    if device and tool_name == "blast_radius" and "Blast radius" in tool_result:
        for line in tool_result.split("\n"):
            if "Blast radius" in line and "—" in line:
                device = line.split("—", 1)[1].strip().split(" ")[0]
                break

    if tool_name == "trace_path":
        # Extract ALL hop devices for path highlighting, e.g. a result line like
        #   "Hop 1: core-rtr-01 [default] (distribution_switch)"
        path_devices = []
        for line in tool_result.split("\n"):
            if line.strip().startswith("Hop "):
                parts = line.split(": ", 1)
                if len(parts) > 1:
                    hop_device = parts[1].split(" ")[0].strip()
                    if hop_device and hop_device not in path_devices:
                        path_devices.append(hop_device)
        if path_devices:
            return {"devices": path_devices}
        # Fallback: extract from a "Path:" line.
        for line in tool_result.split("\n"):
            if line.startswith("Path:"):
                parts = line.split("Path: ", 1)
                if len(parts) > 1:
                    device = parts[1].split(" ")[0].strip()
                    break

    if not device:
        return None

    result = {"device": device}
    if tool_name == "blast_radius" and tool_args.get("member") is not None:
        result["failedMember"] = tool_args["member"]
    return result


def _truncate(text: str, max_chars: int) -> str:
    """Truncate a tool result that exceeds the per-client char limit."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n[Truncated at {max_chars} chars. Use filters to narrow.]"


async def run_tool_loop(
    history: list[dict],
    context: dict,
    *,
    provider: LLMProvider,
    system: str = SYSTEM_PROMPT,
    anonymizer=None,
    max_turns: int = 15,
    max_result_chars: int = MAX_RESULT_CHARS,
) -> AsyncGenerator[dict, None]:
    """Stream a tool-calling conversation as event dicts (see module docstring).

    ``history`` is mutated in place (assistant + tool turns are appended) so the
    provider sees the growing conversation. When ``anonymizer`` is set, the
    history stays anonymized; only dispatch and the streamed events use real data.
    """
    total_in = total_out = 0
    api_calls = 0

    for _ in range(max_turns):
        try:
            result = await provider.run_turn(system=system, history=history, tools=TOOL_SCHEMAS)
        except Exception as exc:
            yield {"type": "error", "data": f"AI service unavailable: {exc}"}
            return
        api_calls += 1

        if result.usage:
            total_in += result.usage.get("input_tokens", 0)
            total_out += result.usage.get("output_tokens", 0)

        if result.tool_calls:
            history.append(
                {"role": "assistant", "content": result.text, "tool_calls": result.tool_calls}
            )
            for tc in result.tool_calls:
                # Deanonymize args before dispatch so tools see real identifiers.
                if anonymizer:
                    args = {
                        k: (anonymizer.deanonymize(v) if isinstance(v, str) else v)
                        for k, v in tc.arguments.items()
                    }
                else:
                    args = tc.arguments

                yield {"type": "tool_status", "data": f"Querying {tc.name}..."}
                yield {"type": "tool_call", "data": {"name": tc.name, "arguments": args}}

                try:
                    tool_result = await dispatch(tc.name, args, context)
                except Exception as exc:
                    tool_result = f"Tool error: {exc}"

                tool_result, inline_highlight = _strip_inline_highlight(tool_result)
                tool_result = _truncate(tool_result, max_result_chars)
                highlight = extract_highlight(tc.name, args, tool_result)

                # The model sees the anonymized result; the local client sees real data.
                stored = anonymizer.anonymize(tool_result) if anonymizer else tool_result
                history.append({"role": "tool", "tool_call_id": tc.id, "content": stored})

                yield {"type": "tool_result", "data": {"name": tc.name, "content": tool_result}}
                if inline_highlight:
                    yield {"type": "highlight", "data": inline_highlight}
                if highlight:
                    yield {"type": "highlight", "data": highlight}
            continue

        # No tool calls — final answer.
        text = result.text or ""
        if anonymizer:
            text = anonymizer.deanonymize(text)
        if text:
            yield {"type": "content", "data": sanitize_math(text)}

        usage = {
            "model": getattr(provider, "model", provider.name),
            "input_tokens": total_in,
            "output_tokens": total_out,
            "total_tokens": total_in + total_out,
            "api_calls": api_calls,
        }
        if anonymizer:
            usage["anonymization"] = anonymizer.get_summary()
        yield {"type": "usage", "data": usage}
        yield {"type": "done", "data": None}
        return

    yield {"type": "error", "data": "(reached the tool-turn limit without a final answer)"}


async def answer(
    question: str,
    *,
    context: dict,
    provider: LLMProvider | None = None,
    system: str | None = None,
    max_turns: int = 8,
) -> str:
    """Run the tool-calling loop for one question and return the grounded answer."""
    provider = provider or get_provider()
    history: list[dict] = [{"role": "user", "content": question}]
    parts: list[str] = []

    async for event in run_tool_loop(
        history, context, provider=provider, system=system or SYSTEM_PROMPT, max_turns=max_turns
    ):
        if event["type"] == "content":
            parts.append(event["data"])
        elif event["type"] == "error":
            return event["data"]

    return "".join(parts) or "(no answer)"
