"""Client-agnostic agent loop: an LLM provider drives the MCP tools to a grounded answer.

The same loop powers any client (CLI, the dashboard SSE stream, the Telegram bot,
another agent). It depends only on the LLM abstraction (``provider.run_turn``) and
the tool registry (``TOOL_SCHEMAS`` + ``dispatch``) — no provider-specific transport
lives here.

``run_tool_loop`` is the streaming core: it yields structured event dicts a client
renders as it sees fit:

    {"type": "tool_status", "data": "Querying get_findings..."}
    {"type": "tool_call",   "data": {"name": "get_findings", "arguments": {...}}}
    {"type": "tool_result", "data": {"name": "get_findings", "content": "...", "status": "ok"}}
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

import logging
import re
from collections.abc import AsyncGenerator

from .llm import LLMProvider, ToolCall, get_provider
from .mcp.registry import MAX_RESULT_CHARS, TOOL_SCHEMAS, ToolResult, dispatch
from .mcp.router import route
from .prompts import load_system_prompt

log = logging.getLogger(__name__)

# The full tool-routing contract, shipped as package data. Loaded once (cached).
SYSTEM_PROMPT = load_system_prompt()

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

    # ── Deterministic-first routing (s21, ADR-0024) ──────────────────────────
    # A question matching a routing.yaml intent narrows the FIRST turn's offered
    # tools — the deterministic layer decides WHICH capability; the model fills
    # arguments and reasons over the result. No match (and every later turn) =
    # the full registry, byte-identical to the pre-s21 loop. The decision is
    # emitted as an audit event so clients and the eval can see WHY a tool was
    # offered, not just that it was called. Routing matches on the latest user
    # message; on the anonymized (cloud) path protocol keywords survive
    # scrubbing — the 9 anonymized entity types are identifiers, not protocols.
    last_user = next(
        (m.get("content") or "" for m in reversed(history) if m.get("role") == "user"),
        "",
    )
    decision = route(last_user)
    if decision:
        yield {
            "type": "routing",
            "data": {"rule": decision.rule_id, "tools": list(decision.tools),
                     "pattern": decision.pattern,
                     "dispatched": decision.dispatch_tool},
        }

    # Deterministic pre-dispatch: an entry with a ``dispatch`` block calls its
    # tool HERE, with static catalogue arguments — no model involvement in the
    # selection or the call. The result is placed in history exactly as a
    # model-initiated call would be, so the model's first turn reasons over it
    # (and keeps full tool freedom for follow-ups). Added after the eval
    # measured schema-narrowing as ADVISORY on the local serving stack: the
    # model bypassed the narrowed set (2026-07-11, ADR-0024).
    if decision and decision.dispatch_tool:
        name, args = decision.dispatch_tool, dict(decision.dispatch_args or {})
        yield {"type": "tool_status", "data": f"Querying {name}..."}
        yield {"type": "tool_call", "data": {"name": name, "arguments": args}}
        try:
            result = await dispatch(name, args, context)
        except Exception as exc:
            result = ToolResult("error", f"Tool error: {exc}")
        tool_text = _truncate(result.text, max_result_chars)
        stored = anonymizer.anonymize(tool_text) if anonymizer else tool_text
        history.append({"role": "assistant", "content": None,
                        "tool_calls": [ToolCall("routed-0", name, args)]})
        history.append({"role": "tool", "tool_call_id": "routed-0", "content": stored})
        yield {"type": "tool_result",
               "data": {"name": name, "content": tool_text, "status": result.status}}
        if result.highlight:
            yield {"type": "highlight", "data": result.highlight}

    for turn in range(max_turns):
        offered = TOOL_SCHEMAS
        if turn == 0 and decision and not decision.dispatch_tool:
            # Narrow-only entries (no static-args dispatch possible): offer just
            # the routed schemas. Advisory on stacks that don't enforce
            # membership — the eval watches the call actually landing.
            offered = [t for t in TOOL_SCHEMAS if t["name"] in decision.tools]
        try:
            result = await provider.run_turn(system=system, history=history, tools=offered)
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
            verbatim_answer = None
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
                    result = await dispatch(tc.name, args, context)
                except Exception as exc:
                    result = ToolResult("error", f"Tool error: {exc}")

                tool_text = _truncate(result.text, max_result_chars)

                # The model sees the anonymized result; the local client sees real data.
                stored = anonymizer.anonymize(tool_text) if anonymizer else tool_text
                history.append({"role": "tool", "tool_call_id": tc.id, "content": stored})

                yield {
                    "type": "tool_result",
                    "data": {"name": tc.name, "content": tool_text,
                             "status": result.status},
                }
                # Structured client side-effects (topology highlight, report
                # panel) come from the envelope — no prose scraping, no markers.
                if result.highlight:
                    yield {"type": "highlight", "data": result.highlight}

                # A verbatim tool's output *is* the answer (product blurb /
                # dashboard tour / capability menu): emit it directly and
                # finalize instead of a second LLM turn — small local models
                # drop the block when asked to re-quote it.
                if result.verbatim and verbatim_answer is None:
                    verbatim_answer = tool_text

            if verbatim_answer is not None:
                # The onboarding tool output is itself the answer — emit it directly
                # rather than relying on the model to re-quote it (see the constant).
                yield {"type": "content", "data": sanitize_math(verbatim_answer)}
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
