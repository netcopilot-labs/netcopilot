"""S21-2: deterministic-first routing inside run_tool_loop.

Stub provider capturing the per-turn ``tools=`` list; no LLM, no Neo4j.
Contract (post pre-dispatch escalation, ADR-0024):

- An entry WITH ``dispatch`` → the loop calls the tool itself (static args),
  places the result in history, and the model narrates with FULL tool freedom.
- An entry WITHOUT ``dispatch`` → first-turn schema narrowing only (advisory).
- Unrouted questions → byte-identical to the pre-s21 loop.
"""
from __future__ import annotations

import asyncio

from netcopilot import orchestrator
from netcopilot.anonymizer import SessionAnonymizer
from netcopilot.llm import LLMResult, ToolCall
from netcopilot.mcp.registry import TOOL_SCHEMAS, ToolResult
from netcopilot.mcp.router import RouteDecision

ROUTED_Q = "how is vrrp configured?"          # the s20 documented misroute
UNROUTED_Q = "how many devices are there?"
ALL_NAMES = [t["name"] for t in TOOL_SCHEMAS]


class ToolCapturingProvider:
    name = "stub"
    model = "stub-model"

    def __init__(self, script):
        self.script = list(script)
        self.seen_tools: list[list[str]] = []
        self.seen_histories: list[list[dict]] = []

    async def run_turn(self, *, system, history, tools, max_tokens=4096):
        self.seen_tools.append([t["name"] for t in tools])
        self.seen_histories.append([dict(m) for m in history])
        return self.script.pop(0)


def _collect(question, provider, **kw):
    async def run():
        history = [{"role": "user", "content": question}]
        return [ev async for ev in orchestrator.run_tool_loop(
            history, {"run_id": "x"}, provider=provider, **kw)]
    return asyncio.run(run())


def _fake_dispatch(monkeypatch, text="redundancy data", **result_kw):
    calls = []

    async def fake(name, args, context):
        calls.append((name, args))
        return ToolResult("ok", text, **result_kw)
    monkeypatch.setattr(orchestrator, "dispatch", fake)
    return calls


# ── Dispatch entries (the packaged seed) ─────────────────────────────────────


def test_routed_dispatch_calls_tool_without_the_model(monkeypatch):
    calls = _fake_dispatch(monkeypatch)
    provider = ToolCapturingProvider([LLMResult(text="the answer", tool_calls=[])])
    events = _collect(ROUTED_Q, provider)

    # The tool was called by the LOOP, before any provider turn.
    assert calls == [("get_redundancy_assessment", {})]
    # Event order: audit first, then the deterministic call, then the answer.
    assert [e["type"] for e in events] == [
        "routing", "tool_status", "tool_call", "tool_result",
        "content", "usage", "done",
    ]
    # Exactly ONE LLM turn (narration) — the selection cost the model nothing.
    assert next(e for e in events if e["type"] == "usage")["data"]["api_calls"] == 1
    # The model saw the tool result in history and full tool freedom.
    assert provider.seen_tools == [ALL_NAMES]
    tool_msg = next(m for m in provider.seen_histories[0] if m.get("role") == "tool")
    assert tool_msg["content"] == "redundancy data"


def test_routing_event_carries_dispatch_audit(monkeypatch):
    _fake_dispatch(monkeypatch)
    provider = ToolCapturingProvider([LLMResult(text="a", tool_calls=[])])
    events = _collect(ROUTED_Q, provider)

    data = next(e for e in events if e["type"] == "routing")["data"]
    assert data["rule"] == "gateway_redundancy_state"
    assert data["dispatched"] == "get_redundancy_assessment"
    assert data["pattern"] and "get_redundancy_assessment" in data["tools"]


def test_dispatch_error_degrades_to_error_result_not_crash(monkeypatch):
    async def boom(name, args, context):
        raise RuntimeError("neo4j down")
    monkeypatch.setattr(orchestrator, "dispatch", boom)
    provider = ToolCapturingProvider([LLMResult(text="sorry", tool_calls=[])])
    events = _collect(ROUTED_Q, provider)

    tr = next(e for e in events if e["type"] == "tool_result")
    assert tr["data"]["status"] == "error" and "neo4j down" in tr["data"]["content"]
    assert events[-1]["type"] == "done"    # the model still answered


def test_dispatch_result_highlight_is_emitted(monkeypatch):
    payload = {"devices": ["core-sw-01"]}
    _fake_dispatch(monkeypatch, highlight=payload)
    provider = ToolCapturingProvider([LLMResult(text="a", tool_calls=[])])
    events = _collect(ROUTED_Q, provider)
    hl = [e for e in events if e["type"] == "highlight"]
    assert len(hl) == 1 and hl[0]["data"] == payload


# ── Narrow-only entries (no static-args dispatch) ────────────────────────────


def test_narrow_only_entry_narrows_first_turn_then_full(monkeypatch):
    _fake_dispatch(monkeypatch)
    monkeypatch.setattr(orchestrator, "route", lambda q: RouteDecision(
        rule_id="narrow_only", tools=("get_findings",), pattern="x"))
    provider = ToolCapturingProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "get_findings", {})]),
        LLMResult(text="answer", tool_calls=[]),
    ])
    events = _collect("anything", provider)

    assert provider.seen_tools[0] == ["get_findings"]   # narrowed turn 1
    assert provider.seen_tools[1] == ALL_NAMES          # full set after
    data = next(e for e in events if e["type"] == "routing")["data"]
    assert data["dispatched"] is None


# ── Unrouted: byte-identical to pre-s21 ──────────────────────────────────────


def test_unrouted_question_is_byte_identical_to_pre_s21(monkeypatch):
    _fake_dispatch(monkeypatch)
    provider = ToolCapturingProvider([LLMResult(text="direct answer", tool_calls=[])])
    events = _collect(UNROUTED_Q, provider)

    assert provider.seen_tools == [ALL_NAMES]
    assert [e["type"] for e in events] == ["content", "usage", "done"]


def test_routing_matches_latest_user_message_in_conversation(monkeypatch):
    # The ROUTED text sits in an OLD message; the latest user message is
    # unrouted → no routing (latest-message-only, follow-up freedom).
    _fake_dispatch(monkeypatch)
    provider = ToolCapturingProvider([LLMResult(text="ok", tool_calls=[])])

    async def run():
        history = [
            {"role": "user", "content": ROUTED_Q},
            {"role": "assistant", "content": "VRRP group 61 ..."},
            {"role": "user", "content": "and the findings on core-sw-01?"},
        ]
        return [ev async for ev in orchestrator.run_tool_loop(
            history, {"run_id": "x"}, provider=provider)]

    events = asyncio.run(run())
    assert provider.seen_tools == [ALL_NAMES]
    assert not [e for e in events if e["type"] == "routing"]


# ── Anonymizer path ──────────────────────────────────────────────────────────


def test_routing_and_dispatch_survive_anonymized_history(monkeypatch):
    # Cloud path: history is anonymized; protocol keywords survive scrubbing.
    # The pre-dispatched result must be ANONYMIZED into history (the model
    # never sees real identifiers) while the streamed event carries real data.
    anon = SessionAnonymizer()
    anon.register_device("core-sw-01")
    anonymized_q = anon.anonymize("how is vrrp configured on core-sw-01?")
    assert "core-sw-01" not in anonymized_q and "vrrp" in anonymized_q.lower()

    _fake_dispatch(monkeypatch, text="core-sw-01 is the active router")
    provider = ToolCapturingProvider([LLMResult(text="answer", tool_calls=[])])
    events = _collect(anonymized_q, provider, anonymizer=anon)

    assert [e for e in events if e["type"] == "routing"]
    tool_msg = next(m for m in provider.seen_histories[0] if m.get("role") == "tool")
    assert "core-sw-01" not in tool_msg["content"]          # history: anonymized
    tr = next(e for e in events if e["type"] == "tool_result")
    assert "core-sw-01" in tr["data"]["content"]            # client event: real
