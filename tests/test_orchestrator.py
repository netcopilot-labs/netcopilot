"""F1-5: the orchestrator loop drives tools and feeds results back (stub provider, no LLM/Neo4j)."""

import asyncio

from netcopilot import orchestrator
from netcopilot.llm import LLMProvider, LLMResult, ToolCall


class StubProvider(LLMProvider):
    """Returns a scripted sequence of LLMResults, recording the history it was given."""

    name = "stub"

    def __init__(self, script):
        self.script = list(script)
        self.seen_histories = []

    async def run_turn(self, *, system, history, tools, max_tokens=4096):
        self.seen_histories.append([dict(m) for m in history])
        return self.script.pop(0)


def test_loop_dispatches_tool_then_returns_final(monkeypatch):
    async def fake_dispatch(name, args, context):
        return f"TOOL[{name}]:ok"

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)

    stub = StubProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "query_topology", {})]),
        LLMResult(text="There are 5 devices.", tool_calls=[]),
    ])
    out = asyncio.run(
        orchestrator.answer("how many devices?", context={"run_id": "x"}, provider=stub)
    )

    assert out == "There are 5 devices."
    # On its second turn the provider saw the tool result fed back into the history.
    last_history = stub.seen_histories[-1]
    assert any(
        m.get("role") == "tool" and "TOOL[query_topology]:ok" in m.get("content", "")
        for m in last_history
    )


def test_loop_returns_final_immediately_when_no_tool_calls(monkeypatch):
    monkeypatch.setattr(orchestrator, "dispatch", lambda *a, **k: None)
    stub = StubProvider([LLMResult(text="hello", tool_calls=[])])
    out = asyncio.run(orchestrator.answer("hi", context={"run_id": "x"}, provider=stub))
    assert out == "hello"


def test_loop_hits_turn_limit(monkeypatch):
    async def fake_dispatch(name, args, context):
        return "tool"

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)
    # Always asks for a tool, never finalizes.
    stub = StubProvider([LLMResult(text=None, tool_calls=[ToolCall("1", "query_topology", {})])] * 5)
    out = asyncio.run(
        orchestrator.answer("loop", context={"run_id": "x"}, provider=stub, max_turns=3)
    )
    assert "tool-turn limit" in out
