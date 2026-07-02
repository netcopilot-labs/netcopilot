"""F4a-2: the streaming run_tool_loop — events, usage, anonymizer integration.

Stub provider + fake dispatch; no real LLM or Neo4j.
"""

import asyncio

from netcopilot import orchestrator
from netcopilot.anonymizer import SessionAnonymizer
from netcopilot.llm import LLMResult, ToolCall


class StubProvider:
    name = "stub"
    model = "stub-model"

    def __init__(self, script):
        self.script = list(script)
        self.seen_histories = []

    async def run_turn(self, *, system, history, tools, max_tokens=4096):
        self.seen_histories.append([dict(m) for m in history])
        return self.script.pop(0)


def _collect(history, provider, **kw):
    async def run():
        return [ev async for ev in orchestrator.run_tool_loop(history, {"run_id": "x"}, provider=provider, **kw)]
    return asyncio.run(run())


def test_stream_emits_full_event_sequence(monkeypatch):
    async def fake_dispatch(name, args, context):
        return "5 devices"

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)
    provider = StubProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "query_topology", {})]),
        LLMResult(text="There are 5 devices.", tool_calls=[]),
    ])
    events = _collect([{"role": "user", "content": "how many?"}], provider)
    types = [e["type"] for e in events]

    assert types == [
        "tool_status", "tool_call", "tool_result", "content", "usage", "done",
    ]
    tr = next(e for e in events if e["type"] == "tool_result")
    assert tr["data"] == {"name": "query_topology", "content": "5 devices"}
    assert next(e for e in events if e["type"] == "content")["data"] == "There are 5 devices."


def test_usage_accumulates_across_turns(monkeypatch):
    async def fake_dispatch(name, args, context):
        return "ok"

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)
    provider = StubProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "get_findings", {})],
                  usage={"input_tokens": 100, "output_tokens": 20}),
        LLMResult(text="done", tool_calls=[], usage={"input_tokens": 50, "output_tokens": 10}),
    ])
    events = _collect([{"role": "user", "content": "q"}], provider)
    usage = next(e for e in events if e["type"] == "usage")["data"]
    assert usage["input_tokens"] == 150 and usage["output_tokens"] == 30
    assert usage["total_tokens"] == 180 and usage["model"] == "stub-model"


def test_sanitize_math_applied_to_content(monkeypatch):
    monkeypatch.setattr(orchestrator, "dispatch", lambda *a, **k: None)
    provider = StubProvider([LLMResult(text=r"latency $\le$ 5ms $\rightarrow$ ok", tool_calls=[])])
    events = _collect([{"role": "user", "content": "q"}], provider)
    assert next(e for e in events if e["type"] == "content")["data"] == "latency ≤ 5ms → ok"


def test_anonymizer_deanonymizes_args_and_content(monkeypatch):
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")          # core-rtr-01 <-> device-1
    seen_args = {}

    async def fake_dispatch(name, args, context):
        seen_args.update(args)
        return "core-rtr-01 has 3 findings"      # real data from the tool

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)
    # The model, seeing anonymized context, emits the anon label in its tool args
    # and final text.
    provider = StubProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "get_findings", {"device": "device-1"})]),
        LLMResult(text="device-1 looks healthy", tool_calls=[]),
    ])
    events = _collect([{"role": "user", "content": "check device-1"}], provider, anonymizer=anon)

    # dispatch saw the DEANONYMIZED real name
    assert seen_args["device"] == "core-rtr-01"
    # the history fed back to the provider stored the ANONYMIZED tool result
    last_history = provider.seen_histories[-1]
    tool_msg = next(m for m in last_history if m.get("role") == "tool")
    assert "device-1" in tool_msg["content"] and "core-rtr-01" not in tool_msg["content"]
    # the content streamed to the local client is DEANONYMIZED
    assert next(e for e in events if e["type"] == "content")["data"] == "core-rtr-01 looks healthy"
    # usage carries the anonymization summary
    assert "anonymization" in next(e for e in events if e["type"] == "usage")["data"]


def test_verbatim_onboarding_tool_emits_result_directly(monkeypatch):
    # list_capabilities returns a ready-to-display menu; the loop must emit it as
    # the answer WITHOUT a second LLM turn (small local models drop it otherwise).
    async def fake_dispatch(name, args, context):
        return "CAPABILITY MENU\n- explore\n- audit"

    monkeypatch.setattr(orchestrator, "dispatch", fake_dispatch)
    # Only ONE scripted turn: a second provider call would IndexError on the empty
    # script, so this also proves the short-circuit skips the redundant LLM turn.
    provider = StubProvider([
        LLMResult(text=None, tool_calls=[ToolCall("1", "list_capabilities", {})],
                  usage={"input_tokens": 100, "output_tokens": 5}),
    ])
    events = _collect([{"role": "user", "content": "what can you do?"}], provider)

    assert [e["type"] for e in events] == [
        "tool_status", "tool_call", "tool_result", "content", "usage", "done",
    ]
    assert next(e for e in events if e["type"] == "content")["data"] == "CAPABILITY MENU\n- explore\n- audit"
    assert next(e for e in events if e["type"] == "usage")["data"]["api_calls"] == 1


def test_provider_error_yields_error_event(monkeypatch):
    class Boom:
        name = "boom"

        async def run_turn(self, **kw):
            raise RuntimeError("down")

    events = _collect([{"role": "user", "content": "q"}], Boom())
    assert events[-1]["type"] == "error" and "AI service unavailable" in events[-1]["data"]
