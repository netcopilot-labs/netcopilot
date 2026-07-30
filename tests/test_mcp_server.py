"""s04: the external MCP surface — registry-driven, envelope on the wire.

In-memory FastMCP client only (no network, no Neo4j): surface identity vs
TOOL_SCHEMAS, dispatch routing, and the ADR-0005 wire shape (text verbatim +
structuredContent{status, verdict?} + error→isError).
"""

import asyncio

import pytest
from fastmcp import Client, FastMCP

import netcopilot.mcp.server as srv
from netcopilot import context
from netcopilot.mcp.registry import TOOL_SCHEMAS
from netcopilot.mcp.result import ToolResult


def _run(coro):
    return asyncio.run(coro)


# ── Surface identity ──────────────────────────────────────────────────────────

def test_surface_lists_every_registry_tool():
    async def check():
        async with Client(srv.mcp) as c:
            tools = await c.list_tools()
        assert {t.name for t in tools} == {s["name"] for s in TOOL_SCHEMAS}
        assert len(tools) == len(TOOL_SCHEMAS)

    _run(check())


def test_surface_schemas_identical_to_registry():
    async def check():
        async with Client(srv.mcp) as c:
            tools = {t.name: t for t in await c.list_tools()}
        for schema in TOOL_SCHEMAS:
            tool = tools[schema["name"]]
            assert tool.description == schema["description"]
            assert tool.inputSchema == schema["parameters"]

    _run(check())


def test_surface_is_generated_not_enumerated():
    # A new registry schema appears on a freshly built server with zero
    # server-code changes.
    extra = {
        "name": "synthetic_probe",
        "description": "test-only schema",
        "parameters": {"type": "object", "properties": {}, "required": []},
    }
    fresh = FastMCP("probe")
    srv.register_tools(server=fresh, schemas=[*TOOL_SCHEMAS, extra])

    async def check():
        async with Client(fresh) as c:
            names = {t.name for t in await c.list_tools()}
        assert "synthetic_probe" in names
        assert len(names) == len(TOOL_SCHEMAS) + 1

    _run(check())


# ── Wire shape (ADR-0005) ─────────────────────────────────────────────────────

def _fake_dispatch(envelope, seen=None):
    async def fake(name, args, ctx):
        if seen is not None:
            seen.append((name, args, ctx))
        return envelope

    return fake


def test_wire_ok_with_verdict(monkeypatch):
    verdict = {"risk_level": "high", "score": 8}
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(ToolResult("ok", "impact text", verdict=verdict)))

    async def check():
        async with Client(srv.mcp) as c:
            res = await c.call_tool("blast_radius", {"device": "d1"})
        assert res.is_error is False
        assert res.content[0].text == "impact text"  # byte-identical, no JSON wrapping
        assert res.structured_content == {"status": "ok", "verdict": verdict}

    _run(check())


def test_wire_no_data_is_a_valid_answer_not_an_error(monkeypatch):
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(ToolResult("no_data", "No routing data.")))

    async def check():
        async with Client(srv.mcp) as c:
            res = await c.call_tool("trace_path", {"source_device": "a", "destination": "b"})
        assert res.is_error is False
        assert res.structured_content == {"status": "no_data"}  # no verdict key when unset

    _run(check())


def test_wire_error_maps_to_iserror_with_envelope_text(monkeypatch):
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(ToolResult("error", "Tool 'query_topology' failed: kaput")))

    async def check():
        async with Client(srv.mcp) as c:
            res = await c.call_tool("query_topology", {}, raise_on_error=False)
        assert res.is_error is True
        assert "Tool 'query_topology' failed: kaput" in res.content[0].text

    _run(check())


def test_wire_highlight_and_verbatim_do_not_travel(monkeypatch):
    envelope = ToolResult("ok", "hops", highlight={"devices": ["a"]}, verbatim=True)
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(envelope))

    async def check():
        async with Client(srv.mcp) as c:
            res = await c.call_tool("trace_path", {"source_device": "a", "destination": "b"})
        assert res.structured_content == {"status": "ok"}  # intra-app fields stay home

    _run(check())


# ── Routing: context building + reserved-key strip ────────────────────────────

def test_call_routes_through_dispatch_with_site_context(monkeypatch):
    seen = []
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(ToolResult("ok", "x"), seen))
    monkeypatch.setattr(context, "is_available", lambda: False)

    async def check():
        async with Client(srv.mcp) as c:
            await c.call_tool("query_topology", {"site": "hq"})

    _run(check())
    name, args, ctx = seen[0]
    assert name == "query_topology"
    assert args["site"] == "hq"
    assert ctx["site"] == "hq"          # site arg steers run resolution
    assert "data_dir" in ctx            # s04-1: every context carries it


def test_reserved_context_arg_is_stripped(monkeypatch):
    seen = []
    monkeypatch.setattr(srv, "dispatch", _fake_dispatch(ToolResult("ok", "x"), seen))
    monkeypatch.setattr(context, "is_available", lambda: False)

    async def check():
        async with Client(srv.mcp) as c:
            await c.call_tool("blast_radius", {"device": "d1", "context": {"run_id": "evil"}})

    _run(check())
    _, args, ctx = seen[0]
    assert "context" not in args
    assert ctx["run_id"] != "evil"      # server-built context wins


# ── Real dispatch path (no mocks): degraded-but-honest without Neo4j ──────────

def test_real_dispatch_neo4j_down_is_an_honest_iserror(monkeypatch):
    # Infrastructure failure is status="error" (s03) → MCP-native isError with
    # the same honest sentence, not a fake-success blob.
    monkeypatch.setattr(context, "is_available", lambda: False)
    import netcopilot.mcp.tools.topology as topology_mod

    monkeypatch.setattr(topology_mod, "is_available", lambda: False)

    async def check():
        async with Client(srv.mcp) as c:
            res = await c.call_tool("query_topology", {}, raise_on_error=False)
        assert res.is_error is True
        assert "Neo4j is unavailable. Cannot query topology." in res.content[0].text

    _run(check())


# ── s24: ask_netcopilot + the two pure surfaces (ADR-0027) ────────────────────

def _fake_loop(events):
    async def fake(history, context, provider=None, **kw):
        for ev in events:
            yield ev

    return fake


def _patch_ask_deps(monkeypatch, events):
    import netcopilot.llm as llm
    import netcopilot.orchestrator as orch

    monkeypatch.setattr(llm, "get_provider", lambda *a, **k: object())
    monkeypatch.setattr(orch, "run_tool_loop", _fake_loop(events))
    monkeypatch.setattr(srv, "build_context",
                        lambda site=None: {"run_id": "r1", "site": site or "demo"})


def _ask_server():
    fresh = FastMCP("ask-surface")
    srv.register_tools(server=fresh, surface="ask")
    return fresh


def test_ask_surface_is_exactly_one_tool():
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            tools = await c.list_tools()
        assert [t.name for t in tools] == ["ask_netcopilot"]

    _run(check())


def test_default_surface_has_no_ask_tool():
    # Two PURE surfaces, never mixed: full stays byte-identical to the
    # registry (the equality tests above), and ask_netcopilot is NOT there.
    async def check():
        async with Client(srv.mcp) as c:
            names = {t.name for t in await c.list_tools()}
        assert "ask_netcopilot" not in names

    _run(check())


def test_ask_tool_is_mcp_only_never_in_registry():
    # The recursion guard: the internal agent must never be offered a tool
    # that invokes itself.
    assert "ask_netcopilot" not in {s["name"] for s in TOOL_SCHEMAS}


def test_unknown_surface_fails_loud():
    with pytest.raises(ValueError, match="MCP_SURFACE"):
        srv.register_tools(server=FastMCP("bad"), surface="minimal")


def test_ask_happy_path_returns_answer_and_tools_used(monkeypatch):
    _patch_ask_deps(monkeypatch, [
        {"type": "tool_call", "data": {"name": "blast_radius"}},
        {"type": "tool_result", "data": {"name": "blast_radius", "status": "ok"}},
        {"type": "content", "data": "core-sw-01 impacts "},
        {"type": "content", "data": "6 devices."},
    ])
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            res = await c.call_tool("ask_netcopilot", {"question": "blast radius of core-sw-01?"})
        assert res.is_error is False
        assert res.content[0].text == "core-sw-01 impacts 6 devices."
        assert res.structured_content == {"status": "ok", "tools_used": ["blast_radius"]}

    _run(check())


def test_ask_empty_question_rejected_before_any_llm(monkeypatch):
    import netcopilot.llm as llm

    def boom(*a, **k):
        raise AssertionError("provider must not be touched")

    monkeypatch.setattr(llm, "get_provider", boom)
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            res = await c.call_tool("ask_netcopilot", {"question": "   "},
                                    raise_on_error=False)
        assert res.is_error is True
        assert "question is required" in res.content[0].text

    _run(check())


def test_ask_loop_error_maps_to_iserror(monkeypatch):
    _patch_ask_deps(monkeypatch, [
        {"type": "error", "data": "AI service unavailable: connection refused"},
    ])
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            res = await c.call_tool("ask_netcopilot", {"question": "hi"},
                                    raise_on_error=False)
        assert res.is_error is True
        assert "AI service unavailable" in res.content[0].text

    _run(check())


def test_ask_timeout_maps_to_iserror(monkeypatch):
    import netcopilot.llm as llm
    import netcopilot.orchestrator as orch

    async def hang(history, context, provider=None, **kw):
        import asyncio as aio
        await aio.sleep(30)
        yield {"type": "content", "data": "never"}

    monkeypatch.setattr(llm, "get_provider", lambda *a, **k: object())
    monkeypatch.setattr(orch, "run_tool_loop", hang)
    monkeypatch.setattr(srv, "build_context", lambda site=None: {"run_id": "r1"})
    monkeypatch.setattr(srv, "ASK_TIMEOUT_S", 0.05)
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            res = await c.call_tool("ask_netcopilot", {"question": "hi"},
                                    raise_on_error=False)
        assert res.is_error is True
        assert "timed out" in res.content[0].text

    _run(check())


def test_ask_empty_answer_is_an_error_not_a_silent_pass(monkeypatch):
    _patch_ask_deps(monkeypatch, [
        {"type": "tool_call", "data": {"name": "get_findings"}},
    ])
    fresh = _ask_server()

    async def check():
        async with Client(fresh) as c:
            res = await c.call_tool("ask_netcopilot", {"question": "findings?"},
                                    raise_on_error=False)
        assert res.is_error is True
        assert "no answer" in res.content[0].text

    _run(check())
