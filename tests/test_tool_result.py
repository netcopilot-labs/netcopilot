"""s03: the ToolResult envelope — the machine-readable tool contract.

Covers the dataclass defaults, dispatch-level statuses (error / unknown tool),
the transitional str-coercion, and truncation preserving envelope fields.
Pure-function tests — no Neo4j, no LLM.
"""

import asyncio

import pytest

from netcopilot.mcp import registry
from netcopilot.mcp.registry import MAX_RESULT_CHARS, ToolResult, VALID_RESULT_STATUSES


def _dispatch(name, args=None, handlers=None, monkeypatch=None):
    if handlers is not None:
        monkeypatch.setitem(registry._HANDLERS, name, handlers)
    return asyncio.run(registry.dispatch(name, args or {}, {"run_id": "x"}))


def test_defaults():
    r = ToolResult("ok", "some text")
    assert (r.verdict, r.highlight, r.verbatim) == (None, None, False)
    assert r.status in VALID_RESULT_STATUSES


def test_unknown_tool_is_error_status_with_same_sentence():
    out = asyncio.run(registry.dispatch("does_not_exist", {}, {}))
    assert out.status == "error"
    assert out.text.startswith("Unknown tool 'does_not_exist'")


def test_handler_exception_is_error_status(monkeypatch):
    async def boom(**kwargs):
        raise RuntimeError("kaput")

    monkeypatch.setitem(registry._HANDLERS, "query_topology", boom)
    out = asyncio.run(registry.dispatch("query_topology", {}, {}))
    assert out.status == "error"
    assert out.text == "Tool 'query_topology' failed: kaput"


def test_non_toolresult_return_fails_loud(monkeypatch):
    # The contract is enforced, not coerced: a bare-string handler is a
    # programming error and must raise, not degrade silently.
    async def legacy(**kwargs):
        return "plain text"

    monkeypatch.setitem(registry._HANDLERS, "query_topology", legacy)
    with pytest.raises(TypeError, match="must return ToolResult"):
        asyncio.run(registry.dispatch("query_topology", {}, {}))


def test_truncation_caps_text_and_preserves_fields(monkeypatch):
    async def huge(**kwargs):
        return ToolResult("ok", "x" * (MAX_RESULT_CHARS + 100),
                          verdict={"k": 1}, verbatim=True)

    monkeypatch.setitem(registry._HANDLERS, "query_topology", huge)
    out = asyncio.run(registry.dispatch("query_topology", {}, {}))
    assert out.text.endswith(f"[Result truncated at {MAX_RESULT_CHARS} chars.]")
    assert out.verdict == {"k": 1} and out.verbatim is True
