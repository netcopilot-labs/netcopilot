"""NetCopilot MCP server — exposes the network-context tools over MCP (FastMCP).

The network IS the MCP server: any MCP-compatible client (Claude Desktop, another
agent, ...) can discover and call these tools. Read-only — never changes devices.

The surface is generated from the registry (``TOOL_SCHEMAS``), so the external
tool list is always identical to the internal one — names, descriptions, and
parameter schemas have a single source of truth, and every call routes through
``dispatch()`` (same contract enforcement, error envelopes, and truncation as
the internal orchestrator path).

    python -m netcopilot.mcp.server
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
# Public import path — works on fastmcp 3.x AND the 4.0 line (verified on
# 3.2.4 and 4.0.0b1, 2026-07-30); the private fastmcp.tools.tool module was
# removed in 4.0.
from fastmcp.tools import Tool as FastMCPTool, ToolResult as MCPToolResult

from netcopilot.context import build_context

from .registry import TOOL_SCHEMAS, dispatch

log = logging.getLogger(__name__)

mcp = FastMCP(
    "NetCopilot Network Intelligence",
    instructions=(
        "Network context tools. Query topology, findings, paths, and analysis for a "
        "collected network. Read-only — never changes devices."
    ),
)


class RegistryTool(FastMCPTool):
    """A FastMCP tool backed by the registry: schema verbatim, calls ``dispatch``.

    Wire shape (ADR-0005): text content is ``envelope.text`` verbatim (what an
    LLM client reads — identical to the internal model-facing text);
    ``structuredContent`` carries the machine-readable ``status`` (+ ``verdict``
    when the tool computed one); ``status="error"`` maps to MCP-native
    ``isError`` via ``ToolError``. ``not_found``/``no_data``/``ambiguous`` are
    valid answers, not errors. ``highlight``/``verbatim`` are intra-app
    presentation hints and do not travel.
    """

    async def run(self, arguments: dict[str, Any]) -> MCPToolResult:
        # `context` is reserved for the server-built run context — a client
        # arg by that name would collide with dispatch's keyword.
        args = {k: v for k, v in arguments.items() if k != "context"}
        envelope = await dispatch(self.name, args, build_context(site=args.get("site")))
        if envelope.status == "error":
            raise ToolError(envelope.text)
        structured: dict[str, Any] = {"status": envelope.status}
        if envelope.verdict is not None:
            structured["verdict"] = envelope.verdict
        return MCPToolResult(content=envelope.text, structured_content=structured)


#: Hang guard for one full agent conversation server-side, kept under common
#: 180 s client budgets. Not a latency promise: a normal ask takes 10-60 s
#: (LLM turns + Neo4j).
ASK_TIMEOUT_S = 170

_ASK_SCHEMA = {
    "name": "ask_netcopilot",
    "description": (
        "Ask the NetCopilot network expert a question in plain language and "
        "get a grounded answer. Runs NetCopilot's FULL internal agent "
        "server-side (deterministic routing plus its complete network-context "
        "toolset) against collected network data: topology, device detail, "
        "findings, paths, redundancy, firewall policy, drift, reports. "
        "Read-only, never changes devices. Answers cite only collected data; "
        "if the network has no data for something, the answer says so. "
        "Typical latency 10-60 seconds (a full agent conversation runs per "
        "call). The structured result lists which internal tools were used."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "The question, in natural language (any language).",
            },
            "site": {
                "type": "string",
                "description": "Optional site identifier. Omit to use the latest loaded run.",
            },
        },
        "required": ["question"],
    },
}


class AskNetCopilotTool(FastMCPTool):
    """The agent as a tool (backlog 7.7, ADR-0027; precedent: Sentry's use_sentry).

    Deliberately MCP-only: it does NOT enter ``TOOL_SCHEMAS``. (1) The
    internal agent must never be offered a tool that recursively invokes
    itself; (2) the eval's 33/33 coverage invariant and the discriminability
    gate stay untouched; (3) the s04 registry-generates-surface property
    holds for the 33, with this one exception living where the exception is.

    Wire shape mirrors RegistryTool: content = the final grounded answer,
    verbatim; ``structuredContent`` = ``{status: "ok", tools_used: [...]}``
    so the client can see which internal tools the agent chose. Loop errors
    (provider down, turn limit) and timeouts map to MCP-native ``isError``.
    """

    async def run(self, arguments: dict[str, Any]) -> MCPToolResult:
        # Imports at call time: the server must boot (and list tools) with no
        # LLM configured; a provider problem surfaces on call, honestly.
        import asyncio

        from netcopilot.llm import get_provider
        from netcopilot.orchestrator import run_tool_loop

        question = (arguments.get("question") or "").strip()
        if not question:
            raise ToolError("question is required")

        try:
            provider = get_provider()
        except Exception as exc:
            raise ToolError(f"No LLM provider configured: {exc}")

        context = build_context(site=arguments.get("site"))
        history = [{"role": "user", "content": question}]
        tools_used: list[str] = []
        parts: list[str] = []

        async def _drain() -> None:
            async for event in run_tool_loop(history, context, provider=provider):
                if event["type"] == "tool_call":
                    tools_used.append(event["data"]["name"])
                elif event["type"] == "content":
                    parts.append(event["data"])
                elif event["type"] == "error":
                    raise ToolError(event["data"])

        try:
            await asyncio.wait_for(_drain(), ASK_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise ToolError(
                f"ask_netcopilot timed out after {ASK_TIMEOUT_S}s "
                f"(tools called so far: {tools_used or 'none'})"
            )

        answer = "".join(parts).strip()
        if not answer:
            raise ToolError("the agent produced no answer (empty response)")
        return MCPToolResult(
            content=answer,
            structured_content={"status": "ok", "tools_used": tools_used},
        )


def _ask_tool() -> AskNetCopilotTool:
    return AskNetCopilotTool(
        name=_ASK_SCHEMA["name"],
        description=_ASK_SCHEMA["description"],
        parameters=_ASK_SCHEMA["parameters"],
    )


def register_tools(
    server: FastMCP = mcp,
    schemas: list[dict] = TOOL_SCHEMAS,
    surface: str | None = None,
) -> None:
    """Register the chosen surface — generated, not enumerated.

    Two PURE surfaces, never mixed (s24, ADR-0027): ``full`` (default) is the
    registry exactly as always, byte-identical, zero breaking; ``ask`` is the
    single meta-tool (~100 schema tokens instead of ~5,500, and the internal
    routing/eval quality travels with it). An unknown value fails LOUD — no
    silent fallback (Article V).
    """
    surface = surface or os.environ.get("MCP_SURFACE", "full")
    if surface == "ask":
        server.add_tool(_ask_tool())
        return
    if surface != "full":
        raise ValueError(
            f"MCP_SURFACE={surface!r} is not a surface (expected 'full' or 'ask')"
        )
    for schema in schemas:
        server.add_tool(
            RegistryTool(
                name=schema["name"],
                description=schema["description"],
                parameters=schema["parameters"],
            )
        )


register_tools()


def main() -> None:
    # Default to stdio (Claude Desktop etc.); bind HTTP in the container so any
    # networked MCP client can reach it. Toggle via MCP_TRANSPORT/MCP_PORT.
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "http":
        mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("MCP_PORT", "3002")))
    else:
        mcp.run()


if __name__ == "__main__":
    main()
