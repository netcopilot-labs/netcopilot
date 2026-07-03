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
from fastmcp.tools.tool import Tool as FastMCPTool, ToolResult as MCPToolResult

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
    """A FastMCP tool backed by the registry: schema verbatim, calls ``dispatch``."""

    async def run(self, arguments: dict[str, Any]) -> MCPToolResult:
        # `context` is reserved for the server-built run context — a client
        # arg by that name would collide with dispatch's keyword.
        args = {k: v for k, v in arguments.items() if k != "context"}
        envelope = await dispatch(self.name, args, build_context(site=args.get("site")))
        return MCPToolResult(content=envelope.text)


def _register_tools() -> None:
    for schema in TOOL_SCHEMAS:
        mcp.add_tool(
            RegistryTool(
                name=schema["name"],
                description=schema["description"],
                parameters=schema["parameters"],
            )
        )


_register_tools()


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
