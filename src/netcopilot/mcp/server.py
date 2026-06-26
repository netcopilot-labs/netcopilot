"""NetCopilot MCP server — exposes the network-context tools over MCP (FastMCP).

The network IS the MCP server: any MCP-compatible client (Claude Desktop, another
agent, ...) can discover and call these tools. Read-only — never changes devices.

    python -m netcopilot.mcp.server
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

from netcopilot.context import build_context

log = logging.getLogger(__name__)

mcp = FastMCP(
    "NetCopilot Network Intelligence",
    instructions=(
        "Network context tools. Query topology, findings, and blast radius for a "
        "collected network. Read-only — never changes devices."
    ),
)


@mcp.tool()
async def query_topology(
    site: str | None = None,
    device_filter: str | None = None,
    include_links: bool = True,
    include_services: bool = False,
) -> str:
    """Get network topology: devices, physical links, routing adjacencies.
    Call this first for any question about network structure or device inventory."""
    from .tools.topology import query_topology as _impl

    return await _impl(
        site=site,
        device_filter=device_filter,
        include_links=include_links,
        include_services=include_services,
        context=build_context(site=site),
    )


@mcp.tool()
async def get_findings(
    device: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    acknowledged: bool | None = None,
    limit: int = 20,
) -> str:
    """Get deterministic rule-engine findings. Filter by device, severity, or category."""
    from .tools.findings import get_findings as _impl

    return await _impl(
        device=device,
        severity=severity,
        category=category,
        acknowledged=acknowledged,
        limit=limit,
        context=build_context(),
    )


@mcp.tool()
async def blast_radius(
    device: str,
    member: int | None = None,
    interface: str | None = None,
    max_hops: int = 3,
) -> str:
    """Analyse the impact of a device failure: directly affected devices and links lost."""
    from .tools.analysis import blast_radius as _impl

    return await _impl(
        device=device,
        member=member,
        interface=interface,
        max_hops=max_hops,
        context=build_context(),
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
