"""F1-4: registry schema + dispatch, and the tool's graceful no-Neo4j path (no Neo4j needed)."""

import asyncio

from netcopilot.mcp import registry
from netcopilot.mcp.tools import topology


def test_schema_normalized_shape():
    by_name = {t["name"]: t for t in registry.TOOL_SCHEMAS}
    assert "query_topology" in by_name
    qt = by_name["query_topology"]
    assert set(qt) == {"name", "description", "parameters"}
    assert qt["parameters"]["type"] == "object"


def test_dispatch_unknown_tool():
    out = asyncio.run(registry.dispatch("does_not_exist", {}, {"run_id": ""}))
    assert "Unknown tool" in out


def test_query_topology_graceful_without_neo4j(monkeypatch):
    monkeypatch.setattr(topology, "is_available", lambda: False)
    out = asyncio.run(topology.query_topology(context={"run_id": "x"}))
    assert "unavailable" in out.lower()
