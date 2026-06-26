"""F1-4: blast_radius registration, graceful no-Neo4j path, and output formatting."""

import asyncio

from netcopilot.mcp import registry
from netcopilot.mcp.tools import analysis


def test_blast_radius_registered():
    names = {t["name"] for t in registry.TOOL_SCHEMAS}
    assert "blast_radius" in names
    assert "blast_radius" in registry._HANDLERS


def test_blast_radius_graceful_without_neo4j(monkeypatch):
    monkeypatch.setattr(analysis, "is_available", lambda: False)
    out = asyncio.run(analysis.blast_radius(device="x", context={"run_id": "r"}))
    assert "unavailable" in out.lower()


def test_analyze_full_failure_formats():
    out = analysis._analyze_full_failure(
        "core-rtr-01",
        [{"neighbor": "dist-sw-01", "role": "distribution_switch", "link_type": "PHYSICAL_CABLE"}],
        [],
    )
    assert "Blast radius — core-rtr-01" in out
    assert "dist-sw-01" in out
    assert "1 directly connected" in out
