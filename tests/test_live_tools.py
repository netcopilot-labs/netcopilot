"""Live tool tests against a real Neo4j — the second test tier.

Gated by NETCOPILOT_LIVE_TESTS=1 so they never run by accident (and never touch a
Neo4j you didn't dedicate to testing). CI sets the flag + a Neo4j service container;
locally they skip unless you opt in.
"""

import asyncio
import logging
import os
import time
from pathlib import Path

import pytest

from netcopilot.graph import client
from netcopilot.graph.loader import load_seed
from netcopilot.mcp import registry

SEED = str(Path(__file__).resolve().parent.parent / "fixtures" / "seed.json")
CTX = {"run_id": "demo-0001", "site": "demo"}


@pytest.fixture(scope="module", autouse=True)
def _seeded():
    if os.environ.get("NETCOPILOT_LIVE_TESTS") != "1":
        pytest.skip("set NETCOPILOT_LIVE_TESTS=1 (+ NEO4J_* to a dedicated test instance)")
    logging.getLogger("netcopilot.graph.client").setLevel(logging.ERROR)
    for _ in range(60):
        client.reset()
        if client.is_available():
            break
        time.sleep(2)
    else:
        pytest.skip("Neo4j not reachable")
    load_seed(SEED)
    yield
    client.close()


def _dispatch(name: str, args: dict) -> str:
    return asyncio.run(registry.dispatch(name, args, CTX))


def test_query_topology_live():
    out = _dispatch("query_topology", {})
    assert "Managed devices: 5" in out
    assert "core-rtr-01" in out


def test_get_findings_live():
    assert "total: 2" in _dispatch("get_findings", {})


def test_get_findings_device_filter_live():
    out = _dispatch("get_findings", {"device": "access-sw-02"})
    assert "total: 1" in out and "access-sw-02" in out


def test_blast_radius_live():
    out = _dispatch("blast_radius", {"device": "core-rtr-01"})
    assert "Affected devices (2)" in out
    assert "dist-sw-01" in out


def test_unknown_device_live():
    out = _dispatch("blast_radius", {"device": "nope-99"})
    assert "not found" in out
