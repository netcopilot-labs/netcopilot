"""S08-1 — "reads clean when not collected" honesty fixes.

Tools must not present a network as clean/complete when devices were never
collected. Uses scripted fake drivers (one result set popped per session.run).
"""

from __future__ import annotations

import asyncio

from netcopilot.mcp.tools import site_summary as site_tool
from netcopilot.mcp.tools import device as device_tool


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def single(self):
        return self._rows[0] if self._rows else None


class _Session:
    def __init__(self, script):
        self._script = script

    def run(self, *a, **k):
        return _Result(self._script.pop(0) if self._script else [])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Driver:
    def __init__(self, script):
        self._script = script

    def session(self):
        return _Session(self._script)


# ── site_summary: uncollected devices stay in the roster, flagged ────────────

def test_site_summary_marks_uncollected_devices(monkeypatch):
    devices = [
        {"name": "sw-01", "role": "core", "building": "HQ", "os_type": "iosxe",
         "cluster_size": 1, "collected": True},
        {"name": "sw-02", "role": "access", "building": "HQ", "os_type": "iosxe",
         "cluster_size": 1, "collected": False},  # uncollected MANAGED device
        # external BGP-peer placeholder (no role/building) — NOT site inventory,
        # must not appear in the roster despite the collected filter removal.
        {"name": "203.0.113.9", "role": None, "building": None, "os_type": None,
         "cluster_size": None, "collected": False},
    ]
    # queries in order: roster, uplinks, ospf areas, bgp
    script = [devices, [], [], []]
    monkeypatch.setattr(site_tool, "is_available", lambda: True)
    monkeypatch.setattr(site_tool, "get_driver", lambda: _Driver(script))
    monkeypatch.setattr(site_tool, "load_findings_enriched", lambda run_id: [])
    res = asyncio.run(site_tool.get_site_summary(context={"run_id": "r"}))
    assert "sw-02" in res.text
    assert "NOT COLLECTED" in res.text  # the uncollected managed device is flagged, not hidden
    assert "203.0.113.9" not in res.text  # external peer excluded from the roster


# ── device_detail: requested sections speak even without a data_dir ──────────

def test_device_detail_sections_speak_without_data_dir(monkeypatch):
    dev_row = {
        "name": "sw-01", "role": "core", "platform": "c9500", "os_type": "iosxe",
        "os_version": "17.9", "site": "s", "cluster_size": 1, "cluster_declared": 1,
        "cluster_members": None, "serial": "SYNTH1", "is_route_reflector": False,
        "rr_cluster_id": None, "collected": True,
    }
    # device lookup, then interfaces, vlans, bgp, ospf queries return empty
    script = [[dev_row]] + [[] for _ in range(8)]
    monkeypatch.setattr(device_tool, "is_available", lambda: True)
    monkeypatch.setattr(device_tool, "get_driver", lambda: _Driver(script))
    monkeypatch.setattr(device_tool, "load_findings_enriched", lambda run_id: [])
    # No data_dir in context → routing/security must say so, not vanish.
    res = asyncio.run(device_tool.get_device_detail(
        device="sw-01", sections=["routing", "security"], context={"run_id": "r"}))
    assert "Routing: not available (no run data directory)" in res.text
    assert "Security config: not available (no run data directory)" in res.text
