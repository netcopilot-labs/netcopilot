"""R1 Phase 2 — VRF-awareness in the OSPF read-path MCP tools.

O4  — get_ospf_detail groups area membership/adjacencies by VRF instead of
      silently merging the same area number across VRFs.
O-lbl — get_device_detail labels OSPF adjacency rows with their VRF (non-default).

Both tools query Neo4j directly, so the driver is faked with a query-substring
dispatcher (the area branch and device-detail run more than one distinct query).
"""
from __future__ import annotations

import asyncio

from netcopilot.mcp.tools import device as device_tool
from netcopilot.mcp.tools import ospf as ospf_tool


class _FakeResult(list):
    """List that also answers .single() like a neo4j Result."""

    def single(self):
        return self[0] if self else None


class _DispatchSession:
    def __init__(self, routes):
        self._routes = routes  # list of (substring, records)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        for substr, recs in self._routes:
            if substr in query:
                return _FakeResult(recs)
        return _FakeResult([])


class _DispatchDriver:
    def __init__(self, routes):
        self._routes = routes

    def session(self):
        return _DispatchSession(self._routes)


# ── O4: get_ospf_detail area grouping ────────────────────────────────────────

def test_ospf_area_grouped_by_vrf_not_merged(monkeypatch):
    """Area 0 in RED and BLUE must render as two VRF-scoped groups, not one
    merged 4-device list."""
    members = [
        {"device": "core-sw-01", "role": "core", "vrf": "RED", "process_id": 1},
        {"device": "acc-sw-03", "role": "access", "vrf": "RED", "process_id": 1},
        {"device": "core-sw-01", "role": "core", "vrf": "BLUE", "process_id": 2},
        {"device": "acc-sw-03", "role": "access", "vrf": "BLUE", "process_id": 2},
    ]
    adjs = [
        {"src": "core-sw-01", "dst": "acc-sw-03", "state": "full",
         "intf_a": "Gi0/1", "intf_b": "Gi0/2", "vrf": "RED"},
        {"src": "core-sw-01", "dst": "acc-sw-03", "state": "full",
         "intf_a": "Gi0/3", "intf_b": "Gi0/4", "vrf": "BLUE"},
    ]
    driver = _DispatchDriver([
        ("MEMBER_OF", members),
        ("r.protocol = 'ospf'", adjs),
    ])
    monkeypatch.setattr(ospf_tool, "is_available", lambda: True)
    monkeypatch.setattr(ospf_tool, "get_driver", lambda: driver)

    out = asyncio.run(ospf_tool.get_ospf_detail(
        area="0", context={"run_id": "r1", "data_dir": ""}))

    assert "VRF RED:" in out
    assert "VRF BLUE:" in out
    # Each VRF group has exactly its own 2 devices — never the merged 4.
    assert out.count("Devices in area 0 (2)") == 2
    assert "Devices in area 0 (4)" not in out


def test_ospf_area_single_vrf_no_group_header(monkeypatch):
    """A single-VRF area shows no per-VRF header (no noise on flat networks)."""
    members = [
        {"device": "r1", "role": "core", "vrf": "default", "process_id": 1},
        {"device": "r2", "role": "core", "vrf": "default", "process_id": 1},
    ]
    driver = _DispatchDriver([
        ("MEMBER_OF", members),
        ("r.protocol = 'ospf'", []),
    ])
    monkeypatch.setattr(ospf_tool, "is_available", lambda: True)
    monkeypatch.setattr(ospf_tool, "get_driver", lambda: driver)

    out = asyncio.run(ospf_tool.get_ospf_detail(
        area="0", context={"run_id": "r1", "data_dir": ""}))

    assert "Devices in area 0 (2)" in out
    assert "VRF default:" not in out
    assert "VRF " not in out  # no grouping header at all


# ── O-lbl: get_device_detail OSPF rows carry the VRF label ────────────────────

def _device_record(name="acc-sw-03"):
    return {
        "name": name, "role": "access", "platform": "C9300",
        "os_type": "iosxe", "os_version": "17.9", "site": "demo",
        "cluster_size": None, "cluster_declared": None, "cluster_members": None,
        "serial": None, "is_route_reflector": None, "rr_cluster_id": None,
        "collected": True,
    }


def test_device_detail_ospf_row_shows_nondefault_vrf(monkeypatch):
    ospf_adjs = [
        {"peer": "core-sw-01", "state": "full", "area": "0", "vrf": "RED"},
        {"peer": "edge-fw-01", "state": "full", "area": "0", "vrf": "default"},
    ]
    driver = _DispatchDriver([
        ("RETURN d.name AS name, d.role AS role, d.platform", [_device_record()]),
        ("r.protocol = 'ospf'", ospf_adjs),
    ])
    monkeypatch.setattr(device_tool, "is_available", lambda: True)
    monkeypatch.setattr(device_tool, "get_driver", lambda: driver)

    out = asyncio.run(device_tool.get_device_detail(
        device="acc-sw-03", sections=["ospf"],
        context={"run_id": "r1", "data_dir": None}))

    # Non-default VRF labelled on its row.
    assert "VRF:RED" in out
    core_line = next(line for line in out.splitlines() if "core-sw-01" in line)
    assert "VRF:RED" in core_line
    # default VRF stays unlabelled (mirrors interface-row convention).
    fw_line = next(line for line in out.splitlines() if "edge-fw-01" in line)
    assert "VRF:" not in fw_line
