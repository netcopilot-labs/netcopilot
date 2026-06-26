"""R1 Phase 1.3 — get_device_bgp is Neo4j-only (facts-fallback removed).

The dashboard BGP endpoint served from two divergent code paths (Neo4j primary +
a facts-fallback whose values drifted). The fallback is gone; this locks the
single Neo4j path's contract + the clean degradation when the graph is absent.
"""
from __future__ import annotations

from netcopilot.dashboard.backend.routes import routing


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, *args, **kwargs):
        return list(self._records)


class _FakeDriver:
    def __init__(self, records):
        self._records = records

    def session(self):
        return _FakeSession(self._records)


def _ibgp_rr_edge() -> dict:
    """One iBGP bilateral edge where this device (core-sw-01) is the reflector."""
    return {
        "peer_name": "bdr-rtr-01", "local_as": 65000, "remote_as": 65000,
        "state": "established", "session_type": "ibgp", "vrf": "default",
        "bgp_type": None, "address_families": ["ipv4 unicast"], "bilateral": True,
        "rid_a": "10.0.0.1", "rid_b": "10.0.0.2", "ka_a": 60, "ka_b": 60,
        "ht_a": 180, "ht_b": 180, "ud_a": "1d", "ud_b": "1d",
        "ms_a": 100, "ms_b": 100, "mr_a": 100, "mr_b": 100,
        "pr_a": 5, "pr_b": 5, "desc_a": "", "desc_b": "",
        "rpi_a": "", "rpi_b": "", "rpo_a": "", "rpo_b": "",
        "bfd_a": False, "bfd_b": False, "gr_a": False, "gr_b": False,
        "pw_a": False, "pw_b": False, "sc_a": False, "sc_b": False,
        "nhs_a": True, "nhs_b": False, "sr_a": True, "sr_b": False,
        "ns_a": [], "ns_b": [], "prefix_count": 5,
        "rr_client": True, "rr_reflector": "core-sw-01",
        "d_is_rr": True, "d_cluster_id": "1.1.1.1", "d_is_start": True,
    }


def test_get_device_bgp_neo4j_happy_path(monkeypatch):
    monkeypatch.setattr(routing, "is_available", lambda: True)
    monkeypatch.setattr(routing, "get_driver", lambda: _FakeDriver([_ibgp_rr_edge()]))

    out = routing.get_device_bgp("core-sw-01", run_id="r1")

    assert out["hostname"] == "core-sw-01"
    procs = out["processes"]
    assert len(procs) == 1
    assert procs[0]["is_route_reflector"] is True
    assert procs[0]["cluster_id"] == "1.1.1.1"
    nbrs = procs[0]["neighbors"]
    assert len(nbrs) == 1
    assert nbrs[0]["session_type"] == "ibgp"
    # device is the reflector -> the peer is its RR-client
    assert nbrs[0]["route_reflector_client"] is True
    assert nbrs[0]["route_reflector"] is False


def test_get_device_bgp_next_hop_self_from_relationship(monkeypatch):
    """R1 Phase 2/B2: next_hop_self / soft_reconfiguration come from the stored
    ROUTING_ADJACENCY properties (this device is side A), not hardcoded False."""
    monkeypatch.setattr(routing, "is_available", lambda: True)
    monkeypatch.setattr(routing, "get_driver", lambda: _FakeDriver([_ibgp_rr_edge()]))

    out = routing.get_device_bgp("core-sw-01", run_id="r1")

    nbr = out["processes"][0]["neighbors"][0]
    # core-sw-01 is startNode (d_is_start=True, bilateral) -> reads the _a side.
    assert nbr["next_hop_self"] is True
    assert nbr["soft_reconfiguration"] is True


def test_get_device_bgp_no_edges_returns_404(monkeypatch):
    monkeypatch.setattr(routing, "is_available", lambda: True)
    monkeypatch.setattr(routing, "get_driver", lambda: _FakeDriver([]))

    resp = routing.get_device_bgp("nobody", run_id="r1")

    assert resp.status_code == 404


def test_get_device_bgp_neo4j_unavailable_returns_503(monkeypatch):
    # No fallback to facts: BGP requires the graph database.
    monkeypatch.setattr(routing, "is_available", lambda: False)

    resp = routing.get_device_bgp("core-sw-01", run_id="r1")

    assert resp.status_code == 503
