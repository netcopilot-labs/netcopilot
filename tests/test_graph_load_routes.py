"""F2-6-b: route loaders + parsers (Genie / FortiGate / per-peer BGP / synthesis).

Pure parsers tested directly; _load_routes driven against the recording fake
driver (no Neo4j). Real Cypher is covered by the gated live test. RFC 5737 IPs.
"""

import json

from netcopilot.graph.loader import (
    _check_bgp_full_table,
    _dedupe_cross_source_static_routes,
    _load_routes,
    _netmask_to_cidr,
    _parse_per_peer_bgp,
    _parse_routes_fortigate,
    _parse_routes_fortigate_static,
    _parse_routes_genie,
    _synthesize_connected_routes_from_interfaces,
)
from test_graph_load_model import FakeDriver

SITE, RUN = "dc", "r1"


def test_dedupe_cross_source_static_routes():
    """R2-RT-1/2: a static route installed in the RIB (``source=dynamic``) AND
    present in the static-config file (``source=static``) collapses to the RIB
    copy; config-only statics and distinct-interface routes survive untouched."""
    rp = [
        # installed static (RIB) + its config copy → collapse, keep RIB (ad=1)
        {"device": "r1", "prefix": "192.0.2.0/24", "vrf": "default", "protocol": "static",
         "next_hop": "198.51.100.1", "interface": "", "ad": 1, "source": "dynamic"},
        {"device": "r1", "prefix": "192.0.2.0/24", "vrf": "default", "protocol": "static",
         "next_hop": "198.51.100.1", "interface": "", "ad": 0, "source": "static"},
        # config-only static (not installed — no RIB twin) → preserved
        {"device": "r1", "prefix": "203.0.113.0/24", "vrf": "default", "protocol": "static",
         "next_hop": "198.51.100.2", "interface": "", "ad": 0, "source": "static"},
        # same prefix, DIFFERENT interface (distinct floating defaults) → both kept
        {"device": "r1", "prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static",
         "next_hop": None, "interface": "wan1", "ad": 254, "source": "static"},
        {"device": "r1", "prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static",
         "next_hop": None, "interface": "wan2", "ad": 254, "source": "static"},
        # an OSPF route sharing prefix+next-hop must NOT be touched (protocol differs)
        {"device": "r1", "prefix": "192.0.2.0/24", "vrf": "default", "protocol": "ospf",
         "next_hop": "198.51.100.1", "interface": "", "ad": 110, "source": "dynamic"},
    ]
    out = _dedupe_cross_source_static_routes(rp)

    installed = [r for r in out if r["prefix"] == "192.0.2.0/24" and r["protocol"] == "static"]
    assert len(installed) == 1 and installed[0]["source"] == "dynamic" and installed[0]["ad"] == 1
    assert any(r["prefix"] == "203.0.113.0/24" for r in out)            # config-only kept
    assert sum(1 for r in out if r["prefix"] == "0.0.0.0/0") == 2       # distinct ifaces kept
    assert any(r["protocol"] == "ospf" for r in out)                   # OSPF untouched
    assert len(out) == 5                                                # 6 → 5 (one dupe dropped)


def test_dedupe_cross_source_noop_without_static_collision():
    """No config copy of an installed route ⇒ identity unchanged."""
    rp = [
        {"device": "r1", "prefix": "192.0.2.0/24", "vrf": "default", "protocol": "ospf",
         "next_hop": "198.51.100.1", "interface": "", "source": "dynamic"},
        {"device": "r1", "prefix": "203.0.113.0/24", "vrf": "default", "protocol": "static",
         "next_hop": "198.51.100.9", "interface": "", "source": "static"},
    ]
    assert _dedupe_cross_source_static_routes(rp) == rp


# --------------------------- pure parsers --------------------------------

def test_netmask_to_cidr():
    assert _netmask_to_cidr("192.0.2.0 255.255.255.0") == "192.0.2.0/24"
    assert _netmask_to_cidr("0.0.0.0 0.0.0.0") == "0.0.0.0/0"
    assert _netmask_to_cidr("garbage") is None


def test_parse_routes_genie_dynamic():
    data = {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
        "192.0.2.0/24": {
            "source_protocol": "ospf", "route_preference": 110, "metric": 20,
            "next_hop": {"next_hop_list": {"1": {
                "next_hop": "198.51.100.254", "outgoing_interface": "GigabitEthernet0/1", "active": True}}},
        },
        "203.0.113.0/24": {  # connected — outgoing_interface only, no next_hop_list
            "source_protocol": "connected", "route_preference": 0,
            "next_hop": {"outgoing_interface": {"GigabitEthernet0/2": {}}},
        },
    }}}}}}
    routes = _parse_routes_genie(data, "core-rtr-01", "dynamic", SITE, RUN)
    by_prefix = {r["prefix"]: r for r in routes}
    assert by_prefix["192.0.2.0/24"]["protocol"] == "ospf"
    assert by_prefix["192.0.2.0/24"]["next_hop"] == "198.51.100.254"
    assert by_prefix["203.0.113.0/24"]["interface"] == "GigabitEthernet0/2"
    assert all(r["device"] == "core-rtr-01" and r["source"] == "dynamic" for r in routes)


def test_parse_routes_genie_skips_summary_only():
    # route_source stats with no vrf → summary-only → no per-prefix routes
    assert _parse_routes_genie({"route_source": {"bgp": {"65001": {"routes": 500000}}}},
                               "edge-rtr-01", "dynamic", SITE, RUN) == []


def test_parse_routes_genie_static_protocol_fallback():
    data = {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
        "192.0.2.8/30": {"route_preference": 1,  # no source_protocol on static file
                         "next_hop": {"next_hop_list": {"1": {"next_hop": "192.0.2.9"}}}},
    }}}}}}
    routes = _parse_routes_genie(data, "core-rtr-01", "static", SITE, RUN)
    assert routes[0]["protocol"] == "static"  # fallback for the static file


def test_parse_routes_fortigate_connected_and_static():
    data = {"vdom": "root", "results": [
        {"type": "connect", "ip_mask": "192.0.2.0/24", "gateway": "0.0.0.0", "interface": "port1"},
        {"type": "static", "ip_mask": "0.0.0.0/0", "gateway": "198.51.100.1", "interface": "wan1"},
    ]}
    routes = _parse_routes_fortigate(data, "fw-01", SITE, RUN)
    by_prefix = {r["prefix"]: r for r in routes}
    assert by_prefix["192.0.2.0/24"]["protocol"] == "connected"  # "connect" normalised
    assert by_prefix["192.0.2.0/24"]["next_hop"] == ""           # connected → no next-hop
    assert by_prefix["0.0.0.0/0"]["next_hop"] == "198.51.100.1"


def test_parse_routes_fortigate_static():
    data = {"vdom": "root", "results": [
        {"status": "enable", "dst": "192.0.2.0 255.255.255.0", "gateway": "198.51.100.1", "device": "port1"},
        {"status": "disable", "dst": "203.0.113.0 255.255.255.0", "gateway": "198.51.100.2"},  # skipped
    ]}
    routes = _parse_routes_fortigate_static(data, "fw-01", SITE, RUN)
    assert len(routes) == 1
    assert routes[0]["prefix"] == "192.0.2.0/24" and routes[0]["protocol"] == "static"


def test_synthesize_connected_routes_from_interfaces():
    interfaces = [
        {"device_id": "core-rtr-01", "name": "Gi0/1", "ip_address": "192.0.2.1",
         "prefix_length": 24, "oper_status": "up"},
        {"device_id": "core-rtr-01", "name": "Gi0/2", "ip_address": "unassigned", "oper_status": "up"},  # skipped
        {"device_id": "core-rtr-01", "name": "Gi0/3", "ip_address": "203.0.113.1",
         "prefix_length": 30, "oper_status": "down"},  # skipped: not up
    ]
    synth = _synthesize_connected_routes_from_interfaces(interfaces, [], SITE, RUN)
    assert len(synth) == 1
    assert synth[0]["prefix"] == "192.0.2.0/24" and synth[0]["protocol"] == "connected"


def test_check_bgp_full_table(tmp_path):
    d = tmp_path / "edge-rtr-01"
    d.mkdir()
    (d / "genie_routing.json").write_text(json.dumps(
        {"route_source": {"bgp": {"65001": {"routes": 950000}}}}))  # > 100k threshold
    (d / "genie_bgp.json").write_text(json.dumps(
        {"instance": {"default": {"bgp_id": 65000, "vrf": {"default": {"neighbor": {
            "198.51.100.9": {"remote_as": 65001}}}}}}}))
    synth = _check_bgp_full_table(d, "edge-rtr-01", SITE, RUN)
    assert synth["prefix"] == "0.0.0.0/0"
    assert synth["next_hop"] == "198.51.100.9"
    assert synth["bgp_route_count"] == 950000


def test_per_peer_bgp_ebgp_ad(tmp_path):
    d = tmp_path / "edge-rtr-01"
    d.mkdir()
    (d / "genie_bgp.json").write_text(json.dumps(
        {"instance": {"default": {"vrf": {"default": {
            "address_family": {"ipv4 unicast": {"local_as": 65000}},
            "neighbor": {"198.51.100.9": {"remote_as": 65001}}}}}}}))  # eBGP
    (d / "genie_bgp_routes_198_51_100_9.json").write_text(json.dumps(
        {"routes": [{"prefix": "203.0.113.0/24", "next_hop": "198.51.100.9", "status": "*>"}]}))
    routes = _parse_per_peer_bgp(d, "edge-rtr-01", SITE, RUN)
    assert len(routes) == 1
    assert routes[0]["ebgp"] is True and routes[0]["ad"] == 20  # eBGP AD
    assert routes[0]["source"] == "per-peer"


def test_per_peer_bgp_ibgp_from_bgp_id(tmp_path):
    # R1-BGP-1: real genie puts the local AS at instance-level `bgp_id`, NOT in the
    # AF block. An iBGP peer (remote_as == bgp_id) must classify iBGP / AD 200; the
    # old code read af.local_as (absent on real data) → local_as=None → every peer
    # defaulted to eBGP / AD 20.
    d = tmp_path / "core-rtr-01"
    d.mkdir()
    (d / "genie_bgp.json").write_text(json.dumps(
        {"instance": {"default": {"bgp_id": 65000, "vrf": {"default": {
            "neighbor": {"10.0.0.2": {"remote_as": 65000}}}}}}}))  # iBGP, no AF local_as
    (d / "genie_bgp_routes_10_0_0_2.json").write_text(json.dumps(
        {"routes": [{"prefix": "203.0.113.0/24", "next_hop": "10.0.0.2", "status": "*>"}]}))
    routes = _parse_per_peer_bgp(d, "core-rtr-01", SITE, RUN)
    assert len(routes) == 1
    assert routes[0]["ebgp"] is False and routes[0]["ad"] == 200  # iBGP AD (was wrongly 20)


# --------------------------- _load_routes (fake driver) ------------------

def test_load_routes_reads_facts_and_creates_route_nodes(tmp_path):
    facts = tmp_path / "run" / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_routing.json").write_text(json.dumps(
        {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
            "192.0.2.0/24": {"source_protocol": "ospf", "route_preference": 110,
                             "next_hop": {"next_hop_list": {"1": {"next_hop": "198.51.100.254"}}}}}}}}}}))
    driver = FakeDriver()
    n = _load_routes(driver, tmp_path / "run", SITE, RUN, interfaces=[])
    assert n == 1
    route_params = next(p["routes"] for c, p in driver.calls if "[:HAS_ROUTE]" in c and "CREATE" in c)
    assert route_params[0]["prefix"] == "192.0.2.0/24"
    assert route_params[0]["protocol"] == "ospf"


def test_load_routes_no_facts_dir_returns_zero(tmp_path):
    assert _load_routes(FakeDriver(), tmp_path / "nope", SITE, RUN, interfaces=[]) == 0
