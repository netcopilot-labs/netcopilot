"""F2-5q: link_builder BGP adjacency extraction.

extract_bgp_adjacencies walks genie_bgp.json per device, resolves peer IPs to
hostnames (via interface IPs), dedups bilateral pairs, and classifies iBGP vs
eBGP. Synthetic ASNs + RFC 5737 IPs.
"""

import json

from netcopilot.parse.cisco_native.bgp_config import parse_bgp_process_config

from netcopilot.model.link_builder import (
    _build_ip_to_hostname_lookup,
    _clean_bgp_description,
    extract_bgp_adjacencies,
)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _intf_doc(loopback_ip):
    return {"Loopback0": {"ipv4": {f"{loopback_ip}/32": {"ip": loopback_ip}}}}


def _bgp_doc(bgp_id, peer_ip, remote_as, state="established"):
    return {"instance": {"default": {"bgp_id": bgp_id, "vrf": {"default": {
        "router_id": None,
        "neighbor": {peer_ip: {
            "remote_as": remote_as, "session_state": state,
            "address_family": {"ipv4 unicast": {}},
        }},
    }}}}}


# =========================================================================
# helpers
# =========================================================================
def test_clean_bgp_description():
    assert _clean_bgp_description("** UPSTREAM **") == "UPSTREAM"
    assert _clean_bgp_description("plain") == "plain"
    assert _clean_bgp_description(None) is None


def test_build_ip_to_hostname(tmp_path):
    core = tmp_path / "core-rtr-01"
    _write(core, "genie_interface.json", _intf_doc("203.0.113.1"))
    idx = _build_ip_to_hostname_lookup({"core-rtr-01": core}, {"core-rtr-01": {"os": "ios-xe"}})
    assert idx["203.0.113.1"] == "core-rtr-01"


# =========================================================================
# extract_bgp_adjacencies
# =========================================================================
def test_bgp_ibgp_bilateral(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-rtr-01"
    _write(core, "genie_interface.json", _intf_doc("203.0.113.1"))
    _write(core, "genie_bgp.json", _bgp_doc(65000, "203.0.113.2", 65000))
    _write(dist, "genie_interface.json", _intf_doc("203.0.113.2"))
    _write(dist, "genie_bgp.json", _bgp_doc(65000, "203.0.113.1", 65000))

    facts_dirs = {"core-rtr-01": core, "dist-rtr-01": dist}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "dist-rtr-01": {"os": "ios-xe"}}
    adjs = extract_bgp_adjacencies(facts_dirs, facts_by_hostname)

    assert len(adjs) == 1
    a = adjs[0]
    assert a["protocol"] == "bgp"
    assert {a["device_a"], a["device_b"]} == {"core-rtr-01", "dist-rtr-01"}
    assert a["state"] == "established"
    assert a["session_type"] == "ibgp"     # local_as == remote_as
    assert a["bilateral"] is True
    assert a["peer_collected"] is True


def test_bgp_ebgp_unresolved_peer(tmp_path):
    """eBGP to an uncollected ISP peer → unilateral, peer_label with AS."""
    core = tmp_path / "core-rtr-01"
    _write(core, "genie_interface.json", _intf_doc("203.0.113.1"))
    _write(core, "genie_bgp.json", _bgp_doc(65000, "198.51.100.99", 64500))
    # bgp_config.json is the canonical config fact (facts_builder writes it via
    # parse_bgp_process_config). link_builder reads it — not running_config — for
    # the neighbor description (R1 Phase 1.3 single-source).
    rc_text = (
        "router bgp 65000\n neighbor 198.51.100.99 remote-as 64500\n"
        " neighbor 198.51.100.99 description UPSTREAM-ISP\n!\n"
    )
    (core / "running_config.txt").write_text(rc_text)
    _write(core, "bgp_config.json", parse_bgp_process_config(rc_text))
    adjs = extract_bgp_adjacencies({"core-rtr-01": core}, {"core-rtr-01": {"os": "ios-xe"}})
    assert len(adjs) == 1
    a = adjs[0]
    assert a["session_type"] == "ebgp"
    assert a["bilateral"] is False
    assert a["peer_collected"] is False
    assert "198.51.100.99" in (a["device_a"], a["device_b"])
    assert a["peer_label"] == "AS 64500 (UPSTREAM-ISP)"


def test_bgp_no_data(tmp_path):
    empty = tmp_path / "core-rtr-01"
    empty.mkdir()
    assert extract_bgp_adjacencies({"core-rtr-01": empty}, {"core-rtr-01": {"os": "ios-xe"}}) == []
