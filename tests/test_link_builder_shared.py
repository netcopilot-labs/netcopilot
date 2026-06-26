"""F2-5r: link_builder shared-services discovery.

discover_shared_services finds VLANs / subnets / OSPF areas / BGP ASNs present
on 2+ devices, aggregating four independent discovery passes. Synthetic genie
fixtures (RFC 5737 IPs, private ASN 65000).
"""

import json

from netcopilot.model.link_builder import (
    _discover_shared_bgp_asns,
    _discover_shared_ospf_areas,
    _discover_shared_subnets,
    _discover_shared_vlans,
    discover_shared_services,
)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _device(tmp_path, name, host_octet):
    """A switch+router with VLAN 999, an IP in 192.0.2.0/24, OSPF area 0, AS 65000."""
    d = tmp_path / name
    _write(d, "genie_vlan.json", {"vlans": {
        "999": {"vlan_id": "999", "name": "LAB-VLAN", "state": "active"},
        "1": {"vlan_id": "1", "name": "default", "state": "active"},  # default → excluded
    }})
    _write(d, "genie_interface.json", {"GigabitEthernet0/0": {
        "vrf": "default",
        "ipv4": {f"192.0.2.{host_octet}/24": {"ip": f"192.0.2.{host_octet}",
                                              "prefix_length": "24"}},
    }})
    _write(d, "genie_ospf.json", {"vrf": {"default": {"address_family": {"ipv4": {
        "instance": {"1": {"areas": {"0.0.0.0": {}}}},
    }}}}})
    _write(d, "genie_bgp.json", {"instance": {"default": {"bgp_id": 65000}}})
    return d


# =========================================================================
# individual passes
# =========================================================================
def test_shared_vlans(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1), "sw-02": _device(tmp_path, "sw-02", 2)}
    vlans = _discover_shared_vlans(dirs)
    ids = {v["identifier"] for v in vlans}
    assert "999" in ids           # shared
    assert "1" not in ids         # default VLAN excluded
    v999 = next(v for v in vlans if v["identifier"] == "999")
    assert v999["name"] == "LAB-VLAN"
    assert v999["members"] == ["sw-01", "sw-02"]


def test_shared_vlan_single_device_not_shared(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1)}
    assert _discover_shared_vlans(dirs) == []   # only 1 device → not shared


def test_shared_subnets(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1), "sw-02": _device(tmp_path, "sw-02", 2)}
    facts = {"sw-01": {"os": "ios-xe"}, "sw-02": {"os": "ios-xe"}}
    subnets = _discover_shared_subnets(dirs, facts)
    assert len(subnets) == 1
    assert subnets[0]["identifier"] == "192.0.2.0/24"
    assert subnets[0]["vrf"] == "default"
    assert {m["hostname"] for m in subnets[0]["members"]} == {"sw-01", "sw-02"}


def test_shared_ospf_areas(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1), "sw-02": _device(tmp_path, "sw-02", 2)}
    areas = _discover_shared_ospf_areas(dirs)
    assert len(areas) == 1
    assert areas[0]["identifier"] == "0.0.0.0"
    assert areas[0]["area_type"] == "backbone"
    assert areas[0]["members"] == ["sw-01", "sw-02"]


def test_shared_bgp_asns(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1), "sw-02": _device(tmp_path, "sw-02", 2)}
    asns = _discover_shared_bgp_asns(dirs)
    assert len(asns) == 1
    assert asns[0]["identifier"] == "65000"
    assert asns[0]["members"] == ["sw-01", "sw-02"]


# =========================================================================
# aggregator
# =========================================================================
def test_discover_shared_services_all_types(tmp_path):
    dirs = {"sw-01": _device(tmp_path, "sw-01", 1), "sw-02": _device(tmp_path, "sw-02", 2)}
    facts = {"sw-01": {"os": "ios-xe"}, "sw-02": {"os": "ios-xe"}}
    services = discover_shared_services(dirs, facts)
    by_type = {s["service_type"] for s in services}
    assert by_type == {"vlan", "subnet", "ospf_area", "bgp_asn"}


def test_discover_shared_services_empty(tmp_path):
    empty = tmp_path / "sw-01"
    empty.mkdir()
    assert discover_shared_services({"sw-01": empty}, {"sw-01": {"os": "ios-xe"}}) == []
