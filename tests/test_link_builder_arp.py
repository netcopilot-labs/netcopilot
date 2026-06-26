"""F2-5e: link_builder subnet index + ARP discovery.

build_subnet_index groups interface IPs by subnet (Cisco genie_interface.json
+ FortiGate fortigate_system_interface.json); discover_arp_subnet_links
correlates genie_arp.json entries against that index to find L3 adjacencies —
the primary path for CDP/LLDP-less devices (FortiGate). Synthetic RFC 5737 IPs.
"""

import json

import pytest

from netcopilot.model.link_builder import (
    _build_ip_to_device_index,
    _parse_fortigate_ip,
    build_subnet_index,
    deduplicate_links,
    discover_arp_subnet_links,
)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _cisco_intf(name, ip, prefix):
    return {name: {"ipv4": {f"{ip}/{prefix}": {"ip": ip, "prefix_length": str(prefix)}}}}


def _arp(intf, *ips):
    return {"interfaces": {intf: {"ipv4": {"neighbors": {
        ip: {"ip": ip, "mac": "1234.5678.9abc"} for ip in ips
    }}}}}


def _iface_rec(host, name, admin="up", oper="up"):
    return {
        "interface_id": f"{host}:{name}", "device_id": host, "name": name,
        "admin_status": admin, "oper_status": oper,
    }


# =========================================================================
# _parse_fortigate_ip
# =========================================================================
@pytest.mark.parametrize("field,expected", [
    ("192.0.2.1 255.255.255.0", ("192.0.2.1", "24")),
    ("198.51.100.1 255.255.255.252", ("198.51.100.1", "30")),
    ("0.0.0.0 0.0.0.0", None),
    ("", None),
    ("192.0.2.1", None),            # missing mask
])
def test_parse_fortigate_ip(field, expected):
    assert _parse_fortigate_ip(field) == expected


# =========================================================================
# build_subnet_index
# =========================================================================
def test_subnet_index_cisco_and_fortigate(tmp_path):
    core = tmp_path / "core-rtr-01"
    edge = tmp_path / "edge-fw-01"
    _write(core, "genie_interface.json", _cisco_intf("Vlan99", "192.0.2.1", 24))
    _write(edge, "fortigate_system_interface.json",
           {"results": [{"name": "port1", "ip": "192.0.2.254 255.255.255.0"}]})

    facts_dirs = {"core-rtr-01": core, "edge-fw-01": edge}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "edge-fw-01": {"os": "fortios"}}
    idx = build_subnet_index(facts_dirs, facts_by_hostname)

    assert "192.0.2.0/24" in idx
    members = idx["192.0.2.0/24"]
    assert ("core-rtr-01", "Vlan99", "192.0.2.1") in members
    assert ("edge-fw-01", "port1", "192.0.2.254") in members


def test_subnet_index_skips_loopback_and_dhcp(tmp_path):
    core = tmp_path / "core-rtr-01"
    doc = {}
    doc.update(_cisco_intf("Loopback0", "203.0.113.1", 32))     # /32 skipped
    doc.update({"Gi0/1": {"ipv4": {"dhcp": {"ip": "dhcp_negotiated", "prefix_length": "24"}}}})
    doc.update(_cisco_intf("Vlan10", "192.0.2.1", 24))          # kept
    _write(core, "genie_interface.json", doc)
    idx = build_subnet_index({"core-rtr-01": core}, {"core-rtr-01": {"os": "ios-xe"}})
    assert "192.0.2.0/24" in idx
    assert "203.0.113.1/32" not in idx
    assert all("dhcp_negotiated" not in ip for members in idx.values() for _, _, ip in members)


def test_ip_to_device_index(tmp_path):
    idx = {"192.0.2.0/24": [("core-rtr-01", "Vlan99", "192.0.2.1"),
                            ("edge-fw-01", "port1", "192.0.2.254")]}
    rev = _build_ip_to_device_index(idx)
    assert rev["192.0.2.1"] == ("core-rtr-01", "Vlan99")
    assert rev["192.0.2.254"] == ("edge-fw-01", "port1")


# =========================================================================
# discover_arp_subnet_links
# =========================================================================
def _arp_scenario(tmp_path, mutual: bool):
    """core-rtr-01 (Cisco) shares Vlan99 subnet with edge-fw-01 (FortiGate).
    core's ARP sees the firewall's IP. If mutual, a second Cisco peer reciprocates."""
    core = tmp_path / "core-rtr-01"
    edge = tmp_path / "edge-fw-01"
    _write(core, "genie_interface.json", _cisco_intf("Vlan99", "192.0.2.1", 24))
    _write(core, "genie_arp.json", _arp("Vlan99", "192.0.2.254"))
    _write(edge, "fortigate_system_interface.json",
           {"results": [{"name": "port1", "ip": "192.0.2.254 255.255.255.0"}]})

    facts_dirs = {"core-rtr-01": core, "edge-fw-01": edge}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "edge-fw-01": {"os": "fortios"}}

    if mutual:
        dist = tmp_path / "dist-sw-01"
        _write(dist, "genie_interface.json", _cisco_intf("Vlan99", "192.0.2.2", 24))
        _write(dist, "genie_arp.json", _arp("Vlan99", "192.0.2.1"))
        # core also sees dist's IP
        _write(core, "genie_arp.json", _arp("Vlan99", "192.0.2.254", "192.0.2.2"))
        facts_dirs["dist-sw-01"] = dist
        facts_by_hostname["dist-sw-01"] = {"os": "ios-xe"}

    return facts_dirs, facts_by_hostname


def test_arp_oneway_to_fortigate(tmp_path):
    facts_dirs, facts_by_hostname = _arp_scenario(tmp_path, mutual=False)
    idx = build_subnet_index(facts_dirs, facts_by_hostname)
    cands = discover_arp_subnet_links(facts_dirs, facts_by_hostname,
                                      set(facts_dirs), idx)
    fw_links = [c for c in cands if "edge-fw-01" in (c.local_device, c.remote_device)]
    assert len(fw_links) == 1
    c = fw_links[0]
    assert c.discovery_method == "arp_subnet"
    assert c.confidence == "medium"
    assert len(c.evidence) == 1                    # one-way (firewall has no ARP)


def test_arp_mutual(tmp_path):
    facts_dirs, facts_by_hostname = _arp_scenario(tmp_path, mutual=True)
    idx = build_subnet_index(facts_dirs, facts_by_hostname)
    cands = discover_arp_subnet_links(facts_dirs, facts_by_hostname,
                                      set(facts_dirs), idx)
    # the core↔dist pair sees each other → mutual (2 evidence strings)
    pair = [c for c in cands
            if {c.local_device, c.remote_device} == {"core-rtr-01", "dist-sw-01"}]
    assert len(pair) == 1
    assert len(pair[0].evidence) == 2


def test_arp_dedup_to_final_link(tmp_path):
    facts_dirs, facts_by_hostname = _arp_scenario(tmp_path, mutual=False)
    idx = build_subnet_index(facts_dirs, facts_by_hostname)
    cands = discover_arp_subnet_links(facts_dirs, facts_by_hostname,
                                      set(facts_dirs), idx)
    interfaces = [_iface_rec("core-rtr-01", "Vlan99")]
    links = deduplicate_links(cands, interfaces)
    fw = [l for l in links if "edge-fw-01" in (l["local_device_id"], l["remote_device_id"])]
    assert len(fw) == 1
    assert fw[0]["discovery_protocol"] == "ARP"
    assert fw[0]["discovery_priority"] == 7
    assert fw[0]["direction"] == "unidirectional"


def test_arp_no_data(tmp_path):
    core = tmp_path / "core-rtr-01"
    core.mkdir()
    assert discover_arp_subnet_links({"core-rtr-01": core}, {"core-rtr-01": {"os": "ios-xe"}},
                                     {"core-rtr-01"}, {}) == []
