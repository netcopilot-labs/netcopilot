"""F2-5g: link_builder FDB-based firewall link discovery.

FortiGate firewalls have no CDP/LLDP and report zero MACs over REST, so
physical switch↔firewall cables are found by chaining:
  switch ARP (FW IP → FW MAC) → switch FDB (FW MAC on a Port-channel) →
  LACP fingerprint (port_priority=255) → FortiGate aggregate member expansion.

This is the most cross-referenced discovery path; the fixture aligns the FW
port MAC across the aggregate's monitor MAC, the switch ARP entry, the switch
FDB entry, and the LACP partner_id so a real link emerges. Synthetic values.

Coverage note: this exercises the single-unit happy path + guard rejections.
The HA-offset / passive-unit-prefix matching branches need multi-unit HA
captures and are exercised by the parity harness (F2-7), not unit fixtures.
"""

import json

from netcopilot.model.link_builder import discover_fdb_firewall_links

FW_MAC = "1234.5678.6001"   # FortiGate agg1 (port1) physical MAC; last-2-bytes 0x6001


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _fortigate(facts_dir, *, with_monitor=True):
    """edge-fw-01: one aggregate agg1=[port1,port2] in VDOM 'data', IP 192.0.2.254."""
    _write(facts_dir, "fortigate_system_interface.json", {"results": [
        {"name": "agg1", "type": "aggregate", "vdom": "data",
         "ip": "192.0.2.254 255.255.255.0",
         "member": [{"interface-name": "port1"}, {"interface-name": "port2"}]},
        {"name": "port1", "type": "physical", "vdom": "data"},
        {"name": "port2", "type": "physical", "vdom": "data"},
    ]})
    if with_monitor:
        # Hardware MACs: agg1's identity == port1's MAC (last-2-bytes 0x6001)
        _write(facts_dir, "fortigate_monitor_interface.json", {"results": {
            "port1": {"mac": "12:34:56:78:60:01"},
            "port2": {"mac": "12:34:56:78:60:02"},
        }})


def _switch(facts_dir, *, prio=255, arp=True, fw_mac=FW_MAC):
    """dist-sw-01: Port-channel1=[Gi1/0/1,Gi1/0/2] bundled to the FortiGate."""
    if arp:
        _write(facts_dir, "genie_arp.json", {"interfaces": {"Vlan99": {"ipv4": {"neighbors": {
            "192.0.2.254": {"ip": "192.0.2.254", "link_layer_address": fw_mac}
        }}}}})
    _write(facts_dir, "genie_fdb.json", {"mac_table": {"vlans": {"99": {"mac_addresses": {
        fw_mac: {"mac_address": fw_mac, "interfaces": {"Port-channel1": {"interface": "Port-channel1"}}}
    }}}}})
    _write(facts_dir, "genie_lag.json", {"interfaces": {"Port-channel1": {"members": {
        "GigabitEthernet1/0/1": {"partner_id": fw_mac, "lacp_port_priority": prio,
                                 "oper_key": 1, "port_num": 1},
        "GigabitEthernet1/0/2": {"partner_id": fw_mac, "lacp_port_priority": prio,
                                 "oper_key": 1, "port_num": 2},
    }}}})


def _facts(fw="edge-fw-01", sw="dist-sw-01"):
    return {sw: {"os": "ios-xe"}, fw: {"os": "fortios"}}


def test_fdb_firewall_member_links(tmp_path):
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    _fortigate(fw)
    _switch(sw)
    facts_dirs = {"edge-fw-01": fw, "dist-sw-01": sw}
    cands = discover_fdb_firewall_links(facts_dirs, _facts())

    assert len(cands) == 2
    pairs = {(c.local_interface, c.remote_interface) for c in cands}
    assert pairs == {("GigabitEthernet1/0/1", "port1"), ("GigabitEthernet1/0/2", "port2")}
    for c in cands:
        assert c.discovery_method == "fdb_firewall"
        assert c.confidence == "high"
        assert c.local_device == "dist-sw-01" and c.remote_device == "edge-fw-01"


def test_fdb_firewall_legacy_no_monitor(tmp_path):
    """Without monitor MACs the legacy sequential formula maps the MAC to the
    only aggregate."""
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    _fortigate(fw, with_monitor=False)
    _switch(sw)
    cands = discover_fdb_firewall_links({"edge-fw-01": fw, "dist-sw-01": sw}, _facts())
    assert len(cands) == 2
    assert {c.remote_interface for c in cands} == {"port1", "port2"}


def test_fdb_firewall_no_firewall(tmp_path):
    sw = tmp_path / "dist-sw-01"
    _switch(sw)
    assert discover_fdb_firewall_links({"dist-sw-01": sw}, {"dist-sw-01": {"os": "ios-xe"}}) == []


def test_fdb_firewall_no_arp_match(tmp_path):
    """Switch never saw the FW IP in ARP → no FW MAC → no links."""
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    _fortigate(fw)
    _switch(sw, arp=False)
    assert discover_fdb_firewall_links({"edge-fw-01": fw, "dist-sw-01": sw}, _facts()) == []


def test_fdb_firewall_cisco_priority_filtered(tmp_path):
    """A Port-channel whose LACP partner uses the Cisco default priority (32768)
    is an indirect path, not a direct firewall cable → filtered out."""
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    _fortigate(fw)
    _switch(sw, prio=32768)
    assert discover_fdb_firewall_links({"edge-fw-01": fw, "dist-sw-01": sw}, _facts()) == []
