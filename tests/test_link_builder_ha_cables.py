"""F2-5i: link_builder FortiGate HA cable-to-member attribution.

attribute_fortigate_ha_cables mutates links in place, tagging each firewall
cable with ha_member ("active"/"passive"/None). Two strategies:
  - Standard HA: passive member's MAC from the 169.254.0.x ARP heartbeat,
    cross-referenced with switch LACP partner system-IDs (5-byte prefix match).
  - Virtual Cluster HA: fdb_firewall links attributed by the switch-side LACP
    partner MAC threshold (< 0x6000 = passive unit).
Synthetic fixtures (invented MACs / serials / VDOM names).
"""

import json

from netcopilot.model.link_builder import (
    _find_heartbeat_mac,
    attribute_fortigate_ha_cables,
)

PASSIVE_MAC = "12:34:56:78:aa:01"      # ARP heartbeat → passive member


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _fw_link(method, sw, sw_intf, fw, fw_intf):
    return {
        "local_device_id": sw, "local_interface_id": f"{sw}:{sw_intf}",
        "remote_device_id": fw, "remote_interface_id": f"{fw}:{fw_intf}",
        "discovery_method": method,
    }


# =========================================================================
# _find_heartbeat_mac
# =========================================================================
def test_find_heartbeat_mac():
    arp = {"results": [
        {"ip": "10.0.0.1", "mac": "00:11:22:33:44:55"},
        {"ip": "169.254.0.2", "mac": PASSIVE_MAC},
    ]}
    assert _find_heartbeat_mac(arp) == PASSIVE_MAC


def test_find_heartbeat_mac_none():
    assert _find_heartbeat_mac({"results": [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]}) is None
    assert _find_heartbeat_mac({"results": [{"ip": "169.254.0.2", "mac": "00:00:00:00:00:00"}]}) is None


# =========================================================================
# no HA → no-op
# =========================================================================
def test_no_ha_fortigate_is_noop(tmp_path):
    links = [_fw_link("lacp_unilateral", "dist-sw-01", "Gi1/0/1", "edge-fw-01", "port1")]
    devices = [{"hostname": "edge-fw-01", "os_family": "fortios", "cluster_declared_size": 1}]
    attribute_fortigate_ha_cables(links, {}, devices, {})
    assert "ha_member" not in links[0]   # standalone FortiGate → untouched


# =========================================================================
# standard HA
# =========================================================================
def test_standard_ha_active_passive(tmp_path):
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    _write(fw, "fortigate_system_ha.json", {"results": {"vcluster-status": "disable"}})
    _write(fw, "fortigate_arp.json", {"results": [
        {"ip": "169.254.0.2", "mac": PASSIVE_MAC},   # passive prefix 12345678aa
    ]})
    # Gi1/0/1 partner shares the passive prefix; Gi1/0/2 does not
    _write(sw, "genie_lag.json", {"interfaces": {"Port-channel1": {"members": {
        "GigabitEthernet1/0/1": {"partner_id": "1234.5678.aa05"},   # → passive
        "GigabitEthernet1/0/2": {"partner_id": "1234.5678.bb05"},   # → active
    }}}})

    facts_dirs = {"edge-fw-01": fw, "dist-sw-01": sw}
    devices = [{"hostname": "edge-fw-01", "os_family": "fortios", "cluster_declared_size": 2}]
    links = [
        _fw_link("lacp_unilateral", "dist-sw-01", "Gi1/0/1", "edge-fw-01", "port1"),
        _fw_link("lacp_unilateral", "dist-sw-01", "Gi1/0/2", "edge-fw-01", "port2"),
        _fw_link("cdp_bilateral", "dist-sw-01", "Gi1/0/3", "edge-fw-01", "port3"),  # non-cable
    ]
    attribute_fortigate_ha_cables(links, facts_dirs, devices, {})

    assert links[0]["ha_member"] == "passive"
    assert links[1]["ha_member"] == "active"
    assert links[2]["ha_member"] is None    # cdp not a cable-based method


# =========================================================================
# virtual cluster HA (fdb_firewall via partner-MAC threshold)
# =========================================================================
def test_vcluster_ha_fdb_threshold(tmp_path):
    fw = tmp_path / "edge-fw-01"
    sw = tmp_path / "dist-sw-01"
    # vcluster setup data must be present or the function returns early.
    # vd_a / vd_b are synthetic VDOM names (any two distinct names work).
    _write(fw, "fortigate_system_interface.json", {"results": [
        {"name": "port1", "vdom": "vd_a"}, {"name": "port2", "vdom": "vd_b"},
    ]})
    _write(fw, "fortigate_system_ha.json", {"results": {
        "vcluster-status": "enable",
        "vcluster": [
            {"vcluster-id": 1, "vdom": [{"name": "vd_a"}]},
            {"vcluster-id": 2, "vdom": [{"name": "vd_b"}]},
        ],
    }})
    _write(fw, "fortigate_ha_peer.json", {"results": [
        {"master": True, "vcluster_id": 1, "serial_no": "SYNTHFGT0001"},
        {"master": True, "vcluster_id": 2, "serial_no": "SYNTHFGT0002"},
    ]})
    # switch LACP partner MACs: one below 0x6000 (passive unit), one at/above (active)
    _write(sw, "genie_lag.json", {"interfaces": {
        "Port-channel1": {"members": {"GigabitEthernet1/0/1": {"partner_id": "1234.5678.5fff"}}},
        "Port-channel2": {"members": {"GigabitEthernet1/0/2": {"partner_id": "1234.5678.6001"}}},
    }})

    facts_dirs = {"edge-fw-01": fw, "dist-sw-01": sw}
    devices = [{
        "hostname": "edge-fw-01", "os_family": "fortios", "cluster_declared_size": 2,
        "cluster_members": [
            {"serial_number": "SYNTHFGT0001", "member_id": 0},
            {"serial_number": "SYNTHFGT0002", "member_id": 1},
        ],
    }]
    links = [
        _fw_link("fdb_firewall", "dist-sw-01", "Gi1/0/1", "edge-fw-01", "port1"),
        _fw_link("fdb_firewall", "dist-sw-01", "Gi1/0/2", "edge-fw-01", "port2"),
        _fw_link("lacp_unilateral", "dist-sw-01", "Gi1/0/3", "edge-fw-01", "port3"),
    ]
    attribute_fortigate_ha_cables(links, facts_dirs, devices, {})

    assert links[0]["ha_member"] == "passive"   # partner last-2 0x5fff < 0x6000
    assert links[1]["ha_member"] == "active"     # partner last-2 0x6001 >= 0x6000
    assert links[2]["ha_member"] is None         # non-fdb in vcluster mode → None
