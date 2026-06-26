"""F2-5d: link_builder LACP discovery (partner-MAC resolution via genie_lag.json).

Synthetic Genie LAG + interface fixtures. LACP resolves each bundle member's
partner_id (a MAC) to a hostname via a MAC→hostname table built from
genie_interface.json / genie_lag.json, then resolves the remote interface via
partner_port_num. A→B + B→A promote to lacp_bilateral.
"""

import json

from netcopilot.model.link_builder import (
    _normalize_mac,
    _strip_lacp_priority_prefix,
    deduplicate_links,
    discover_lacp_links,
)

MAC_A = "aaaa.0000.0001"
MAC_B = "bbbb.0000.0002"


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _lag(po_name, member, partner_id, port_num, partner_port_num,
         system_id_mac, prio=32768):
    return {"interfaces": {po_name: {
        "system_id_mac": system_id_mac,
        "members": {member: {
            "partner_id": partner_id,
            "port_num": port_num,
            "partner_port_num": partner_port_num,
            "lacp_port_priority": prio,
        }},
    }}}


def _intf(name, mac):
    return {name: {"phys_address": mac}}


def _iface_rec(host, name, admin="up", oper="up"):
    return {
        "interface_id": f"{host}:{name}",
        "device_id": host,
        "name": name,
        "admin_status": admin,
        "oper_status": oper,
    }


# =========================================================================
# pure helpers
# =========================================================================
def test_normalize_mac_formats():
    assert _normalize_mac("1234.5678.9abc") == "123456789abc"
    assert _normalize_mac("12:34:56:78:9a:bc") == "123456789abc"
    assert _normalize_mac("12-34-56-78-9A-BC") == "123456789abc"


def test_strip_lacp_priority_prefix():
    # IOS XR partner_id with 4-char priority prefix → strip to last 12 hex
    assert _strip_lacp_priority_prefix("8000.aabb.ccdd.eeff") == "aabbccddeeff"
    # already-12 stays put
    assert _strip_lacp_priority_prefix("aabb.ccdd.eeff") == "aabbccddeeff"


# =========================================================================
# discover_lacp_links
# =========================================================================
def test_lacp_bilateral(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    # core: Po1/Gi0/0 (port_num 10) partners with B's MAC, B's port 20
    _write(core, "genie_interface.json", _intf("GigabitEthernet0/0", MAC_A))
    _write(core, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet0/0", MAC_B, 10, 20, MAC_A))
    # dist: Po1/Gi1/0/3 (port_num 20) partners with A's MAC, A's port 10
    _write(dist, "genie_interface.json", _intf("GigabitEthernet1/0/3", MAC_B))
    _write(dist, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet1/0/3", MAC_A, 20, 10, MAC_B))

    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    cands = discover_lacp_links(facts_dirs, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "lacp_bilateral"
    assert c.confidence == "high"
    assert {c.local_device, c.remote_device} == {"core-rtr-01", "dist-sw-01"}
    assert len(c.evidence) == 2                  # merged A→B + B→A


def test_lacp_unilateral_peer_uncollected(tmp_path):
    core = tmp_path / "core-rtr-01"
    # peer MAC known (indexed from a peer interface file) but peer has no LAG back
    dist = tmp_path / "dist-sw-01"
    _write(core, "genie_interface.json", _intf("GigabitEthernet0/0", MAC_A))
    _write(core, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet0/0", MAC_B, 10, 20, MAC_A))
    _write(dist, "genie_interface.json", _intf("GigabitEthernet1/0/3", MAC_B))

    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    cands = discover_lacp_links(facts_dirs, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    assert cands[0].discovery_method == "lacp_unilateral"
    assert cands[0].confidence == "medium"       # Cisco default priority 32768
    assert cands[0].remote_device == "dist-sw-01"


def test_lacp_fortigate_fingerprint_high_confidence(tmp_path):
    """port_priority=255 (FortiGate LACP fingerprint) upgrades a unilateral link
    to high confidence."""
    core = tmp_path / "core-rtr-01"
    edge = tmp_path / "edge-fw-01"
    _write(core, "genie_interface.json", _intf("GigabitEthernet0/0", MAC_A))
    _write(core, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet0/0", MAC_B, 10, 20, MAC_A, prio=255))
    # firewall MAC indexed via its system interface file
    _write(edge, "fortigate_system_interface.json",
           {"results": [{"name": "port1", "macaddr": MAC_B}]})

    cands = discover_lacp_links({"core-rtr-01": core, "edge-fw-01": edge},
                                {"core-rtr-01", "edge-fw-01"})
    assert len(cands) == 1
    assert cands[0].discovery_method == "lacp_unilateral"
    assert cands[0].confidence == "high"         # fingerprint upgrade
    assert cands[0].remote_device == "edge-fw-01"


def test_lacp_no_data(tmp_path):
    core = tmp_path / "core-rtr-01"
    core.mkdir()
    assert discover_lacp_links({"core-rtr-01": core}, {"core-rtr-01"}) == []


def test_lacp_parsed_lag_fallback(tmp_path):
    """When genie_lag.json is absent, parsed_lag.json (show etherchannel) is used."""
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write(core, "genie_interface.json", _intf("GigabitEthernet0/0", MAC_A))
    _write(core, "parsed_lag.json",
           _lag("Port-channel1", "GigabitEthernet0/0", MAC_B, 10, 20, MAC_A))
    _write(dist, "genie_interface.json", _intf("GigabitEthernet1/0/3", MAC_B))

    cands = discover_lacp_links({"core-rtr-01": core, "dist-sw-01": dist},
                                {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    assert cands[0].remote_device == "dist-sw-01"


def test_lacp_dedup_to_final_link(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write(core, "genie_interface.json", _intf("GigabitEthernet0/0", MAC_A))
    _write(core, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet0/0", MAC_B, 10, 20, MAC_A))
    _write(dist, "genie_interface.json", _intf("GigabitEthernet1/0/3", MAC_B))
    _write(dist, "genie_lag.json",
           _lag("Port-channel1", "GigabitEthernet1/0/3", MAC_A, 20, 10, MAC_B))

    cands = discover_lacp_links({"core-rtr-01": core, "dist-sw-01": dist},
                                {"core-rtr-01", "dist-sw-01"})
    interfaces = [_iface_rec("core-rtr-01", "Gi0/0"), _iface_rec("dist-sw-01", "Gi1/0/3")]
    links = deduplicate_links(cands, interfaces)
    assert len(links) == 1
    assert links[0]["discovery_protocol"] == "LACP"
    assert links[0]["discovery_priority"] == 5
    assert links[0]["direction"] == "bidirectional"
