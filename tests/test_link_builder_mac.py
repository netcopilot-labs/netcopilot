"""F2-5f: link_builder MAC-table (FDB) + subnet-only discovery.

discover_mac_subnet_links cross-references a switch's genie_fdb.json against a
MAC→device index (from genie_interface.json) + the subnet index → physical-port
links. discover_subnet_only_links is the L5 fallback: pairs sharing a small
subnet with no better evidence. Synthetic fixtures (RFC 5737 IPs, invented MACs).
"""

import json

from netcopilot.model.link_builder import (
    LinkCandidate,
    _build_mac_to_device_index,
    _make_pair_key,
    build_subnet_index,
    deduplicate_links,
    discover_mac_subnet_links,
    discover_subnet_only_links,
)

MAC_CORE = "1234.5678.9abc"


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _intf(name, ip=None, prefix=24, mac=None):
    rec = {}
    if ip:
        rec["ipv4"] = {f"{ip}/{prefix}": {"ip": ip, "prefix_length": str(prefix)}}
    if mac:
        rec["mac_address"] = mac
    return {name: rec}


def _fdb(vlan, mac, intf, entry_type="dynamic"):
    return {"mac_table": {"vlans": {str(vlan): {"vlan": vlan, "mac_addresses": {
        mac: {"mac_address": mac, "interfaces": {
            intf: {"interface": intf, "entry_type": entry_type}
        }}
    }}}}}


def _iface_rec(host, name):
    return {"interface_id": f"{host}:{name}", "device_id": host, "name": name,
            "admin_status": "up", "oper_status": "up"}


# =========================================================================
# _build_mac_to_device_index
# =========================================================================
def test_mac_index_prefers_shorter_interface(tmp_path):
    core = tmp_path / "core-rtr-01"
    doc = {}
    doc.update(_intf("GigabitEthernet0/2", mac=MAC_CORE))
    doc.update(_intf("GigabitEthernet0/2.1000", mac=MAC_CORE))   # sub-iface, same MAC
    _write(core, "genie_interface.json", doc)
    idx = _build_mac_to_device_index({"core-rtr-01": core})
    assert idx[MAC_CORE] == ("core-rtr-01", "GigabitEthernet0/2")  # physical parent wins


def test_mac_index_skips_bluetooth_and_app(tmp_path):
    core = tmp_path / "core-rtr-01"
    doc = {}
    doc.update(_intf("Bluetooth0/4", mac="aaaa.0000.0001"))
    doc.update(_intf("AppGigabitEthernet0/0/0", mac="aaaa.0000.0002"))
    doc.update(_intf("GigabitEthernet0/0", mac=MAC_CORE))
    _write(core, "genie_interface.json", doc)
    idx = _build_mac_to_device_index({"core-rtr-01": core})
    assert idx == {MAC_CORE: ("core-rtr-01", "GigabitEthernet0/0")}


# =========================================================================
# discover_mac_subnet_links
# =========================================================================
def _mac_scenario(tmp_path, entry_type="dynamic", fdb_intf="GigabitEthernet1/0/6"):
    """dist-sw-01 (switch) learns core-rtr-01's MAC on a physical port; both
    share 192.0.2.0/24."""
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write(core, "genie_interface.json",
           _intf("GigabitEthernet0/0", ip="192.0.2.1", mac=MAC_CORE))
    dist_doc = {}
    dist_doc.update(_intf("Vlan99", ip="192.0.2.2"))
    _write(dist, "genie_interface.json", dist_doc)
    _write(dist, "genie_fdb.json", _fdb(99, MAC_CORE, fdb_intf, entry_type))

    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "dist-sw-01": {"os": "ios-xe"}}
    idx = build_subnet_index(facts_dirs, facts_by_hostname)
    return facts_dirs, idx


def test_mac_subnet_physical_link(tmp_path):
    facts_dirs, idx = _mac_scenario(tmp_path)
    cands = discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx)
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "mac_subnet"
    assert c.confidence == "low"
    assert {c.local_device, c.remote_device} == {"core-rtr-01", "dist-sw-01"}


def test_mac_subnet_skips_static(tmp_path):
    facts_dirs, idx = _mac_scenario(tmp_path, entry_type="static")
    assert discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx) == []


def test_mac_subnet_skips_svi_and_portchannel(tmp_path):
    facts_dirs, idx = _mac_scenario(tmp_path, fdb_intf="Vlan99")
    assert discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx) == []
    facts_dirs, idx = _mac_scenario(tmp_path, fdb_intf="Port-channel1")
    assert discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx) == []


def test_mac_subnet_requires_shared_subnet(tmp_path):
    """If the FDB-learned owner shares no subnet with the switch → skip
    (likely a transitive MAC)."""
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    # different subnets → no overlap
    _write(core, "genie_interface.json",
           _intf("GigabitEthernet0/0", ip="192.0.2.1", mac=MAC_CORE))
    _write(dist, "genie_interface.json", _intf("Vlan99", ip="198.51.100.2"))
    _write(dist, "genie_fdb.json", _fdb(99, MAC_CORE, "GigabitEthernet1/0/6"))
    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    idx = build_subnet_index(facts_dirs,
                             {"core-rtr-01": {"os": "ios-xe"}, "dist-sw-01": {"os": "ios-xe"}})
    assert discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx) == []


def test_mac_subnet_dedup_to_final_link(tmp_path):
    facts_dirs, idx = _mac_scenario(tmp_path)
    cands = discover_mac_subnet_links(facts_dirs, set(facts_dirs), idx)
    interfaces = [_iface_rec("dist-sw-01", "Gi1/0/6"), _iface_rec("core-rtr-01", "Gi0/0")]
    links = deduplicate_links(cands, interfaces)
    assert len(links) == 1
    assert links[0]["discovery_protocol"] == "MAC"
    assert links[0]["discovery_priority"] == 9


# =========================================================================
# discover_subnet_only_links
# =========================================================================
def test_subnet_only_pair(tmp_path):
    idx = {"192.0.2.0/24": [("core-rtr-01", "Gi0/0", "192.0.2.1"),
                            ("dist-sw-01", "Vlan99", "192.0.2.2")]}
    cands = discover_subnet_only_links(idx, {"core-rtr-01", "dist-sw-01"}, set())
    assert len(cands) == 1
    assert cands[0].discovery_method == "subnet_only"
    assert cands[0].confidence == "very_low"


def test_subnet_only_skips_large_subnet():
    idx = {"192.0.0.0/16": [("core-rtr-01", "Gi0/0", "192.0.2.1"),
                            ("dist-sw-01", "Vlan99", "192.0.3.2")]}
    assert discover_subnet_only_links(idx, set(), set()) == []


def test_subnet_only_skips_crowded_subnet():
    # 4 unique hosts on one /24 → shared broadcast domain → skipped (limit 3)
    members = [(f"sw-{i}", "Vlan10", f"192.0.2.{i}") for i in range(1, 5)]
    idx = {"192.0.2.0/24": members}
    assert discover_subnet_only_links(idx, set(), set()) == []


def test_subnet_only_skips_existing_pair():
    idx = {"192.0.2.0/24": [("core-rtr-01", "Gi0/0", "192.0.2.1"),
                            ("dist-sw-01", "Gi0/1", "192.0.2.2")]}
    # pre-seed the canonical pair key as already discovered by a higher level
    a = LinkCandidate("core-rtr-01", "Gi0/0", "gigabitethernet0/0",
                      "dist-sw-01", "Gi0/1", "gigabitethernet0/1",
                      "cdp_bilateral", "very_high")
    existing = {_make_pair_key(a)}
    assert discover_subnet_only_links(idx, set(), existing) == []
