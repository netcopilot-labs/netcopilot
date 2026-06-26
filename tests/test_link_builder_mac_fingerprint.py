"""MAC-fingerprint physical-cable discovery (protocol-free).

discover_mac_fingerprint_links proves physical cabling without CDP/LLDP by
cross-referencing ARP (IP->MAC) against a global index of every interface's
burned-in hardware MAC. Phase 1 = L3 routed ports; Phase 2 = L2 switchports via
FDB. Synthetic RFC 5737 / documentation MACs.
"""

import json

from netcopilot.model.link_builder import (
    LinkCandidate,
    _build_hw_mac_to_device_index,
    classify_link_type,
    deduplicate_links,
    discover_mac_fingerprint_links,
)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _cisco_intf(macs):
    # macs: {intf_name: mac_dot}
    return {n: {"phys_address": m, "mac_address": m} for n, m in macs.items()}


def _cisco_arp(entries):
    # entries: list of (intf, ip, mac_dot)
    out = {"interfaces": {}}
    for intf, ip, mac in entries:
        out["interfaces"].setdefault(intf, {"ipv4": {"neighbors": {}}})
        out["interfaces"][intf]["ipv4"]["neighbors"][ip] = {
            "ip": ip, "link_layer_address": mac, "origin": "dynamic",
        }
    return out


def _fg_monitor(ports):
    # ports: {port_name: mac_colon}
    return {"results": {p: {"name": p, "id": p, "mac": m} for p, m in ports.items()}}


def _fg_arp(entries):
    # entries: list of (interface, ip, mac_colon)
    return {"results": [{"interface": i, "ip": ip, "mac": m} for i, ip, m in entries]}


def _fdb(vlan, mac_to_port):
    # mac_to_port: {mac_dot: port}
    macs = {
        m: {"interfaces": {p: {"interface": p, "entry_type": "dynamic"}}}
        for m, p in mac_to_port.items()
    }
    return {"mac_table": {"vlans": {str(vlan): {"mac_addresses": macs}}}}


def _iface(host, name, admin="up", oper="up"):
    return {
        "interface_id": f"{host}:{name}", "device_id": host, "name": name,
        "admin_status": admin, "oper_status": oper,
    }


# MACs (A = router-a Gi0/0/0/0, B = router-b Gi0/0/0/0)
MAC_A = "aac1.abea.0001"
MAC_B = "aac1.abeb.0002"


# 1 -------------------------------------------------------------------------
def test_hw_mac_index_cisco_and_fortigate(tmp_path):
    """Cisco dot-format + FortiGate colon-format for the same underlying MAC
    normalize to one key; both (host, intf) tuples are kept."""
    _write(tmp_path / "sw", "genie_interface.json",
           _cisco_intf({"GigabitEthernet1/0/4": "0c00.816a.2a76"}))
    _write(tmp_path / "fw", "fortigate_monitor_interface.json",
           _fg_monitor({"port2": "0c:00:81:6a:2a:76"}))
    idx = _build_hw_mac_to_device_index({"sw": tmp_path / "sw", "fw": tmp_path / "fw"})
    assert "0c00816a2a76" in idx
    assert idx["0c00816a2a76"] == {("sw", "GigabitEthernet1/0/4"), ("fw", "port2")}


# 2 -------------------------------------------------------------------------
def test_l3_bilateral_routed(tmp_path):
    """Two routers ARP each other's hardware MAC on routed ports -> one
    mac_fingerprint_bilateral / very_high candidate with both physical ports."""
    da, db = tmp_path / "router-a", tmp_path / "router-b"
    _write(da, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0/0/0": MAC_A}))
    _write(db, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0/0/0": MAC_B}))
    _write(da, "genie_arp.json", _cisco_arp([("GigabitEthernet0/0/0/0", "198.51.100.2", MAC_B)]))
    _write(db, "genie_arp.json", _cisco_arp([("GigabitEthernet0/0/0/0", "198.51.100.1", MAC_A)]))
    fd = {"router-a": da, "router-b": db}
    cands = discover_mac_fingerprint_links(fd, {}, {"router-a", "router-b"}, {})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "mac_fingerprint_bilateral"
    assert c.confidence == "very_high"
    assert {c.local_interface, c.remote_interface} == {"GigabitEthernet0/0/0/0"}
    assert c.peer_collected is True


# 3 -------------------------------------------------------------------------
def test_l3_unilateral_no_return_arp(tmp_path):
    """B's hardware MAC is known (collected) but B has no return ARP -> a single
    mac_fingerprint_unilateral / high candidate; remote port from the index."""
    da, db = tmp_path / "router-a", tmp_path / "router-b"
    _write(da, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0/0/0": MAC_A}))
    _write(db, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0/0/0": MAC_B}))
    _write(da, "genie_arp.json", _cisco_arp([("GigabitEthernet0/0/0/0", "198.51.100.2", MAC_B)]))
    # router-b has NO genie_arp.json
    fd = {"router-a": da, "router-b": db}
    cands = discover_mac_fingerprint_links(fd, {}, {"router-a", "router-b"}, {})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "mac_fingerprint_unilateral"
    assert c.confidence == "high"
    assert c.local_device == "router-a"
    assert c.remote_device == "router-b"
    assert c.remote_interface == "GigabitEthernet0/0/0/0"  # from index (unambiguous)


# 4 -------------------------------------------------------------------------
def test_fortigate_colon_mac_match(tmp_path):
    """A switch's ARP (dot MAC) matches a FortiGate port's colon MAC -> bilateral
    cable switch:Gi <-> fw:port2 (format unification)."""
    dsw, dfw = tmp_path / "sw", tmp_path / "fw"
    _write(dsw, "genie_interface.json", _cisco_intf({"GigabitEthernet1/0/4": "0c00.816a.2a76"}))
    _write(dsw, "genie_arp.json",
           _cisco_arp([("GigabitEthernet1/0/4", "198.51.100.14", "aac1.ab9f.f7a9")]))
    _write(dfw, "fortigate_monitor_interface.json", _fg_monitor({"port2": "aa:c1:ab:9f:f7:a9"}))
    _write(dfw, "fortigate_arp.json",
           _fg_arp([("port2", "198.51.100.13", "0c:00:81:6a:2a:76")]))
    fd = {"sw": dsw, "fw": dfw}
    cands = discover_mac_fingerprint_links(fd, {}, {"sw", "fw"}, {})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "mac_fingerprint_bilateral"
    pair = {(c.local_device, c.local_interface), (c.remote_device, c.remote_interface)}
    assert pair == {("sw", "GigabitEthernet1/0/4"), ("fw", "port2")}


# 5 -------------------------------------------------------------------------
def test_dedup_supersedes_arp_subnet():
    """A fingerprint candidate and an arp_subnet candidate on the same interface
    pair -> one link, fingerprint wins, both evidence strings preserved."""
    fp = LinkCandidate(
        "router-a", "GigabitEthernet0/0/0/0", "gigabitethernet0/0/0/0",
        "router-b", "GigabitEthernet0/0/0/0", "gigabitethernet0/0/0/0",
        "mac_fingerprint_bilateral", "very_high", evidence=["macfp:a↔b"],
    )
    arp = LinkCandidate(
        "router-a", "GigabitEthernet0/0/0/0", "gigabitethernet0/0/0/0",
        "router-b", "GigabitEthernet0/0/0/0", "gigabitethernet0/0/0/0",
        "arp_subnet", "medium", evidence=["arp:a→b"],
    )
    ifaces = [_iface("router-a", "GigabitEthernet0/0/0/0"),
              _iface("router-b", "GigabitEthernet0/0/0/0")]
    links = deduplicate_links([fp, arp], ifaces)
    assert len(links) == 1
    assert links[0]["discovery_method"] == "mac_fingerprint_bilateral"
    assert links[0]["confidence"] == "very_high"
    assert len(links[0]["evidence"]) == 2


# 6 -------------------------------------------------------------------------
def test_svi_local_uses_fdb(tmp_path):
    """When A's ARP interface is an SVI, the physical ports are recovered from the
    FDB on both ends -> bilateral physical cable on the physical ports."""
    da, db = tmp_path / "sw-a", tmp_path / "sw-b"
    mac_a_port = "0c00.aaaa.1111"   # sw-a Gi1/0/1 hardware MAC
    mac_b_port = "0c00.bbbb.2222"   # sw-b Gi1/0/1 hardware MAC
    _write(da, "genie_interface.json", _cisco_intf({"GigabitEthernet1/0/1": mac_a_port}))
    _write(db, "genie_interface.json", _cisco_intf({"GigabitEthernet1/0/1": mac_b_port}))
    # A's ARP learns B's IP on its SVI Vlan10; the MAC is sw-b's port MAC
    _write(da, "genie_arp.json", _cisco_arp([("Vlan10", "198.51.100.2", mac_b_port)]))
    _write(db, "genie_arp.json", _cisco_arp([("Vlan10", "198.51.100.1", mac_a_port)]))
    # FDBs: each switch learns the peer's port MAC on its physical port
    _write(da, "genie_fdb.json", _fdb(10, {mac_b_port: "GigabitEthernet1/0/1"}))
    _write(db, "genie_fdb.json", _fdb(10, {mac_a_port: "GigabitEthernet1/0/1"}))
    fd = {"sw-a": da, "sw-b": db}
    cands = discover_mac_fingerprint_links(fd, {}, {"sw-a", "sw-b"}, {})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "mac_fingerprint_bilateral"
    pair = {(c.local_device, c.local_interface), (c.remote_device, c.remote_interface)}
    assert pair == {("sw-a", "GigabitEthernet1/0/1"), ("sw-b", "GigabitEthernet1/0/1")}


# 7 -------------------------------------------------------------------------
def test_l2_no_fdb_no_phantom(tmp_path):
    """SVI ARP but no FDB to resolve the local physical port -> no phantom cable."""
    da, db = tmp_path / "sw-a", tmp_path / "sw-b"
    mac_b_port = "0c00.bbbb.2222"
    _write(da, "genie_interface.json", _cisco_intf({"GigabitEthernet1/0/1": "0c00.aaaa.1111"}))
    _write(db, "genie_interface.json", _cisco_intf({"GigabitEthernet1/0/1": mac_b_port}))
    _write(da, "genie_arp.json", _cisco_arp([("Vlan10", "198.51.100.2", mac_b_port)]))
    # no genie_fdb.json anywhere
    fd = {"sw-a": da, "sw-b": db}
    cands = discover_mac_fingerprint_links(fd, {}, {"sw-a", "sw-b"}, {})
    assert cands == []


# 8 -------------------------------------------------------------------------
def test_multiaccess_subnet_skipped(tmp_path):
    """Three devices on one shared segment, each ARPing the other two on a single
    interface -> every interface is multi-access -> zero fingerprint cables."""
    macs = {"a": "0c00.0000.000a", "b": "0c00.0000.000b", "c": "0c00.0000.000c"}
    ips = {"a": "198.51.100.1", "b": "198.51.100.2", "c": "198.51.100.3"}
    fd = {}
    for me in ("a", "b", "c"):
        d = tmp_path / me
        _write(d, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0": macs[me]}))
        others = [(o, ips[o], macs[o]) for o in ("a", "b", "c") if o != me]
        _write(d, "genie_arp.json", _cisco_arp([("GigabitEthernet0/0", ip, m) for _o, ip, m in others]))
        fd[me] = d
    cands = discover_mac_fingerprint_links(fd, {}, set(fd), {})
    assert cands == []


# 9 -------------------------------------------------------------------------
def test_intra_device_dup_mac_resolves_correct_port(tmp_path):
    """Remote device reuses one MAC across two ports; the bilateral cross-check
    picks the port from the REMOTE's own ARP, not an index guess."""
    da, db = tmp_path / "router-a", tmp_path / "core"
    dup = "0c00.816a.2a64"  # core reuses this on Gi1/0/1 AND Gi1/0/5
    _write(da, "genie_interface.json", _cisco_intf({"GigabitEthernet0/0/0/1": MAC_A}))
    _write(db, "genie_interface.json",
           _cisco_intf({"GigabitEthernet1/0/1": dup, "GigabitEthernet1/0/5": dup}))
    _write(da, "genie_arp.json", _cisco_arp([("GigabitEthernet0/0/0/1", "198.51.100.2", dup)]))
    # core's ARP toward router-a is on Gi1/0/1 (the REAL cable)
    _write(db, "genie_arp.json", _cisco_arp([("GigabitEthernet1/0/1", "198.51.100.1", MAC_A)]))
    fd = {"router-a": da, "core": db}
    cands = discover_mac_fingerprint_links(fd, {}, set(fd), {})
    assert len(cands) == 1
    c = cands[0]
    pair = {(c.local_device, c.local_interface), (c.remote_device, c.remote_interface)}
    assert pair == {("router-a", "GigabitEthernet0/0/0/1"), ("core", "GigabitEthernet1/0/1")}


# 10 ------------------------------------------------------------------------
def test_classify_fingerprint_physical_and_svi():
    """A routed fingerprint link classifies as physical; one with a virtual (SVI)
    endpoint stays l3_reachability (Priority 4 wins over the cable method)."""
    routed = {
        "local_device_id": "router-a", "remote_device_id": "core",
        "local_interface_id": "router-a:GigabitEthernet0/0/0/1",
        "remote_interface_id": "core:GigabitEthernet1/0/1",
        "discovery_method": "mac_fingerprint_bilateral", "confidence": "very_high",
    }
    assert classify_link_type(routed, {}, set(), set()) == "physical"

    svi = dict(routed, local_interface_id="router-a:Vlan99")
    assert classify_link_type(svi, {}, set(), set()) == "l3_reachability"
