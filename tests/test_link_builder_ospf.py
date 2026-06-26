"""F2-5p: link_builder OSPF adjacency + LSDB extraction.

extract_ospf_adjacencies walks genie_ospf.json per device, resolves neighbor
router-ids to hostnames, and dedups bilateral pairs; extract_ospf_lsdb pulls
LSA entries from the default-VRF database. Synthetic genie_ospf fixtures.
"""

import json

from netcopilot.model.link_builder import (
    _area_id_to_int,
    _best_area_type,
    _default_area_type,
    _discover_shared_ospf_areas,
    extract_ospf_adjacencies,
    extract_ospf_lsdb,
)


def _ospf_neighbor_doc(router_id, intf, neighbor_rid, neighbor_ip):
    """Genie OSPF Ops doc: one process/area/interface with one neighbor."""
    return {"vrf": {"default": {"address_family": {"ipv4": {"instance": {"1": {
        "router_id": router_id,
        "areas": {"0.0.0.0": {"interfaces": {intf: {
            "neighbors": {neighbor_rid: {"address": neighbor_ip, "state": "full"}},
        }}}},
    }}}}}}}


def _write(facts_dir, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / "genie_ospf.json").write_text(json.dumps(doc))


# =========================================================================
# helpers
# =========================================================================
def test_area_id_to_int():
    assert _area_id_to_int("0.0.0.0") == 0
    assert _area_id_to_int("0.0.0.2") == 2
    assert _area_id_to_int("0.0.0.102") == 102
    assert _area_id_to_int("5") == 5


def test_default_area_type():
    assert _default_area_type("0.0.0.0") == "backbone"
    assert _default_area_type("0.0.0.2") == "normal"


def test_best_area_type():
    assert _best_area_type("totally-stub", "normal") == "totally-stub"
    assert _best_area_type("normal", "stub") == "stub"
    assert _best_area_type(None, "backbone") == "backbone"


# =========================================================================
# extract_ospf_adjacencies
# =========================================================================
def test_ospf_bilateral_adjacency(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-rtr-01"
    _write(core, _ospf_neighbor_doc("203.0.113.1", "GigabitEthernet0/0", "203.0.113.2", "192.0.2.2"))
    _write(dist, _ospf_neighbor_doc("203.0.113.2", "GigabitEthernet0/1", "203.0.113.1", "192.0.2.1"))

    adjs = extract_ospf_adjacencies({"core-rtr-01": core, "dist-rtr-01": dist})
    assert len(adjs) == 1
    a = adjs[0]
    assert a["protocol"] == "ospf"
    assert {a["device_a"], a["device_b"]} == {"core-rtr-01", "dist-rtr-01"}
    assert a["state"] == "full"
    assert a["area"] == "0.0.0.0"
    assert a["area_type"] == "backbone"
    assert a["bilateral"] is True
    assert a["peer_collected"] is True


def test_ospf_unilateral_unresolved_neighbor(tmp_path):
    core = tmp_path / "core-rtr-01"
    # neighbor router-id 203.0.113.9 is not in inventory → unresolved, unilateral
    _write(core, _ospf_neighbor_doc("203.0.113.1", "GigabitEthernet0/0", "203.0.113.9", "192.0.2.9"))
    adjs = extract_ospf_adjacencies({"core-rtr-01": core})
    assert len(adjs) == 1
    a = adjs[0]
    assert a["bilateral"] is False
    assert a["peer_collected"] is False
    assert "203.0.113.9" in (a["device_a"], a["device_b"])   # router-id as device name


def test_ospf_neighbor_resolves_by_interface_ip_when_router_id_unknown(tmp_path):
    # A Cisco router reports an OSPF neighbor whose router-id (9.9.9.9) is NOT a
    # collected router-id — but whose link interface address is a collected
    # FortiGate port IP. The neighbor must resolve to the FortiGate (not a phantom
    # external peer). The FortiGate has no genie_ospf, so its router-id is never
    # in the lookup — the interface-IP fallback is the only path.
    core = tmp_path / "core-sw-01"
    _write(core, _ospf_neighbor_doc("198.51.100.100", "GigabitEthernet1/0/4",
                                    "9.9.9.9", "198.51.100.14"))
    fw = tmp_path / "edge-fw-01"
    fw.mkdir(parents=True)
    (fw / "fortigate_system_interface.json").write_text(json.dumps(
        {"results": [{"name": "port2", "ip": "198.51.100.14 255.255.255.252"}]}))
    adjs = extract_ospf_adjacencies({"core-sw-01": core, "edge-fw-01": fw})
    assert len(adjs) == 1
    a = adjs[0]
    assert {a["device_a"], a["device_b"]} == {"core-sw-01", "edge-fw-01"}
    assert a["peer_collected"] is True            # resolved, not external


def test_ospf_neighbor_stays_external_when_address_unresolvable(tmp_path):
    # Router-id unknown AND the interface address matches no collected device →
    # still a genuine external peer (router-id as identity).
    core = tmp_path / "core-sw-01"
    _write(core, _ospf_neighbor_doc("198.51.100.100", "GigabitEthernet1/0/1",
                                    "9.9.9.9", "203.0.113.99"))
    adjs = extract_ospf_adjacencies({"core-sw-01": core})
    assert len(adjs) == 1
    a = adjs[0]
    assert a["peer_collected"] is False
    assert "9.9.9.9" in (a["device_a"], a["device_b"])


def test_ospf_no_data(tmp_path):
    empty = tmp_path / "core-rtr-01"
    empty.mkdir()
    assert extract_ospf_adjacencies({"core-rtr-01": empty}) == []


# =========================================================================
# extract_ospf_lsdb
# =========================================================================
def test_ospf_lsdb(tmp_path):
    core = tmp_path / "core-rtr-01"
    doc = {"vrf": {"default": {"address_family": {"ipv4": {"instance": {"1": {
        "areas": {"0.0.0.0": {"database": {"lsa_types": {
            "1": {"lsas": {"203.0.113.1 203.0.113.1": {"ospfv2": {
                "header": {"lsa_id": "203.0.113.1", "adv_router": "203.0.113.1"},
                "body": {"router": {"num_of_links": 3}},
            }}}},
            "3": {"lsas": {"192.0.2.0 203.0.113.1": {"ospfv2": {
                "header": {"lsa_id": "192.0.2.0", "adv_router": "203.0.113.1"},
                "body": {"summary": {"network_mask": "255.255.255.0",
                                     "topologies": {"0": {"metric": 10}}}},
            }}}},
        }}}},
    }}}}}}}
    _write(core, doc)
    lsdb = extract_ospf_lsdb({"core-rtr-01": core})
    by_type = {e["lsa_type"]: e for e in lsdb}
    assert by_type[1]["num_links"] == 3
    assert by_type[1]["area_id"] == "0.0.0.0"
    assert by_type[3]["prefix"] == "192.0.2.0/24"   # mask → CIDR
    assert by_type[3]["metric"] == 10


def test_ospf_lsdb_no_data(tmp_path):
    empty = tmp_path / "core-rtr-01"
    empty.mkdir()
    assert extract_ospf_lsdb({"core-rtr-01": empty}) == []


def _multi_vrf_ospf(procs_by_vrf):
    """Genie OSPF doc with given {vrf: [(process_id, router_id)]}, all area 0."""
    vrf = {}
    for vname, plist in procs_by_vrf.items():
        inst = {pid: {"router_id": rid, "areas": {"0.0.0.0": {}}} for pid, rid in plist}
        vrf[vname] = {"address_family": {"ipv4": {"instance": inst}}}
    return {"vrf": vrf}


def _quirk_red_doc(rid, intf, nbr_rid, nbr_ip):
    """genie_ospf where proc 10 is copied under the 'default' block (router-id +
    area, but NO interfaces/neighbors — the quirk) and lives for real under the
    'RED' block (rid=None, but the interface + neighbor are here)."""
    return {"vrf": {
        "default": {"address_family": {"ipv4": {"instance": {"10": {
            "router_id": rid,
            "areas": {"0.0.0.0": {"interfaces": {}}},
        }}}}},
        "RED": {"address_family": {"ipv4": {"instance": {"10": {
            "router_id": None,
            "areas": {"0.0.0.0": {"interfaces": {intf: {
                "neighbors": {nbr_rid: {"address": nbr_ip, "state": "full"}},
            }}}},
        }}}}},
    }}


def test_ospf_genie_default_block_copy_no_phantom_adjacency(tmp_path):
    """O3 (R1): genie copies proc 10 under 'default' (router-id/stats) while the
    interfaces+neighbors live only in the real RED block. extract_ospf_adjacencies
    walks neighbors, so it must yield exactly ONE adjacency in VRF RED — never a
    phantom 'default'-VRF half-record. Mirrors the real demo (default block has 0
    interfaces) — verified, not just asserted."""
    a = tmp_path / "acc-sw-03"
    b = tmp_path / "core-sw-01"
    _write(a, _quirk_red_doc("198.51.100.113", "GigabitEthernet0/1", "198.51.100.225", "192.0.2.2"))
    _write(b, _quirk_red_doc("198.51.100.225", "GigabitEthernet1/0/5", "198.51.100.113", "192.0.2.1"))
    adjs = extract_ospf_adjacencies({"acc-sw-03": a, "core-sw-01": b})
    assert len(adjs) == 1
    assert adjs[0]["vrf"] == "RED"
    assert adjs[0]["bilateral"] is True


def test_shared_ospf_areas_ignores_genie_default_block_quirk(tmp_path):
    """R1 Phase 2: genie copies every process under the 'default' VRF block
    (RED proc 10 / BLUE proc 20 appear under 'default' too). The area-membership
    builder must NOT make a RED/BLUE-only device a member of the *default* area.
    acc-sw runs only proc 10 (RED) + proc 20 (BLUE) — no real default process —
    so it belongs to RED and BLUE area 0.0.0.0, never default."""
    core = tmp_path / "core-sw"
    bdr = tmp_path / "bdr-rtr"
    acc = tmp_path / "acc-sw"
    # core: real default proc 1 + RED/BLUE (with the genie default-block copies)
    _write(core, _multi_vrf_ospf({
        "default": [("1", "1.1.1.1"), ("10", "1.1.1.10"), ("20", "1.1.1.20")],
        "RED": [("10", None)], "BLUE": [("20", None)],
    }))
    bdr.mkdir(parents=True, exist_ok=True)
    (bdr / "genie_ospf.json").write_text(json.dumps(
        _multi_vrf_ospf({"default": [("1", "2.2.2.2")]})))
    # acc: only RED + BLUE, with their genie default-block copies (no proc 1)
    _write(acc, _multi_vrf_ospf({
        "default": [("10", "3.3.3.10"), ("20", "3.3.3.20")],
        "RED": [("10", None)], "BLUE": [("20", None)],
    }))

    areas = _discover_shared_ospf_areas(
        {"core-sw": core, "bdr-rtr": bdr, "acc-sw": acc})
    by_vrf = {a["vrf"]: set(a["members"]) for a in areas}

    # default area: only devices with a REAL default process — acc-sw excluded.
    assert by_vrf["default"] == {"core-sw", "bdr-rtr"}
    assert "acc-sw" not in by_vrf["default"]
    assert by_vrf["RED"] == {"core-sw", "acc-sw"}
    assert by_vrf["BLUE"] == {"core-sw", "acc-sw"}
