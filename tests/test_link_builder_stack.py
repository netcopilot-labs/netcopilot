"""F2-5h: link_builder stack-interconnect discovery (Cisco C9300 cable / C9500 SVL).

Stack links are self-referential (same hostname, distinct member_id). Produced
as final link dicts (no dedup). Built from collected stack_ports data, or — when
that wasn't collected — from running_config.txt SVL stanzas / cluster_members.
Synthetic device dicts + config text (no genie).
"""

from netcopilot.model.link_builder import (
    _parse_svl_ports_from_config,
    _svl_mirror_interface,
    discover_stack_interconnect_links,
)

SVL_CONFIG = """\
!
interface HundredGigE1/0/1
 stackwise-virtual link 1
!
interface HundredGigE2/0/1
 stackwise-virtual link 1
!
interface HundredGigE1/0/2
 stackwise-virtual dual-active-detection
!
interface HundredGigE2/0/2
 stackwise-virtual dual-active-detection
!
interface GigabitEthernet1/0/48
 description uplink
!
"""


# =========================================================================
# helpers
# =========================================================================
def test_svl_mirror_interface():
    assert _svl_mirror_interface("HundredGigE1/0/1", 1, 2) == "HundredGigE2/0/1"
    assert _svl_mirror_interface("HundredGigE2/0/1", 1, 2) == "HundredGigE2/0/1"  # from mismatch


def test_parse_svl_ports_from_config(tmp_path):
    cfg = tmp_path / "running_config.txt"
    cfg.write_text(SVL_CONFIG)
    ports = _parse_svl_ports_from_config(cfg)
    by_subtype = {p["subtype"]: p for p in ports}
    assert set(by_subtype) == {"svl", "dad"}
    assert by_subtype["svl"]["local_intf"] == "HundredGigE1/0/1"
    assert by_subtype["svl"]["remote_intf"] == "HundredGigE2/0/1"
    assert by_subtype["svl"]["member_from"] == 1 and by_subtype["svl"]["member_to"] == 2


def test_parse_svl_missing_file(tmp_path):
    assert _parse_svl_ports_from_config(tmp_path / "nope.txt") == []


# =========================================================================
# discover_stack_interconnect_links
# =========================================================================
def test_stack_c9300_cable():
    dev = {
        "hostname": "stack-sw-01",
        "platform": "C9300-48P",
        "stack_ports": [
            # member 1 → 2 (kept) and the reverse 2 → 1 (skipped by member>=neighbor)
            {"port_type": "cable", "member_id": 1, "neighbor_member": 2, "port_id": 1,
             "link_active": True, "status": "OK", "cable_length": "50cm"},
            {"port_type": "cable", "member_id": 2, "neighbor_member": 1, "port_id": 1,
             "link_active": True},
        ],
    }
    links = discover_stack_interconnect_links([dev])
    assert len(links) == 1
    link = links[0]
    assert link["link_type"] == "stack_interconnect"
    assert link["stack_subtype"] == "cable"
    assert link["confidence"] == "very_high"
    assert link["local_member_id"] == 1 and link["remote_member_id"] == 2
    assert link["local_device_id"] == link["remote_device_id"] == "stack-sw-01"


def test_stack_c9500_svl():
    dev = {
        "hostname": "core-sw-01",
        "platform": "C9500",
        "cluster_declared_size": 2,
        "stack_ports": [
            {"port_type": "svl", "member_id": 1, "interface": "HundredGigE1/0/1",
             "link_status": "Up", "svl_id": 1},
            # member 2 entry skipped (member > declared_size//2)
            {"port_type": "svl", "member_id": 2, "interface": "HundredGigE2/0/1",
             "link_status": "Up", "svl_id": 1},
        ],
    }
    links = discover_stack_interconnect_links([dev])
    assert len(links) == 1
    link = links[0]
    assert link["local_interface_id"] == "core-sw-01:HundredGigE1/0/1"
    assert link["remote_interface_id"] == "core-sw-01:HundredGigE2/0/1"
    assert link["svl_id"] == 1
    assert link["status"] == "up"


def test_stack_c9500_config_svl_fallback(tmp_path):
    """No stack_ports collected, but a C9500 with cluster_members → SVL fibers
    parsed from running_config."""
    cfg_dir = tmp_path / "core-sw-01"
    cfg_dir.mkdir()
    (cfg_dir / "running_config.txt").write_text(SVL_CONFIG)
    dev = {
        "hostname": "core-sw-01",
        "platform": "C9500",
        "stack_ports": [],
        "cluster_members": [{"member_id": 1}, {"member_id": 2}],
    }
    links = discover_stack_interconnect_links([dev], {"core-sw-01": cfg_dir})
    # one svl + one dad fiber from the config
    assert len(links) == 2
    assert {l["stack_subtype"] for l in links} == {"svl", "dad"}
    assert all(l["discovery_method"] == "config_svl" for l in links)


def test_stack_generic_inferred_fallback():
    """No stack_ports, non-C9500 platform → single inferred link, medium."""
    dev = {
        "hostname": "stack-sw-09",
        "platform": "C9300-24T",
        "stack_ports": [],
        "cluster_members": [{"member_id": 1}, {"member_id": 2}],
    }
    links = discover_stack_interconnect_links([dev])
    assert len(links) == 1
    assert links[0]["discovery_method"] == "stack_inferred"
    assert links[0]["confidence"] == "medium"
    assert links[0]["stack_subtype"] == "cable"


def test_stack_single_member_no_links():
    dev = {"hostname": "sw-01", "platform": "C9300", "stack_ports": [],
           "cluster_members": [{"member_id": 1}]}
    assert discover_stack_interconnect_links([dev]) == []


def test_stack_no_data():
    assert discover_stack_interconnect_links([{"hostname": "sw-01"}]) == []


def test_stack_c9500_svl_recovers_dad_from_config(tmp_path):
    """R2-SVL-DAD: when stack_ports is collected it carries only the SVL
    data-plane fibers, NOT the DAD link (which lives in config). The DAD cable
    must still be recovered from running_config so it isn't silently dropped when
    stack_ports happens to be present."""
    cfg_dir = tmp_path / "core-sw-01"
    cfg_dir.mkdir()
    (cfg_dir / "running_config.txt").write_text(SVL_CONFIG)  # SVL Hu1/0/1 + DAD Hu1/0/2
    dev = {
        "hostname": "core-sw-01",
        "platform": "C9500",
        "cluster_declared_size": 2,
        "stack_ports": [  # SVL data-plane only — no DAD entry (matches genie reality)
            {"port_type": "svl", "member_id": 1, "interface": "HundredGigE1/0/1",
             "link_status": "Up", "svl_id": 1},
            {"port_type": "svl", "member_id": 2, "interface": "HundredGigE2/0/1",
             "link_status": "Up", "svl_id": 1},
        ],
    }
    links = discover_stack_interconnect_links([dev], {"core-sw-01": cfg_dir})
    subtypes = sorted(l["stack_subtype"] for l in links)
    assert subtypes == ["dad", "svl"], f"expected svl+dad, got {subtypes}"
    dad = next(l for l in links if l["stack_subtype"] == "dad")
    assert dad["discovery_method"] == "config_svl"
    assert dad["local_interface_id"] == "core-sw-01:Hu1/0/2"
    assert dad["remote_interface_id"] == "core-sw-01:Hu2/0/2"
    # the SVL fiber already in stack_ports must NOT be duplicated
    assert sum(1 for l in links if l["stack_subtype"] == "svl") == 1
