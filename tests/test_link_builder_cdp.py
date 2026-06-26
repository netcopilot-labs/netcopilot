"""F2-5b: link_builder core — CDP discovery + candidate dedup.

Covers the CDP path end-to-end: canonical ``facts["cdp_neighbors"]`` →
``discover_cdp_links`` → ``deduplicate_links`` → final link dicts. Uses
synthetic device names (core-rtr-01 / dist-sw-01 / edge-fw-01).
"""

import pytest

from netcopilot.model.link_builder import (
    LinkCandidate,
    deduplicate_links,
    discover_cdp_links,
    sanitize_cdp_hostname,
    _make_pair_key,
)


def _cdp(local, neighbor, neighbor_intf):
    return {
        "local_interface": local,
        "neighbor_hostname": neighbor,
        "neighbor_interface": neighbor_intf,
    }


def _iface(host, name, admin="up", oper="up"):
    return {
        "interface_id": f"{host}:{name}",
        "device_id": host,
        "name": name,
        "admin_status": admin,
        "oper_status": oper,
    }


# =========================================================================
# sanitize_cdp_hostname
# =========================================================================
@pytest.mark.parametrize("raw,expected", [
    ("dist-sw-01", "dist-sw-01"),
    ("core-rtr-01   Gig 1/0/8   168   R S I  Switch Gig 1/0/3", "core-rtr-01"),
    ("  spaced-host  ", "spaced-host"),
    ("", ""),
    ("   ", ""),
])
def test_sanitize_cdp_hostname(raw, expected):
    assert sanitize_cdp_hostname(raw) == expected


# =========================================================================
# discover_cdp_links
# =========================================================================
def test_cdp_bilateral():
    facts = {
        "core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "dist-sw-01", "Gi1/0/3")]},
        "dist-sw-01": {"cdp_neighbors": [_cdp("Gi1/0/3", "core-rtr-01", "Gi0/0")]},
    }
    cands = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1                      # A→B and B→A collapse to one
    c = cands[0]
    assert c.discovery_method == "cdp_bilateral"
    assert c.confidence == "very_high"
    assert c.peer_collected is True
    assert len(c.evidence) == 2                  # both directions recorded


def test_cdp_unilateral_unmanaged_peer():
    facts = {
        "core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "unmanaged-sw", "Gi5/0/1")]},
    }
    cands = discover_cdp_links(facts, {"core-rtr-01"})
    assert len(cands) == 1
    c = cands[0]
    assert c.discovery_method == "cdp_unilateral"
    assert c.confidence == "high"
    assert c.peer_collected is False            # peer has no facts
    assert len(c.evidence) == 1


def test_cdp_bilateral_across_format_variants():
    """Space-form CDP ("Gig 1/0/3") and full form ("GigabitEthernet1/0/3")
    canonicalize to the same identity → still detected as bilateral."""
    facts = {
        "core-rtr-01": {"cdp_neighbors": [_cdp("Gig 0/0", "dist-sw-01", "Gig 1/0/3")]},
        "dist-sw-01": {"cdp_neighbors": [
            _cdp("GigabitEthernet1/0/3", "core-rtr-01", "GigabitEthernet0/0")
        ]},
    }
    cands = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    assert cands[0].discovery_method == "cdp_bilateral"


def test_cdp_skips_incomplete_entries():
    facts = {
        "core-rtr-01": {"cdp_neighbors": [
            {"local_interface": "Gi0/0", "neighbor_hostname": "", "neighbor_interface": "Gi1/0/3"},
            {"local_interface": "", "neighbor_hostname": "dist-sw-01", "neighbor_interface": "Gi1/0/3"},
        ]},
    }
    assert discover_cdp_links(facts, {"core-rtr-01"}) == []


def test_cdp_sanitizes_corrupted_neighbor_hostname():
    facts = {
        "core-rtr-01": {"cdp_neighbors": [
            _cdp("Gi0/0", "dist-sw-01   Gig 1/0/3   168   R", "Gi1/0/3")
        ]},
    }
    cands = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    assert cands[0].remote_device == "dist-sw-01"


def test_cdp_configured_hostname_mapping(tmp_path):
    """A device collected as inventory name 'dist-sw-01' whose running config
    sets 'hostname dist-sw-01a' is reported as 'dist-sw-01a' by CDP neighbors;
    facts_dirs running_config.txt maps it back to the inventory name."""
    inv_dir = tmp_path / "dist-sw-01"
    inv_dir.mkdir()
    (inv_dir / "running_config.txt").write_text("!\nhostname dist-sw-01a\n!\n")
    core_dir = tmp_path / "core-rtr-01"
    core_dir.mkdir()

    facts = {
        # core-rtr-01 sees the *configured* hostname over CDP
        "core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "dist-sw-01a", "Gi1/0/3")]},
        "dist-sw-01": {"cdp_neighbors": [_cdp("Gi1/0/3", "core-rtr-01", "Gi0/0")]},
    }
    facts_dirs = {"core-rtr-01": core_dir, "dist-sw-01": inv_dir}
    cands = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"}, facts_dirs)
    assert len(cands) == 1
    # remote resolved back to inventory name → bilateral match succeeds
    assert cands[0].discovery_method == "cdp_bilateral"
    assert {cands[0].local_device, cands[0].remote_device} == {"core-rtr-01", "dist-sw-01"}


# =========================================================================
# _make_pair_key
# =========================================================================
def test_make_pair_key_is_symmetric():
    a = LinkCandidate("core-rtr-01", "Gi0/0", "gigabitethernet0/0",
                      "dist-sw-01", "Gi1/0/3", "gigabitethernet1/0/3",
                      "cdp_bilateral", "very_high")
    b = LinkCandidate("dist-sw-01", "Gi1/0/3", "gigabitethernet1/0/3",
                      "core-rtr-01", "Gi0/0", "gigabitethernet0/0",
                      "cdp_bilateral", "very_high")
    assert _make_pair_key(a) == _make_pair_key(b)


# =========================================================================
# deduplicate_links
# =========================================================================
def test_dedup_cdp_to_final_link():
    facts = {
        "core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "dist-sw-01", "Gi1/0/3")]},
        "dist-sw-01": {"cdp_neighbors": [_cdp("Gi1/0/3", "core-rtr-01", "Gi0/0")]},
    }
    cands = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"})
    interfaces = [_iface("core-rtr-01", "Gi0/0"), _iface("dist-sw-01", "Gi1/0/3")]
    links = deduplicate_links(cands, interfaces)

    assert len(links) == 1
    link = links[0]
    assert link["link_id"] == "core-rtr-01:Gi0/0--dist-sw-01:Gi1/0/3"
    assert link["status"] == "up"
    assert link["direction"] == "bidirectional"
    assert link["discovery_method"] == "cdp_bilateral"
    assert link["discovery_protocol"] == "CDP"
    assert link["discovery_priority"] == 1
    assert link["peer_collected"] is True


def test_dedup_canonical_orientation_local_is_smaller_device():
    """R2-CDP-1: the final link's 'local' side is the lexicographically-smaller
    (device, interface) endpoint, regardless of which candidate side won dedup —
    so the A/B ends are stable and not coupled to discovery/iteration order."""
    # Candidate whose OWN 'local' is the alphabetically-LARGER device.
    cand = LinkCandidate("zebra-sw", "Gi9/0/1", "gigabitethernet9/0/1",
                         "alpha-sw", "Gi1/0/1", "gigabitethernet1/0/1",
                         "cdp_bilateral", "very_high",
                         evidence=["cdp:zebra-sw→alpha-sw", "cdp:alpha-sw→zebra-sw"])
    interfaces = [_iface("alpha-sw", "Gi1/0/1"), _iface("zebra-sw", "Gi9/0/1")]
    link = deduplicate_links([cand], interfaces)[0]

    # Canonical: smaller device (alpha-sw) is local even though the candidate's
    # local was zebra-sw.
    assert link["local_device_id"] == "alpha-sw"
    assert link["remote_device_id"] == "zebra-sw"
    assert link["local_interface_id"] == "alpha-sw:Gi1/0/1"
    assert link["remote_interface_id"] == "zebra-sw:Gi9/0/1"
    assert link["link_id"] == "alpha-sw:Gi1/0/1--zebra-sw:Gi9/0/1"


def test_dedup_highest_confidence_wins_and_merges_evidence():
    """Same pair found by two methods → highest confidence wins, evidence merges,
    direction is bidirectional if ANY candidate was bilateral."""
    low = LinkCandidate("core-rtr-01", "Gi0/0", "gigabitethernet0/0",
                        "dist-sw-01", "Gi1/0/3", "gigabitethernet1/0/3",
                        "arp_subnet", "medium", evidence=["arp:core-rtr-01→dist-sw-01"])
    high = LinkCandidate("core-rtr-01", "Gi0/0", "gigabitethernet0/0",
                         "dist-sw-01", "Gi1/0/3", "gigabitethernet1/0/3",
                         "cdp_bilateral", "very_high",
                         evidence=["cdp:core-rtr-01→dist-sw-01", "cdp:dist-sw-01→core-rtr-01"])
    interfaces = [_iface("core-rtr-01", "Gi0/0"), _iface("dist-sw-01", "Gi1/0/3")]
    links = deduplicate_links([low, high], interfaces)

    assert len(links) == 1
    link = links[0]
    assert link["discovery_method"] == "cdp_bilateral"   # very_high beats medium
    assert link["confidence"] == "very_high"
    assert link["direction"] == "bidirectional"
    assert set(link["evidence"]) == {
        "cdp:core-rtr-01→dist-sw-01", "cdp:dist-sw-01→core-rtr-01",
        "arp:core-rtr-01→dist-sw-01",
    }


def test_dedup_status_down_when_oper_down():
    cands = discover_cdp_links(
        {
            "core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "dist-sw-01", "Gi1/0/3")]},
            "dist-sw-01": {"cdp_neighbors": [_cdp("Gi1/0/3", "core-rtr-01", "Gi0/0")]},
        },
        {"core-rtr-01", "dist-sw-01"},
    )
    interfaces = [
        _iface("core-rtr-01", "Gi0/0", oper="down"),
        _iface("dist-sw-01", "Gi1/0/3"),
    ]
    assert deduplicate_links(cands, interfaces)[0]["status"] == "down"


def test_dedup_status_local_only_when_peer_interface_missing():
    """Peer (unmanaged) interface absent but local side up → local-only status
    (the calculate_link_status partial-data branch), direction unidirectional."""
    cands = discover_cdp_links(
        {"core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "unmanaged-sw", "Gi5/0/1")]}},
        {"core-rtr-01"},
    )
    links = deduplicate_links(cands, [_iface("core-rtr-01", "Gi0/0")])
    assert links[0]["status"] == "up"
    assert links[0]["direction"] == "unidirectional"


def test_dedup_status_unknown_when_both_interfaces_missing():
    cands = discover_cdp_links(
        {"core-rtr-01": {"cdp_neighbors": [_cdp("Gi0/0", "unmanaged-sw", "Gi5/0/1")]}},
        {"core-rtr-01"},
    )
    # no interface records at all → both endpoints unknown → unknown
    links = deduplicate_links(cands, [])
    assert links[0]["status"] == "unknown"


def test_dedup_empty():
    assert deduplicate_links([], []) == []
