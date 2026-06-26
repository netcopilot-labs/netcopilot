"""F2-5c: link_builder LLDP discovery (reads genie_lldp.json from facts_dirs).

Synthetic Genie LLDP fixtures (invented hostnames/interfaces). LLDP is the
first genie-evidence discovery slice — it reads facts/<host>/genie_lldp.json
rather than the canonical facts dict.
"""

import json

from netcopilot.model.link_builder import (
    deduplicate_links,
    discover_lldp_links,
)


def _lldp_doc(local_intf, remote_host, remote_intf):
    """Build a Genie LLDP Ops document for one neighbor on one local interface."""
    return {
        "interfaces": {
            local_intf: {
                "port_id": {
                    local_intf: {
                        "neighbors": {
                            remote_host: {
                                "system_name": remote_host,
                                "neighbor_id": remote_host,
                                "port_id": remote_intf,
                            }
                        }
                    }
                }
            }
        }
    }


def _write_lldp(facts_dir, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / "genie_lldp.json").write_text(json.dumps(doc))


def _iface(host, name, admin="up", oper="up"):
    return {
        "interface_id": f"{host}:{name}",
        "device_id": host,
        "name": name,
        "admin_status": admin,
        "oper_status": oper,
    }


def test_lldp_bilateral(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write_lldp(core, _lldp_doc("GigabitEthernet0/0", "dist-sw-01", "GigabitEthernet1/0/3"))
    _write_lldp(dist, _lldp_doc("GigabitEthernet1/0/3", "core-rtr-01", "GigabitEthernet0/0"))

    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    cands = discover_lldp_links(facts_dirs, {"core-rtr-01", "dist-sw-01"})
    assert len(cands) == 1
    assert cands[0].discovery_method == "lldp_bilateral"
    assert cands[0].confidence == "very_high"
    assert len(cands[0].evidence) == 2


def test_lldp_unilateral(tmp_path):
    core = tmp_path / "core-rtr-01"
    _write_lldp(core, _lldp_doc("GigabitEthernet0/0", "unmanaged-sw", "GigabitEthernet9/9"))
    facts_dirs = {"core-rtr-01": core}
    cands = discover_lldp_links(facts_dirs, {"core-rtr-01"})
    assert len(cands) == 1
    assert cands[0].discovery_method == "lldp_unilateral"
    assert cands[0].confidence == "high"
    assert cands[0].peer_collected is False


def test_lldp_mac_port_id_skipped(tmp_path):
    """LLDP port_id that is a MAC address can't be matched to an interface name."""
    core = tmp_path / "core-rtr-01"
    _write_lldp(core, _lldp_doc("GigabitEthernet0/0", "dist-sw-01", "00:1a:2b:3c:4d:5e"))
    cands = discover_lldp_links({"core-rtr-01": core}, {"core-rtr-01", "dist-sw-01"})
    assert cands == []


def test_lldp_empty_file(tmp_path):
    core = tmp_path / "core-rtr-01"
    core.mkdir()
    (core / "genie_lldp.json").write_text("{}")
    assert discover_lldp_links({"core-rtr-01": core}, {"core-rtr-01"}) == []


def test_lldp_missing_file(tmp_path):
    core = tmp_path / "core-rtr-01"
    core.mkdir()
    assert discover_lldp_links({"core-rtr-01": core}, {"core-rtr-01"}) == []


def test_lldp_skips_incomplete_neighbor(tmp_path):
    core = tmp_path / "core-rtr-01"
    core.mkdir()
    # neighbor with no port_id → skipped
    doc = {"interfaces": {"GigabitEthernet0/0": {"port_id": {"GigabitEthernet0/0": {
        "neighbors": {"dist-sw-01": {"system_name": "dist-sw-01"}}
    }}}}}
    (core / "genie_lldp.json").write_text(json.dumps(doc))
    assert discover_lldp_links({"core-rtr-01": core}, {"core-rtr-01"}) == []


def test_lldp_dedup_to_final_link(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write_lldp(core, _lldp_doc("GigabitEthernet0/0", "dist-sw-01", "GigabitEthernet1/0/3"))
    _write_lldp(dist, _lldp_doc("GigabitEthernet1/0/3", "core-rtr-01", "GigabitEthernet0/0"))

    cands = discover_lldp_links({"core-rtr-01": core, "dist-sw-01": dist},
                                {"core-rtr-01", "dist-sw-01"})
    interfaces = [_iface("core-rtr-01", "Gi0/0"), _iface("dist-sw-01", "Gi1/0/3")]
    links = deduplicate_links(cands, interfaces)
    assert len(links) == 1
    link = links[0]
    assert link["discovery_protocol"] == "LLDP"
    assert link["discovery_priority"] == 2
    assert link["direction"] == "bidirectional"
    # interface_ids normalized to short form (matching the interface records)
    assert link["link_id"] == "core-rtr-01:Gi0/0--dist-sw-01:Gi1/0/3"
    assert link["status"] == "up"
