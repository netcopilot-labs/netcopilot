"""F2-5j: link_builder FDB-based management link discovery (SVL standby members).

A stack's standby member keeps a unique BIA MAC on Gi0/0 (physically up but
silent). The mgmt switch's FDB learns it, so we can infer an OOB management
cable the protocol methods miss. Cross-references cluster_members[].mac_address
(from show_version) with the mgmt_switch genie_fdb.json. Synthetic MACs.
"""

import json

from netcopilot.model.link_builder import (
    _member_id_from_port,
    discover_mgmt_fdb_member_links,
)

MAC_M1 = "1234.5678.0001"
MAC_M2 = "1234.5678.0002"


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _fdb(vlan, *mac_port_pairs):
    return {"mac_table": {"vlans": {str(vlan): {"mac_addresses": {
        mac: {"mac_address": mac, "interfaces": {port: {"interface": port}}}
        for mac, port in mac_port_pairs
    }}}}}


def _stack_device():
    return {
        "device_id": "core-sw-01", "hostname": "core-sw-01",
        "cluster_members": [
            {"member_id": 1, "mac_address": MAC_M1},
            {"member_id": 2, "mac_address": MAC_M2},
        ],
    }


# =========================================================================
# _member_id_from_port
# =========================================================================
def test_member_id_from_port():
    assert _member_id_from_port("Gi1/0/5") == 1
    assert _member_id_from_port("GigabitEthernet2/0/4") == 2
    assert _member_id_from_port("Vlan99") is None


# =========================================================================
# discover_mgmt_fdb_member_links
# =========================================================================
def test_mgmt_fdb_standby_link(tmp_path):
    mgmt = tmp_path / "mgmt-sw-01"
    # member 2's MAC learned on the mgmt switch's Gi1/0/5 in VLAN 99
    _write(mgmt, "genie_fdb.json", _fdb(99, (MAC_M2, "GigabitEthernet1/0/5")))
    facts_dirs = {"mgmt-sw-01": mgmt}
    role_by_device = {"mgmt-sw-01": "mgmt_switch", "core-sw-01": "core"}

    links = discover_mgmt_fdb_member_links(
        [_stack_device()], [], facts_dirs, {99}, role_by_device,
    )
    assert len(links) == 1
    link = links[0]
    assert link["discovery_method"] == "fdb_mgmt"
    assert link["link_type"] == "management"
    assert link["mgmt_type"] == "oob"
    assert link["local_device_id"] == "core-sw-01"
    assert link["local_interface_id"] == "core-sw-01:Gi0/0"
    assert link["remote_interface_id"] == "mgmt-sw-01:Gi1/0/5"
    assert link["source_member_id"] == 2
    assert link["target_member_id"] == 1   # derived from Gi1/0/5


def test_mgmt_fdb_skips_member_with_existing_mgmt_link(tmp_path):
    mgmt = tmp_path / "mgmt-sw-01"
    # both members' MACs present in the FDB
    _write(mgmt, "genie_fdb.json", _fdb(
        99, (MAC_M1, "GigabitEthernet1/0/4"), (MAC_M2, "GigabitEthernet1/0/5"),
    ))
    facts_dirs = {"mgmt-sw-01": mgmt}
    role_by_device = {"mgmt-sw-01": "mgmt_switch", "core-sw-01": "core"}
    # member 1 already has a management link → only member 2 gets a new one
    existing = [{
        "link_type": "management", "local_device_id": "core-sw-01",
        "source_member_id": 1,
    }]
    links = discover_mgmt_fdb_member_links(
        [_stack_device()], existing, facts_dirs, {99}, role_by_device,
    )
    assert len(links) == 1
    assert links[0]["source_member_id"] == 2


def test_mgmt_fdb_skips_portchannel(tmp_path):
    mgmt = tmp_path / "mgmt-sw-01"
    _write(mgmt, "genie_fdb.json", _fdb(99, (MAC_M2, "Port-channel1")))
    links = discover_mgmt_fdb_member_links(
        [_stack_device()], [], {"mgmt-sw-01": mgmt}, {99},
        {"mgmt-sw-01": "mgmt_switch"},
    )
    assert links == []


def test_mgmt_fdb_only_scans_mgmt_switch(tmp_path):
    """A device with the member MAC in FDB but role != mgmt_switch is ignored."""
    other = tmp_path / "dist-sw-01"
    _write(other, "genie_fdb.json", _fdb(99, (MAC_M2, "GigabitEthernet1/0/5")))
    links = discover_mgmt_fdb_member_links(
        [_stack_device()], [], {"dist-sw-01": other}, {99},
        {"dist-sw-01": "distribution"},
    )
    assert links == []


def test_mgmt_fdb_no_mgmt_vlans():
    assert discover_mgmt_fdb_member_links([_stack_device()], [], {}, set(), {}) == []


def test_mgmt_fdb_no_member_macs(tmp_path):
    mgmt = tmp_path / "mgmt-sw-01"
    _write(mgmt, "genie_fdb.json", _fdb(99, (MAC_M2, "GigabitEthernet1/0/5")))
    dev = {"device_id": "core-sw-01", "hostname": "core-sw-01", "cluster_members": []}
    links = discover_mgmt_fdb_member_links(
        [dev], [], {"mgmt-sw-01": mgmt}, {99}, {"mgmt-sw-01": "mgmt_switch"},
    )
    assert links == []
