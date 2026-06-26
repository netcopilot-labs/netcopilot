"""F2-5o: link_builder L3 metadata enrichment (IP / subnet / VRF).

enrich_l3_metadata annotates each link's endpoints with IP/prefix/VRF from
genie_interface.json (Cisco) + fortigate_system_interface.json (FortiGate),
and computes the shared subnet. Synthetic RFC 5737 fixtures.
"""

import json

from netcopilot.model.link_builder import (
    _build_interface_ip_index,
    enrich_l3_metadata,
)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _cisco_intf(name, ip, prefix=24, vrf=None, secondary=False):
    rec = {"ipv4": {f"{ip}/{prefix}": {"ip": ip, "prefix_length": str(prefix),
                                       "secondary": secondary}}}
    if vrf:
        rec["vrf"] = vrf
    return {name: rec}


def _link(local="core-rtr-01", li="Gi0/0", remote="dist-sw-01", ri="Gi1/0/3"):
    return {
        "local_device_id": local, "remote_device_id": remote,
        "local_interface_id": f"{local}:{li}", "remote_interface_id": f"{remote}:{ri}",
    }


# =========================================================================
# _build_interface_ip_index
# =========================================================================
def test_ip_index_cisco(tmp_path):
    d = tmp_path / "core-rtr-01"
    _write(d, "genie_interface.json", _cisco_intf("GigabitEthernet0/0", "192.0.2.1", 24, vrf="Mgmt-vrf"))
    idx = _build_interface_ip_index({"core-rtr-01": d}, {"core-rtr-01": {"os": "ios-xe"}})
    entry = idx["core-rtr-01"]["gigabitethernet0/0"]
    assert entry == {"ip": "192.0.2.1", "prefix_length": "24", "vrf": "Mgmt-vrf"}


def test_ip_index_fortigate(tmp_path):
    d = tmp_path / "edge-fw-01"
    _write(d, "fortigate_system_interface.json",
           {"results": [{"name": "port1", "ip": "192.0.2.254 255.255.255.0", "vdom": "root"}]})
    idx = _build_interface_ip_index({"edge-fw-01": d}, {"edge-fw-01": {"os": "fortios"}})
    entry = idx["edge-fw-01"]["port1"]
    assert entry == {"ip": "192.0.2.254", "prefix_length": "24", "vrf": "default"}  # root → default


def test_ip_index_skips_secondary(tmp_path):
    d = tmp_path / "core-rtr-01"
    doc = {"GigabitEthernet0/0": {"ipv4": {
        "192.0.2.1/24": {"ip": "192.0.2.1", "prefix_length": "24", "secondary": False},
        "192.0.2.2/24": {"ip": "192.0.2.2", "prefix_length": "24", "secondary": True},
    }}}
    _write(d, "genie_interface.json", doc)
    idx = _build_interface_ip_index({"core-rtr-01": d}, {"core-rtr-01": {"os": "ios-xe"}})
    assert idx["core-rtr-01"]["gigabitethernet0/0"]["ip"] == "192.0.2.1"  # primary only


# =========================================================================
# enrich_l3_metadata
# =========================================================================
def test_enrich_l3_shared_subnet(tmp_path):
    core = tmp_path / "core-rtr-01"
    dist = tmp_path / "dist-sw-01"
    _write(core, "genie_interface.json", _cisco_intf("GigabitEthernet0/0", "192.0.2.1", 24))
    _write(dist, "genie_interface.json", _cisco_intf("GigabitEthernet1/0/3", "192.0.2.2", 24))
    facts_dirs = {"core-rtr-01": core, "dist-sw-01": dist}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "dist-sw-01": {"os": "ios-xe"}}

    link = _link()
    enrich_l3_metadata([link], facts_dirs, facts_by_hostname)
    assert link["l3"]["local"] == {"ip": "192.0.2.1", "prefix_length": "24", "vrf": "default"}
    assert link["l3"]["remote"] == {"ip": "192.0.2.2", "prefix_length": "24", "vrf": "default"}
    assert link["l3"]["subnet"] == "192.0.2.0/24"


def test_enrich_l3_one_sided(tmp_path):
    core = tmp_path / "core-rtr-01"
    _write(core, "genie_interface.json", _cisco_intf("GigabitEthernet0/0", "192.0.2.1", 24))
    facts_dirs = {"core-rtr-01": core}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "dist-sw-01": {"os": "ios-xe"}}

    link = _link()
    enrich_l3_metadata([link], facts_dirs, facts_by_hostname)
    assert link["l3"]["local"]["ip"] == "192.0.2.1"
    assert link["l3"]["remote"] is None
    assert link["l3"]["subnet"] == "192.0.2.0/24"   # from local side


def test_enrich_l3_routed_no_ip_is_none(tmp_path):
    core = tmp_path / "core-rtr-01"
    _write(core, "genie_interface.json", _cisco_intf("GigabitEthernet0/0", "192.0.2.1", 24))
    facts_dirs = {"core-rtr-01": core}
    facts_by_hostname = {"core-rtr-01": {"os": "ios-xe"}, "dist-sw-01": {"os": "ios-xe"}}

    link = _link(li="Hu9/9", ri="Hu9/9")   # neither interface has IP data
    enrich_l3_metadata([link], facts_dirs, facts_by_hostname)
    assert link["l3"] is None
