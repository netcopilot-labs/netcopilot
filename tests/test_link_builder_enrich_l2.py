"""F2-5n: link_builder L2 metadata enrichment (VLAN / switchport mode).

enrich_l2_metadata annotates each link's endpoints with VLAN context from
genie_vlan.json (access ports, SVIs, sub-interface tags) plus trunk data from
parsed switchport interface records. Synthetic genie_vlan fixtures.
"""

import json

from netcopilot.model.link_builder import (
    _build_vlan_name_index,
    _build_vlan_port_index,
    _resolve_l2_for_interface,
    enrich_l2_metadata,
)

VLAN_DOC = {"vlans": {
    "99": {"vlan_id": "99", "name": "MGMT", "state": "active",
           "interfaces": ["GigabitEthernet1/0/3"]},
    "1000": {"vlan_id": "1000", "name": "DATA", "state": "active", "interfaces": []},
    "1002": {"vlan_id": "1002", "name": "fddi-default", "state": "suspend",
             "interfaces": []},
}}


def _vlan_dir(tmp_path, name="dist-sw-01"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "genie_vlan.json").write_text(json.dumps(VLAN_DOC))
    return d


def _link(local="dist-sw-01", li="Gi1/0/3", remote="core-rtr-01", ri="Gi0/0"):
    return {
        "local_device_id": local, "remote_device_id": remote,
        "local_interface_id": f"{local}:{li}", "remote_interface_id": f"{remote}:{ri}",
    }


# =========================================================================
# index builders
# =========================================================================
def test_build_vlan_port_index(tmp_path):
    idx = _build_vlan_port_index({"dist-sw-01": _vlan_dir(tmp_path)})
    ports = idx["dist-sw-01"]
    # keyed by both canonical and original name
    assert ports["gigabitethernet1/0/3"] == {"vlan_id": "99", "vlan_name": "MGMT"}
    assert ports["GigabitEthernet1/0/3"]["vlan_id"] == "99"


def test_build_vlan_name_index_skips_suspend(tmp_path):
    names = _build_vlan_name_index({"dist-sw-01": _vlan_dir(tmp_path)})["dist-sw-01"]
    assert names == {"99": "MGMT", "1000": "DATA"}   # 1002 (suspend) excluded


# =========================================================================
# _resolve_l2_for_interface
# =========================================================================
def test_resolve_l2_access(tmp_path):
    d = _vlan_dir(tmp_path)
    ports = _build_vlan_port_index({"dist-sw-01": d})
    names = _build_vlan_name_index({"dist-sw-01": d})
    # short form Gi1/0/3 canonicalizes to match the genie full form
    r = _resolve_l2_for_interface("dist-sw-01", "Gi1/0/3", ports, names)
    assert r == {"mode": "access", "vlan": {"id": "99", "name": "MGMT"}}


def test_resolve_l2_svi(tmp_path):
    d = _vlan_dir(tmp_path)
    names = _build_vlan_name_index({"dist-sw-01": d})
    r = _resolve_l2_for_interface("dist-sw-01", "Vlan99", {}, names)
    assert r == {"mode": "svi", "vlan": {"id": "99", "name": "MGMT"}}


def test_resolve_l2_subinterface(tmp_path):
    d = _vlan_dir(tmp_path)
    names = _build_vlan_name_index({"dist-sw-01": d})
    r = _resolve_l2_for_interface("dist-sw-01", "Gi0/2.1000", {}, names)
    assert r == {"mode": "subinterface", "vlan": {"id": "1000", "name": "DATA"}}


def test_resolve_l2_routed_is_none(tmp_path):
    d = _vlan_dir(tmp_path)
    ports = _build_vlan_port_index({"dist-sw-01": d})
    names = _build_vlan_name_index({"dist-sw-01": d})
    assert _resolve_l2_for_interface("dist-sw-01", "Hu1/0/1", ports, names) is None


# =========================================================================
# enrich_l2_metadata
# =========================================================================
def test_enrich_l2_access_endpoint(tmp_path):
    facts_dirs = {"dist-sw-01": _vlan_dir(tmp_path)}
    link = _link(li="Gi1/0/3")
    enrich_l2_metadata([link], facts_dirs)
    assert link["l2"]["local"] == {"mode": "access", "vlan": {"id": "99", "name": "MGMT"}}
    assert link["l2"]["remote"] is None   # core-rtr-01 has no VLAN data


def test_enrich_l2_routed_link_is_none(tmp_path):
    facts_dirs = {"dist-sw-01": _vlan_dir(tmp_path)}
    link = _link(li="Hu1/0/1", ri="Hu0/0/1/0")
    enrich_l2_metadata([link], facts_dirs)
    assert link["l2"] is None


def test_enrich_l2_trunk_from_interfaces(tmp_path):
    facts_dirs = {"dist-sw-01": _vlan_dir(tmp_path)}
    link = _link(li="Gi1/0/5")   # not an access port in the VLAN doc
    interfaces = [{
        "device_id": "dist-sw-01", "name": "Gi1/0/5",
        "switchport_mode": "trunk", "trunk_vlans": [10, 99], "native_vlan": 1,
    }]
    enrich_l2_metadata([link], facts_dirs, interfaces)
    trunk = link["l2"]["local"]["trunk"]
    assert trunk["mode"] == "trunk"
    assert trunk["vlans_carried"] == ["10", "99"]
    assert trunk["native_vlan"] == 1
