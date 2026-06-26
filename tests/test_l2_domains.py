"""Unit tests for connectivity-based L2 broadcast-domain discovery.

Synthetic model dicts (interfaces + links) only — no run/facts needed, since
``discover_l2_domains`` is a pure function of the built model collections.
"""

from netcopilot.model.l2_domains import discover_l2_domains


def _access(dev, name, vlan):
    return {"device_id": dev, "interface_id": f"{dev}:{name}", "name": name,
            "switchport_mode": "access", "access_vlan": vlan, "trunk_vlans": None}


def _trunk(dev, name, vlans):
    return {"device_id": dev, "interface_id": f"{dev}:{name}", "name": name,
            "switchport_mode": "trunk", "access_vlan": None, "trunk_vlans": vlans}


def _svi(dev, vlan):
    return {"device_id": dev, "interface_id": f"{dev}:Vl{vlan}", "name": f"Vl{vlan}",
            "switchport_mode": None}


def _trunk_link(dev_a, if_a, vlans_a, dev_b, if_b, vlans_b):
    """An L2 trunk<->trunk link. ``vlans_*`` are STRINGS, mirroring the real
    ``l2.*.trunk.vlans_carried`` shape (the int/str hazard)."""
    return {
        "local_device_id": dev_a, "local_interface_id": f"{dev_a}:{if_a}",
        "remote_device_id": dev_b, "remote_interface_id": f"{dev_b}:{if_b}",
        "link_id": f"{dev_a}:{if_a}__{dev_b}:{if_b}",
        "l2": {
            "local": {"mode": "trunk", "trunk": {"vlans_carried": vlans_a}},
            "remote": {"mode": "trunk", "trunk": {"vlans_carried": vlans_b}},
        },
    }


def _svi_link(trunk_dev, trunk_if, vlans, svi_dev, svi_vlan):
    """A trunk<->svi link: the svi endpoint is the L3 gateway, NOT a bridge."""
    return {
        "local_device_id": trunk_dev, "local_interface_id": f"{trunk_dev}:{trunk_if}",
        "remote_device_id": svi_dev, "remote_interface_id": f"{svi_dev}:Vl{svi_vlan}",
        "link_id": f"{trunk_dev}:{trunk_if}__{svi_dev}:Vl{svi_vlan}",
        "l2": {
            "local": {"mode": "trunk", "trunk": {"vlans_carried": vlans}},
            "remote": {"mode": "svi", "vlan": {"id": str(svi_vlan), "name": "X"}},
        },
    }


def _by_id(domains):
    return {d["id"]: d for d in domains}


def test_trunk_link_merges_into_one_domain():
    interfaces = [_trunk("sw-a", "Gi0/1", [10, 20]), _trunk("sw-b", "Gi0/1", [10, 20])]
    links = [_trunk_link("sw-a", "Gi0/1", ["10", "20"], "sw-b", "Gi0/1", ["10", "20"])]
    domains = discover_l2_domains(interfaces, links)
    v10 = [d for d in domains if d["vlan_id"] == 10]
    assert len(v10) == 1
    assert v10[0]["member_devices"] == ["sw-a", "sw-b"]
    assert v10[0]["id"] == "vlan10-dom0"
    assert v10[0]["trunk_links"] == ["sw-a:Gi0/1__sw-b:Gi0/1"]


def test_isolated_device_is_singleton_domain():
    # sw-c carries VLAN 10 (access) but has NO L2 link -> its own domain.
    interfaces = [
        _trunk("sw-a", "Gi0/1", [10]), _trunk("sw-b", "Gi0/1", [10]),
        _access("sw-c", "Gi0/2", 10),
    ]
    links = [_trunk_link("sw-a", "Gi0/1", ["10"], "sw-b", "Gi0/1", ["10"])]
    v10 = [d for d in discover_l2_domains(interfaces, links) if d["vlan_id"] == 10]
    members = sorted(d["member_devices"] for d in v10)
    assert members == [["sw-a", "sw-b"], ["sw-c"]]  # two separate domains
    singleton = next(d for d in v10 if d["member_devices"] == ["sw-c"])
    assert singleton["access_ports"] == ["sw-c:Gi0/2"]
    assert singleton["trunk_links"] == []


def test_trunk_not_carrying_vlan_does_not_bridge():
    # Both switches have an access port in VLAN 10, but the trunk between them
    # carries only VLAN 20 -> VLAN 10 must NOT bridge; VLAN 20 must.
    interfaces = [_access("sw-a", "Gi0/2", 10), _access("sw-b", "Gi0/2", 10)]
    links = [_trunk_link("sw-a", "Gi0/1", ["20"], "sw-b", "Gi0/1", ["20"])]
    domains = discover_l2_domains(interfaces, links)
    v10 = [d for d in domains if d["vlan_id"] == 10]
    v20 = [d for d in domains if d["vlan_id"] == 20]
    assert sorted(d["member_devices"] for d in v10) == [["sw-a"], ["sw-b"]]  # not bridged
    assert v20[0]["member_devices"] == ["sw-a", "sw-b"]                      # bridged via link


def test_svi_endpoint_does_not_bridge():
    # A trunk<->svi link is the routed boundary; sw-a and sw-b stay separate.
    # Both have an access port in VLAN 10 (definite membership); the svi link
    # must not merge them.
    interfaces = [_access("sw-a", "Gi0/2", 10), _access("sw-b", "Gi0/2", 10),
                  _svi("sw-b", 10)]
    links = [_svi_link("sw-a", "Gi0/1", ["10"], "sw-b", 10)]
    v10 = [d for d in discover_l2_domains(interfaces, links) if d["vlan_id"] == 10]
    assert sorted(d["member_devices"] for d in v10) == [["sw-a"], ["sw-b"]]
    # the SVI is attached to sw-b's domain, not bridging it
    swb = next(d for d in v10 if d["member_devices"] == ["sw-b"])
    assert swb["svis"] == ["sw-b:Vl10"]


def test_str_int_vlan_normalization():
    # interface trunk_vlans are ints; vlans_carried are strings — must match.
    interfaces = [_trunk("sw-a", "Gi0/1", [10]), _trunk("sw-b", "Gi0/1", [10])]
    links = [_trunk_link("sw-a", "Gi0/1", ["10"], "sw-b", "Gi0/1", ["10"])]
    v10 = [d for d in discover_l2_domains(interfaces, links) if d["vlan_id"] == 10]
    assert v10[0]["member_devices"] == ["sw-a", "sw-b"]  # would be 2 singletons if str!=int


def test_deterministic_under_reversed_input():
    interfaces = [
        _trunk("sw-a", "Gi0/1", [10, 20]), _trunk("sw-b", "Gi0/1", [10, 20]),
        _trunk("sw-c", "Gi0/2", [10, 20]), _access("sw-d", "Gi0/3", 10), _svi("sw-a", 10),
    ]
    links = [
        _trunk_link("sw-a", "Gi0/1", ["10", "20"], "sw-b", "Gi0/1", ["10", "20"]),
        _trunk_link("sw-b", "Gi0/2", ["10", "20"], "sw-c", "Gi0/2", ["10", "20"]),
    ]
    forward = discover_l2_domains(interfaces, links)
    reverse = discover_l2_domains(list(reversed(interfaces)), list(reversed(links)))
    assert forward == reverse  # byte-identical regardless of input order


def test_vlan_name_resolved_from_l2_metadata():
    interfaces = [_trunk("sw-a", "Gi0/1", [10]), _svi("sw-b", 10)]
    links = [_svi_link("sw-a", "Gi0/1", ["10"], "sw-b", 10)]  # svi side names VLAN "X"
    v10 = [d for d in discover_l2_domains(interfaces, links) if d["vlan_id"] == 10]
    assert all(d["name"] == "X" for d in v10)
