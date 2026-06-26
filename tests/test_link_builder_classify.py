"""F2-5l: link_builder link-type + management classification.

classify_link_type maps a (post-dedup, post-enrichment) link to one of
physical / management / infrastructure / l3_reachability / subnet_association
via an ordered rule table; classify_mgmt_type splits management links into
oob / inband. Synthetic link dicts + role maps.
"""

from netcopilot.model.link_builder import (
    _get_link_access_vlan,
    _intf_carries_mgmt_vlan,
    _is_mgmt_port_name,
    classify_link_type,
    classify_mgmt_type,
)


def _link(method="cdp_bilateral", local="core-rtr-01", remote="dist-sw-01",
          local_intf="Gi0/0", remote_intf="Gi1/0/1", dp=1, **extra):
    d = {
        "discovery_method": method,
        "local_device_id": local, "remote_device_id": remote,
        "local_interface_id": f"{local}:{local_intf}",
        "remote_interface_id": f"{remote}:{remote_intf}",
        "discovery_priority": dp,
    }
    d.update(extra)
    return d


# =========================================================================
# helpers
# =========================================================================
def test_get_link_access_vlan():
    access = {"l2": {"local": {"mode": "access", "vlan": {"id": 99}}}}
    assert _get_link_access_vlan(access) == 99
    trunk = {"l2": {"local": {"mode": "trunk"}}}
    assert _get_link_access_vlan(trunk) is None
    assert _get_link_access_vlan({}) is None


def test_is_mgmt_port_name():
    for i in ("core-rtr-01:Gi0/0", "core-rtr-01:GigabitEthernet0/0",
              "core-rtr-01:MgmtEth0/RP0/CPU0/0", "Management1"):
        assert _is_mgmt_port_name(i) is True
    for i in ("core-rtr-01:Gi1/0/1", "core-rtr-01:Hu0/0/1/0"):
        assert _is_mgmt_port_name(i) is False


def test_intf_carries_mgmt_vlan():
    intf_by_id = {
        "sw:Gi1/0/1": {"trunk_vlans": [10, 99]},
        "sw:Gi1/0/2": {"access_vlan": 99},
        "sw:Gi1/0/3": {"access_vlan": 10},
    }
    assert _intf_carries_mgmt_vlan("sw:Gi1/0/1", intf_by_id, {99}) is True
    assert _intf_carries_mgmt_vlan("sw:Gi1/0/2", intf_by_id, {99}) is True
    assert _intf_carries_mgmt_vlan("sw:Gi1/0/3", intf_by_id, {99}) is False
    assert _intf_carries_mgmt_vlan("sw:absent", intf_by_id, {99}) is False


# =========================================================================
# classify_link_type — by priority
# =========================================================================
def test_p0_access_vlan_not_mgmt_is_physical():
    link = _link(method="cdp_bilateral", remote="mgmt-sw-01",
                 l2={"local": {"mode": "access", "vlan": {"id": 94}}})
    role = {"mgmt-sw-01": "mgmt_switch"}
    # VLAN 94 not in mgmt_vlans {99} → physical despite mgmt_switch endpoint
    assert classify_link_type(link, role, set(), set(), {99}) == "physical"


def test_p1a_mgmt_switch_l3_mgmt_port():
    link = _link(method="arp_subnet", local="core-rtr-01", remote="mgmt-sw-01",
                 local_intf="Gi0/0", dp=7)
    role = {"mgmt-sw-01": "mgmt_switch", "core-rtr-01": "core"}
    assert classify_link_type(link, role, set(), set()) == "management"


def test_p1a_mgmt_switch_l3_virtual_is_l3reach():
    link = _link(method="arp_subnet", local="core-rtr-01", remote="mgmt-sw-01",
                 local_intf="Vlan99", dp=7)
    role = {"mgmt-sw-01": "mgmt_switch", "core-rtr-01": "core"}
    assert classify_link_type(link, role, set(), set()) == "l3_reachability"


def test_p1b_mgmt_switch_cable_mgmt_port():
    link = _link(method="cdp_bilateral", local="core-rtr-01", remote="mgmt-sw-01",
                 local_intf="Gi0/0", dp=1)
    role = {"mgmt-sw-01": "mgmt_switch", "core-rtr-01": "core"}
    assert classify_link_type(link, role, set(), set()) == "management"


def test_p1c_mgmt_switch_cable_carries_mgmt_vlan_is_infra():
    link = _link(method="cdp_bilateral", local="dist-sw-01", remote="mgmt-sw-01",
                 local_intf="Gi1/0/1", remote_intf="Gi1/0/2", dp=1)
    role = {"mgmt-sw-01": "mgmt_switch", "dist-sw-01": "distribution"}
    intf_by_id = {"dist-sw-01:Gi1/0/1": {"trunk_vlans": [99]}}
    assert classify_link_type(link, role, set(), set(), {99}, intf_by_id) == "infrastructure"


def test_p1d_mgmt_switch_confirmed_cable_no_mgmt_vlan_is_physical():
    link = _link(method="cdp_bilateral", local="dist-sw-01", remote="mgmt-sw-01",
                 local_intf="Gi1/0/1", remote_intf="Gi1/0/2", dp=1)
    role = {"mgmt-sw-01": "mgmt_switch", "dist-sw-01": "distribution"}
    assert classify_link_type(link, role, set(), set(), {99}, {}) == "physical"


def test_p2_mgmt_interface_confirmed_is_management():
    link = _link(method="cdp_bilateral", local_intf="Gi0/0")
    mgmt_ifaces = {"core-rtr-01:Gi0/0"}
    assert classify_link_type(link, {}, set(), mgmt_ifaces) == "management"


def test_p2_mgmt_interface_unconfirmed_is_l3reach():
    link = _link(method="arp_subnet", local_intf="Gi0/0", dp=7)
    mgmt_ifaces = {"core-rtr-01:Gi0/0"}
    assert classify_link_type(link, {}, set(), mgmt_ifaces) == "l3_reachability"


def test_p2_mgmt_subnet_is_management():
    link = _link(method="arp_subnet", l3={"subnet": "192.0.2.0/24"}, dp=7)
    assert classify_link_type(link, {}, {"192.0.2.0/24"}, set()) == "management"


def test_p3_subnet_only_is_association():
    link = _link(method="subnet_only", dp=11)
    assert classify_link_type(link, {}, set(), set()) == "subnet_association"


def test_p4_virtual_interface_is_l3reach():
    link = _link(method="cdp_bilateral", local_intf="Loopback0")
    assert classify_link_type(link, {}, set(), set()) == "l3_reachability"


def test_p5_confirmed_cable_is_physical():
    assert classify_link_type(_link(method="cdp_bilateral"), {}, set(), set()) == "physical"


def test_p6_unconfirmed_is_l3reach():
    assert classify_link_type(_link(method="mac_subnet", dp=9), {}, set(), set()) == "l3_reachability"


# =========================================================================
# classify_mgmt_type
# =========================================================================
def test_mgmt_type_none_for_non_management():
    assert classify_mgmt_type({"link_type": "physical"}, {}) is None


def test_mgmt_type_mgmt_switch_is_oob():
    link = {"link_type": "management", "local_device_id": "core-rtr-01",
            "remote_device_id": "mgmt-sw-01"}
    assert classify_mgmt_type(link, {"mgmt-sw-01": "mgmt_switch"}) == "oob"


def test_mgmt_type_both_oob():
    link = {"link_type": "management", "local_device_id": "a", "remote_device_id": "b",
            "local_interface_id": "a:Gi1/0/1", "remote_interface_id": "b:Gi1/0/1"}
    assert classify_mgmt_type(link, {}, {"a", "b"}) == "oob"


def test_mgmt_type_one_oob_is_inband():
    link = {"link_type": "management", "local_device_id": "a", "remote_device_id": "b",
            "local_interface_id": "a:Gi1/0/1", "remote_interface_id": "b:Gi1/0/1"}
    assert classify_mgmt_type(link, {}, {"a"}) == "inband"


def test_mgmt_type_mgmt_port_name_is_oob():
    link = {"link_type": "management", "local_device_id": "a", "remote_device_id": "b",
            "local_interface_id": "a:Mgmt0", "remote_interface_id": "b:Gi1/0/1"}
    assert classify_mgmt_type(link, {}) == "oob"


def test_mgmt_type_default_inband():
    link = {"link_type": "management", "local_device_id": "a", "remote_device_id": "b",
            "local_interface_id": "a:Gi1/0/1", "remote_interface_id": "b:Gi1/0/2"}
    assert classify_mgmt_type(link, {}) == "inband"
