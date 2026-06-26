"""F2-5m: link_builder management-subnet detection + inband-link synthesis.

detect_management_subnets derives mgmt subnets/interfaces/VLANs from model data;
compute_oob_device_names flags devices whose management_ip is in a mgmt subnet;
create_inband_mgmt_links traces the L2 VLAN path (leaf → hub → upstream →
gateway) for inband-managed devices using genie_routing.json. Synthetic data.
"""

import json

from netcopilot.model.link_builder import (
    _find_mgmt_vrf_context,
    _safe_ip_network,
    compute_oob_device_names,
    create_inband_mgmt_links,
    detect_management_subnets,
)

# genie_routing.json: MGMT VRF, mgmt_ip connected via Vlan99, default → 192.0.2.1
ROUTING = {"vrf": {"MGMT": {"address_family": {"ipv4": {"routes": {
    "192.0.2.0/24": {"source_protocol": "connected",
                     "next_hop": {"outgoing_interface": {"Vlan99": {}}}},
    "0.0.0.0/0": {"next_hop": {"next_hop_list": {"1": {"next_hop": "192.0.2.1"}}}},
}}}}}}


# =========================================================================
# _safe_ip_network
# =========================================================================
def test_safe_ip_network():
    assert str(_safe_ip_network("192.0.2.0/24")) == "192.0.2.0/24"
    assert str(_safe_ip_network("192.0.2.5/24")) == "192.0.2.0/24"   # strict=False
    assert _safe_ip_network("not-a-subnet") is None


# =========================================================================
# detect_management_subnets
# =========================================================================
def test_detect_management_subnets():
    devices = [{"device_id": "core-rtr-01", "management_ip": "192.0.2.10"}]
    interfaces = [{
        "interface_id": "core-rtr-01:Vlan99", "ip_address": "192.0.2.10/24",
        "name": "Vlan99",
    }]
    subnets, iface_ids, vlans = detect_management_subnets(devices, interfaces, [])
    assert subnets == {"192.0.2.0/24"}
    assert iface_ids == {"core-rtr-01:Vlan99"}
    assert vlans == {99}


def test_detect_management_subnets_no_mgmt_ip():
    assert detect_management_subnets([{"device_id": "a"}], [], []) == (set(), set(), set())


# =========================================================================
# compute_oob_device_names
# =========================================================================
def test_compute_oob_device_names():
    devices = [
        {"device_id": "a", "management_ip": "192.0.2.10"},   # in mgmt subnet → OOB
        {"device_id": "b", "management_ip": "198.51.100.5"},  # elsewhere → inband
    ]
    assert compute_oob_device_names(devices, {"192.0.2.0/24"}) == {"a"}


def test_compute_oob_empty_subnets():
    assert compute_oob_device_names([{"device_id": "a", "management_ip": "192.0.2.1"}], set()) == set()


# =========================================================================
# _find_mgmt_vrf_context
# =========================================================================
def test_find_mgmt_vrf_context():
    assert _find_mgmt_vrf_context(ROUTING, "192.0.2.10") == ("192.0.2.1", "MGMT", 99)


def test_find_mgmt_vrf_context_no_match():
    assert _find_mgmt_vrf_context(ROUTING, "203.0.113.5") is None
    assert _find_mgmt_vrf_context(ROUTING, "not-an-ip") is None


# =========================================================================
# create_inband_mgmt_links
# =========================================================================
def _routing_dir(tmp_path, name):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "genie_routing.json").write_text(json.dumps(ROUTING))
    return d


def test_inband_direct_gateway_no_physical(tmp_path):
    """Inband device with no physical infra neighbor → one direct gateway link."""
    devices = [{"device_id": "leaf-sw-01", "management_ip": "192.0.2.10"}]
    facts_dirs = {"leaf-sw-01": _routing_dir(tmp_path, "leaf-sw-01")}
    all_ips = {"192.0.2.1": "core-rtr-01"}   # gateway IP → device
    links = create_inband_mgmt_links(
        devices, set(), set(), facts_dirs, all_ips, links=[], interfaces=[],
    )
    assert len(links) == 1
    link = links[0]
    assert link["local_device_id"] == "leaf-sw-01"
    assert link["remote_device_id"] == "core-rtr-01"
    assert link["link_type"] == "management" and link["mgmt_type"] == "inband"
    assert link["discovery_method"] == "inband_vlan_path"
    assert link["mgmt_vlan"] == 99 and link["mgmt_vrf"] == "MGMT"


def test_inband_hop_via_physical_upstream(tmp_path):
    """Inband device with a physical infra neighbor → device→upstream→gateway hops."""
    devices = [
        {"device_id": "leaf-sw-01", "management_ip": "192.0.2.10"},
        {"device_id": "dist-sw-01"},   # infra upstream
    ]
    facts_dirs = {"leaf-sw-01": _routing_dir(tmp_path, "leaf-sw-01")}
    all_ips = {"192.0.2.1": "core-rtr-01"}
    phys = [{"link_type": "physical", "local_device_id": "leaf-sw-01",
             "remote_device_id": "dist-sw-01"}]
    links = create_inband_mgmt_links(
        devices, set(), set(), facts_dirs, all_ips, links=phys, interfaces=[],
    )
    pairs = {(l["local_device_id"], l["remote_device_id"]) for l in links}
    assert ("leaf-sw-01", "dist-sw-01") in pairs   # hub → upstream
    assert ("dist-sw-01", "core-rtr-01") in pairs    # upstream → gateway


def test_inband_skips_oob_device(tmp_path):
    devices = [{"device_id": "leaf-sw-01", "management_ip": "192.0.2.10"}]
    facts_dirs = {"leaf-sw-01": _routing_dir(tmp_path, "leaf-sw-01")}
    links = create_inband_mgmt_links(
        devices, {"leaf-sw-01"}, set(), facts_dirs, {"192.0.2.1": "core-rtr-01"},
        links=[], interfaces=[],
    )
    assert links == []


def test_inband_skips_existing_mgmt_source(tmp_path):
    devices = [{"device_id": "leaf-sw-01", "management_ip": "192.0.2.10"}]
    facts_dirs = {"leaf-sw-01": _routing_dir(tmp_path, "leaf-sw-01")}
    links = create_inband_mgmt_links(
        devices, set(), {"leaf-sw-01"}, facts_dirs, {"192.0.2.1": "core-rtr-01"},
        links=[], interfaces=[],
    )
    assert links == []


def test_inband_no_routing_file(tmp_path):
    devices = [{"device_id": "leaf-sw-01", "management_ip": "192.0.2.10"}]
    empty = tmp_path / "leaf-sw-01"
    empty.mkdir()
    links = create_inband_mgmt_links(
        devices, set(), set(), {"leaf-sw-01": empty}, {"192.0.2.1": "core-rtr-01"},
        links=[], interfaces=[],
    )
    assert links == []
