"""F2-5-final: protocol discovery — running-config text → Genie families."""

from netcopilot.collect.protocol_discovery import ALWAYS_COLLECT, discover_protocols

CORE = sorted(ALWAYS_COLLECT)


def test_empty_config_returns_core_set_only():
    assert discover_protocols("") == CORE
    assert discover_protocols("   \n  \n") == CORE


def test_none_like_empty_is_core_set():
    assert discover_protocols(None) == CORE  # type: ignore[arg-type]


def test_iosxe_switch_detects_configured_families():
    config = "\n".join([
        "hostname core-sw-01",
        "spanning-tree mode rapid-pvst",
        "vlan 10",
        "ntp server 192.0.2.200",
        "interface Vlan10",
        " standby 1 ip 192.0.2.1",
        "router ospf 1",
        "router bgp 65001",
    ])
    families = discover_protocols(config)
    for expected in ("ospf", "bgp", "vlan", "stp", "hsrp", "ntp"):
        assert expected in families
    # core families always present
    assert set(CORE).issubset(families)


def test_iosxr_router_detects_xr_syntax():
    config = "\n".join([
        "router isis CORE",
        "router bgp 65001",
        "router static",
        "router hsrp",
        "vrf MGMT",
    ])
    families = discover_protocols(config)
    for expected in ("isis", "bgp", "static_routing", "hsrp", "vrf"):
        assert expected in families
    # IOS XR is L3-only — no spanning tree / vlan keywords
    assert "stp" not in families
    assert "vlan" not in families


def test_no_false_positives_for_unconfigured_protocols():
    config = "hostname edge-rtr-01\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0"
    families = discover_protocols(config)
    for absent in ("ospf", "bgp", "isis", "lisp", "vxlan", "pim"):
        assert absent not in families
    # but the core set is still there
    assert families == CORE


def test_multicast_routing_fires_both_pim_and_mcast():
    config = "ip multicast-routing\n"
    families = discover_protocols(config)
    assert "pim" in families
    assert "mcast" in families


def test_switchport_mode_triggers_vlan_without_explicit_vlan_db():
    config = "interface GigabitEthernet1/0/1\n switchport mode trunk\n"
    assert "vlan" in discover_protocols(config)


def test_result_is_sorted_and_deduplicated():
    config = "router ospf 1\nrouter ospf 2\nvlan 10\nvlan 20\n"
    families = discover_protocols(config)
    assert families == sorted(families)
    assert len(families) == len(set(families))
