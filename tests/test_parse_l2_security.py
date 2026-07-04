"""S10-1: config_parser l2_security section — DHCP snooping, port-security,
BPDU-guard, switchport-protected.

Synthetic IOS-XE config (grammar mirrors real IOS-XE switch shapes). Pure parser,
no Neo4j. storm-control is intentionally absent (cut on zero real evidence).
"""

from netcopilot.collect.config_parser import (
    _expand_vlan_list,
    _parse_l2_security,
    parse_security_config,
)

# A compact IOS-XE access switch: snooping global + trust uplink, an access port
# with port-security + bpduguard + protected, and a trunk uplink (trust only).
_CFG = """\
hostname acc-sw-01
!
ip dhcp snooping vlan 10,20,30-32
ip dhcp snooping
spanning-tree portfast bpduguard default
!
interface Port-channel1
 description uplink
 switchport mode trunk
 ip dhcp snooping trust
!
interface GigabitEthernet1/0/1
 description host port
 switchport access vlan 10
 switchport mode access
 switchport protected
 switchport port-security maximum 3
 switchport port-security violation restrict
 switchport port-security aging time 1
 switchport port-security
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport port-security
!
"""


def test_dhcp_snooping_parsed():
    l2 = _parse_l2_security(_CFG)
    d = l2["dhcp_snooping"]
    assert d["enabled"] is True
    assert d["vlans"] == [10, 20, 30, 31, 32]          # range expanded + sorted
    assert d["trust_interfaces"] == ["Port-channel1"]   # only the uplink is trusted


def test_port_security_parsed_with_fields():
    ps = _parse_l2_security(_CFG)["port_security"]
    assert set(ps) == {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}
    g1 = ps["GigabitEthernet1/0/1"]
    assert g1 == {"enabled": True, "maximum": 3, "violation": "restrict", "aging_time": 1}
    # Gi1/0/2 has the bare enable line only — no fabricated max/violation
    assert ps["GigabitEthernet1/0/2"] == {"enabled": True}


def test_bpduguard_global_and_per_interface():
    bg = _parse_l2_security(_CFG)["bpduguard"]
    assert bg["global_default"] is True
    assert bg["interfaces"] == ["GigabitEthernet1/0/1"]


def test_protected_ports():
    assert _parse_l2_security(_CFG)["protected"] == ["GigabitEthernet1/0/1"]


def test_empty_when_no_l2_security():
    # A router config with none of the features → empty section, not fabricated.
    assert _parse_l2_security("hostname r1\n!\nrouter bgp 65000\n") == {}


def test_expand_vlan_list():
    assert _expand_vlan_list("10") == [10]
    assert _expand_vlan_list("10,20") == [10, 20]
    assert _expand_vlan_list("30-32") == [30, 31, 32]
    assert _expand_vlan_list("bad") == []


def test_registered_as_16th_section_and_coverage():
    sc = parse_security_config(_CFG, os_family="ios-xe")
    assert sc["_parser_coverage"]["sections_attempted"] == 16
    assert sc["_parser_coverage"]["sections_detail"]["l2_security"] == "parsed"
    assert "l2_security" in sc


def test_section_empty_on_config_without_l2sec():
    sc = parse_security_config("hostname r1\n!\n", os_family="ios-xe")
    assert sc["_parser_coverage"]["sections_detail"]["l2_security"] == "empty"
    assert sc["l2_security"] == {}
