"""R2-VLAN-1: trunk allowed-VLAN parsing in VLAN_NO_INTERFACES.

The rule's _get_trunk_vlans_from_config must collect the base
"switchport trunk allowed vlan" line AND every "... allowed vlan add"
continuation line (the previous re.search read only the first line, dropping
'add' continuations → under-counted carried VLANs → false-positive findings).
"""

from netcopilot.rules.rules.vlan_no_interfaces import _get_trunk_vlans_from_config


def test_trunk_allowed_vlan_add_continuations_are_unioned():
    """Base line + two 'add' lines → union of all three (the bug fix)."""
    config = (
        "interface TenGigabitEthernet1/0/1\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan 200,201,209-211\n"
        " switchport trunk allowed vlan add 300,301\n"
        " switchport trunk allowed vlan add 400\n"
        "!\n"
    )
    vlans = _get_trunk_vlans_from_config(config)
    assert vlans == {200, 201, 209, 210, 211, 300, 301, 400}


def test_trunk_unfiltered_returns_none():
    """A trunk with no explicit allowed-vlan line carries ALL VLANs → None."""
    config = (
        "interface TenGigabitEthernet1/0/2\n"
        " switchport mode trunk\n"
        "!\n"
    )
    assert _get_trunk_vlans_from_config(config) is None


def test_no_trunk_returns_empty():
    """No trunk interfaces at all → empty set (nothing carried)."""
    config = (
        "interface GigabitEthernet1/0/3\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
    )
    assert _get_trunk_vlans_from_config(config) == set()


def test_multiple_trunks_one_unfiltered_wins_none():
    """If any trunk is unfiltered, the device carries all VLANs → None."""
    config = (
        "interface Te1/0/1\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan 10,20\n"
        "!\n"
        "interface Te1/0/2\n"
        " switchport mode trunk\n"   # no allowed-vlan line → unfiltered
        "!\n"
    )
    assert _get_trunk_vlans_from_config(config) is None
