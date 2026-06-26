"""L2 view trunk membership (#3 fix): an UNFILTERED trunk carries all VLANs.

A switch with no access ports but an unfiltered ("all VLANs") trunk is a transit
member of every VLAN and must appear when that VLAN is selected. The model
represents an unfiltered trunk as trunk_vlans=None, an explicit filter as a list,
and "allowed vlan none" as [].
"""

from netcopilot.dashboard.backend.routes.topology import _trunk_carries_vlan


def test_unfiltered_trunk_carries_every_vlan():
    # trunk_vlans is None → no allowed-vlan filter → carries ALL VLANs (the fix)
    assert _trunk_carries_vlan(None, 10) is True
    assert _trunk_carries_vlan(None, 4094) is True


def test_explicit_trunk_carries_only_listed():
    assert _trunk_carries_vlan([10, 20], 10) is True
    assert _trunk_carries_vlan([10, 20], 30) is False


def test_explicit_none_carries_nothing():
    # `switchport trunk allowed vlan none` → [] → carries no VLAN
    assert _trunk_carries_vlan([], 10) is False


def test_string_vlan_ids_are_handled():
    assert _trunk_carries_vlan(["10", "20"], 20) is True
    assert _trunk_carries_vlan(["10", "20"], 99) is False


def test_garbage_entries_are_skipped():
    assert _trunk_carries_vlan([None, "x", 10], 10) is True
    assert _trunk_carries_vlan([None, "x"], 10) is False
