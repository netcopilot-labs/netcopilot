"""STP_ROOT_BRIDGE_CONFLICT must be scoped to an L2 broadcast domain.

Two switches that both claim root for a VLAN at the same priority are only a
real conflict when they are in the SAME broadcast domain. Routed-apart switches
(same VLAN id, separate domains) are each legitimately their own root — the
false positive the ID-based grouping produced (verified on the demo, where
``acc-sw-01`` is isolated behind the firewall).
"""

from netcopilot.rules.cross_device.interface_rules import _check_stp_root_conflict


def _stp_root(vlan, priority, addr):
    """genie_stp for a device that claims STP root for ``vlan`` (its own bridge
    address == the designated-root address)."""
    return {"genie_stp": {"rapid_pvst": {"default": {"vlans": {str(vlan): {
        "bridge_priority": priority, "bridge_address": addr,
        "designated_root_priority": priority, "designated_root_address": addr,
    }}}}}}


def _dom(vlan, members):
    return {"vlan_id": vlan, "member_devices": list(members)}


# Both switches claim root for VLAN 10 at the same priority.
_FACTS = {
    "sw-a": _stp_root(10, 32768, "aaaa.aaaa.aaaa"),
    "sw-b": _stp_root(10, 32768, "bbbb.bbbb.bbbb"),
}


def test_same_domain_dual_root_fires():
    # Both in ONE broadcast domain -> a genuine contested root election.
    domains = [_dom(10, ["sw-a", "sw-b"])]
    findings = _check_stp_root_conflict(_FACTS, domains)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "STP_ROOT_BRIDGE_CONFLICT"
    assert f.evidence["key_facts"]["devices"] == ["sw-a", "sw-b"]


def test_cross_domain_same_vlan_is_silent():
    # Same VLAN id, but two SEPARATE domains (routed apart) -> not a conflict.
    domains = [_dom(10, ["sw-a"]), _dom(10, ["sw-b"])]
    assert _check_stp_root_conflict(_FACTS, domains) == []


def test_same_domain_different_priority_is_silent():
    # A clear single root (different priorities) is never a conflict.
    facts = {
        "sw-a": _stp_root(10, 4096, "aaaa.aaaa.aaaa"),
        "sw-b": _stp_root(10, 32768, "bbbb.bbbb.bbbb"),
    }
    assert _check_stp_root_conflict(facts, [_dom(10, ["sw-a", "sw-b"])]) == []


def test_no_domain_for_vlan_is_silent():
    # VLAN has no L2 broadcast domain at all (e.g. not switched / pruned off the
    # trunks) -> claimants cannot contend -> no finding.
    assert _check_stp_root_conflict(_FACTS, [_dom(20, ["sw-a", "sw-b"])]) == []


def test_legacy_none_falls_back_to_global():
    # Backward-compat: a caller that does not thread l2_domains keeps the old
    # global grouping (so the rule still fires rather than silently going dark).
    findings = _check_stp_root_conflict(_FACTS, None)
    assert len(findings) == 1
