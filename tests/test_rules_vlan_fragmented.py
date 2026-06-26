"""VLAN_FRAGMENTED fires when one VLAN id forms 2+ separate L2 broadcast domains."""

from netcopilot.rules.cross_device.interface_rules import _check_vlan_fragmented


def _dom(vlan, members, dom_id):
    return {"vlan_id": vlan, "id": dom_id, "member_devices": members,
            "access_ports": [], "trunk_links": [], "svis": []}


def test_fires_when_vlan_split_into_two_domains():
    domains = [
        _dom(10, ["acc-sw-01"], "vlan10-dom0"),                  # isolated island
        _dom(10, ["acc-sw-03", "core-sw-01"], "vlan10-dom1"),    # trunked island
        _dom(20, ["acc-sw-03", "core-sw-01"], "vlan20-dom0"),    # clean
    ]
    findings = _check_vlan_fragmented(domains)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "VLAN_FRAGMENTED"
    assert f.evidence["key_facts"]["vlan_id"] == "10"
    assert f.evidence["key_facts"]["domain_count"] == 2
    assert f.evidence["key_facts"]["domains"] == [
        ["acc-sw-01"], ["acc-sw-03", "core-sw-01"]
    ]
    # flat device list — the loader attaches the finding to these
    assert f.evidence["key_facts"]["devices"] == [
        "acc-sw-01", "acc-sw-03", "core-sw-01"
    ]
    assert f.evidence["element_id"] == "vlan_fragmented::10"


def test_silent_when_every_vlan_is_one_domain():
    domains = [_dom(10, ["a", "b"], "vlan10-dom0"), _dom(20, ["a"], "vlan20-dom0")]
    assert _check_vlan_fragmented(domains) == []


def test_silent_on_empty_or_none():
    assert _check_vlan_fragmented([]) == []
    assert _check_vlan_fragmented(None) == []
