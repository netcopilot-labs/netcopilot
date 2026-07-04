"""S10-2: L2 edge-security rules — precise misconfig (HIGH/low) + absence (low/info).

Rules read the model (interfaces + links + device L2-sec fields). The critical
guard is over-firing: absence rules must never flag uplink/trunk ports. Synthetic
models; no Neo4j, no facts.
"""

from netcopilot.rules.rules.l2_edge_security import (
    L2SecAccessPortsNoBpduGuardRule,
    L2SecAccessPortsNoPortSecurityRule,
    L2SecAccessVlanNotSnoopedRule,
    L2SecDhcpTrustOnAccessRule,
    L2SecNoDhcpSnoopingRule,
    L2SecPortSecurityWeakViolationRule,
)


def _intf(dev, name, mode, vlan=None, **extra):
    d = {"interface_id": f"{dev}:{name}", "device_id": dev, "name": name, "switchport_mode": mode}
    if vlan is not None:
        d["access_vlan"] = vlan
    d.update(extra)
    return d


def _model():
    # sw-01: an access switch, snooping on VLAN 10 with trust on the uplink (OK)
    # AND on an access port (violation). Gi1/0/1 access vlan10, port-security
    # violation=protect. Gi1/0/2 access vlan20 (not snooped), no port-security,
    # no bpduguard. Gi1/0/24 is the trunk uplink (a link endpoint).
    devices = [{
        "device_id": "sw-01", "hostname": "sw-01",
        "dhcp_snooping": {"enabled": True, "vlans": [10], "trust_interfaces": ["Gi1/0/24", "Gi1/0/1"]},
    }]
    interfaces = [
        _intf("sw-01", "Gi1/0/24", "trunk"),  # uplink
        _intf("sw-01", "Gi1/0/1", "access", 10, port_security={"enabled": True, "violation": "protect"}),
        _intf("sw-01", "Gi1/0/2", "access", 20),   # vlan20 unsnooped
        _intf("sw-01", "Gi1/0/3", "access", 20),   # 2nd host port on vlan20 → ≥2 guard fires
    ]
    links = [{
        "local_device_id": "sw-01", "local_interface_id": "sw-01:Gi1/0/24",
        "remote_device_id": "core-01", "remote_interface_id": "core-01:Gi1/0/1",
    }]
    return {"devices": devices, "interfaces": interfaces, "links": links}


def _fire(rule_cls, model):
    return rule_cls().evaluate(model, {})


# ── precise ──────────────────────────────────────────────────────────────────

def test_dhcp_trust_on_access_fires_only_on_access_port():
    f = _fire(L2SecDhcpTrustOnAccessRule, _model())
    # trust on Gi1/0/1 (access) fires; trust on Gi1/0/24 (uplink) does NOT
    assert len(f) == 1
    assert "Gi1/0/1" in f[0].message and "Gi1/0/24" not in f[0].message


def test_port_security_weak_violation_fires():
    f = _fire(L2SecPortSecurityWeakViolationRule, _model())
    assert len(f) == 1 and "protect" in f[0].message and "Gi1/0/1" in f[0].message


def test_access_vlan_not_snooped_fires_for_vlan20_only():
    f = _fire(L2SecAccessVlanNotSnoopedRule, _model())
    # vlan10 is snooped; vlan20 is unsnooped with 2 host ports → fires once
    assert len(f) == 1 and "VLAN 20" in f[0].message and "2 host port" in f[0].message


def test_single_port_unsnooped_vlan_does_not_fire():
    # A lone access port on an unsnooped VLAN (e.g. an emergency mgmt port) is
    # noise, not a gap — the ≥2 host-port guard suppresses it. (S10 FP-tuning.)
    model = {
        "devices": [{"device_id": "sw-01", "hostname": "sw-01",
                     "dhcp_snooping": {"enabled": True, "vlans": [10]}}],
        "interfaces": [_intf("sw-01", "Gi1/0/20", "access", 1201, description="Emergency MGMT")],
        "links": [],
    }
    assert _fire(L2SecAccessVlanNotSnoopedRule, model) == []


# ── absence (aggregated per device) ──────────────────────────────────────────

def test_no_port_security_aggregates_and_excludes_uplink():
    f = _fire(L2SecAccessPortsNoPortSecurityRule, _model())
    # Gi1/0/2 + Gi1/0/3 lack port-security among the 3 host ports (uplink excluded)
    assert len(f) == 1 and "2/3" in f[0].message


def test_no_bpduguard_aggregates_both_host_ports():
    f = _fire(L2SecAccessPortsNoBpduGuardRule, _model())
    assert len(f) == 1 and "3/3" in f[0].message


def test_no_dhcp_snooping_does_not_fire_when_enabled():
    assert _fire(L2SecNoDhcpSnoopingRule, _model()) == []


# ── over-fire guards ─────────────────────────────────────────────────────────

def test_uplink_port_never_flagged_by_absence_rules():
    # A switch whose ONLY unprotected port is the trunk uplink → zero findings.
    model = {
        "devices": [{"device_id": "sw-01", "hostname": "sw-01"}],
        "interfaces": [_intf("sw-01", "Gi1/0/24", "trunk")],
        "links": [{"local_device_id": "sw-01", "local_interface_id": "sw-01:Gi1/0/24",
                   "remote_device_id": "core", "remote_interface_id": "core:Gi1/0/1"}],
    }
    assert _fire(L2SecAccessPortsNoPortSecurityRule, model) == []
    assert _fire(L2SecAccessPortsNoBpduGuardRule, model) == []
    assert _fire(L2SecNoDhcpSnoopingRule, model) == []


def test_router_with_no_access_ports_is_skipped():
    model = {
        "devices": [{"device_id": "rtr-01", "hostname": "rtr-01"}],
        "interfaces": [_intf("rtr-01", "Gi0/0/0", "routed")],
        "links": [],
    }
    for rule in (L2SecNoDhcpSnoopingRule, L2SecAccessPortsNoPortSecurityRule,
                 L2SecAccessPortsNoBpduGuardRule):
        assert _fire(rule, model) == []


def test_global_bpduguard_default_suppresses_absence():
    model = {
        "devices": [{"device_id": "sw-01", "hostname": "sw-01", "bpduguard_default": True}],
        "interfaces": [_intf("sw-01", "Gi1/0/1", "access", 10)],
        "links": [],
    }
    assert _fire(L2SecAccessPortsNoBpduGuardRule, model) == []


def test_no_dhcp_snooping_fires_when_absent():
    model = {
        "devices": [{"device_id": "sw-01", "hostname": "sw-01"}],  # no dhcp_snooping
        "interfaces": [_intf("sw-01", "Gi1/0/1", "access", 10)],
        "links": [],
    }
    f = _fire(L2SecNoDhcpSnoopingRule, model)
    assert len(f) == 1 and "disabled" in f[0].message.lower()
