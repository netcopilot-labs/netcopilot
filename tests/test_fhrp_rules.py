"""S20-3 — the 14 FHRP rules fire on crafted failures and stay quiet on a healthy pair."""
from netcopilot.rules.rules import fhrp_health as F


def _member(host, **kw):
    m = dict(hostname=host, interface="Vlan60", priority=120, state="active",
             preempt=True, version=2, hello_sec=3, hold_sec=10, tracked=True,
             authenticated=True, adv_interval=1.0)
    m.update(kw)
    return m


def _group(protocol="hsrp", vip="198.51.100.129", group_number=60, members=None,
           active_device="core"):
    return {"service_type": "fhrp_group", "protocol": protocol, "vip": vip,
            "group_number": group_number, "interface": "Vlan60",
            "members": members, "active_device": active_device}


def _model(group, interfaces=None):
    return {"shared_services": [group], "interfaces": interfaces or [], "devices": []}


def _model_with_iface(group, host, ip, prefix):
    return {
        "shared_services": [group],
        "devices": [{"device_id": host, "hostname": host}],
        "interfaces": [{"device_id": host, "name": "Vlan60",
                        "ip_address": ip, "prefix_length": prefix}],
    }


def _fires(rule, model):
    return [f.rule_id for f in rule.evaluate(model, {})]


# --- HSRP -------------------------------------------------------------------
def test_hsrp_group_not_active():
    g = _group(members=[_member("core", state="init"), _member("acc", state="listen")])
    assert "HSRP_GROUP_NOT_ACTIVE" in _fires(F.HsrpGroupNotActiveRule(), _model(g))


def test_hsrp_no_standby_peer():
    g = _group(members=[_member("core", state="active")])
    assert "HSRP_NO_STANDBY_PEER" in _fires(F.HsrpNoStandbyPeerRule(), _model(g))


def test_hsrp_preempt_disabled():
    g = _group(members=[_member("core", preempt=False), _member("acc", state="standby")])
    assert "HSRP_PREEMPT_DISABLED" in _fires(F.HsrpPreemptDisabledRule(), _model(g))


def test_hsrp_tracking_missing():
    g = _group(members=[_member("core", tracked=False)])
    assert "HSRP_TRACKING_MISSING" in _fires(F.HsrpTrackingMissingRule(), _model(g))


def test_hsrp_auth_missing():
    g = _group(members=[_member("core", authenticated=False)])
    assert "HSRP_AUTH_MISSING" in _fires(F.HsrpAuthMissingRule(), _model(g))


def test_hsrp_vip_not_in_subnet():
    g = _group(vip="198.51.100.129", members=[_member("core")])
    model = _model_with_iface(g, "core", "10.0.0.1", 24)   # vip not in 10.0.0.0/24
    assert "HSRP_VIP_NOT_IN_SUBNET" in _fires(F.HsrpVipNotInSubnetRule(), model)


def test_hsrp_priority_conflict():
    g = _group(members=[_member("core", priority=120), _member("acc", state="standby", priority=120)])
    assert "HSRP_PRIORITY_CONFLICT" in _fires(F.HsrpPriorityConflictRule(), _model(g))


def test_hsrp_hello_timer_mismatch():
    g = _group(members=[_member("core", hello_sec=3), _member("acc", state="standby", hello_sec=5)])
    assert "HSRP_HELLO_TIMER_MISMATCH" in _fires(F.HsrpHelloTimerMismatchRule(), _model(g))


def test_hsrp_version_mismatch():
    g = _group(members=[_member("core", version=2), _member("acc", state="standby", version=1)])
    assert "HSRP_VERSION_MISMATCH" in _fires(F.HsrpVersionMismatchRule(), _model(g))


# --- VRRP -------------------------------------------------------------------
def test_vrrp_group_not_master():
    g = _group(protocol="vrrp", vip="198.51.100.145", group_number=61, active_device=None,
               members=[_member("core", state="backup"), _member("acc", state="backup")])
    assert "VRRP_GROUP_NOT_MASTER" in _fires(F.VrrpGroupNotMasterRule(), _model(g))


def test_vrrp_priority_conflict():
    g = _group(protocol="vrrp", members=[_member("core", state="master", priority=120),
                                         _member("acc", state="backup", priority=120)])
    assert "VRRP_PRIORITY_CONFLICT" in _fires(F.VrrpPriorityConflictRule(), _model(g))


def test_vrrp_adv_interval_mismatch():
    g = _group(protocol="vrrp", members=[_member("core", state="master", adv_interval=1.0),
                                         _member("acc", state="backup", adv_interval=3.0)])
    assert "VRRP_ADVERTISEMENT_INTERVAL_MISMATCH" in _fires(F.VrrpAdvIntervalMismatchRule(), _model(g))


def test_vrrp_preempt_disabled():
    g = _group(protocol="vrrp", members=[_member("core", state="master", preempt=False)])
    assert "VRRP_PREEMPT_DISABLED" in _fires(F.VrrpPreemptDisabledRule(), _model(g))


def test_vrrp_vip_not_in_subnet():
    g = _group(protocol="vrrp", vip="198.51.100.145", members=[_member("core", state="master")])
    model = _model_with_iface(g, "core", "10.0.0.1", 24)
    assert "VRRP_VIP_NOT_IN_SUBNET" in _fires(F.VrrpVipNotInSubnetRule(), model)


# --- healthy pair: no critical/high false positives -------------------------
def test_healthy_pair_no_critical_findings():
    hsrp = _group(members=[_member("core", state="active", priority=120),
                           _member("acc", state="standby", priority=100)])
    model = _model_with_iface(hsrp, "core", "198.51.100.130", 28)   # vip .129 in .128/28
    model["interfaces"].append({"device_id": "acc", "name": "Vlan60",
                                "ip_address": "198.51.100.131", "prefix_length": 28})
    model["devices"].append({"device_id": "acc", "hostname": "acc"})
    for rule_cls in (F.HsrpGroupNotActiveRule, F.HsrpNoStandbyPeerRule,
                     F.HsrpVipNotInSubnetRule, F.HsrpPriorityConflictRule,
                     F.HsrpHelloTimerMismatchRule, F.HsrpVersionMismatchRule):
        assert _fires(rule_cls(), model) == [], rule_cls.rule_id
