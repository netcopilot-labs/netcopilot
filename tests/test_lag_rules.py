"""S22-4: LAG health rules — one crafted failure per rule + healthy-pair negative.

Facts-first rules: each test writes genie_lag.json (and friends) into a tmp
run dir shaped exactly like the live campus-ha capture (verified 2026-07-11).
"""
from __future__ import annotations

import json

import pytest

from netcopilot.rules.rules.lag_health import (
    LagBundleOperDownRule,
    LagLacpSystemIdMismatchRule,
    LagMemberCountMismatchRule,
    LagMemberNotBundledRule,
    LagMemberSpeedInconsistentRule,
    LagMinLinksNotMetRule,
    LagStaticBundleRule,
    StpEtherchannelMisconfigGuardDisabledRule,
)


def _member(bundled=True, partner="0c00.017d.1a00"):
    return {"interface": "x", "bundled": bundled, "activity": "active",
            "lacp_port_priority": 32768, "partner_id": partner, "oper_key": 1}


def _write(tmp_path, host, lag=None, stp=None, config=None):
    d = tmp_path / "facts" / host
    d.mkdir(parents=True, exist_ok=True)
    if lag is not None:
        (d / "genie_lag.json").write_text(json.dumps(lag))
    if stp is not None:
        (d / "genie_stp.json").write_text(json.dumps(stp))
    if config is not None:
        (d / "running_config.txt").write_text(config)


def _model(*hosts, interfaces=None, links=None):
    return {"devices": [{"hostname": h, "os_family": "iosxe"} for h in hosts],
            "interfaces": interfaces or [], "links": links or []}


def _ctx(tmp_path):
    return {"run_path": str(tmp_path)}


def _lag(po="Port-channel1", protocol="lacp", oper="up", members=None):
    return {"system_priority": 32768, "interfaces": {po: {
        "name": po, "bundle_id": 1, "protocol": protocol, "oper_status": oper,
        "members": members if members is not None else
        {"GigabitEthernet1/0/1": _member()},
    }}}


# ── Healthy pair (campus-ha shape): NO rule fires ────────────────────────────


HEALTHY_RULES = [
    LagBundleOperDownRule, LagMemberNotBundledRule, LagStaticBundleRule,
    LagMemberSpeedInconsistentRule, LagMinLinksNotMetRule,
    LagLacpSystemIdMismatchRule, LagMemberCountMismatchRule,
]


@pytest.mark.parametrize("rule_cls", HEALTHY_RULES)
def test_healthy_pair_fires_nothing(tmp_path, rule_cls):
    _write(tmp_path, "core-sw-01", lag=_lag(), config="interface Port-channel1\n")
    _write(tmp_path, "acc-sw-03", lag=_lag(), config="interface Port-channel1\n")
    model = _model("core-sw-01", "acc-sw-03", links=[{
        "local_interface_id": "core-sw-01:Po1",
        "remote_interface_id": "acc-sw-03:Po1"}])
    assert rule_cls().evaluate(model, _ctx(tmp_path)) == []


# ── One crafted failure per rule ─────────────────────────────────────────────


def test_bundle_oper_down(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(oper="down"))
    f = LagBundleOperDownRule().evaluate(_model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and f[0].severity == "critical"
    assert "operationally down" in f[0].message


def test_member_not_bundled(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(members={
        "Gi1/0/1": _member(bundled=True), "Gi1/0/2": _member(bundled=False)}))
    f = LagMemberNotBundledRule().evaluate(_model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and "NOT bundled" in f[0].message


def test_static_bundle(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(protocol=None))
    f = LagStaticBundleRule().evaluate(_model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and "without a negotiation protocol" in f[0].message


def test_member_speed_inconsistent(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(members={
        "GigabitEthernet1/0/1": _member(), "GigabitEthernet1/0/2": _member()}))
    interfaces = [
        {"device_id": "sw1", "name": "Gi1/0/1", "speed": "1000mb/s"},
        {"device_id": "sw1", "name": "Gi1/0/2", "speed": "100mb/s"},
    ]
    f = LagMemberSpeedInconsistentRule().evaluate(
        _model("sw1", interfaces=interfaces), _ctx(tmp_path))
    assert len(f) == 1 and f[0].severity == "critical"


def test_min_links_not_met(tmp_path):
    config = "interface Port-channel1\n port-channel min-links 2\n!\n"
    _write(tmp_path, "sw1", lag=_lag(members={
        "Gi1/0/1": _member(bundled=True), "Gi1/0/2": _member(bundled=False)}),
        config=config)
    f = LagMinLinksNotMetRule().evaluate(_model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and "below the configured min-links 2" in f[0].message


def test_min_links_absent_means_silent(tmp_path):
    # No minimum declared -> nothing to be "not met" (never invented).
    _write(tmp_path, "sw1", lag=_lag(members={"Gi1/0/1": _member(bundled=False)}),
           config="interface Port-channel1\n!\n")
    assert LagMinLinksNotMetRule().evaluate(_model("sw1"), _ctx(tmp_path)) == []


def test_partner_system_id_mismatch(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(members={
        "Gi1/0/1": _member(partner="0c00.aaaa.aaaa"),
        "Gi1/0/2": _member(partner="0c00.bbbb.bbbb")}))
    f = LagLacpSystemIdMismatchRule().evaluate(_model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and "different" in f[0].message


def test_partner_null_ignored(tmp_path):
    # A 0000.0000.0000 partner (no LACP partner yet) must not fake a mismatch.
    _write(tmp_path, "sw1", lag=_lag(members={
        "Gi1/0/1": _member(partner="0c00.aaaa.aaaa"),
        "Gi1/0/2": _member(partner="0000.0000.0000")}))
    assert LagLacpSystemIdMismatchRule().evaluate(_model("sw1"), _ctx(tmp_path)) == []


def test_member_count_mismatch(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(members={
        "Gi1/0/1": _member(), "Gi1/0/2": _member()}))
    _write(tmp_path, "sw2", lag=_lag(members={"Gi1/0/5": _member()}))
    model = _model("sw1", "sw2", links=[{
        "local_interface_id": "sw1:Po1", "remote_interface_id": "sw2:Po1"}])
    f = LagMemberCountMismatchRule().evaluate(model, _ctx(tmp_path))
    assert len(f) == 1 and "disagree on member count" in f[0].message


def test_etherchannel_guard_disabled(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(),
           stp={"global": {"etherchannel_misconfig_guard": False}})
    f = StpEtherchannelMisconfigGuardDisabledRule().evaluate(
        _model("sw1"), _ctx(tmp_path))
    assert len(f) == 1 and "guard is disabled" in f[0].message


def test_guard_enabled_silent(tmp_path):
    _write(tmp_path, "sw1", lag=_lag(),
           stp={"global": {"etherchannel_misconfig_guard": True}})
    assert StpEtherchannelMisconfigGuardDisabledRule().evaluate(
        _model("sw1"), _ctx(tmp_path)) == []


def test_no_lag_facts_means_silent(tmp_path):
    # Device without genie_lag.json: rules stay silent (absence, not failure).
    _write(tmp_path, "sw1", stp={"global": {"etherchannel_misconfig_guard": False}})
    for rule_cls in HEALTHY_RULES + [StpEtherchannelMisconfigGuardDisabledRule]:
        assert rule_cls().evaluate(_model("sw1"), _ctx(tmp_path)) == []
