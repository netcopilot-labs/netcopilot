"""S20: FHRP drift — observed HSRP/VRRP groups vs NetBox-declared FHRP groups.

Unit-tests the ``_compare_fhrp`` comparator (both directions) and the
``_observed_fhrp`` facts reader in isolation — no Neo4j, no live NetBox. The
observed side is the exact shape ``link_builder._discover_fhrp_groups`` emits.
"""
from __future__ import annotations

import json

from netcopilot.declared_state.drift import (
    DriftReport,
    _compare_fhrp,
    _observed_fhrp,
)


class _FhrpAdapter:
    """Minimal declared source exposing only get_fhrp_groups (the adapter extra)."""

    def __init__(self, groups):
        self._groups = groups

    def get_fhrp_groups(self):
        return list(self._groups)


def _obs_group(protocol, group, vip, hosts, active=None):
    return {
        "service_type": "fhrp_group",
        "identifier": f"{vip}/{group}",
        "protocol": protocol,
        "group_number": group,
        "vip": vip,
        "interface": "Vlan60",
        "members": [{"hostname": h} for h in hosts],
        "active_device": active or (hosts[0] if hosts else None),
    }


def _decl_group(family, group, vip, name="gw"):
    return {"protocol": family, "protocol_family": family, "group_id": group,
            "vips": [vip] if vip else [], "name": name, "netbox_id": 1}


def _report():
    return DriftReport(run_id="demo-run", declared_source="Fake")


def test_fhrp_quiet_when_declared_matches_observed():
    obs = [_obs_group("hsrp", 60, "198.51.100.129",
                      ["core-sw-01", "core-sw-02"], "core-sw-01")]
    r = _report()
    _compare_fhrp(obs, _FhrpAdapter([_decl_group("hsrp", 60, "198.51.100.129")]), r)
    assert r.findings == [], r.counts_by_rule


def test_fhrp_unknown_in_netbox_when_running_but_undeclared():
    obs = [_obs_group("vrrp", 61, "198.51.100.145", ["core-sw-01"])]
    r = _report()
    _compare_fhrp(obs, _FhrpAdapter([]), r)
    assert [f.rule_id for f in r.findings] == ["INTENT_FHRP_UNKNOWN_IN_NETBOX"]
    f = r.findings[0]
    assert f.severity == "info"
    # Anchors to the active/first member so it attaches to a real :Device node.
    assert f.evidence["element_id"] == "core-sw-01"
    assert "198.51.100.145" in f.message


def test_fhrp_missing_in_network_when_declared_but_not_running():
    r = _report()
    _compare_fhrp([], _FhrpAdapter([_decl_group("hsrp", 99, "203.0.113.1")]), r)
    assert [f.rule_id for f in r.findings] == ["INTENT_FHRP_MISSING_IN_NETWORK"]
    assert r.findings[0].severity == "low"


def test_fhrp_vrrp_family_matches_v2v3_documentation():
    # NetBox documents 'vrrp3'; the run observes normalized 'vrrp' — the family
    # comparison must NOT manufacture drift from the v2/v3 detail.
    obs = [_obs_group("vrrp", 61, "198.51.100.145", ["core-sw-01"])]
    decl = [{"protocol": "vrrp3", "protocol_family": "vrrp", "group_id": 61,
             "vips": ["198.51.100.145"], "name": "gw", "netbox_id": 1}]
    r = _report()
    _compare_fhrp(obs, _FhrpAdapter(decl), r)
    assert r.findings == [], r.counts_by_rule


def test_fhrp_source_without_helper_is_all_unknown():
    class _Bare:  # no get_fhrp_groups → contributes no declared groups
        pass

    obs = [_obs_group("hsrp", 60, "198.51.100.129", ["core-sw-01"])]
    r = _report()
    _compare_fhrp(obs, _Bare(), r)
    assert [f.rule_id for f in r.findings] == ["INTENT_FHRP_UNKNOWN_IN_NETBOX"]


def test_observed_fhrp_reads_run_facts(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    d = tmp_path / "demo-run" / "facts" / "core-sw-01"
    d.mkdir(parents=True)
    (d / "genie_vrrp.json").write_text(json.dumps({
        "interface": {"Vlan61": {"group": {"61": {
            "virtual_ip_address": "198.51.100.145",
            "state": "master", "priority": 120,
        }}}}
    }))
    groups = _observed_fhrp("demo-run")
    assert len(groups) == 1
    g = groups[0]
    assert g["protocol"] == "vrrp"
    assert g["group_number"] == 61
    assert g["vip"] == "198.51.100.145"


def test_observed_fhrp_empty_without_facts(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    assert _observed_fhrp("no-such-run") == []
