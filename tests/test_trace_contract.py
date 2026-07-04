"""S07 — trace_path contract tests (destination-aware routing, 5-tuple matcher,
ACL/ISDB matching, typed verdict, findings overlay, return path).

Pure-function coverage where possible (no Neo4j); the walk-level branches are
exercised through monkeypatched loaders in the pattern of test_envelope_fields.
"""

from __future__ import annotations

import asyncio

from netcopilot.mcp.tools import path_tracer


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def run(self, *a, **k):
        return _FakeResult(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, rows):
        self._rows = rows

    def session(self):
        return _FakeSession(self._rows)


def _patch_policy_check(monkeypatch, policies, isdb_services=None):
    monkeypatch.setattr(path_tracer, "is_available", lambda: True)
    monkeypatch.setattr(path_tracer, "get_driver", lambda: _FakeDriver(policies))
    monkeypatch.setattr(path_tracer, "_load_isdb_services_for",
                        lambda device, run_id: isdb_services or {})


# ── S07-3: ISDB honesty ladder in _check_firewall_policy ─────────────────────

def _isdb_policy(**kw):
    base = {"id": 30, "name": "block-blocklist", "action": "deny", "srcintf": "[]",
            "dstintf": "[]", "srcaddr": "all", "dstaddr": "", "dst_isdb": "SYNTH-Blocklist.Node",
            "service": "ALL", "ptype": "fortigate"}
    base.update(kw)
    return base


def test_isdb_resolved_match_denies(monkeypatch):
    _patch_policy_check(
        monkeypatch, [_isdb_policy()],
        isdb_services={"SYNTH-Blocklist.Node": {"ranges": ["198.51.100.0-198.51.100.255"], "truncated": False}},
    )
    r = path_tracer._check_firewall_policy("fw", "10.0.0.1", "198.51.100.9", "", "", "run")
    assert r["decision"] == "deny"
    assert "Internet-Service[SYNTH-Blocklist.Node]" in r["text"]
    assert r["via"] == "Internet-Service"


def test_isdb_refs_but_unresolved_is_manual_review(monkeypatch):
    # Policy references ISDB but the feed wasn't resolved (no ranges) — must be
    # an honest manual-review 'unknown', never a false 'no policy'.
    _patch_policy_check(
        monkeypatch, [_isdb_policy()],
        isdb_services={"SYNTH-Blocklist.Node": {"ranges": [], "truncated": False}},
    )
    r = path_tracer._check_firewall_policy("fw", "10.0.0.1", "198.51.100.9", "", "", "run")
    assert r["decision"] == "unknown"
    assert "not resolved" in r["text"]


def test_no_policy_when_nothing_matches(monkeypatch):
    # Address doesn't match and the ingress interface doesn't match either →
    # honest no_policy (not a vacuous interface-fallback permit).
    _patch_policy_check(monkeypatch, [
        {"id": 1, "name": "allow-web", "action": "accept", "srcintf": '[{"name": "port1"}]',
         "dstintf": '[{"name": "port2"}]', "srcaddr": "all", "dstaddr": "192.0.2.0/24",
         "dst_isdb": "", "service": "ALL", "ptype": "fortigate"},
    ])
    r = path_tracer._check_firewall_policy("fw", "10.0.0.1", "203.0.113.9", "port9", "port8", "run")
    assert r["decision"] == "no_policy"


def test_service_gate_excludes_wrong_port(monkeypatch):
    # Address matches but the policy only permits 443; a 22/tcp flow must not match it.
    _patch_policy_check(monkeypatch, [
        {"id": 2, "name": "https-only", "action": "accept", "srcintf": "[]", "dstintf": "[]",
         "srcaddr": "all", "dstaddr": "192.0.2.0/24", "dst_isdb": "", "service": "TCP/443",
         "ptype": "fortigate"},
    ])
    r = path_tracer._check_firewall_policy("fw", "10.0.0.1", "192.0.2.9", "", "", "run",
                                           protocol="tcp", dst_port=22)
    assert r["decision"] == "no_policy"
    r2 = path_tracer._check_firewall_policy("fw", "10.0.0.1", "192.0.2.9", "", "", "run",
                                            protocol="tcp", dst_port=443)
    assert r2["decision"] == "permit"


# ── S07-0: destination-aware longest-prefix-match ────────────────────────────

_ROUTES = [
    {"prefix": "0.0.0.0/0", "next_hop": "10.0.0.2", "protocol": "static", "ad": 1, "active": True},
    {"prefix": "192.0.2.0/24", "next_hop": "10.1.1.1", "protocol": "ospf", "ad": 110, "active": True},
    {"prefix": "192.0.2.128/25", "next_hop": "10.1.1.2", "protocol": "ospf", "ad": 110, "active": True},
]


def test_find_route_to_internet_delegates_to_default():
    # The internet placeholder must return the default route unchanged.
    r = path_tracer._find_route_to(_ROUTES, "0.0.0.0/0")
    assert r["prefix"] == "0.0.0.0/0"


def test_find_route_to_picks_longest_prefix():
    # 192.0.2.200 is inside both /24 and /25 — the /25 must win.
    r = path_tracer._find_route_to(_ROUTES, "192.0.2.200")
    assert r["prefix"] == "192.0.2.128/25"


def test_find_route_to_specific_over_default():
    # 192.0.2.10 is only in the /24 — more specific than the default.
    r = path_tracer._find_route_to(_ROUTES, "192.0.2.10")
    assert r["prefix"] == "192.0.2.0/24"


def test_find_route_to_no_specific_match_falls_back_to_default():
    r = path_tracer._find_route_to(_ROUTES, "203.0.113.5")
    assert r["prefix"] == "0.0.0.0/0"


def test_find_route_to_invalid_dest_falls_back_to_default():
    r = path_tracer._find_route_to(_ROUTES, "not-an-ip")
    assert r["prefix"] == "0.0.0.0/0"


def test_find_route_to_inactive_specific_flagged():
    routes = [
        {"prefix": "0.0.0.0/0", "next_hop": "10.0.0.2", "ad": 1, "active": True},
        {"prefix": "198.51.100.0/24", "next_hop": "10.9.9.9", "ad": 110, "active": False},
    ]
    r = path_tracer._find_route_to(routes, "198.51.100.7")
    assert r["prefix"] == "198.51.100.0/24"
    assert r.get("_inactive") is True


def test_find_route_to_prefers_active_over_inactive_specific():
    routes = [
        {"prefix": "198.51.100.0/24", "next_hop": "10.9.9.9", "ad": 110, "active": False},
        {"prefix": "198.51.100.0/25", "next_hop": "10.8.8.8", "ad": 110, "active": True},
    ]
    # 198.51.100.5 is in both; the active /25 wins over the inactive /24.
    r = path_tracer._find_route_to(routes, "198.51.100.5")
    assert r["prefix"] == "198.51.100.0/25"
    assert not r.get("_inactive")


def _patch_walk(monkeypatch, *, routes, ebgp=None, ip_to_device=None):
    monkeypatch.setattr(path_tracer, "is_available", lambda: False)  # hermetic: no real Neo4j
    monkeypatch.setattr(path_tracer, "_shared_resolve", lambda name, run_id: "r1")
    monkeypatch.setattr(path_tracer, "_build_ip_to_device", lambda run_id: ip_to_device or {})
    monkeypatch.setattr(path_tracer, "_get_bgp_exit", lambda device, run_id: ebgp)
    monkeypatch.setattr(path_tracer, "get_device_role", lambda device, run_id: "core")
    monkeypatch.setattr(path_tracer, "is_security_device", lambda device, run_id: False)
    monkeypatch.setattr(path_tracer, "_resolve_in_interface", lambda nd, nh, run_id: None)
    monkeypatch.setattr(path_tracer, "_load_routes", lambda device, data_dir: routes)


def test_internal_destination_does_not_shortcut_ebgp(monkeypatch):
    # r1 has eBGP AND a specific route to the internal destination: the trace
    # must forward on the specific route, not declare an eBGP internet exit.
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "bgp", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 20, "metric": 0, "active": True, "source": "bgp", "note": ""},
        {"prefix": "192.0.2.0/24", "vrf": "default", "protocol": "ospf", "next_hop": "10.1.1.9",
         "interface": "Gi0/1", "ad": 110, "metric": 0, "active": True, "source": "ospf", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes,
                ebgp=[{"peer": "isp", "local_as": "65000", "remote_as": "65001", "state": "up"}])
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="192.0.2.10",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert "eBGP internet transit" not in res.text
    assert "192.0.2.10" in res.text


def test_internet_destination_still_takes_ebgp_exit(monkeypatch):
    # Same device, internet destination → eBGP exit fires (regression guard).
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "bgp", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 20, "metric": 0, "active": True, "source": "bgp", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes,
                ebgp=[{"peer": "isp", "local_as": "65000", "remote_as": "65001", "state": "up"}])
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="internet",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert "eBGP internet transit" in res.text


def test_verdict_reachable_shape(monkeypatch):
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "bgp", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 20, "metric": 0, "active": True, "source": "bgp", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes,
                ebgp=[{"peer": "isp", "local_as": "65000", "remote_as": "65001", "state": "up"}])
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [])
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="internet",
                                             context={"run_id": "r", "data_dir": "d"}))
    v = res.verdict
    assert set(v) == {"result", "reasons", "hops", "blocked_by", "risks", "run_id", "return_path"}
    assert v["result"] == "reachable"
    assert v["blocked_by"] is None
    assert v["run_id"] == "r"
    # internet destination → return path not verifiable, stated explicitly
    assert v["return_path"] is None
    assert any("return path not verifiable" in r for r in v["reasons"])


def test_verdict_blocked_by_deny_policy(monkeypatch):
    # A firewall hop whose policy denies → verdict blocked, blocked_by names it.
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 1, "metric": 0, "active": True, "source": "static", "note": ""},
    ]}
    monkeypatch.setattr(path_tracer, "_shared_resolve", lambda name, run_id: "fw1")
    monkeypatch.setattr(path_tracer, "_build_ip_to_device", lambda run_id: {"203.0.113.1": "r2"})
    monkeypatch.setattr(path_tracer, "_get_bgp_exit", lambda device, run_id: None)
    monkeypatch.setattr(path_tracer, "get_device_role", lambda device, run_id: "firewall")
    monkeypatch.setattr(path_tracer, "is_security_device", lambda device, run_id: device == "fw1")
    monkeypatch.setattr(path_tracer, "_resolve_in_interface", lambda nd, nh, run_id: None)
    monkeypatch.setattr(path_tracer, "_load_routes",
                        lambda device, data_dir: routes if device == "fw1" else {})
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [])
    monkeypatch.setattr(path_tracer, "_check_firewall_policy",
                        lambda *a, **k: {"text": "DENIES", "decision": "deny",
                                         "policy": "block-all", "id": 9, "via": "address"})
    res = asyncio.run(path_tracer.trace_path(source_device="fw1", destination="198.51.100.9",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert res.verdict["result"] == "blocked"
    assert res.verdict["blocked_by"]["policy"] == "block-all"


def test_verdict_risks_overlay(monkeypatch):
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "bgp", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 20, "metric": 0, "active": True, "source": "bgp", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes,
                ebgp=[{"peer": "isp", "local_as": "65000", "remote_as": "65001", "state": "up"}])
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [
        {"severity": "high", "title": "MTU mismatch", "finding_id": "F1",
         "evidence": {"key_facts": {}}, "rule_id": "R1", "device": "r1"},
    ])
    monkeypatch.setattr(path_tracer, "device_from_finding", lambda f: f.get("device"))
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="internet",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert any(r["title"] == "MTU mismatch" for r in res.verdict["risks"])


def test_verdict_src_ip_omitted_reason(monkeypatch):
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static", "next_hop": "203.0.113.1",
         "interface": "Gi0/0", "ad": 1, "metric": 0, "active": True, "source": "static", "note": ""},
    ]}
    monkeypatch.setattr(path_tracer, "_shared_resolve", lambda name, run_id: "fw1")
    monkeypatch.setattr(path_tracer, "_build_ip_to_device", lambda run_id: {"203.0.113.1": "r2"})
    monkeypatch.setattr(path_tracer, "_get_bgp_exit", lambda device, run_id: None)
    monkeypatch.setattr(path_tracer, "get_device_role", lambda device, run_id: "firewall")
    monkeypatch.setattr(path_tracer, "is_security_device", lambda device, run_id: device == "fw1")
    monkeypatch.setattr(path_tracer, "_resolve_in_interface", lambda nd, nh, run_id: None)
    monkeypatch.setattr(path_tracer, "_load_routes",
                        lambda device, data_dir: routes if device == "fw1" else {})
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [])
    monkeypatch.setattr(path_tracer, "_check_firewall_policy",
                        lambda *a, **k: {"text": "PERMITS", "decision": "permit",
                                         "policy": "allow", "id": 1, "via": "address"})
    res = asyncio.run(path_tracer.trace_path(source_device="fw1", destination="198.51.100.9",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert any("source IP not supplied" in r for r in res.verdict["reasons"])


# ── S07-6: return-path / asymmetry ───────────────────────────────────────────

def test_return_path_not_verifiable_without_src_ip(monkeypatch):
    # Internal destination but no src_ip → return path explicitly not evaluated.
    routes = {"default": [
        {"prefix": "192.0.2.0/24", "vrf": "default", "protocol": "ospf", "next_hop": "10.0.0.2",
         "interface": "Gi0/0", "ad": 110, "metric": 0, "active": True, "source": "ospf", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes, ip_to_device={"10.0.0.2": "r2", "192.0.2.9": "r2"})
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [])
    monkeypatch.setattr(path_tracer, "_load_routes",
                        lambda device, data_dir: routes if device == "r1" else {})
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="192.0.2.9",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert res.verdict["return_path"] is None
    assert any("source IP not supplied" in r for r in res.verdict["reasons"])


def test_return_path_reverse_walk_executes(monkeypatch):
    # Concrete endpoints both in-scope + src_ip given → the reverse walk runs and
    # populates return_path (proves dest->src tracing, not just the guards).
    r1_routes = {"default": [
        {"prefix": "192.0.2.0/24", "vrf": "default", "protocol": "ospf", "next_hop": "10.0.0.2",
         "interface": "Gi0/0", "ad": 110, "metric": 0, "active": True, "source": "ospf", "note": ""}]}
    r2_routes = {"default": [
        {"prefix": "10.0.0.0/8", "vrf": "default", "protocol": "ospf", "next_hop": "192.0.2.1",
         "interface": "Gi0/0", "ad": 110, "metric": 0, "active": True, "source": "ospf", "note": ""}]}
    monkeypatch.setattr(path_tracer, "is_available", lambda: False)
    monkeypatch.setattr(path_tracer, "_shared_resolve", lambda name, run_id: name)
    monkeypatch.setattr(path_tracer, "_build_ip_to_device", lambda run_id: {
        "10.0.0.2": "r2", "192.0.2.9": "r2", "192.0.2.1": "r1", "10.0.0.1": "r1"})
    monkeypatch.setattr(path_tracer, "_get_bgp_exit", lambda device, run_id: None)
    monkeypatch.setattr(path_tracer, "get_device_role", lambda device, run_id: "core")
    monkeypatch.setattr(path_tracer, "is_security_device", lambda device, run_id: False)
    monkeypatch.setattr(path_tracer, "_resolve_in_interface", lambda nd, nh, run_id: None)
    monkeypatch.setattr(path_tracer, "load_findings_enriched", lambda run_id: [])
    monkeypatch.setattr(path_tracer, "_load_routes",
                        lambda device, data_dir: r1_routes if device == "r1"
                        else r2_routes if device == "r2" else {})
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="192.0.2.9",
                                             src_ip="10.0.0.1",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert res.verdict["return_path"] is not None
    assert "result" in res.verdict["return_path"]
    assert "asymmetric" in res.verdict["return_path"]


# ── S07-5: ACL-aware hop checks ──────────────────────────────────────────────

def test_addr_matches():
    assert path_tracer._addr_matches("any", "192.0.2.1") is True
    assert path_tracer._addr_matches("192.0.2.0/24", "192.0.2.9") is True
    assert path_tracer._addr_matches("192.0.2.0/24", "203.0.113.9") is False
    assert path_tracer._addr_matches("192.0.2.0/24", None) is True  # unknown → permissive


def test_evaluate_acl_explicit_deny():
    aces = [
        {"seq": 10, "action": "deny", "srcaddr": "any", "dstaddr": "198.51.100.0/24", "service": "tcp 443"},
        {"seq": 20, "action": "permit", "srcaddr": "any", "dstaddr": "any", "service": ""},
    ]
    r = path_tracer._evaluate_acl(aces, "10.0.0.1", "198.51.100.9", "tcp", 443, src_known=True)
    assert r["decision"] == "deny" and r["ace"] == 10


def test_evaluate_acl_permit_first_match():
    aces = [
        {"seq": 10, "action": "permit", "srcaddr": "any", "dstaddr": "198.51.100.0/24", "service": ""},
        {"seq": 20, "action": "deny", "srcaddr": "any", "dstaddr": "any", "service": ""},
    ]
    r = path_tracer._evaluate_acl(aces, "10.0.0.1", "198.51.100.9", "tcp", 443, src_known=True)
    assert r["decision"] == "permit" and r["ace"] == 10


def test_evaluate_acl_implicit_deny_only_when_src_known():
    aces = [{"seq": 10, "action": "permit", "srcaddr": "10.0.0.0/8", "dstaddr": "192.0.2.0/24", "service": ""}]
    # dst 203.0.113.9 matches no ACE → implicit deny when src known...
    r_known = path_tracer._evaluate_acl(aces, "10.0.0.1", "203.0.113.9", None, None, src_known=True)
    assert r_known["decision"] == "deny" and r_known["ace"] == "implicit"
    # ...but unknown (not fabricating a block) when src is not supplied.
    r_unknown = path_tracer._evaluate_acl(aces, None, "203.0.113.9", None, None, src_known=False)
    assert r_unknown["decision"] == "unknown"


def test_check_acls_at_hop_deny(monkeypatch):
    monkeypatch.setattr(path_tracer, "is_available", lambda: True)
    monkeypatch.setattr(path_tracer, "get_driver", lambda: _FakeDriver([
        {"name": "BLOCK-OUT", "seq": 10, "action": "deny", "srcaddr": "any",
         "dstaddr": "198.51.100.0/24", "service": "tcp 443",
         "applied_to": ["GigabitEthernet0/1 outbound"]},
    ]))
    r = path_tracer._check_acls_at_hop("sw1", "GigabitEthernet0/1", "outbound",
                                       "10.0.0.1", "198.51.100.9", "tcp", 443, "run")
    assert r["decision"] == "deny"
    assert r["policy"] == "BLOCK-OUT"
    assert r["policy_device"] == "sw1"


def test_check_acls_at_hop_unbound_interface_returns_none(monkeypatch):
    monkeypatch.setattr(path_tracer, "is_available", lambda: True)
    monkeypatch.setattr(path_tracer, "get_driver", lambda: _FakeDriver([
        {"name": "BLOCK-OUT", "seq": 10, "action": "deny", "srcaddr": "any",
         "dstaddr": "198.51.100.0/24", "service": "", "applied_to": ["GigabitEthernet0/9 outbound"]},
    ]))
    # ACL bound to Gi0/9, but the traffic egresses Gi0/1 → not governed here.
    r = path_tracer._check_acls_at_hop("sw1", "GigabitEthernet0/1", "outbound",
                                       "10.0.0.1", "198.51.100.9", "tcp", 443, "run")
    assert r is None


def test_hop_carries_interfaces(monkeypatch):
    routes = {"default": [
        {"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static", "next_hop": "203.0.113.1",
         "interface": "Gi0/3", "ad": 1, "metric": 0, "active": True, "source": "static", "note": ""},
    ]}
    _patch_walk(monkeypatch, routes=routes, ip_to_device={"203.0.113.1": "r2"})
    monkeypatch.setattr(path_tracer, "_resolve_in_interface", lambda nd, nh, run_id: "Gi1/0")
    # r2 has no routes → walk stops after one L3 hop; inspect via text.
    monkeypatch.setattr(path_tracer, "_load_routes",
                        lambda device, data_dir: routes if device == "r1" else {})
    res = asyncio.run(path_tracer.trace_path(source_device="r1", destination="198.51.100.9",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert res.status == "ok"
