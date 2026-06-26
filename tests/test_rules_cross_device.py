"""F3f: Phase-3 cross-device rules — compare parameters between connected devices.

run_cross_device_rules pre-loads device facts, builds device degree from the
topology, and runs the cross-device families (BGP/OSPF/interface/topology/static
route). Contract + a model-only behavioral check (single-uplink redundancy).
Deep behavioral coverage lands in the F3h goldens.
"""

import json

from netcopilot.rules.cross_device import run_cross_device_rules


def _model(devices, links):
    return {"devices": devices, "interfaces": [], "links": links, "adjacencies": []}


def _facts(tmp_path, hostnames):
    # the evaluator skips entirely if no device facts are present; give each
    # device a minimal device_facts.json so the model-based rules still run.
    for h in hostnames:
        d = tmp_path / h
        d.mkdir(parents=True)
        (d / "device_facts.json").write_text(json.dumps({"hostname": h, "os": "ios-xe"}))
    return tmp_path


def test_run_cross_device_returns_tuple(tmp_path):
    _facts(tmp_path, ["core-rtr-01"])
    findings, executed, errors = run_cross_device_rules(
        _model([{"hostname": "core-rtr-01", "role": "core"}], []), tmp_path)
    assert isinstance(findings, list) and isinstance(executed, list) and isinstance(errors, list)


def test_single_uplink_redundancy(tmp_path):
    # core-rtr-01 <-> dist-sw-01 (each degree 1) + a firewall fw-01 single-homed.
    model = _model(
        devices=[
            {"hostname": "core-rtr-01", "role": "core"},
            {"hostname": "dist-sw-01", "role": "distribution"},
            {"hostname": "fw-01", "role": "firewall"},
        ],
        links=[
            {"link_id": "l1", "status": "up", "peer_collected": True,
             "local_device_id": "core-rtr-01", "remote_device_id": "dist-sw-01"},
            {"link_id": "l2", "status": "up", "peer_collected": True,
             "local_device_id": "dist-sw-01", "remote_device_id": "fw-01"},
        ],
    )
    _facts(tmp_path, ["core-rtr-01", "dist-sw-01", "fw-01"])
    findings, executed, errors = run_cross_device_rules(model, tmp_path)
    uplink = {f.evidence["element_id"] for f in findings if f.rule_id == "LINK_SINGLE_UPLINK"}
    assert "core-rtr-01::single_uplink" in uplink   # degree 1, non-firewall → flagged
    assert "fw-01::single_uplink" not in uplink      # firewall single-uplink is expected
    # dist-sw-01 has degree 2 (two links) → not single-homed
    assert "dist-sw-01::single_uplink" not in uplink
    assert "LINK_SINGLE_UPLINK" in executed


# =========================================================================
# Route-reflector rules — read config-only data (genie omits it) from the
# model adjacency (route_reflector_client_{a,b}) and the bgp_config.json fact.
# =========================================================================

from netcopilot.rules.cross_device.bgp_rules import (
    _check_cluster_id_duplicate,
    _check_rr_client,
)


def _rr_neighbor(rr_client):
    return {"remote_as": 64496, "route_reflector_client": rr_client}


def test_rr_client_asymmetric_both_sides_flagged():
    # Misconfig: both ends mark the other as route-reflector client.
    findings = []
    adj = {"route_reflector_client_a": True, "route_reflector_client_b": True}
    _check_rr_client(findings, adj, "rr-01", "rr-02", "rr-01:bgp--rr-02:bgp")
    assert [f.rule_id for f in findings] == ["BGP_ROUTE_REFLECTOR_CLIENT_ASYMMETRIC"]


def test_rr_client_correct_one_sided_no_finding():
    # Correct RR: reflector marks client, client does not reflect back.
    findings = []
    adj = {"route_reflector_client_a": False, "route_reflector_client_b": True}
    _check_rr_client(findings, adj, "bdr-01", "core-01", "bdr-01:bgp--core-01:bgp")
    assert findings == []


def test_rr_client_missing_flags_no_finding():
    # External/uncollected side → flags absent (None) → no false positive.
    findings = []
    _check_rr_client(findings, {}, "core-01", "isp-01", "core-01:bgp--isp-01:bgp")
    assert findings == []


def test_cluster_id_duplicate_two_rrs_same_explicit_id():
    facts = {
        "rr-01": {"bgp_config": {"router_id": "10.0.0.1", "cluster_id": "1.1.1.1",
                                 "neighbors": {"10.0.0.9": _rr_neighbor(True)}}},
        "rr-02": {"bgp_config": {"router_id": "10.0.0.2", "cluster_id": "1.1.1.1",
                                 "neighbors": {"10.0.0.9": _rr_neighbor(True)}}},
    }
    findings = _check_cluster_id_duplicate(facts)
    assert [f.rule_id for f in findings] == ["BGP_CLUSTER_ID_DUPLICATE"]
    assert set(findings[0].evidence["key_facts"]["devices"]) == {"rr-01", "rr-02"}


def test_cluster_id_duplicate_default_router_id_fallback():
    # Neither RR sets an explicit cluster-id → both default to their router-id.
    # Two RRs that happen to share a router-id collide on the effective cid.
    facts = {
        "rr-01": {"bgp_config": {"router_id": "10.0.0.5", "cluster_id": None,
                                 "neighbors": {"10.0.0.9": _rr_neighbor(True)}}},
        "rr-02": {"bgp_config": {"router_id": "10.0.0.5", "cluster_id": None,
                                 "neighbors": {"10.0.0.9": _rr_neighbor(True)}}},
    }
    findings = _check_cluster_id_duplicate(facts)
    assert [f.rule_id for f in findings] == ["BGP_CLUSTER_ID_DUPLICATE"]


def test_cluster_id_single_rr_no_finding():
    facts = {
        "rr-01": {"bgp_config": {"router_id": "10.0.0.1", "cluster_id": None,
                                 "neighbors": {"10.0.0.9": _rr_neighbor(True)}}},
        "bdr-01": {"bgp_config": {"router_id": "10.0.0.9", "cluster_id": None,
                                  "neighbors": {"10.0.0.1": _rr_neighbor(False)}}},
    }
    assert _check_cluster_id_duplicate(facts) == []


def test_cluster_id_non_rr_devices_not_counted():
    # Two plain iBGP speakers sharing a router-id are NOT route reflectors,
    # so the cluster-id duplicate rule must not fire on them.
    facts = {
        "spk-01": {"bgp_config": {"router_id": "10.0.0.7", "cluster_id": None,
                                  "neighbors": {"10.0.0.8": _rr_neighbor(False)}}},
        "spk-02": {"bgp_config": {"router_id": "10.0.0.7", "cluster_id": None,
                                  "neighbors": {"10.0.0.7": _rr_neighbor(False)}}},
    }
    assert _check_cluster_id_duplicate(facts) == []


# BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID was dormant (read genie, which omits the
# config-only RR fields). Now reads bgp_config.json — proven live here.

from netcopilot.rules.rules.bgp_advanced import BgpRouteReflectorNoClusterIdRule  # noqa: E402


def _write_bgp_config(run_path, host, cfg):
    d = run_path / "facts" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / "bgp_config.json").write_text(json.dumps(cfg))


def _no_cluster_id_findings(run_path, host):
    return BgpRouteReflectorNoClusterIdRule().evaluate(
        {"devices": [{"hostname": host}]}, {"run_path": str(run_path)})


def test_rr_no_cluster_id_fires(tmp_path):
    _write_bgp_config(tmp_path, "rr-01", {
        "cluster_id": None, "neighbors": {"10.0.0.9": _rr_neighbor(True)}})
    out = _no_cluster_id_findings(tmp_path, "rr-01")
    assert [f.rule_id for f in out] == ["BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID"]
    assert out[0].evidence["key_facts"]["rr_client_count"] == 1


def test_rr_with_explicit_cluster_id_no_finding(tmp_path):
    _write_bgp_config(tmp_path, "rr-01", {
        "cluster_id": "1.1.1.1", "neighbors": {"10.0.0.9": _rr_neighbor(True)}})
    assert _no_cluster_id_findings(tmp_path, "rr-01") == []


def test_non_rr_no_cluster_id_finding(tmp_path):
    # No route-reflector-client neighbor → not an RR → no finding.
    _write_bgp_config(tmp_path, "spk-01", {
        "cluster_id": None, "neighbors": {"10.0.0.9": _rr_neighbor(False)}})
    assert _no_cluster_id_findings(tmp_path, "spk-01") == []


# =========================================================================
# O5 — OSPF_ADJACENCY_ASYMMETRIC must not fire on a collection gap (R1 Phase 2).
# A unilateral OSPF adjacency where the non-reporting side never exposed OSPF
# (e.g. a FortiGate) is incomplete data, not a misconfiguration.
# =========================================================================

from netcopilot.rules.cross_device.ospf_rules import evaluate_adjacency


def _ospf_unilateral_adj(dev_a, dev_b, intf_a):
    """bilateral=False OSPF adjacency: dev_a reported, dev_b's interface unknown."""
    return {
        "protocol": "ospf", "device_a": dev_a, "device_b": dev_b,
        "interface_a": intf_a, "interface_b": None,
        "bilateral": False, "peer_collected": True,
        "state": "full", "area": "0.0.0.0",
    }


def test_ospf_asymmetric_skipped_when_peer_has_no_ospf():
    adjs = [_ospf_unilateral_adj("acc-sw-01", "edge-fw-01", "Gi1/0/1")]
    facts = {"acc-sw-01": {"genie_ospf": {"vrf": {}}}, "edge-fw-01": {}}  # fw: no OSPF
    assert [f.rule_id for f in evaluate_adjacency(adjs, facts)] == []


# =========================================================================
# OSPF MTU IP-MTU normalization (OSPF_MTU_MISMATCH_DBD false-positive fix)
# IOS XR reports the L2 interface MTU (default 1514, includes the 14-byte
# Ethernet header); IOS XE reports the IP MTU (1500). OSPF DBD negotiates on
# the IP MTU, so a default XR<->XE link must NOT be flagged as a mismatch.
# =========================================================================

from netcopilot.rules.cross_device.helpers import normalize_ip_mtu as _normalize_ip_mtu


def _facts_os(os_name):
    return {"device_facts": {"os": os_name}}


def test_normalize_strips_xr_l2_header():
    # XR default 1514 -> IP MTU 1500; XR jumbo 9014 -> 9000.
    assert _normalize_ip_mtu(_facts_os("ios-xr"), 1514) == 1500
    assert _normalize_ip_mtu(_facts_os("iosxr"), 9014) == 9000   # spelling-agnostic


def test_normalize_leaves_xe_unchanged():
    # IOS XE already reports the IP MTU.
    assert _normalize_ip_mtu(_facts_os("ios-xe"), 1500) == 1500
    assert _normalize_ip_mtu(_facts_os("ios-xe"), 9000) == 9000


def test_normalize_makes_default_xr_xe_link_match():
    # The false-positive case: XR 1514 and XE 1500 are the SAME IP MTU.
    assert _normalize_ip_mtu(_facts_os("ios-xr"), 1514) == _normalize_ip_mtu(_facts_os("ios-xe"), 1500)


def test_normalize_preserves_genuine_mismatch():
    # A real mismatch (one side jumbo) still differs after normalization.
    assert _normalize_ip_mtu(_facts_os("ios-xr"), 1514) != _normalize_ip_mtu(_facts_os("ios-xe"), 9000)


def test_normalize_handles_none_and_missing_os():
    assert _normalize_ip_mtu(_facts_os("ios-xr"), None) is None
    assert _normalize_ip_mtu({}, 1500) == 1500   # unknown OS -> unchanged


# --- INTF_MTU_MISMATCH: IP-MTU comparison + <=14 ambiguity suppression ------

from netcopilot.rules.cross_device.interface_rules import _check_mtu


def _intf(mtu, up=True):
    return {"mtu": mtu, "oper_status": "up" if up else "down"}


def test_intf_mtu_default_xr_xe_no_finding():
    # XR 1514 (L2) vs XE 1500 (IP) -> same IP MTU -> no finding.
    f = _check_mtu("rtr", "Gi0/0/0/1", _intf(1514), _facts_os("ios-xr"),
                   "sw", "Gi1/0/1", _intf(1500), _facts_os("ios-xe"), "eid")
    assert f == []


def test_intf_mtu_jumbo_14byte_zone_no_finding():
    # XR 9216 (L2 -> IP 9202) vs XE 9216: a 14-byte difference is the
    # convention-ambiguity zone -> suppressed (Option A).
    f = _check_mtu("rtr", "Hu0/0/1/0", _intf(9216), _facts_os("ios-xr"),
                   "sw", "Hu1/0/1", _intf(9216), _facts_os("ios-xe"), "eid")
    assert f == []


def test_intf_mtu_real_mismatch_fires():
    # An unambiguous mismatch (> 14 bytes) still fires.
    f = _check_mtu("sw-a", "Gi0/1", _intf(1500), _facts_os("ios-xe"),
                   "sw-b", "Gi0/1", _intf(9000), _facts_os("ios-xe"), "eid")
    assert len(f) == 1
    assert f[0].rule_id == "INTF_MTU_MISMATCH"


def test_ospf_asymmetric_fires_when_peer_exposed_ospf_but_no_reverse():
    adjs = [_ospf_unilateral_adj("acc-sw-01", "dist-sw-01", "Gi1/0/1")]
    facts = {"acc-sw-01": {"genie_ospf": {"vrf": {}}},
             "dist-sw-01": {"genie_ospf": {"vrf": {}}}}  # peer HAS OSPF → real asymmetry
    assert [f.rule_id for f in evaluate_adjacency(adjs, facts)] == ["OSPF_ADJACENCY_ASYMMETRIC"]


# =========================================================================
# O1 (corrected) — OSPF_ROUTER_ID_DUPLICATE reads the model adjacencies'
# VRF-resolved router-ids, NOT genie (which stores every rid under "default").
# =========================================================================

from netcopilot.rules.cross_device.ospf_rules import _check_router_id_duplicate


def _ospf_adj(vrf, dev_a, rid_a, dev_b, rid_b):
    return {"protocol": "ospf", "vrf": vrf,
            "device_a": dev_a, "router_id_a": rid_a,
            "device_b": dev_b, "router_id_b": rid_b}


def test_ospf_router_id_dup_across_vrfs_no_false_positive():
    adjs = [_ospf_adj("RED", "r1", "1.1.1.1", "core", "9.9.9.9"),
            _ospf_adj("BLUE", "r2", "1.1.1.1", "core", "8.8.8.8")]
    assert [f.rule_id for f in _check_router_id_duplicate(adjs)] == []


def test_ospf_router_id_dup_same_vrf_fires():
    adjs = [_ospf_adj("default", "r1", "1.1.1.1", "core", "9.9.9.9"),
            _ospf_adj("default", "r2", "1.1.1.1", "core", "9.9.9.9")]
    assert [f.rule_id for f in _check_router_id_duplicate(adjs)] == ["OSPF_ROUTER_ID_DUPLICATE"]


def test_ospf_router_id_genie_default_storage_not_misattributed():
    # The exact demo case: acc-sw-03 reuses ids across RED/BLUE. genie would store
    # both under "default"; the model adjacency carries the real VRF -> no finding.
    adjs = [_ospf_adj("RED", "acc-sw-03", "198.51.100.113", "core-sw-01", "198.51.100.225"),
            _ospf_adj("BLUE", "acc-sw-03", "198.51.100.115", "core-sw-01", "198.51.100.229")]
    assert [f.rule_id for f in _check_router_id_duplicate(adjs)] == []


# =========================================================================
# O1 — OSPF_AREA_SINGLE_ABR is per-VRF: area N in RED is a different domain
# from area N in BLUE, so they must not merge (R1 Phase 2).
# =========================================================================

from netcopilot.rules.cross_device.ospf_rules import _check_area_single_abr


def _ospf_area_adj(vrf, area, dev_a, dev_b):
    return {"protocol": "ospf", "vrf": vrf, "area": area,
            "device_a": dev_a, "device_b": dev_b,
            "router_id_a": None, "router_id_b": None}


def test_ospf_single_abr_is_per_vrf():
    # Single-ABR area 0.0.0.1 in BOTH RED and BLUE -> two findings, not one merged.
    adjs = [
        _ospf_area_adj("RED", "0.0.0.0", "core", "r1"),
        _ospf_area_adj("RED", "0.0.0.1", "core", "a1"),
        _ospf_area_adj("BLUE", "0.0.0.0", "core", "r2"),
        _ospf_area_adj("BLUE", "0.0.0.1", "core", "a2"),
    ]
    out = _check_area_single_abr(adjs)
    assert [f.rule_id for f in out] == ["OSPF_AREA_SINGLE_ABR", "OSPF_AREA_SINGLE_ABR"]
    assert sorted(f.evidence["key_facts"]["vrf"] for f in out) == ["BLUE", "RED"]


# =========================================================================
# OSPF reference-bandwidth / SPF-timer consistency is per VRF domain, and
# reads the value for the domain's own process despite the genie default-block
# quirk (R1 Phase 2 — closing the deferred global-comparison item).
# =========================================================================

from netcopilot.rules.cross_device.ospf_rules import (  # noqa: E402
    _check_reference_bandwidth,
    _check_spf_timer_inconsistent,
)


def _proc(ref_bw=None, spf=None):
    pd = {"areas": {"0.0.0.0": {}}}
    if ref_bw is not None:
        pd["auto_cost"] = {"reference_bandwidth": ref_bw}
    if spf is not None:
        pd["spf_control"] = {"throttle": {"spf": spf}}
    return pd


def _ospf_facts(blocks):
    """genie_ospf facts: {vrf_block: {process_id: proc_dict}}."""
    vrf = {
        vname: {"address_family": {"ipv4": {"instance": insts}}}
        for vname, insts in blocks.items()
    }
    return {"genie_ospf": {"vrf": vrf}}


def _dom_adj(vrf, a, b):
    return {"protocol": "ospf", "vrf": vrf, "device_a": a, "device_b": b}


def test_ref_bw_no_cross_vrf_false_positive():
    """RED domain @100 and BLUE domain @40 are separate domains — no finding."""
    facts = {
        "r1": _ospf_facts({"RED": {"10": _proc(ref_bw=100)}}),
        "r2": _ospf_facts({"RED": {"10": _proc(ref_bw=100)}}),
        "b1": _ospf_facts({"BLUE": {"20": _proc(ref_bw=40)}}),
        "b2": _ospf_facts({"BLUE": {"20": _proc(ref_bw=40)}}),
    }
    adjs = [_dom_adj("RED", "r1", "r2"), _dom_adj("BLUE", "b1", "b2")]
    assert [f.rule_id for f in _check_reference_bandwidth(adjs, facts)] == []


def test_ref_bw_within_domain_inconsistent_fires():
    facts = {
        "r1": _ospf_facts({"RED": {"10": _proc(ref_bw=100)}}),
        "r2": _ospf_facts({"RED": {"10": _proc(ref_bw=40)}}),
    }
    out = _check_reference_bandwidth([_dom_adj("RED", "r1", "r2")], facts)
    assert [f.rule_id for f in out] == ["OSPF_REFERENCE_BANDWIDTH_INCONSISTENT"]
    assert out[0].evidence["key_facts"]["vrf"] == "RED"


def test_ref_bw_genie_default_block_quirk_attributed_to_real_vrf():
    """proc 10 lives in the RED block but genie stores its value under the
    'default' block (quirk). The differing values must be attributed to RED and
    fire a RED finding — never compared as a 'default' domain."""
    facts = {
        "r1": _ospf_facts({
            "default": {"10": _proc(ref_bw=100)},
            "RED": {"10": _proc()},
        }),
        "r2": _ospf_facts({
            "default": {"10": _proc(ref_bw=40)},
            "RED": {"10": _proc()},
        }),
    }
    out = _check_reference_bandwidth([_dom_adj("RED", "r1", "r2")], facts)
    assert [f.rule_id for f in out] == ["OSPF_REFERENCE_BANDWIDTH_INCONSISTENT"]
    assert out[0].evidence["key_facts"]["vrf"] == "RED"


def test_spf_timer_per_vrf_isolation_then_within_domain():
    t1, t2 = {"start": 50}, {"start": 99}
    facts = {
        "r1": _ospf_facts({"RED": {"10": _proc(spf=t1)}}),
        "r2": _ospf_facts({"RED": {"10": _proc(spf=t1)}}),
        "b1": _ospf_facts({"BLUE": {"20": _proc(spf=t2)}}),
        "b2": _ospf_facts({"BLUE": {"20": _proc(spf=t2)}}),
    }
    adjs = [_dom_adj("RED", "r1", "r2"), _dom_adj("BLUE", "b1", "b2")]
    # RED uniform, BLUE uniform (different from RED) — separate domains, no finding
    assert [f.rule_id for f in _check_spf_timer_inconsistent(adjs, facts)] == []
    # now make RED inconsistent → exactly one RED finding
    facts["r2"] = _ospf_facts({"RED": {"10": _proc(spf=t2)}})
    out = _check_spf_timer_inconsistent(adjs, facts)
    assert [f.rule_id for f in out] == ["OSPF_SPF_TIMER_INCONSISTENT"]
    assert out[0].evidence["key_facts"]["vrf"] == "RED"
