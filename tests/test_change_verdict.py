"""s05-1: the change-validation verdict engine — every policy rule covered.

Pure tests: synthetic RunData models run through the real compute_diff, then
evaluate_change. No I/O, no Neo4j, no mocks of our own code.
"""

from netcopilot.diff.engine import RunData, compute_diff
from netcopilot.diff.verdict import ChangeVerdict, evaluate_change


def _device(device_id, **kw):
    return {"device_id": device_id, "role": "access_switch", **kw}


def _iface(device_id, name, **kw):
    return {
        "interface_id": f"{device_id}:{name}",
        "device_id": device_id,
        "name": name,
        "admin_status": "up",
        "oper_status": "up",
        **kw,
    }


def _link(dev_a, if_a, dev_b, if_b, **kw):
    return {
        "link_id": f"{dev_a}:{if_a}--{dev_b}:{if_b}",
        "local_device_id": dev_a,
        "local_interface_id": f"{dev_a}:{if_a}",
        "remote_device_id": dev_b,
        "remote_interface_id": f"{dev_b}:{if_b}",
        "status": "up",
        **kw,
    }


def _finding(rule_id, element_id, severity, title="t"):
    return {
        "finding_id": f"{rule_id}::{element_id}",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "message": "m",
        "evidence": {"element_type": "device", "element_id": element_id},
    }


def _run(run_id, devices=(), interfaces=(), links=(), lsdb=(), findings=()):
    model = {
        "devices": list(devices),
        "interfaces": list(interfaces),
        "links": list(links),
        "adjacencies": [],
        "shared_services": [],
        "l2_domains": [],
        "ospf_lsdb": list(lsdb),
    }
    return RunData(run_id=run_id, site="lab1", model=model, findings=list(findings))


BASE_DEVICES = [_device("sw-a"), _device("sw-b")]
BASE_IFACES = [_iface("sw-a", "Gi1"), _iface("sw-b", "Gi1")]


def _verdict(before, after, scope=None):
    return evaluate_change(compute_diff(before, after), before, after, scope)


# ── pass ──────────────────────────────────────────────────────────────────────

def test_empty_diff_is_pass():
    a = _run("r1", BASE_DEVICES, BASE_IFACES)
    b = _run("r2", BASE_DEVICES, BASE_IFACES)
    v = _verdict(a, b)
    assert v.result == "pass" and v.reasons == ()


def test_all_drift_inside_scope_is_pass():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    changed = [_iface("sw-a", "Gi1", oper_status="down"), _iface("sw-b", "Gi1")]
    after = _run("r2", BASE_DEVICES, changed)
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "pass"
    assert v.counts["in_scope"] == 1 and v.counts["out_of_scope"] == 0


# ── fail ──────────────────────────────────────────────────────────────────────

def test_new_high_finding_fails_even_in_scope():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    after = _run("r2", BASE_DEVICES, BASE_IFACES,
                 findings=[_finding("R1", "sw-a", "high", "bad thing")])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "fail"
    assert v.reasons[0]["code"] == "new_finding" and v.reasons[0]["severity"] == "high"
    assert "bad thing" in v.reasons[0]["detail"]


def test_new_critical_finding_fails_without_scope():
    before = _run("r1", BASE_DEVICES)
    after = _run("r2", BASE_DEVICES, findings=[_finding("R1", "sw-a", "critical")])
    assert _verdict(before, after).result == "fail"


def test_out_of_scope_change_fails():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    changed = [_iface("sw-a", "Gi1"), _iface("sw-b", "Gi1", oper_status="down")]
    after = _run("r2", BASE_DEVICES, changed)
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "fail"
    assert v.reasons[0]["code"] == "out_of_scope_change"
    assert "sw-b" in v.reasons[0]["detail"]


def test_out_of_scope_removed_link_fails():
    link = _link("sw-b", "Gi1", "sw-c", "Gi1")
    before = _run("r1", BASE_DEVICES, BASE_IFACES, links=[link])
    after = _run("r2", BASE_DEVICES, BASE_IFACES, links=[])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "fail"
    assert v.counts["out_of_scope"] == 1


def test_link_with_one_scoped_endpoint_is_in_scope():
    link_before = _link("sw-a", "Gi1", "sw-b", "Gi1", status="up")
    link_after = _link("sw-a", "Gi1", "sw-b", "Gi1", status="down")
    before = _run("r1", BASE_DEVICES, BASE_IFACES, links=[link_before])
    after = _run("r2", BASE_DEVICES, BASE_IFACES, links=[link_after])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "pass"          # any endpoint in scope → expected change
    assert v.counts["in_scope"] == 1


# ── warn ──────────────────────────────────────────────────────────────────────

def test_new_minor_finding_warns():
    before = _run("r1", BASE_DEVICES)
    after = _run("r2", BASE_DEVICES, findings=[_finding("R1", "sw-a", "low")])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "warn"
    assert v.reasons[0]["code"] == "new_minor_findings"


def test_drift_without_scope_warns():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    changed = [_iface("sw-a", "Gi1", oper_status="down"), _iface("sw-b", "Gi1")]
    after = _run("r2", BASE_DEVICES, changed)
    v = _verdict(before, after)        # no scope declared
    assert v.result == "warn"
    assert v.reasons[0]["code"] == "unscoped_drift"


def test_unattributed_lsdb_change_warns_never_fails():
    lsa_before = {"area_id": "0.0.0.0", "lsa_type": 1, "lsa_id": "198.51.100.1",
                  "adv_router": "198.51.100.1", "num_links": 2}
    lsa_after = dict(lsa_before, num_links=3)
    before = _run("r1", BASE_DEVICES, BASE_IFACES, lsdb=[lsa_before])
    after = _run("r2", BASE_DEVICES, BASE_IFACES, lsdb=[lsa_after])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "warn"
    assert v.reasons[0]["code"] == "unattributed_change"
    assert v.reasons[0]["entity_type"] == "ospf_lsdb"
    assert v.counts["unattributed"] == 1 and v.counts["out_of_scope"] == 0


def test_changed_finding_warns():
    before = _run("r1", BASE_DEVICES, findings=[_finding("R1", "sw-a", "low", "old")])
    after = _run("r2", BASE_DEVICES,
                 findings=[_finding("R1", "sw-a", "low", "new title")])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "warn"
    assert any(r["code"] == "changed_findings" for r in v.reasons)


# ── neutral signals ───────────────────────────────────────────────────────────

def test_resolved_finding_is_positive_not_a_reason():
    before = _run("r1", BASE_DEVICES, findings=[_finding("R1", "sw-a", "high")])
    after = _run("r2", BASE_DEVICES, findings=[])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "pass"
    assert v.counts["resolved_findings"] == 1


def test_new_info_finding_counted_but_neutral():
    before = _run("r1", BASE_DEVICES)
    after = _run("r2", BASE_DEVICES, findings=[_finding("R1", "sw-a", "info")])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "pass"
    assert v.counts["new_findings"] == {"info": 1}


def test_info_tier_field_change_never_affects_verdict():
    # bgp prefix-count style fields are INFO-tier by field policy on
    # adjacencies; use an interface info field instead: pick one from policy.
    from netcopilot.diff import field_policy as fp

    info_field = next(iter(fp.INFO_FIELDS))
    before = _run("r1", BASE_DEVICES, [_iface("sw-b", "Gi1", **{info_field: 1})])
    after = _run("r2", BASE_DEVICES, [_iface("sw-b", "Gi1", **{info_field: 2})])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "pass"
    assert v.counts["info"] == 1 and v.counts["drift_total"] == 0


# ── determinism + shape ───────────────────────────────────────────────────────

def test_same_inputs_same_verdict():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    changed = [_iface("sw-a", "Gi1", oper_status="down"), _iface("sw-b", "Gi1", oper_status="down")]
    after = _run("r2", BASE_DEVICES, changed)
    v1 = _verdict(before, after, scope=frozenset({"sw-a"}))
    v2 = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v1.to_dict() == v2.to_dict()


def test_verdict_dict_shape_is_frozen():
    # The structuredContent contract external clients pin (ADR-0006).
    v = ChangeVerdict(result="pass")
    d = v.to_dict()
    assert set(d) == {"result", "reasons", "counts"}
    assert isinstance(d["reasons"], list) and isinstance(d["counts"], dict)


def test_fails_ordered_before_warns():
    before = _run("r1", BASE_DEVICES, BASE_IFACES)
    changed = [_iface("sw-a", "Gi1"), _iface("sw-b", "Gi1", oper_status="down")]
    after = _run("r2", BASE_DEVICES, changed,
                 findings=[_finding("R1", "sw-a", "low")])
    v = _verdict(before, after, scope=frozenset({"sw-a"}))
    assert v.result == "fail"
    codes = [r["code"] for r in v.reasons]
    assert codes.index("out_of_scope_change") < codes.index("new_minor_findings")
