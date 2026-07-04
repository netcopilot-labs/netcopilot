"""S09-3 / S09-4: firewall_policies as a diffable entity type.

The engine iterates ENTITY_TYPES generically, so registering firewall_policies
(stable key + element-ref + field policy) is all it takes for diff_runs to see
policy drift. These tests drive compute_diff over in-memory RunData (policy
dicts injected via model_extra) and load_run over on-disk runs (artifact present
/ absent). Device attribution: a policy halos its device node.
"""

import json

import pytest

from netcopilot.diff.engine import RunData, compute_diff, load_run


def _fw(policyid, *, device="fw-01", action="accept", srcaddr="0.0.0.0/0",
        dstaddr="192.0.2.0/24", service="TCP/443", dst_isdb="", **extra):
    p = {
        "policyid": policyid, "seq": policyid, "name": f"pol-{policyid}",
        "status": "enable", "action": action, "srcaddr": srcaddr,
        "dstaddr": dstaddr, "service": service, "dst_isdb": dst_isdb,
        "policy_type": "fortigate", "device": device, "site": "t1",
        "run_id": "ignored",
    }
    p.update(extra)
    return p


def _acl(seq, *, device="sw-01", name="BLOCK-IN", action="permit",
         srcaddr="any", dstaddr="any", service="any"):
    return {
        "policyid": seq, "seq": seq, "name": name, "status": "enable",
        "action": action, "srcaddr": srcaddr, "dstaddr": dstaddr,
        "service": service, "policy_type": "acl", "acl_type": "IPv4",
        "applied_to": [], "device": device, "site": "t1", "run_id": "ignored",
    }


def _run(run_id, policies):
    model = {
        "devices": [], "interfaces": [], "links": [], "adjacencies": [],
        "shared_services": [], "l2_domains": [], "ospf_lsdb": [],
        "firewall_policies": policies,
    }
    return RunData(run_id=run_id, site="t1", model=model, findings=[])


def _entry(changes, key):
    return next(c for c in changes if c["key"] == key)


# ── S09-3: the four required drift shapes ────────────────────────────────────

def test_action_flip_is_drift_attributed_to_device():
    res = compute_diff(_run("A", [_fw(1, action="accept")]),
                       _run("B", [_fw(1, action="deny")]))
    e = _entry(res.changes, "fw-01:fw:1")
    assert e["tier"] == "changed"
    assert e["element_type"] == "device" and e["element_id"] == "fw-01"
    fields = {f["field"]: (f["before"], f["after"]) for f in e["changed_fields"]}
    assert fields["action"] == ("accept", "deny")


def test_new_and_removed_rule():
    res = compute_diff(_run("A", [_fw(1), _fw(2)]),
                       _run("B", [_fw(1), _fw(3)]))
    tiers = {c["key"]: c["tier"] for c in res.changes}
    assert tiers["fw-01:fw:3"] == "added"
    assert tiers["fw-01:fw:2"] == "removed"
    assert "fw-01:fw:1" not in tiers          # unchanged → no entry


def test_changed_service_is_drift():
    res = compute_diff(_run("A", [_fw(1, service="TCP/443")]),
                       _run("B", [_fw(1, service="TCP/8443")]))
    e = _entry(res.changes, "fw-01:fw:1")
    fields = {f["field"] for f in e["changed_fields"]}
    assert "service" in fields and e["tier"] == "changed"


def test_new_isdb_reference_is_drift():
    res = compute_diff(_run("A", [_fw(1, dst_isdb="")]),
                       _run("B", [_fw(1, dst_isdb="Tor-Relay")]))
    e = _entry(res.changes, "fw-01:fw:1")
    fields = {f["field"]: (f["before"], f["after"]) for f in e["changed_fields"]}
    assert fields["dst_isdb"] == ("", "Tor-Relay")


# ── noise suppression: seq reorder + run_id are NOT drift ────────────────────

def test_seq_reorder_alone_is_not_drift():
    # Same policy identity + config, only its enumeration slot moved.
    res = compute_diff(_run("A", [_fw(1, seq=1)]),
                       _run("B", [_fw(1, seq=9)]))
    assert res.changes == []


def test_run_id_difference_is_not_drift():
    a = _fw(1); a["run_id"] = "2026-01-01"
    b = _fw(1); b["run_id"] = "2026-02-02"
    assert compute_diff(_run("A", [a]), _run("B", [b])).changes == []


# ── S09-3: ACL keying + multi-device collision safety ────────────────────────

def test_acl_ace_permit_to_deny_is_drift():
    res = compute_diff(_run("A", [_acl(10, action="permit")]),
                       _run("B", [_acl(10, action="deny")]))
    e = _entry(res.changes, "sw-01:acl:BLOCK-IN:10")
    assert e["tier"] == "changed" and e["element_id"] == "sw-01"


def test_same_policyid_on_two_devices_does_not_collide():
    # policyid=1 on fw-01 and fw-02 — distinct keys via the device prefix.
    res = compute_diff(
        _run("A", [_fw(1, device="fw-01"), _fw(1, device="fw-02")]),
        _run("B", [_fw(1, device="fw-01", action="deny"), _fw(1, device="fw-02")]),
    )
    changed = {c["key"] for c in res.changes if c["tier"] == "changed"}
    assert changed == {"fw-01:fw:1"}          # only fw-01's flip, no collision error


# ── S09-3: on-disk artifact — present + absent (backward compatible) ─────────

def _write_run(runs_dir, run_id, *, policies=None):
    run = runs_dir / run_id
    (run / "model").mkdir(parents=True)
    (run / "findings").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(
        json.dumps({"devices": [], "interfaces": [], "links": [],
                    "model_metadata": {"site": "t1"}}))
    (run / "findings" / "findings.json").write_text(json.dumps({"findings": []}))
    if policies is not None:
        (run / "policies").mkdir(parents=True)
        (run / "policies" / "policies.json").write_text(json.dumps({"policies": policies}))


def test_load_run_reads_policies_artifact(tmp_path):
    _write_run(tmp_path, "run-A", policies=[_fw(1)])
    rd = load_run("run-A", runs_dir=tmp_path)
    assert rd.model["firewall_policies"] == [_fw(1)]


def test_absent_artifact_is_empty_not_false_drift(tmp_path):
    # A run predating the feature (no policies.json) vs one with a policy: the
    # policy shows as ADDED, never as a spurious "all removed" on the old side.
    _write_run(tmp_path, "run-old")                       # no policies.json
    _write_run(tmp_path, "run-new", policies=[_fw(1)])
    before = load_run("run-old", runs_dir=tmp_path)
    after = load_run("run-new", runs_dir=tmp_path)
    assert before.model["firewall_policies"] == []
    res = compute_diff(before, after)
    assert {c["key"]: c["tier"] for c in res.changes} == {"fw-01:fw:1": "added"}


def test_two_old_runs_no_policy_drift(tmp_path):
    _write_run(tmp_path, "run-1")
    _write_run(tmp_path, "run-2")
    res = compute_diff(load_run("run-1", runs_dir=tmp_path),
                       load_run("run-2", runs_dir=tmp_path))
    assert [c for c in res.changes if c["entity_type"] == "firewall_policies"] == []
