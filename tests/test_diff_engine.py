"""S01-1: run-to-run diff engine + field policy.

Pure engine tests on synthetic model/findings dicts (no disk, no Neo4j). All
IPs are RFC 5737 documentation ranges; all hostnames synthetic.

Covers the S01-1 acceptance checklist:
  - added / removed / changed / info sets, keyed by stable ID
  - pure-counter deltas → no change; the four info signals → info, not drift
  - accepts same-site pairs; rejects cross-site pairs
  - deterministic (same inputs → identical diff)
"""

from __future__ import annotations

import json

import pytest

from netcopilot.diff import field_policy as fp
from netcopilot.diff.engine import RunData, compute_diff, load_run


# ---------------------------------------------------------------------------
# Synthetic run builders
# ---------------------------------------------------------------------------
def _device(hostname, site="demo", **over):
    d = {
        "device_id": hostname,
        "hostname": hostname,
        "site": site,
        "os_family": "iosxe",
        "role": "access_switch",
        "vlans": [],
    }
    d.update(over)
    return d


def _iface(device, name, **over):
    i = {
        "interface_id": f"{device}:{name}",
        "device_id": device,
        "name": name,
        "admin_status": "up",
        "oper_status": "up",
        "mtu": 1500,
    }
    i.update(over)
    return i


def _link(a_dev, a_if, b_dev, b_if, status="up", **over):
    lk = {
        "link_id": f"{a_dev}:{a_if}--{b_dev}:{b_if}",
        "local_device_id": a_dev,
        "local_interface_id": f"{a_dev}:{a_if}",
        "remote_device_id": b_dev,
        "remote_interface_id": f"{b_dev}:{b_if}",
        "status": status,
    }
    lk.update(over)
    return lk


def _finding(rule_id, element_id, element_type="device", severity="high", **kf):
    return {
        "finding_id": f"{rule_id}::{element_id}",
        "rule_id": rule_id,
        "severity": severity,
        "title": rule_id.replace("_", " ").title(),
        "message": f"{rule_id} on {element_id}",
        "evidence": {"element_type": element_type, "element_id": element_id, "key_facts": kf},
        "recommendation": "fix it",
        "detected_at": "2026-07-01T00:00:00+00:00",
    }


def _run(run_id, *, devices=None, interfaces=None, links=None, findings=None, **model_extra):
    model = {
        "devices": devices or [],
        "interfaces": interfaces or [],
        "links": links or [],
        "adjacencies": [],
        "shared_services": [],
        "l2_domains": [],
        "ospf_lsdb": [],
    }
    model.update(model_extra)
    site = None
    for d in model["devices"]:
        if d.get("site"):
            site = d["site"]
            break
    return RunData(run_id=run_id, site=site, model=model, findings=findings or [])


def _by(changes, tier):
    return {c["key"] for c in changes if c["tier"] == tier}


def _entry(changes, key):
    return next(c for c in changes if c["key"] == key)


# ---------------------------------------------------------------------------
# Added / removed / changed, keyed by stable ID
# ---------------------------------------------------------------------------
def test_added_removed_changed_devices_and_links():
    before = _run(
        "A",
        devices=[_device("acc-sw-01"), _device("acc-sw-02")],
        links=[_link("acc-sw-01", "Gi0/1", "core-sw-01", "Gi0/1")],
    )
    after = _run(
        "B",
        devices=[_device("acc-sw-01"), _device("acc-sw-03")],  # -02 removed, -03 added
        links=[_link("acc-sw-01", "Gi0/1", "core-sw-01", "Gi0/1", status="down")],  # changed
    )
    res = compute_diff(before, after)

    assert _by(res.changes, "added") == {"acc-sw-03"}
    assert _by(res.changes, "removed") == {"acc-sw-02"}
    assert "acc-sw-01:Gi0/1--core-sw-01:Gi0/1" in _by(res.changes, "changed")

    link_entry = _entry(res.changes, "acc-sw-01:Gi0/1--core-sw-01:Gi0/1")
    assert link_entry["element_type"] == "link"
    assert link_entry["changed_fields"] == [{"field": "status", "before": "up", "after": "down"}]

    # removed device carries its prior data (for ghost rendering)
    removed = _entry(res.changes, "acc-sw-02")
    assert removed["before"]["device_id"] == "acc-sw-02"
    assert removed["element_type"] == "device"

    assert res.summary == {"added": 1, "removed": 1, "changed": 1, "info": 0}


def test_interface_oper_status_is_drift_not_info():
    before = _run("A", devices=[_device("acc-sw-01")], interfaces=[_iface("acc-sw-01", "Gi0/1")])
    after = _run(
        "A2",
        devices=[_device("acc-sw-01")],
        interfaces=[_iface("acc-sw-01", "Gi0/1", oper_status="down")],
    )
    res = compute_diff(before, after)
    entry = _entry(res.changes, "acc-sw-01:Gi0/1")
    assert entry["tier"] == "changed"
    assert entry["element_type"] == "device"  # interface halos its owning node
    assert entry["changed_fields"] == [{"field": "oper_status", "before": "up", "after": "down"}]


def test_vlan_membership_change_is_drift():
    before = _run("A", devices=[_device("core-sw-01", vlans=[{"vlan_id": 10, "name": "USERS"}])])
    after = _run(
        "B",
        devices=[_device("core-sw-01", vlans=[{"vlan_id": 10, "name": "USERS"}, {"vlan_id": 20, "name": "VOICE"}])],
    )
    res = compute_diff(before, after)
    entry = _entry(res.changes, "core-sw-01")
    assert entry["tier"] == "changed"
    assert [f["field"] for f in entry["changed_fields"]] == ["vlans"]


# ---------------------------------------------------------------------------
# Volatile (no change) vs info tier
# ---------------------------------------------------------------------------
def test_pure_counter_delta_produces_no_change():
    before = _run(
        "A", devices=[_device("core-sw-01")],
        interfaces=[_iface("core-sw-01", "Gi0/1", in_octets=1000, out_packets=50)],
    )
    after = _run(
        "B", devices=[_device("core-sw-01")],
        interfaces=[_iface("core-sw-01", "Gi0/1", in_octets=999999, out_packets=7777)],
    )
    res = compute_diff(before, after)
    assert res.changes == []
    assert res.summary == {"added": 0, "removed": 0, "changed": 0, "info": 0}


def test_info_signals_land_in_info_not_drift():
    before = _run(
        "A", devices=[_device("bdr-rtr-01")],
        interfaces=[_iface("bdr-rtr-01", "Gi0/0", prefixes_received=100, arp_count=40)],
    )
    after = _run(
        "B", devices=[_device("bdr-rtr-01")],
        interfaces=[_iface("bdr-rtr-01", "Gi0/0", prefixes_received=105, arp_count=42)],
    )
    res = compute_diff(before, after)
    entry = _entry(res.changes, "bdr-rtr-01:Gi0/0")
    assert entry["tier"] == "info"
    changed = {f["field"] for f in entry["changed_fields"]}
    assert changed == {"prefixes_received", "arp_count"}
    assert res.summary["info"] == 1
    assert res.summary["changed"] == 0


def test_drift_and_info_on_same_entity_is_changed_showing_drift_fields():
    before = _run(
        "A", devices=[_device("bdr-rtr-01")],
        interfaces=[_iface("bdr-rtr-01", "Gi0/0", prefixes_received=100)],
    )
    after = _run(
        "B", devices=[_device("bdr-rtr-01")],
        interfaces=[_iface("bdr-rtr-01", "Gi0/0", prefixes_received=105, oper_status="down")],
    )
    res = compute_diff(before, after)
    entry = _entry(res.changes, "bdr-rtr-01:Gi0/0")
    # drift present → entity is "changed"; the field list shows the drift field
    assert entry["tier"] == "changed"
    assert [f["field"] for f in entry["changed_fields"]] == ["oper_status"]


def test_bilateral_counter_suffix_is_volatile():
    # Adjacency fields are bilateral (_a/_b). BGP message counters
    # (msg_sent_a/_b, msg_rcvd_a/_b) are pure counters → no change, even though
    # only the suffixed forms appear in the data.
    adj = lambda **o: {"protocol": "bgp", "device_a": "203.0.113.2", "device_b": "bdr-rtr-01",
                       "vrf": "default", "process_id": "", "area": "", **o}
    before = _run("A", devices=[_device("bdr-rtr-01")],
                  adjacencies=[adj(msg_sent_a=10, msg_rcvd_b=4153, state="established")])
    after = _run("B", devices=[_device("bdr-rtr-01")],
                 adjacencies=[adj(msg_sent_a=99, msg_rcvd_b=9999, state="established")])
    assert compute_diff(before, after).changes == []


def test_bgp_up_down_duration_is_info_not_drift():
    # up_down ("2d21h") is the BGP session Up/Down duration — a session-uptime
    # signal that advances every collection → info, not drift. Bilateral suffix.
    adj = lambda **o: {"protocol": "bgp", "device_a": "203.0.113.2", "device_b": "bdr-rtr-01",
                       "vrf": "default", "process_id": "", "area": "", "state": "established", **o}
    before = _run("A", devices=[_device("bdr-rtr-01")], adjacencies=[adj(up_down_b="2d21h")])
    after = _run("B", devices=[_device("bdr-rtr-01")], adjacencies=[adj(up_down_b="3d05h")])
    res = compute_diff(before, after)
    key = fp.STABLE_KEYS["adjacencies"](adj())
    entry = _entry(res.changes, key)
    assert entry["tier"] == "info"
    assert [f["field"] for f in entry["changed_fields"]] == ["up_down_b"]


def test_field_bucket_suffix_stripping():
    # exact + _a/_b base both resolve; drift fields with an _a/_b tail whose base
    # is in no set stay drift (e.g. router_id_a, hold_time_b, cost_a).
    assert fp.field_bucket("msg_sent") == "volatile"
    assert fp.field_bucket("msg_sent_a") == "volatile"
    assert fp.field_bucket("up_down_b") == "info"
    assert fp.field_bucket("prefixes_received") == "info"
    assert fp.field_bucket("router_id_a") == "drift"
    assert fp.field_bucket("hold_time_b") == "drift"
    assert fp.field_bucket("oper_status") == "drift"


def test_volatile_detected_at_on_finding_is_not_a_change():
    f_before = _finding("LINK_DOWN", "core-sw-01")
    f_after = _finding("LINK_DOWN", "core-sw-01")
    f_after["detected_at"] = "2099-01-01T00:00:00+00:00"  # only volatile differs
    res = compute_diff(
        _run("A", devices=[_device("core-sw-01")], findings=[f_before]),
        _run("B", devices=[_device("core-sw-01")], findings=[f_after]),
    )
    assert res.changes == []


# ---------------------------------------------------------------------------
# Findings diff
# ---------------------------------------------------------------------------
def test_findings_added_removed_changed():
    before = _run(
        "A", devices=[_device("core-sw-01")],
        findings=[_finding("A_RULE", "core-sw-01"), _finding("B_RULE", "core-sw-01", severity="low")],
    )
    after = _run(
        "B", devices=[_device("core-sw-01")],
        findings=[
            _finding("B_RULE", "core-sw-01", severity="high"),  # severity changed
            _finding("C_RULE", "core-sw-01"),  # added
        ],
    )
    res = compute_diff(before, after)
    assert _by(res.changes, "removed") == {"A_RULE::core-sw-01"}
    assert _by(res.changes, "added") == {"C_RULE::core-sw-01"}
    changed = _entry(res.changes, "B_RULE::core-sw-01")
    assert changed["tier"] == "changed"
    assert changed["element_type"] == "device"
    assert [f["field"] for f in changed["changed_fields"]] == ["severity"]


# ---------------------------------------------------------------------------
# Ordering / list canonicalisation
# ---------------------------------------------------------------------------
def test_reordered_list_field_is_not_a_change():
    before = _run("A", devices=[_device("core-sw-01", cluster_members=["m1", "m2"])])
    after = _run("B", devices=[_device("core-sw-01", cluster_members=["m2", "m1"])])
    res = compute_diff(before, after)
    assert res.changes == []


# ---------------------------------------------------------------------------
# Site enforcement
# ---------------------------------------------------------------------------
def test_same_site_pair_is_accepted():
    a = _run("A", devices=[_device("d1", site="demo")])
    b = _run("B", devices=[_device("d1", site="demo")])
    assert compute_diff(a, b).site == "demo"


def test_cross_site_pair_is_rejected():
    a = _run("A", devices=[_device("d1", site="demo")])
    b = _run("B", devices=[_device("d1", site="lab-x")])
    with pytest.raises(ValueError, match="cross-site"):
        compute_diff(a, b)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
def test_deterministic_same_inputs_identical_output():
    before = _run(
        "A",
        devices=[_device("acc-sw-01"), _device("acc-sw-02")],
        interfaces=[_iface("acc-sw-01", "Gi0/1"), _iface("acc-sw-02", "Gi0/1")],
        links=[_link("acc-sw-01", "Gi0/1", "core-sw-01", "Gi0/1")],
        findings=[_finding("R1", "acc-sw-01")],
    )
    after = _run(
        "B",
        devices=[_device("acc-sw-01", role="dist_switch"), _device("acc-sw-03")],
        interfaces=[_iface("acc-sw-01", "Gi0/1", oper_status="down")],
        links=[_link("acc-sw-01", "Gi0/1", "core-sw-01", "Gi0/1", status="down")],
        findings=[_finding("R2", "acc-sw-03")],
    )
    r1 = json.dumps(compute_diff(before, after).to_dict(), sort_keys=True)
    r2 = json.dumps(compute_diff(before, after).to_dict(), sort_keys=True)
    assert r1 == r2


def test_shared_services_ospf_area_disambiguated_by_process_and_vrf():
    # Two ospf_area services share identifier "0.0.0.0" but differ by
    # process_id + vrf — they must be distinct entities, not a duplicate-key
    # crash (regression: this shape appears in real runs).
    svc_a = {"service_type": "ospf_area", "identifier": "0.0.0.0", "process_id": "1", "vrf": "default", "members": ["a"]}
    svc_b = {"service_type": "ospf_area", "identifier": "0.0.0.0", "process_id": "20", "vrf": "BLUE", "members": ["b"]}
    before = _run("A", devices=[_device("core-sw-01")], shared_services=[svc_a, svc_b])
    after = _run("B", devices=[_device("core-sw-01")], shared_services=[svc_a])  # BLUE area removed
    res = compute_diff(before, after)
    assert _by(res.changes, "removed") == {"ospf_area:0.0.0.0:20:BLUE"}
    assert res.summary["removed"] == 1


def test_shared_services_volatile_ospf_counters_are_ignored():
    # spf_runs / lsa_count live on ospf_area services and are volatile.
    svc = lambda **o: {"service_type": "ospf_area", "identifier": "0.0.0.0", "process_id": "1",
                       "vrf": "default", "members": ["a"], **o}
    before = _run("A", devices=[_device("core-sw-01")], shared_services=[svc(spf_runs=10, lsa_count=3)])
    after = _run("B", devices=[_device("core-sw-01")], shared_services=[svc(spf_runs=15, lsa_count=6)])
    assert compute_diff(before, after).changes == []


def test_duplicate_stable_key_raises():
    dup = _run("A", devices=[_device("d1"), _device("d1")])
    other = _run("B", devices=[_device("d1")])
    with pytest.raises(ValueError, match="duplicate stable key"):
        compute_diff(dup, other)


# ---------------------------------------------------------------------------
# Disk loader
# ---------------------------------------------------------------------------
def test_load_run_missing_model_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="model not found"):
        load_run("nope", runs_dir=tmp_path)


def test_load_run_reads_model_and_findings(tmp_path):
    run_dir = tmp_path / "r1"
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    (run_dir / "model" / "network_model.json").write_text(
        json.dumps({"devices": [_device("d1", site="demo")], "interfaces": []})
    )
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": [_finding("R1", "d1")]})
    )
    rd = load_run("r1", runs_dir=tmp_path)
    assert rd.site == "demo"
    assert rd.run_id == "r1"
    assert len(rd.findings) == 1


def test_load_run_missing_findings_raises(tmp_path):
    run_dir = tmp_path / "r1"
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "model" / "network_model.json").write_text(json.dumps({"devices": []}))
    with pytest.raises(FileNotFoundError, match="findings not found"):
        load_run("r1", runs_dir=tmp_path)


# ---------------------------------------------------------------------------
# Field-policy sanity (guards against accidental bucket moves)
# ---------------------------------------------------------------------------
def test_field_policy_buckets_are_disjoint():
    assert fp.VOLATILE_FIELDS.isdisjoint(fp.INFO_FIELDS)


def test_status_fields_are_drift():
    for f in ("oper_status", "admin_status", "status", "state"):
        assert f not in fp.VOLATILE_FIELDS
        assert f not in fp.INFO_FIELDS
