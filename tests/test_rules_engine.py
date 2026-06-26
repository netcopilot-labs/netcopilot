"""F3b: rules engine core — catalog loader, generic evaluator, engine, findings writer."""

import json

import yaml

from netcopilot.rules.catalog_loader import load_catalog
from netcopilot.rules.engine import (
    _apply_cis_severity,
    _build_summary,
    _merge_and_dedup,
    run_rules,
)
from netcopilot.rules.finding import Finding
from netcopilot.rules.findings_writer import write_findings
from netcopilot.rules.generic_evaluator import evaluate_device


def _ospf_rule(rid="OSPF_NEIGHBOR_NOT_FULL", severity="critical", **eval_extra):
    ev = {"source": "genie_ospf", "iterate": "vrf.*.neighbor.*",
          "condition": {"field": "state", "operator": "not_equals", "value": "full"},
          "element_id": "{hostname}/ospf/{vrf}/nbr/{neighbor}",
          "evidence": "state={state}", "skip_if_missing": True}
    ev.update(eval_extra)
    return {"rule_id": rid, "severity": severity, "category": "x", "protocol": "ospf",
            "tier": "surface", "description": "desc", "eval": ev}


def _write_catalog(tmp_path, rules):
    p = tmp_path / "rule-catalog.yaml"
    p.write_text(yaml.safe_dump(rules))
    return str(p)


# ----------------------------- catalog_loader ----------------------------

def test_catalog_filters_and_maps_severity(tmp_path):
    rules = [
        _ospf_rule(severity="warning"),                         # → high
        {"rule_id": "NO_EVAL", "severity": "critical"},          # skipped: no eval
        {**_ospf_rule("CROSS_X"), "cross_device": True},         # skipped: cross-device
        {**_ospf_rule("BAD"), "eval": {"source": "x"}},          # skipped: invalid eval
    ]
    cr = load_catalog(_write_catalog(tmp_path, rules))
    assert cr.stats["loaded"] == 1
    assert cr.stats["skipped_no_eval"] == 1
    assert cr.stats["skipped_cross_device"] == 1
    assert cr.stats["skipped_invalid"] == 1
    rd = cr.rules[0]
    assert rd.rule_id == "OSPF_NEIGHBOR_NOT_FULL"
    assert rd.python_severity == "high"   # 'warning' → 'high'
    assert "genie_ospf" in cr.rules_by_source()


def test_catalog_python_severity_override(tmp_path):
    cr = load_catalog(_write_catalog(tmp_path, [_ospf_rule(severity="warning", python_severity="low")]))
    assert cr.rules[0].python_severity == "low"


# ---------------------------- generic_evaluator --------------------------

def test_evaluate_device_single_condition():
    cr_rules = load_catalog  # noqa: keep import obvious
    from netcopilot.rules.catalog_loader import load_catalog as lc
    import tempfile, pathlib
    cat = pathlib.Path(tempfile.mkdtemp()) / "c.yaml"
    cat.write_text(yaml.safe_dump([_ospf_rule()]))
    by_source = lc(str(cat)).rules_by_source()
    facts = {"genie_ospf": {"vrf": {"default": {"neighbor": {
        "192.0.2.9": {"state": "init"},   # violates (not full)
        "192.0.2.10": {"state": "full"},  # passes
    }}}}}
    findings = evaluate_device("core-rtr-01", facts, by_source)
    assert len(findings) == 1
    assert findings[0].finding_id == "OSPF_NEIGHBOR_NOT_FULL::core-rtr-01/ospf/default/nbr/192.0.2.9"
    assert findings[0].evidence["key_facts"]["actual_value"] == "init"


def test_evaluate_device_os_family_filter(tmp_path):
    by_source = load_catalog(_write_catalog(tmp_path, [_ospf_rule(os_family="iosxr")])).rules_by_source()
    facts = {"genie_ospf": {"vrf": {"default": {"neighbor": {"192.0.2.9": {"state": "init"}}}}}}
    assert evaluate_device("d", facts, by_source, os_family="iosxe") == []   # filtered out
    assert len(evaluate_device("d", facts, by_source, os_family="iosxr")) == 1


def test_evaluate_device_missing_source_skipped(tmp_path):
    by_source = load_catalog(_write_catalog(tmp_path, [_ospf_rule()])).rules_by_source()
    assert evaluate_device("d", {"genie_bgp": {}}, by_source) == []  # no genie_ospf → skip


# ------------------------------- engine ----------------------------------

def _finding(rid, eid="e", sev="high"):
    return Finding.create(rid, sev, "t", "device", eid, "m", {}, "r")


def test_merge_and_dedup_phase1_wins():
    p1 = [_finding("R", "same")]
    p2 = [_finding("R", "same"), _finding("R", "other")]
    merged = _merge_and_dedup(p1, p2)
    assert {f.finding_id for f in merged} == {"R::same", "R::other"}
    assert len(merged) == 2  # the duplicate R::same kept once (phase1)


def test_apply_cis_severity():
    findings = [_finding("CIS_XE_1", "d", "high"), _finding("LINK_DOWN", "l", "high")]
    out = {f.rule_id: f.severity for f in _apply_cis_severity(findings)}
    assert out["CIS_XE_1"] == "cis"      # CIS prefix → severity 'cis'
    assert out["LINK_DOWN"] == "high"    # untouched


def test_build_summary_counts():
    s = _build_summary([_finding("A", "1", "high"), _finding("A", "2", "high"), _finding("B", "3", "low")])
    assert s["by_severity"]["high"] == 2 and s["by_severity"]["low"] == 1
    assert s["by_rule"] == {"A": 2, "B": 1}


def _build_run(tmp_path, rid="r1"):
    run = tmp_path / "runs" / rid
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps({"devices": [], "interfaces": [], "links": []}))
    (run / "manifest.json").write_text(json.dumps({"run_id": rid, "devices": []}))
    facts = run / "facts" / "core-rtr-01"; facts.mkdir(parents=True)
    (facts / "genie_ospf.json").write_text(json.dumps(
        {"vrf": {"default": {"neighbor": {"192.0.2.9": {"state": "init"}}}}}))
    return tmp_path / "runs"


def test_run_rules_end_to_end(tmp_path):
    cat = _write_catalog(tmp_path, [_ospf_rule()])
    runs = _build_run(tmp_path)
    result = run_rules("r1", runs_base=str(runs), catalog_path=cat)
    assert result["metadata"]["total_findings"] == 1
    assert result["metadata"]["rules_executed_phase2"] == 1
    assert result["findings"][0]["severity"] == "critical"
    assert "lab_context" not in result          # internal-only key must not appear
    # Phase 3 (cross_device) is now extracted → runs without an import error
    assert not any("PHASE3" in e["rule_id"] for e in result["errors"])


def test_run_rules_phase2_failure_isolated(tmp_path):
    runs = _build_run(tmp_path)
    # bad catalog path → Phase 2 fails but run_rules still returns
    result = run_rules("r1", runs_base=str(runs), catalog_path=str(tmp_path / "nope.yaml"))
    assert result["metadata"]["total_findings"] == 0
    assert any("PHASE2" in e["rule_id"] for e in result["errors"])


# --------------------------- findings_writer -----------------------------

def test_write_findings_produces_json(tmp_path):
    cat = _write_catalog(tmp_path, [_ospf_rule()])
    runs = _build_run(tmp_path)
    result = run_rules("r1", runs_base=str(runs), catalog_path=cat)
    paths = write_findings(result, "r1", runs_base=str(runs))
    findings = json.loads(paths["findings"].read_text())
    summary = json.loads(paths["summary"].read_text())
    assert findings["metadata"]["total_findings"] == 1
    assert len(findings["findings"]) == 1
    assert summary["by_severity"]["critical"] == 1
    assert "lab_expected_count" not in summary  # internal-only key must not appear


def test_write_findings_validates_keys(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="missing required keys"):
        write_findings({"metadata": {}}, "r1", runs_base=str(tmp_path))
