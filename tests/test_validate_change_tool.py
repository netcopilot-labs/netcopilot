"""s05-2: the validate_change MCP tool — envelope, defaults, failure modes.

Fixture runs on disk (tmp_path RUNS_DIR), the real engine underneath — the
same layering as test_run_diff_tool.
"""

import asyncio
import json

import pytest

from netcopilot.mcp.registry import TOOL_SCHEMAS, dispatch
from netcopilot.mcp.tools.validate import validate_change


def _write_run(runs_dir, run_id, site="lab1", devices=(), interfaces=(), findings=()):
    run = runs_dir / run_id
    (run / "model").mkdir(parents=True)
    (run / "findings").mkdir(parents=True)
    model = {
        "devices": list(devices),
        "interfaces": list(interfaces),
        "links": [],
        "adjacencies": [],
        "shared_services": [],
        "l2_domains": [],
        "ospf_lsdb": [],
        "model_metadata": {"site": site},
    }
    (run / "model" / "network_model.json").write_text(json.dumps(model))
    (run / "findings" / "findings.json").write_text(json.dumps({"findings": list(findings)}))


def _device(device_id, **kw):
    return {"device_id": device_id, "role": "access_switch", **kw}


def _iface(device_id, name, **kw):
    return {"interface_id": f"{device_id}:{name}", "device_id": device_id,
            "name": name, "oper_status": "up", **kw}


def _finding(rule_id, element_id, severity):
    return {"finding_id": f"{rule_id}::{element_id}", "rule_id": rule_id,
            "severity": severity, "title": "t", "message": "m",
            "evidence": {"element_type": "device", "element_id": element_id}}


@pytest.fixture()
def runs(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-01-01_10-00-00",
               devices=[_device("sw-a"), _device("sw-b")],
               interfaces=[_iface("sw-a", "Gi1"), _iface("sw-b", "Gi1")])
    _write_run(tmp_path, "2026-01-02_10-00-00",
               devices=[_device("sw-a"), _device("sw-b")],
               interfaces=[_iface("sw-a", "Gi1", oper_status="down"),
                           _iface("sw-b", "Gi1")])
    return tmp_path


def _call(**kwargs):
    ctx = kwargs.pop("context", {"run_id": "2026-01-02_10-00-00"})
    return asyncio.run(validate_change(context=ctx, **kwargs))


def test_registered_as_26th_tool():
    names = {s["name"] for s in TOOL_SCHEMAS}
    assert "validate_change" in names


def test_pass_when_drift_in_scope(runs):
    out = _call(run_before="2026-01-01_10-00-00", run_after="2026-01-02_10-00-00",
                scope_devices=["sw-a"])
    assert out.status == "ok"
    assert out.verdict["result"] == "pass"
    assert "✅ PASS" in out.text and "Declared scope: sw-a" in out.text


def test_fail_out_of_scope_with_reason_in_text(runs):
    out = _call(run_before="2026-01-01_10-00-00", run_after="2026-01-02_10-00-00",
                scope_devices=["sw-b"])
    assert out.verdict["result"] == "fail"
    assert out.verdict["reasons"][0]["code"] == "out_of_scope_change"
    assert "❌ FAIL" in out.text and "sw-a" in out.text


def test_defaults_resolve_current_and_previous_run(runs):
    out = _call()  # run_after ← context run, run_before ← previous same-site run
    assert out.status == "ok"
    assert "2026-01-01_10-00-00 → 2026-01-02_10-00-00" in out.text
    assert out.verdict["result"] == "warn"          # drift, no scope declared
    assert out.verdict["reasons"][0]["code"] == "unscoped_drift"


def test_unknown_run_is_not_found_with_hint(runs):
    out = _call(run_before="nope", run_after="2026-01-02_10-00-00")
    assert out.status == "not_found"
    assert "2026-01-01_10-00-00" in out.text        # available runs listed


def test_earliest_run_is_no_data(runs):
    out = _call(run_after="2026-01-01_10-00-00")
    assert out.status == "no_data"
    assert "pre-change run" in out.text


def test_unknown_scope_device_is_flagged(runs):
    out = _call(run_before="2026-01-01_10-00-00", run_after="2026-01-02_10-00-00",
                scope_devices=["sw-a", "sw-typo"])
    assert "sw-typo" in out.text and "not present in either run" in out.text
    assert out.verdict["result"] == "pass"          # sw-a covers the drift


def test_dispatch_routes_validate_change(runs):
    out = asyncio.run(dispatch(
        "validate_change",
        {"run_before": "2026-01-01_10-00-00", "run_after": "2026-01-02_10-00-00"},
        {"run_id": "2026-01-02_10-00-00"},
    ))
    assert out.status == "ok" and out.verdict is not None


def test_verdict_structured_shape(runs):
    out = _call(run_before="2026-01-01_10-00-00", run_after="2026-01-02_10-00-00",
                scope_devices=["sw-a"])
    assert set(out.verdict) == {"result", "reasons", "counts"}
    assert set(out.verdict["counts"]) >= {"drift_total", "in_scope", "out_of_scope",
                                          "unattributed", "new_findings",
                                          "resolved_findings", "info"}
