"""S01-3: diff_runs MCP tool — registration, dispatch, and graceful errors.

Disk-based (reads RUNS_DIR); no Neo4j. Synthetic runs, RFC 5737 IPs.
"""

from __future__ import annotations

import asyncio
import json

from netcopilot.mcp import registry
from netcopilot.mcp.tools import onboarding, run_diff


def _write_run(runs_dir, run_id, *, site="demo", devices=None, findings=None):
    run_dir = runs_dir / run_id
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    devs = devices if devices is not None else [{"device_id": "core-sw-01", "site": site}]
    model = {"devices": devs, "interfaces": [], "links": [], "adjacencies": [],
             "shared_services": [], "l2_domains": [], "ospf_lsdb": []}
    (run_dir / "model" / "network_model.json").write_text(json.dumps(model))
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": findings or []})
    )


def _call(**kwargs):
    ctx = kwargs.pop("context", {"run_id": "", "site": "demo"})
    return asyncio.run(run_diff.diff_runs(context=ctx, **kwargs))


# ---------------------------------------------------------------------------
# Registration / categorization / dispatch
# ---------------------------------------------------------------------------
def test_diff_runs_registered_and_categorized():
    names = {s["name"] for s in registry.TOOL_SCHEMAS}
    assert "diff_runs" in names
    assert "diff_runs" in registry._HANDLERS
    assert onboarding._TOOL_CATEGORIES.get("diff_runs") == onboarding._CAT_TROUBLESHOOT


def test_diff_runs_schema_shape():
    schema = next(s for s in registry.TOOL_SCHEMAS if s["name"] == "diff_runs")
    assert set(schema) == {"name", "description", "parameters"}
    assert set(schema["parameters"]["properties"]) == {"run_a", "run_b"}
    assert schema["parameters"]["required"] == []


def test_dispatch_routes_diff_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    _write_run(tmp_path, "runB", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                          {"device_id": "acc-sw-09", "site": "demo"}])
    out = asyncio.run(registry.dispatch("diff_runs", {"run_a": "runA", "run_b": "runB"}, {"run_id": ""}))
    assert "Drift runA → runB" in out
    assert "acc-sw-09" in out


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------
def test_two_explicit_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    _write_run(tmp_path, "runB", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                          {"device_id": "acc-sw-09", "site": "demo"}])
    out = _call(run_a="runA", run_b="runB")
    assert "added: 1" in out
    assert "ADDED (1)" in out
    assert "acc-sw-09" in out


def test_identical_runs_report_no_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    _write_run(tmp_path, "runB")
    out = _call(run_a="runA", run_b="runB")
    assert "No drift" in out


def test_single_run_b_auto_previous(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00",
               devices=[{"device_id": "core-sw-01", "site": "demo"},
                        {"device_id": "new-sw", "site": "demo"}])
    out = _call(run_b="2026-06-23_09-00-00")
    assert "Drift 2026-06-23_08-00-00 → 2026-06-23_09-00-00" in out
    assert "new-sw" in out


def test_zero_arg_uses_context_run(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00",
               devices=[{"device_id": "core-sw-01", "site": "demo"},
                        {"device_id": "new-sw", "site": "demo"}])
    out = _call(context={"run_id": "2026-06-23_09-00-00", "site": "demo"})
    assert "→ 2026-06-23_09-00-00" in out
    assert "new-sw" in out


# ---------------------------------------------------------------------------
# Graceful errors — return a clean message, never raise
# ---------------------------------------------------------------------------
def test_unknown_run_returns_clean_message(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    out = _call(run_a="runA", run_b="ghost")
    assert out.startswith("diff_runs:")
    assert "not found" in out


def test_no_previous_returns_clean_message(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")  # only run
    out = _call(run_b="2026-06-23_08-00-00")
    assert out.startswith("diff_runs:")
    assert "no previous same-site run" in out


def test_no_run_at_all_returns_clean_message(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    out = _call(context={"run_id": "", "site": "demo"})
    assert out.startswith("diff_runs:")
    assert "no run to compare" in out


def test_cross_site_returns_clean_message(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA", devices=[{"device_id": "d1", "site": "demo"}])
    _write_run(tmp_path, "runB", devices=[{"device_id": "d1", "site": "other"}])
    out = _call(run_a="runA", run_b="runB")
    assert out.startswith("diff_runs:")
    assert "cross-site" in out
