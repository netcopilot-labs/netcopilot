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
    assert set(schema["parameters"]["properties"]) == {"run_a", "run_b", "runs_back"}
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
    assert "earliest run" in out


def test_runs_back_resolves_nth_predecessor(tmp_path, monkeypatch):
    # "N runs ago" must resolve to exactly one run — the Nth chronological
    # predecessor — never a menu. Non-timestamp ids sort after and don't count.
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")  # 2 runs ago
    _write_run(tmp_path, "2026-06-23_09-00-00")  # 1 run ago (previous)
    _write_run(tmp_path, "2026-06-23_10-00-00")  # current
    _write_run(tmp_path, "campus")               # same-site seed run, not "N ago"
    out = _call(run_b="2026-06-23_10-00-00", runs_back=2)
    assert "Drift 2026-06-23_08-00-00 → 2026-06-23_10-00-00" in out
    out1 = _call(run_b="2026-06-23_10-00-00", runs_back=1)  # == previous run
    assert "Drift 2026-06-23_09-00-00 → 2026-06-23_10-00-00" in out1


def test_runs_back_beyond_history_lists_what_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_09-00-00")
    _write_run(tmp_path, "2026-06-23_10-00-00")  # current — only 1 predecessor
    out = _call(run_b="2026-06-23_10-00-00", runs_back=5)
    assert "only 1 run" in out and "cannot go 5 back" in out
    assert "2026-06-23_09-00-00" in out


def test_successful_diff_footer_lists_other_runs(tmp_path, monkeypatch):
    # A default diff (current vs previous) must still surface the OTHER runs, so
    # the model can resolve "2 runs ago" instead of concluding none exist.
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")  # 2 runs ago
    _write_run(tmp_path, "2026-06-23_09-00-00")  # previous
    _write_run(tmp_path, "2026-06-23_10-00-00")  # current
    out = _call(run_b="2026-06-23_10-00-00")      # defaults run_a -> previous
    assert "Drift 2026-06-23_09-00-00 → 2026-06-23_10-00-00" in out
    assert "Other runs on record" in out
    assert "2026-06-23_08-00-00" in out           # the 2-runs-ago run is offered
    # the two runs being diffed are not repeated in the footer
    assert out.count("2026-06-23_09-00-00") == 1


def test_bad_run_a_lists_available_runs_for_retry(tmp_path, monkeypatch):
    # A run_a the model can't have known (e.g. "run-2" or a human date) must not
    # dead-end: the tool lists the real run_ids so the agent retries correctly.
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00")
    _write_run(tmp_path, "2026-06-23_10-00-00")
    out = _call(run_a="run-2", run_b="2026-06-23_10-00-00")
    assert "not found" in out
    # every real run_id is offered back, with a human timestamp to disambiguate
    assert "2026-06-23_08-00-00" in out and "2026-06-23_09-00-00" in out
    assert "Jun 2026" in out


def test_available_runs_are_site_scoped_and_sorted(tmp_path, monkeypatch):
    # The retry list for a bad run_a is scoped to the newer run's site.
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "2026-06-23_09-00-00", site="demo")
    _write_run(tmp_path, "2026-06-23_08-00-00", site="demo")
    _write_run(tmp_path, "2026-06-23_07-00-00", site="other")  # different site
    out = _call(run_a="ghost", run_b="2026-06-23_09-00-00")
    assert "2026-06-23_08-00-00" in out            # same site, listed
    assert "2026-06-23_07-00-00" not in out         # other site, excluded
    # oldest-first ordering
    assert out.index("2026-06-23_08-00-00") < out.index("2026-06-23_09-00-00")


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
