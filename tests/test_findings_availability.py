"""S08-0 — the findings-availability contract.

`load_findings_enriched` distinguishes "store unreachable/errored" (raises
FindingsUnavailable) from "run genuinely has no findings" ([]). No consumer may
render "0 findings" when the store is simply down — the false-clean the sprint
removes. Primary findings tools surface `error`; ancillary consumers note the
gap and continue.
"""

from __future__ import annotations

import asyncio

import pytest

from netcopilot import findings as findings_mod
from netcopilot.findings import FindingsUnavailable
from netcopilot.mcp.tools import analyze as analyze_tool
from netcopilot.mcp.tools import device as device_tool
from netcopilot.mcp.tools import explain as explain_tool
from netcopilot.mcp.tools import path_tracer


def _raise(run_id):
    raise FindingsUnavailable("Neo4j is unavailable")


# ── the loader contract ──────────────────────────────────────────────────────

def test_loader_raises_when_unavailable(monkeypatch):
    monkeypatch.setattr(findings_mod, "is_available", lambda: False)
    with pytest.raises(FindingsUnavailable):
        findings_mod.load_findings_enriched("run-x")


# ── primary tools: honest error, not false-clean ─────────────────────────────

def test_analyze_findings_errors_when_unavailable(monkeypatch):
    monkeypatch.setattr(analyze_tool, "load_findings_enriched", _raise)
    res = asyncio.run(analyze_tool.analyze_findings(rule_id="R", context={"run_id": "x"}))
    assert res.status == "error"


# ── ancillary consumers: note the gap, still succeed ─────────────────────────

def test_explain_finding_notes_unavailable_not_inactive(monkeypatch):
    # Rule explanation still returns; the "Active in this run" section says the
    # store was unavailable rather than implying the rule is inactive.
    monkeypatch.setattr(explain_tool, "load_findings_enriched", _raise)
    monkeypatch.setattr(explain_tool, "_load_catalog",
                        lambda: {"R": {"rule_id": "R", "description": "d", "severity": "high"}})
    res = asyncio.run(explain_tool.explain_finding(rule_id="R", context={"run_id": "x"}))
    assert res.status == "ok"
    assert "unavailable" in res.text.lower()


def test_findings_overlay_degrades_to_empty_when_unavailable(monkeypatch):
    # The trace risks overlay is ancillary — an unreachable store yields no
    # risks, the trace itself is unaffected (never raises).
    monkeypatch.setattr(path_tracer, "load_findings_enriched", _raise)
    assert path_tracer._findings_on_path(["dev-a"], "run-x") == []
