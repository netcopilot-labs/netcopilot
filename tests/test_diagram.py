"""Diagram module: finding-annotator severity handling + build smoke.

Regression: the severity taxonomy includes ``info`` (the single largest
severity bucket in practice), but the annotator's ``SEVERITY_ORDER`` originally
omitted it, crashing the highest-severity-wins lookup whenever two findings —
one of them ``info`` — landed on the same element.
"""

import pytest

from netcopilot.diagram.finding_annotator import FindingAnnotator


def _finding(eid, sev, etype="device"):
    return {
        "finding_id": eid,
        "severity": sev,
        "evidence": {"element_type": etype, "element_id": eid},
    }


def test_annotator_handles_info_severity_without_crashing():
    # Two findings on the same device incl. 'info' — used to raise
    # ValueError: 'info' is not in list.
    findings = {"findings": [_finding("dev1", "info"), _finding("dev1", "high")]}
    ann = FindingAnnotator(findings, {})
    assert ann.element_severity_map["dev1"] == "high"  # highest severity wins


def test_annotator_accepts_every_valid_severity():
    sevs = ["critical", "high", "low", "info", "cis"]
    findings = {"findings": [_finding(f"d{i}", s) for i, s in enumerate(sevs)]}
    ann = FindingAnnotator(findings, {})  # must not raise
    assert set(ann.element_severity_map.values()) == set(sevs)


def test_annotator_severity_order_covers_valid_severities():
    # SEVERITY_ORDER must rank every value the findings taxonomy can emit.
    for sev in ("critical", "high", "low", "info", "cis"):
        assert sev in FindingAnnotator.SEVERITY_ORDER


def test_build_diagram_missing_run_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    from netcopilot.diagram import build_diagram

    with pytest.raises(FileNotFoundError):
        build_diagram("does-not-exist")
