"""S01-4: GET /api/diff/{run_id} — the dashboard diff endpoint.

Disk-based (no Neo4j). Uses FastAPI TestClient with diff.RUNS_DIR pointed at a
tmp runs dir. Synthetic runs, RFC 5737 IPs. Auth is disabled (no DASHBOARD_USER
in the test env), so requests pass through.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from netcopilot.dashboard.backend import main
from netcopilot.dashboard.backend.routes import diff

client = TestClient(main.app)


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


def test_diff_vs_previous_same_site(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00",
               devices=[{"device_id": "core-sw-01", "site": "demo"},
                        {"device_id": "new-sw", "site": "demo"}])
    r = client.get("/api/diff/2026-06-23_09-00-00")
    assert r.status_code == 200
    body = r.json()
    assert body["run_a"] == "2026-06-23_08-00-00"
    assert body["run_b"] == "2026-06-23_09-00-00"
    assert body["summary"]["added"] == 1
    assert any(c["key"] == "new-sw" and c["tier"] == "added" for c in body["changes"])


def test_diff_against_override(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    _write_run(tmp_path, "base")
    _write_run(tmp_path, "mid", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                         {"device_id": "x", "site": "demo"}])
    _write_run(tmp_path, "top", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                         {"device_id": "x", "site": "demo"},
                                         {"device_id": "y", "site": "demo"}])
    r = client.get("/api/diff/top", params={"against": "base"})
    assert r.status_code == 200
    body = r.json()
    assert body["run_a"] == "base"
    assert body["summary"]["added"] == 2  # x and y both added vs base


def test_diff_unknown_run_404(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    r = client.get("/api/diff/does-not-exist")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]


def test_diff_unknown_against_404(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    _write_run(tmp_path, "runX")
    r = client.get("/api/diff/runX", params={"against": "ghost"})
    assert r.status_code == 404
    assert "ghost" in r.json()["detail"]


def test_diff_no_previous_returns_200_with_note(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    _write_run(tmp_path, "2026-06-23_08-00-00")  # only run of the site
    r = client.get("/api/diff/2026-06-23_08-00-00")
    assert r.status_code == 200
    body = r.json()
    assert body["run_a"] is None
    assert body["changes"] == []
    assert "note" in body
    assert body["site"] == "demo"


def test_diff_cross_site_400(tmp_path, monkeypatch):
    monkeypatch.setattr(diff, "RUNS_DIR", tmp_path)
    _write_run(tmp_path, "runA", devices=[{"device_id": "d1", "site": "demo"}])
    _write_run(tmp_path, "runB", devices=[{"device_id": "d1", "site": "other"}])
    r = client.get("/api/diff/runB", params={"against": "runA"})
    assert r.status_code == 400
    assert "cross-site" in r.json()["detail"]
