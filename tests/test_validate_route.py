"""s05-4: GET /api/validate/{run_id} — the diff payload plus its verdict.

FastAPI TestClient over fixture runs on disk; asserts the superset contract
(/api/diff shape + verdict key) the DriftPanel banner consumes.
"""

import importlib
import json

import pytest
from fastapi.testclient import TestClient


def _write_run(runs_dir, run_id, *, site="demo", interfaces=(), findings=()):
    run_dir = runs_dir / run_id
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    model = {
        "devices": [{"device_id": "core-sw-01", "site": site},
                    {"device_id": "acc-sw-09", "site": site}],
        "interfaces": list(interfaces),
        "links": [], "adjacencies": [], "shared_services": [],
        "l2_domains": [], "ospf_lsdb": [],
    }
    (run_dir / "model" / "network_model.json").write_text(json.dumps(model))
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": list(findings)}))


def _iface(device_id, name, **kw):
    return {"interface_id": f"{device_id}:{name}", "device_id": device_id,
            "name": name, "oper_status": "up", **kw}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    _write_run(tmp_path, "2026-06-23_08-00-00",
               interfaces=[_iface("core-sw-01", "Gi1"), _iface("acc-sw-09", "Gi1")])
    _write_run(tmp_path, "2026-06-23_09-00-00",
               interfaces=[_iface("core-sw-01", "Gi1", oper_status="down"),
                           _iface("acc-sw-09", "Gi1")])
    from netcopilot.dashboard.backend.routes import validate as validate_route

    monkeypatch.setattr(validate_route, "RUNS_DIR", tmp_path)
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(validate_route.router)
    return TestClient(app)


def test_superset_of_diff_payload_with_verdict(client):
    r = client.get("/api/validate/2026-06-23_09-00-00")
    assert r.status_code == 200
    d = r.json()
    assert {"run_a", "run_b", "site", "summary", "changes", "verdict"} <= set(d)
    assert d["verdict"]["result"] == "warn"            # drift, no scope
    assert d["verdict"]["reasons"][0]["code"] == "unscoped_drift"


def test_scope_param_changes_the_verdict(client):
    ok = client.get("/api/validate/2026-06-23_09-00-00?scope=core-sw-01").json()
    assert ok["verdict"]["result"] == "pass"
    bad = client.get("/api/validate/2026-06-23_09-00-00?scope=acc-sw-09").json()
    assert bad["verdict"]["result"] == "fail"
    assert bad["verdict"]["reasons"][0]["code"] == "out_of_scope_change"


def test_against_param_overrides_comparison_run(client):
    r = client.get(
        "/api/validate/2026-06-23_09-00-00?against=2026-06-23_08-00-00")
    assert r.status_code == 200
    assert r.json()["run_a"] == "2026-06-23_08-00-00"


def test_earliest_run_returns_null_verdict_with_note(client):
    d = client.get("/api/validate/2026-06-23_08-00-00").json()
    assert d["verdict"] is None and "note" in d and d["changes"] == []


def test_unknown_run_404(client):
    assert client.get("/api/validate/nope").status_code == 404
