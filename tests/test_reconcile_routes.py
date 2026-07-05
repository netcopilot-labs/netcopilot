"""S12-1: Reconcile API routes (ADR-0014) — route contracts + write-gate honesty.

staging / bootstrap / Neo4j are mocked; the contract under test is the HTTP
layer: pagination, filter pass-through, status-code mapping (404 not_pending,
403 writes_disabled, 502 auth abort, 503 no Neo4j), the SSE event framing,
and the labs bootstrap contract (run_id required, inventory via env).
All test data is synthetic (invented device names, demo site).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from netcopilot.dashboard.backend import main
from netcopilot.declared_state.gate import WritesDisabled
from netcopilot.declared_state.staging import AuthAbortError

client = TestClient(main.app)


# ── Route registration smoke ─────────────────────────────────────────────────


class TestReconcileRoutesRegistered:

    def test_all_10_routes_in_openapi(self):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        paths = resp.json()["paths"]
        expected = [
            "/api/reconcile/status",
            "/api/reconcile/pending",
            "/api/reconcile/approve/{candidate_id}",
            "/api/reconcile/reject/{candidate_id}",
            "/api/reconcile/modify/{candidate_id}",
            "/api/reconcile/approve_bulk",
            "/api/reconcile/approve_bulk/stream",
            "/api/reconcile/reject_bulk",
            "/api/reconcile/bootstrap",
            "/api/reconcile/history",
        ]
        for path in expected:
            assert path in paths, f"missing route: {path}"

    def test_methods_per_route(self):
        paths = client.get("/openapi.json").json()["paths"]
        assert "get" in paths["/api/reconcile/status"]
        assert "get" in paths["/api/reconcile/pending"]
        assert "post" in paths["/api/reconcile/approve/{candidate_id}"]
        assert "post" in paths["/api/reconcile/reject/{candidate_id}"]
        assert "patch" in paths["/api/reconcile/modify/{candidate_id}"]
        assert "post" in paths["/api/reconcile/approve_bulk"]
        assert "get" in paths["/api/reconcile/approve_bulk/stream"]
        assert "post" in paths["/api/reconcile/reject_bulk"]
        assert "post" in paths["/api/reconcile/bootstrap"]
        assert "get" in paths["/api/reconcile/history"]


# ── GET /api/reconcile/status ────────────────────────────────────────────────


class TestStatusEndpoint:

    def test_default_gate_off_unconfigured(self, monkeypatch):
        monkeypatch.delenv("NETBOX_WRITE_ENABLED", raising=False)
        monkeypatch.delenv("NETBOX_URL", raising=False)
        monkeypatch.delenv("NETBOX_API_TOKEN", raising=False)
        body = client.get("/api/reconcile/status").json()
        assert body == {"write_enabled": False, "netbox_configured": False}

    def test_gate_on_configured(self, monkeypatch):
        monkeypatch.setenv("NETBOX_WRITE_ENABLED", "true")
        monkeypatch.setenv("NETBOX_URL", "http://netbox.example.test:8000")
        monkeypatch.setenv("NETBOX_API_TOKEN", "demo-token")
        body = client.get("/api/reconcile/status").json()
        assert body == {"write_enabled": True, "netbox_configured": True}


# ── GET /api/reconcile/pending ──────────────────────────────────────────────


class TestPendingEndpoint:

    def test_returns_paginated_results(self):
        rows = [
            {"id": f"p{i}", "netbox_object_type": "device",
             "payload": {"name": f"acc-sw-{i:02d}"}, "priority": 50,
             "source": "bootstrap"} for i in range(7)
        ]
        with patch("netcopilot.declared_state.staging.list_pending", return_value=rows):
            resp = client.get("/api/reconcile/pending?page=1&page_size=3")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 7
        assert body["page"] == 1
        assert body["page_size"] == 3
        assert len(body["results"]) == 3

    def test_passes_filters_through(self):
        captured = {}

        def fake_list(**kw):
            captured.update(kw)
            return []

        with patch("netcopilot.declared_state.staging.list_pending", side_effect=fake_list):
            client.get("/api/reconcile/pending?source=bootstrap&object_type=device&min_priority=70")
        assert captured["source"] == "bootstrap"
        assert captured["object_type"] == "device"
        assert captured["min_priority"] == 70

    def test_dedup_key_filter_in_memory(self):
        rows = [
            {"id": "p1", "netbox_object_type": "device",
             "payload": {"name": "core-rtr-01"}, "priority": 50, "source": "bootstrap"},
            {"id": "p2", "netbox_object_type": "device",
             "payload": {"name": "core-rtr-02"}, "priority": 50, "source": "bootstrap"},
            {"id": "p3", "netbox_object_type": "site",
             "payload": {"slug": "demo"}, "priority": 50, "source": "bootstrap"},
        ]
        with patch("netcopilot.declared_state.staging.list_pending", return_value=rows):
            resp = client.get("/api/reconcile/pending?dedup_key=rtr-01")
        body = resp.json()
        assert body["count"] == 1
        assert body["results"][0]["payload"]["name"] == "core-rtr-01"


# ── POST /api/reconcile/approve/{id} ────────────────────────────────────────


class TestApproveEndpoint:

    def test_success_returns_outcome(self):
        ok_result = {
            "outcome": "success", "audit_id": "audit-1",
            "api_response_status": 201, "netbox_object_id": 42,
        }
        with patch("netcopilot.declared_state.staging.approve", return_value=ok_result):
            resp = client.post("/api/reconcile/approve/pending-1")
        assert resp.status_code == 200
        assert resp.json() == ok_result

    def test_404_when_not_pending(self):
        with patch("netcopilot.declared_state.staging.approve", return_value=None):
            resp = client.post("/api/reconcile/approve/missing")
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"]["code"] == "not_pending"

    def test_403_when_writes_disabled(self):
        with patch("netcopilot.declared_state.staging.approve",
                   side_effect=WritesDisabled("approve requires NETBOX_WRITE_ENABLED=true")):
            resp = client.post("/api/reconcile/approve/p1")
        assert resp.status_code == 403
        detail = resp.json()["detail"]["error"]
        assert detail["code"] == "writes_disabled"
        assert "NETBOX_WRITE_ENABLED" in detail["message"]

    def test_502_on_auth_abort(self):
        with patch("netcopilot.declared_state.staging.approve",
                   side_effect=AuthAbortError("HTTP 401")):
            resp = client.post("/api/reconcile/approve/p1")
        assert resp.status_code == 502
        assert resp.json()["detail"]["error"]["code"] == "netbox_auth_abort"


# ── POST /api/reconcile/reject/{id} ─────────────────────────────────────────


class TestRejectEndpoint:

    def test_success(self):
        with patch("netcopilot.declared_state.staging.reject", return_value=True):
            resp = client.post("/api/reconcile/reject/pending-1")
        assert resp.status_code == 200
        assert resp.json()["rejected"] is True

    def test_404_when_missing(self):
        with patch("netcopilot.declared_state.staging.reject", return_value=False):
            resp = client.post("/api/reconcile/reject/missing")
        assert resp.status_code == 404


# ── PATCH /api/reconcile/modify/{id} ────────────────────────────────────────


class TestModifyEndpoint:

    def test_accepts_payload_wrapped(self):
        captured = {}

        def fake_modify(cid, payload):
            captured["candidate_id"] = cid
            captured["payload"] = payload
            return True

        with patch("netcopilot.declared_state.staging.modify", side_effect=fake_modify):
            resp = client.patch(
                "/api/reconcile/modify/pending-1",
                json={"payload": {"name": "acc-sw-01-renamed"}},
            )
        assert resp.status_code == 200
        assert captured["payload"] == {"name": "acc-sw-01-renamed"}

    def test_accepts_payload_unwrapped(self):
        captured = {}

        def fake_modify(cid, payload):
            captured["payload"] = payload
            return True

        with patch("netcopilot.declared_state.staging.modify", side_effect=fake_modify):
            resp = client.patch(
                "/api/reconcile/modify/pending-1",
                json={"name": "acc-sw-01-renamed"},
            )
        assert resp.status_code == 200
        assert captured["payload"] == {"name": "acc-sw-01-renamed"}

    def test_400_on_non_dict_payload(self):
        # FastAPI rejects a non-object body before our handler runs
        resp = client.patch("/api/reconcile/modify/pending-1", json=[1, 2, 3])
        assert resp.status_code in (400, 422)

    def test_404_when_missing(self):
        with patch("netcopilot.declared_state.staging.modify", return_value=False):
            resp = client.patch("/api/reconcile/modify/missing", json={"name": "X"})
        assert resp.status_code == 404


# ── POST /api/reconcile/approve_bulk (synchronous) ──────────────────────────


class TestApproveBulkEndpoint:

    def test_synchronous_returns_summary(self):
        fake_summary = {
            "written": 5, "auto_resolved": 0, "failed": 0,
            "aborted": False, "abort_reason": None,
            "failed_ids": [], "duration_ms": 1234, "total": 5,
        }
        with patch("netcopilot.declared_state.staging.approve_bulk", return_value=fake_summary):
            resp = client.post("/api/reconcile/approve_bulk", json={"source": "bootstrap"})
        assert resp.status_code == 200
        assert resp.json() == fake_summary

    def test_passes_filters_through(self):
        captured = {}

        def fake_bulk(**kw):
            captured.update(kw)
            return {"written": 0, "auto_resolved": 0, "failed": 0,
                    "aborted": False, "abort_reason": None,
                    "failed_ids": [], "duration_ms": 0, "total": 0}

        with patch("netcopilot.declared_state.staging.approve_bulk", side_effect=fake_bulk):
            client.post(
                "/api/reconcile/approve_bulk",
                json={"source": "bootstrap", "object_type": "device",
                      "min_priority": 50, "ids": ["x", "y"]},
            )
        assert captured["source"] == "bootstrap"
        assert captured["object_type"] == "device"
        assert captured["min_priority"] == 50
        assert captured["ids"] == ["x", "y"]

    def test_403_when_writes_disabled(self):
        with patch("netcopilot.declared_state.staging.approve_bulk",
                   side_effect=WritesDisabled("bulk approve requires NETBOX_WRITE_ENABLED=true")):
            resp = client.post("/api/reconcile/approve_bulk", json={})
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"]["code"] == "writes_disabled"


# ── GET /api/reconcile/approve_bulk/stream (SSE) ────────────────────────────


class TestApproveBulkStream:

    def test_sse_emits_progress_and_complete_events(self):
        def fake_bulk(*, progress_callback, **_kw):
            progress_callback({"event": "progress",
                               "data": {"position": 1, "total": 2, "status": "written"}})
            progress_callback({"event": "progress",
                               "data": {"position": 2, "total": 2, "status": "written"}})
            summary = {"written": 2, "auto_resolved": 0, "failed": 0,
                       "aborted": False, "abort_reason": None,
                       "failed_ids": [], "duration_ms": 100, "total": 2}
            progress_callback({"event": "complete", "data": summary})
            return summary

        with patch("netcopilot.declared_state.staging.approve_bulk", side_effect=fake_bulk):
            resp = client.get("/api/reconcile/approve_bulk/stream?source=bootstrap")
        assert resp.status_code == 200
        body = resp.text
        assert "event: progress" in body
        assert "event: complete" in body
        # Each SSE event ends with a blank line
        assert body.count("\n\n") >= 3

    def test_sse_gate_off_emits_aborted_event(self):
        # EventSource can't read a 403 body — the refusal travels in-band.
        with patch("netcopilot.declared_state.staging.approve_bulk",
                   side_effect=WritesDisabled("requires NETBOX_WRITE_ENABLED=true")):
            resp = client.get("/api/reconcile/approve_bulk/stream")
        assert resp.status_code == 200
        assert "event: aborted" in resp.text
        assert "writes_disabled" in resp.text

    def test_sse_crash_emits_aborted_event(self):
        with patch("netcopilot.declared_state.staging.approve_bulk",
                   side_effect=RuntimeError("boom")):
            resp = client.get("/api/reconcile/approve_bulk/stream")
        assert resp.status_code == 200
        assert "event: aborted" in resp.text
        assert "internal_error" in resp.text


# ── POST /api/reconcile/reject_bulk ─────────────────────────────────────────


class TestRejectBulkEndpoint:

    def test_returns_summary(self):
        with patch(
            "netcopilot.declared_state.staging.reject_bulk",
            return_value={"rejected": 3, "not_found": 0, "total": 3},
        ):
            resp = client.post("/api/reconcile/reject_bulk", json={"ids": ["a", "b", "c"]})
        assert resp.status_code == 200
        assert resp.json() == {"rejected": 3, "not_found": 0, "total": 3}


# ── POST /api/reconcile/bootstrap ───────────────────────────────────────────


class TestBootstrapEndpoint:

    def test_returns_summary(self, monkeypatch):
        monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/inventory/lab.yaml")
        fake_result = MagicMock()
        fake_result.new = {"device": 3, "interface": 24, "site": 1}
        fake_result.skipped = {}
        fake_result.warnings = []
        fake_result.format_summary.return_value = "Staged 28 candidates"
        captured = {}

        def fake_run(run_id, inventory_path):
            captured["run_id"] = run_id
            captured["inventory_path"] = inventory_path
            return fake_result

        with patch("netcopilot.declared_state.bootstrap.run", side_effect=fake_run):
            resp = client.post("/api/reconcile/bootstrap", json={"run_id": "demo-run"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["new"] == {"device": 3, "interface": 24, "site": 1}
        assert "Staged 28 candidates" in body["summary"]
        assert captured == {"run_id": "demo-run",
                            "inventory_path": "/data/inventory/lab.yaml"}

    def test_body_inventory_path_overrides_env(self, monkeypatch):
        monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/inventory/lab.yaml")
        fake_result = MagicMock()
        fake_result.new = {}
        fake_result.skipped = {}
        fake_result.warnings = []
        fake_result.format_summary.return_value = "Staged 0 candidates"
        captured = {}

        def fake_run(run_id, inventory_path):
            captured["inventory_path"] = inventory_path
            return fake_result

        with patch("netcopilot.declared_state.bootstrap.run", side_effect=fake_run):
            client.post("/api/reconcile/bootstrap",
                        json={"run_id": "demo-run", "inventory_path": "/other/inv.yaml"})
        assert captured["inventory_path"] == "/other/inv.yaml"

    def test_400_without_run_id(self):
        resp = client.post("/api/reconcile/bootstrap", json={})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"]["code"] == "run_id_required"

    def test_400_without_inventory(self, monkeypatch):
        monkeypatch.delenv("NETBOX_BOOTSTRAP_INVENTORY", raising=False)
        resp = client.post("/api/reconcile/bootstrap", json={"run_id": "demo-run"})
        assert resp.status_code == 400
        detail = resp.json()["detail"]["error"]
        assert detail["code"] == "inventory_unconfigured"
        assert "netcopilot netbox bootstrap" in detail["message"]  # CLI guidance

    def test_500_on_bootstrap_exception(self, monkeypatch):
        monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/inventory/lab.yaml")
        with patch("netcopilot.declared_state.bootstrap.run",
                   side_effect=RuntimeError("Neo4j unavailable")):
            resp = client.post("/api/reconcile/bootstrap", json={"run_id": "demo-run"})
        assert resp.status_code == 500
        assert resp.json()["detail"]["error"]["code"] == "bootstrap_failed"


# ── POST /api/reconcile/stage_from_finding (s13) ────────────────────────────


class TestStageFromFindingEndpoint:

    def test_success(self):
        result = {"staged": 1, "skipped": 0, "candidate_ids": ["cand-1"]}
        with patch("netcopilot.declared_state.drift.stage_correction",
                   return_value=result) as sc:
            resp = client.post("/api/reconcile/stage_from_finding",
                               json={"finding_id": "INTENT_SERIAL_DRIFT::acc-sw-01",
                                     "run_id": "demo-run"})
        assert resp.status_code == 200
        assert resp.json() == result
        assert sc.call_args.args == ("INTENT_SERIAL_DRIFT::acc-sw-01", "demo-run")

    def test_400_missing_params(self):
        resp = client.post("/api/reconcile/stage_from_finding", json={"finding_id": "x"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"]["code"] == "missing_params"

    def test_404_finding_not_found(self):
        with patch("netcopilot.declared_state.drift.stage_correction",
                   side_effect=KeyError("no finding")):
            resp = client.post("/api/reconcile/stage_from_finding",
                               json={"finding_id": "x", "run_id": "r"})
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"]["code"] == "finding_not_found"

    def test_400_not_correctable(self):
        from netcopilot.declared_state.drift import NotCorrectable
        with patch("netcopilot.declared_state.drift.stage_correction",
                   side_effect=NotCorrectable("informational rule")):
            resp = client.post("/api/reconcile/stage_from_finding",
                               json={"finding_id": "x", "run_id": "r"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"]["code"] == "not_correctable"

    def test_502_netbox_unreachable(self):
        from netcopilot.declared_state.drift import DriftSourceUnavailable
        with patch("netcopilot.declared_state.drift.stage_correction",
                   side_effect=DriftSourceUnavailable("down")):
            resp = client.post("/api/reconcile/stage_from_finding",
                               json={"finding_id": "x", "run_id": "r"})
        assert resp.status_code == 502
        assert resp.json()["detail"]["error"]["code"] == "netbox_unreachable"


# ── GET /api/reconcile/history ──────────────────────────────────────────────


class TestHistoryEndpoint:

    def test_503_when_neo4j_unavailable(self):
        with patch("netcopilot.graph.client.is_available", return_value=False):
            resp = client.get("/api/reconcile/history")
        assert resp.status_code == 503
        assert resp.json()["detail"]["error"]["code"] == "neo4j_unavailable"

    def test_success_only_filter_translates_to_cypher_clause(self):
        fake_session = MagicMock()
        fake_session.run.return_value.single.return_value = {"n": 0}
        fake_session.run.return_value.__iter__ = lambda self: iter([])
        fake_driver = MagicMock()
        fake_driver.session.return_value.__enter__ = lambda s: fake_session
        fake_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        with patch("netcopilot.graph.client.is_available", return_value=True), \
             patch("netcopilot.graph.client.get_driver", return_value=fake_driver):
            resp = client.get("/api/reconcile/history?success_only=true&source=bootstrap")
        assert resp.status_code == 200
        # Verify the cypher built by the endpoint includes the success filter
        cyphers = [call.args[0] for call in fake_session.run.call_args_list]
        joined = " ".join(cyphers)
        assert "api_response_status >= 200" in joined
        assert "w.source = $source" in joined
