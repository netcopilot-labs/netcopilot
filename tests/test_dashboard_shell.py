"""F4c-1: dashboard backend shell — health, legend, security headers, auth.

Uses FastAPI's TestClient (no Neo4j required: /api/runs returns 503 when Neo4j is
unavailable, which is a valid non-401 pass-through under disabled auth).
"""

import pytest
from fastapi.testclient import TestClient

from netcopilot.dashboard.backend import main
from netcopilot.dashboard.backend.routes import agent_chat, analyze, devices, findings, reports, runs, topology

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def _no_neo4j(monkeypatch):
    """Keep the shell tests hermetic — never connect to any real Neo4j.

    Several routes call is_available(); without this stub they would hit the
    default bolt://localhost:7687, which is a real instance. We force
    'unavailable' so the routes take their deterministic no-Neo4j path. Each
    route imports is_available at module level, so patch each module's binding.
    """
    monkeypatch.setattr("netcopilot.graph.client.is_available", lambda: False)
    # netcopilot.findings binds is_available at import; load_findings_enriched uses
    # it, so patch there too or the findings/analyze routes hit a real Neo4j.
    monkeypatch.setattr("netcopilot.findings.is_available", lambda: False)
    monkeypatch.setattr(runs, "is_available", lambda: False)
    monkeypatch.setattr(topology, "is_available", lambda: False)
    monkeypatch.setattr(devices, "is_available", lambda: False)
    monkeypatch.setattr(analyze, "is_available", lambda: False)
    monkeypatch.setattr(agent_chat, "is_available", lambda: False)
    if hasattr(reports, "is_available"):
        monkeypatch.setattr(reports, "is_available", lambda: False)


def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] in ("ok", "degraded")


def test_legend_shape():
    body = client.get("/api/legend").json()
    assert len(body["severities"]) == 5
    assert any(s["id"] == "critical" for s in body["severities"])
    assert any(role["id"] == "border_router" for role in body["roles"])
    assert body["default_role"]["color"]


def test_legend_has_no_obs_roles():
    ids = {role["id"] for role in client.get("/api/legend").json()["roles"]}
    assert not any(("venue" in i or "mrh" in i) for i in ids)


def test_security_headers_present():
    r = client.get("/api/legend")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_runs_passthrough_when_auth_disabled():
    # No DASHBOARD_USER set → auth disabled → not 401 (503 without Neo4j, or 200).
    assert client.get("/api/runs").status_code in (200, 503)


def test_auth_enforced_when_enabled(monkeypatch):
    monkeypatch.setattr(main, "_AUTH_ENABLED", True)
    monkeypatch.setattr(main, "_DASHBOARD_USER", "operator")
    monkeypatch.setattr(main, "_DASHBOARD_PASSWORD", "s3cr3t")

    assert client.get("/api/runs").status_code == 401          # no creds
    assert client.get("/api/runs", auth=("operator", "nope")).status_code == 401  # wrong
    # correct creds → past auth (503 without Neo4j, or 200) — never 401
    assert client.get("/api/runs", auth=("operator", "s3cr3t")).status_code != 401


def test_topology_requires_run_id():
    # missing required run_id query param → 422 (FastAPI validation), before Neo4j
    assert client.get("/api/topology").status_code == 422


def test_topology_503_when_no_neo4j():
    assert client.get("/api/topology?run_id=x").status_code == 503


def test_device_503_when_no_neo4j():
    assert client.get("/api/device/core-rtr-01?run_id=x").status_code == 503


def test_findings_404_for_unknown_run():
    # run_exists() is False for a run with no on-disk findings.json → 404
    assert client.get("/api/findings/nonexistent-run").status_code == 404


def test_analyze_404_when_no_findings():
    # No Neo4j → load_findings_enriched returns None → "no findings" → 404.
    assert client.get("/api/analyze/r1/SOME_RULE").status_code == 404


def test_agent_models_endpoint():
    data = client.get("/api/agent/models").json()
    ids = {m["id"] for m in data["models"]}
    # Config-driven: assert structure, not specific ids (a user models.yaml varies).
    assert data["models"] and data["active"] in ids
    assert all({"id", "label"} <= set(m) for m in data["models"])


def test_set_model_switch_and_invalid():
    ids = [m["id"] for m in client.get("/api/agent/models").json()["models"]]
    assert client.post(f"/api/agent/models/{ids[0]}").json()["active"] == ids[0]
    assert client.post("/api/agent/models/nope").status_code == 400


def test_agent_chat_streams_with_stub_provider(monkeypatch):
    from netcopilot.llm import LLMResult

    class _Stub:
        name = "ollama"
        model = "stub"

        async def run_turn(self, **kw):
            return LLMResult(text="hello there", tool_calls=[])

    monkeypatch.setattr(agent_chat, "get_provider", lambda *a, **k: _Stub())
    r = client.post(
        "/api/agent/chat/r1",
        json={"message": "hi", "session_id": "s1", "history": []},
    )
    assert r.status_code == 200
    assert '"type": "content"' in r.text and "hello there" in r.text
    assert '"type": "done"' in r.text


def test_agent_chat_provider_error_streams_error(monkeypatch):
    def _boom(*a, **k):
        raise ValueError("no api key")

    monkeypatch.setattr(agent_chat, "get_provider", _boom)
    r = client.post("/api/agent/chat/r1", json={"message": "hi", "session_id": "s2"})
    assert r.status_code == 200
    assert '"type": "error"' in r.text and '"type": "done"' in r.text


def test_reports_route_registered():
    # The reports router is mounted (unknown run → 404, not route-not-found).
    assert client.get("/api/reports/nonexistent-run").status_code in (404, 503)


def test_legend_public_even_with_auth_enabled(monkeypatch):
    monkeypatch.setattr(main, "_AUTH_ENABLED", True)
    monkeypatch.setattr(main, "_DASHBOARD_USER", "operator")
    monkeypatch.setattr(main, "_DASHBOARD_PASSWORD", "s3cr3t")
    assert client.get("/api/legend").status_code == 200        # public route, no creds
