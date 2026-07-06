"""S16-3: service-layer routes — list + join trigger.

The join engine and Neo4j are mocked; under test is the HTTP contract:
joined-vs-empty disambiguation, 404 unloaded run, 503 NetBox-down,
400 unloaded-run join. Synthetic data.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from netcopilot.dashboard.backend import main

client = TestClient(main.app)


def test_routes_registered():
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/services" in paths
    assert "/api/services/join" in paths


def _driver_returning(rows):
    session = MagicMock()
    session.run.return_value = [{"s": r} for r in rows]
    driver = MagicMock()
    driver.session.return_value.__enter__ = lambda self: session
    driver.session.return_value.__exit__ = lambda self, *a: False
    return driver


def test_list_services_disambiguates_never_joined():
    with patch("netcopilot.graph.client.get_site_for_run", return_value="demo"), \
         patch("netcopilot.graph.client.get_driver", return_value=_driver_returning([])):
        resp = client.get("/api/services", params={"run_id": "r1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["joined"] is False and body["services"] == []


def test_list_services_returns_rows():
    rows = [{"name": "cam-lobby-01", "ip": "198.51.100.26", "located": True,
             "location_method": "arp", "device": "acc-sw-03"}]
    with patch("netcopilot.graph.client.get_site_for_run", return_value="demo"), \
         patch("netcopilot.graph.client.get_driver", return_value=_driver_returning(rows)):
        resp = client.get("/api/services", params={"run_id": "r1"})
    body = resp.json()
    assert body["joined"] is True
    assert body["services"][0]["name"] == "cam-lobby-01"


def test_list_services_404_on_unloaded_run():
    with patch("netcopilot.graph.client.get_site_for_run", return_value=None):
        resp = client.get("/api/services", params={"run_id": "ghost"})
    assert resp.status_code == 404


def test_join_503_when_netbox_down():
    from netcopilot.declared_state.services import ServiceSourceUnavailable
    with patch("netcopilot.declared_state.services.run_service_join",
               side_effect=ServiceSourceUnavailable("netbox down")):
        resp = client.post("/api/services/join", json={"run_id": "r1"})
    assert resp.status_code == 503
    assert "netbox down" in resp.json()["detail"]


def test_join_400_when_run_not_loaded():
    with patch("netcopilot.declared_state.services.run_service_join",
               side_effect=ValueError("Run 'r1' is not loaded")):
        resp = client.post("/api/services/join", json={"run_id": "r1"})
    assert resp.status_code == 400


def test_join_returns_summary():
    report = MagicMock()
    report.run_id, report.site = "r1", "demo"
    report.services = [1, 2, 3]
    report.counts_by_method.return_value = {"arp": 2, "none": 1}
    report.skipped_infrastructure = ["x"]
    report.format_summary.return_value = "3 service(s)"
    report.warnings = []
    with patch("netcopilot.declared_state.services.run_service_join", return_value=report):
        resp = client.post("/api/services/join", json={"run_id": "r1"})
    body = resp.json()
    assert body["services"] == 3 and body["by_method"] == {"arp": 2, "none": 1}
