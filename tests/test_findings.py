"""F1-4: findings module (element_id parsing, device derivation) + get_findings wiring."""

import asyncio

from netcopilot.findings import FindingsUnavailable, _devices_from_element_id, device_from_finding
from netcopilot.mcp import registry
from netcopilot.mcp.tools import findings as findings_tool


def test_devices_from_element_id_formats():
    assert _devices_from_element_id("core-rtr-01") == ["core-rtr-01"]
    assert _devices_from_element_id("dev:Gi0/0") == ["dev"]
    assert _devices_from_element_id("a:Gi--b:Gi") == ["a", "b"]
    assert _devices_from_element_id("stp_vlan_1::x") == []
    assert _devices_from_element_id("") == []


def test_device_from_finding_via_element_id():
    f = {"evidence": {"element_id": "access-sw-02"}, "finding_id": "demo-f1"}
    assert device_from_finding(f) == "access-sw-02"


def test_get_findings_registered():
    names = {t["name"] for t in registry.TOOL_SCHEMAS}
    assert "get_findings" in names
    assert "get_findings" in registry._HANDLERS


def test_get_findings_unavailable_is_error_not_false_clean(monkeypatch):
    # S08-0: the findings store being unreachable must NOT read as "no findings"
    # (the false-clean the sprint removed) — it is an honest error.
    def _raise(run_id):
        raise FindingsUnavailable("Neo4j is unavailable")
    monkeypatch.setattr(findings_tool, "load_findings_enriched", _raise)
    res = asyncio.run(findings_tool.get_findings(context={"run_id": "x"}))
    assert res.status == "error"
    assert "Cannot read findings" in res.text


def test_get_findings_genuinely_empty_is_no_data(monkeypatch):
    # The honest empty case is preserved: a real finding-free run reads no_data.
    monkeypatch.setattr(findings_tool, "load_findings_enriched", lambda run_id: [])
    res = asyncio.run(findings_tool.get_findings(context={"run_id": "x"}))
    assert res.status == "no_data"
    assert "No findings recorded" in res.text
