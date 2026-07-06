"""S13-2: the 2 drift MCP tools — ToolResult envelope, honest failure modes.

Drift core is mocked; the contract under test is the envelope: unconfigured
inventory / unreachable NetBox → ``error`` (never fake-clean), missing run →
``not_found``, results → ``ok`` with a drift/clean verdict.
"""
import asyncio
from unittest.mock import MagicMock, patch

from netcopilot.declared_state.drift import DriftReport, DriftSourceUnavailable
from netcopilot.mcp.registry import TOOL_SCHEMAS, _HANDLERS
from netcopilot.mcp.tools import drift_check
from netcopilot.rules.finding import Finding


def _run(coro):
    return asyncio.run(coro)


CTX = {"run_id": "demo-run"}


def test_registered_32_tools_with_drift():
    names = [s["name"] for s in TOOL_SCHEMAS]
    assert len(names) == 33
    for t in ("run_drift_check", "compare_declared_vs_actual"):
        assert t in names and t in _HANDLERS


def test_drift_check_without_inventory_is_error(monkeypatch):
    monkeypatch.delenv("NETBOX_BOOTSTRAP_INVENTORY", raising=False)
    out = _run(drift_check.run_drift_check(context=CTX))
    assert out.status == "error"
    assert "NETBOX_BOOTSTRAP_INVENTORY" in out.text


def test_drift_check_without_run_is_error(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    out = _run(drift_check.run_drift_check(context={}))
    assert out.status == "error" and "run" in out.text.lower()


def test_drift_check_unreachable_source_is_error_not_clean(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    with patch("netcopilot.declared_state.drift.run_drift_check",
               side_effect=DriftSourceUnavailable("NetBox down")):
        out = _run(drift_check.run_drift_check(context=CTX))
    assert out.status == "error"
    assert "NetBox down" in out.text
    assert out.verdict is None  # no clean verdict when the source is unknown


def test_drift_check_clean_verdict(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    report = DriftReport(run_id="demo-run", declared_source="NetBoxAdapter",
                         devices_checked=3, interfaces_checked=10)
    with patch("netcopilot.declared_state.drift.run_drift_check", return_value=report):
        out = _run(drift_check.run_drift_check(context=CTX))
    assert out.status == "ok"
    assert out.verdict["result"] == "clean"
    assert out.highlight is None


def test_drift_check_drift_verdict_and_highlight(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    findings = [
        Finding(
            finding_id="INTENT_SERIAL_DRIFT::acc-sw-01", rule_id="INTENT_SERIAL_DRIFT",
            severity="high", title="Serial number drift", message="m",
            evidence={"element_type": "device", "element_id": "acc-sw-01",
                      "key_facts": {}},
            recommendation="r",
        ),
        Finding(
            finding_id="INTENT_DEVICE_MISSING_IN_NETWORK::ghost-sw",
            rule_id="INTENT_DEVICE_MISSING_IN_NETWORK",
            severity="high", title="Declared device absent", message="m",
            evidence={"element_type": "device", "element_id": "ghost-sw",
                      "key_facts": {}},
            recommendation="r",
        ),
    ]
    report = DriftReport(run_id="demo-run", declared_source="NetBoxAdapter",
                         findings=findings, devices_checked=4)
    with patch("netcopilot.declared_state.drift.run_drift_check", return_value=report):
        out = _run(drift_check.run_drift_check(context=CTX))
    assert out.status == "ok"
    assert out.verdict["result"] == "drift"
    assert out.verdict["counts_by_rule"]["INTENT_SERIAL_DRIFT"] == 1
    # highlight only devices that exist in the run (missing-in-network doesn't)
    assert out.highlight == {"devices": ["acc-sw-01"]}
    assert "INTENT_SERIAL_DRIFT" in out.text


def test_compare_unreachable_netbox_is_error(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    adapter = MagicMock()
    adapter.ping.side_effect = ConnectionError("down")
    with patch.object(drift_check, "_resolve_run", return_value="demo-run"), \
         patch("netcopilot.declared_state.get_source", return_value=adapter):
        out = _run(drift_check.compare_declared_vs_actual(device="acc-sw-01", context=CTX))
    assert out.status == "error"
    assert "unknown (not empty)" in out.text


def test_compare_device_on_neither_side_is_not_found(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    adapter = MagicMock()
    adapter.ping.return_value = None
    adapter.get_device.return_value = None
    observed = {"devices": {"acc-sw-01": {}}, "interfaces": {}, "sites": {"demo"}}
    with patch("netcopilot.declared_state.get_source", return_value=adapter), \
         patch.object(drift_check, "_derive_observed", create=True), \
         patch("netcopilot.declared_state.drift._derive_observed", return_value=observed):
        out = _run(drift_check.compare_declared_vs_actual(device="ghost", context=CTX))
    assert out.status == "not_found"
    assert "acc-sw-01" in out.text  # names what IS in the run


def test_compare_reports_field_drift(monkeypatch):
    monkeypatch.setenv("NETBOX_BOOTSTRAP_INVENTORY", "/data/lab.yaml")
    adapter = MagicMock()
    adapter.ping.return_value = None
    adapter.get_device.return_value = {
        "name": "acc-sw-01", "serial": "STALE9999", "platform": "Cisco IOS-XE",
        "site": "demo",
    }
    adapter.get_interfaces.return_value = [
        {"name": "Gi1/0/1", "enabled": False, "description": "", "mtu": 1500,
         "mac_address": "12:34:56:78:9A:BC"},
    ]
    observed = {
        "devices": {"acc-sw-01": {"serial": "SYNTH0001", "platform": "Cisco IOS-XE",
                                  "site": "demo", "inventory_name": "acc-sw-01"}},
        "interfaces": {"acc-sw-01": {"Gi1/0/1": {
            "enabled": True, "description": "", "mtu": 1500,
            "mac_address": "1234.5678.9abc"}}},
        "sites": {"demo"},
    }
    with patch("netcopilot.declared_state.get_source", return_value=adapter), \
         patch("netcopilot.declared_state.drift._derive_observed", return_value=observed):
        out = _run(drift_check.compare_declared_vs_actual(device="acc-sw-01", context=CTX))
    assert out.status == "ok"
    assert "≠ DRIFT" in out.text                  # serial drift marked
    assert "Gi1/0/1.enabled" in out.text          # attr drift row
    assert "mac_address" not in out.text          # normalised MACs equal → no row
    assert out.highlight == {"device": "acc-sw-01"}
