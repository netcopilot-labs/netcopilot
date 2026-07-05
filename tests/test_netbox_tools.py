"""S11-4: the 4 NetBox MCP tools — ToolResult envelope, honest failure modes.

NetBox/Neo4j are mocked; the contract under test is the envelope: unavailable →
``error`` (never fake-empty), missing object → ``not_found``, empty result →
``no_data``, data → ``ok``.
"""
import asyncio
from unittest.mock import MagicMock, patch

from netcopilot.mcp.registry import TOOL_SCHEMAS, _HANDLERS
from netcopilot.mcp.tools import netbox as nb_tools


def _run(coro):
    return asyncio.run(coro)


CTX = {"run_id": "demo-run"}


def test_registered_32_tools_with_netbox():
    names = [s["name"] for s in TOOL_SCHEMAS]
    assert len(names) == 32
    for t in ("get_netbox_device", "get_netbox_site",
              "list_netbox_pending_writes", "get_netbox_write_history"):
        assert t in names and t in _HANDLERS


def test_get_netbox_device_unconfigured_is_error(monkeypatch):
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_API_TOKEN", raising=False)
    out = _run(nb_tools.get_netbox_device(name="acc-sw-01", context=CTX))
    assert out.status == "error"
    assert "NETBOX_URL" in out.text          # actionable, not fake-empty


def test_get_netbox_device_found_and_not_found():
    adapter = MagicMock()
    adapter.get_device.side_effect = lambda n: (
        {"name": "acc-sw-01", "mgmt_ip": "192.0.2.11", "role": "access_switch",
         "platform": "iosxe", "site": "demo", "status": "active", "netbox_id": 1}
        if n == "acc-sw-01" else None)
    with patch.object(nb_tools, "_adapter_or_error", return_value=(adapter, None)):
        ok = _run(nb_tools.get_netbox_device(name="acc-sw-01", context=CTX))
        assert ok.status == "ok" and "192.0.2.11" in ok.text
        assert ok.highlight == {"device": "acc-sw-01"}
        missing = _run(nb_tools.get_netbox_device(name="ghost", context=CTX))
        assert missing.status == "not_found" and "bootstrap" in missing.text


def test_get_netbox_site_lists_known_on_miss():
    adapter = MagicMock()
    adapter.get_sites.return_value = [{"slug": "demo", "name": "demo", "netbox_id": 1}]
    with patch.object(nb_tools, "_adapter_or_error", return_value=(adapter, None)):
        out = _run(nb_tools.get_netbox_site(slug="nope", context=CTX))
        assert out.status == "not_found" and "demo" in out.text


def test_list_pending_no_neo4j_is_error(monkeypatch):
    monkeypatch.setattr(nb_tools, "is_available", lambda: False)
    out = _run(nb_tools.list_netbox_pending_writes(context=CTX))
    assert out.status == "error" and "Neo4j" in out.text


def test_list_pending_empty_is_no_data(monkeypatch):
    monkeypatch.setattr(nb_tools, "is_available", lambda: True)
    with patch("netcopilot.declared_state.staging.list_pending", return_value=[]):
        out = _run(nb_tools.list_netbox_pending_writes(context=CTX))
    assert out.status == "no_data"


def test_write_history_rows_render(monkeypatch):
    monkeypatch.setattr(nb_tools, "is_available", lambda: True)
    session = MagicMock()
    row = {"timestamp": "2026-01-01T00:00:00+00:00", "api_response_status": 201,
           "api_method": "POST", "netbox_object_type": "device",
           "dedup_key": "acc-sw-01", "source": "bootstrap"}
    session.run.return_value = [{"w": row}]
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    monkeypatch.setattr(nb_tools, "get_driver", lambda: driver)
    out = _run(nb_tools.get_netbox_write_history(context=CTX))
    assert out.status == "ok" and "OK 201" in out.text and "acc-sw-01" in out.text


def test_write_history_empty_is_no_data(monkeypatch):
    monkeypatch.setattr(nb_tools, "is_available", lambda: True)
    session = MagicMock()
    session.run.return_value = []
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    monkeypatch.setattr(nb_tools, "get_driver", lambda: driver)
    out = _run(nb_tools.get_netbox_write_history(context=CTX))
    assert out.status == "no_data" and "not written" in out.text
