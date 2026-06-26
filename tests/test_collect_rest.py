"""F2-3c: FortiGate REST adapter (httpx). Transport mocked — no live devices."""

import json

import httpx
import pytest

from netcopilot.collect import RestAdapter, applicable_strategies
from netcopilot.collect import rest as rest_mod
from netcopilot.collect.rest import FORTIGATE_ENDPOINTS

DEVICE = {"name": "edge-fw-01", "mgmt_ip": "192.0.2.254", "os": "fortios"}


class _Resp:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data
        self.text = "" if data is not None else "error body"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=self)

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, handler):
        self._handler = handler
        self.calls = []  # list of (url, params)

    def get(self, url, params=None):
        self.calls.append((url, params))
        return self._handler(url)

    def close(self):
        pass


def _patch(monkeypatch, handler):
    """Patch httpx.Client; returns a holder whose ['client'] is the fake (for call inspection)."""
    holder = {}

    def make(**kw):
        holder["client"] = _FakeClient(handler)
        return holder["client"]

    monkeypatch.setattr(rest_mod.httpx, "Client", make)
    return holder


def test_supports_fortios_only():
    a = RestAdapter()
    assert a.supports({"os": "fortios"}) is True
    assert a.supports({"os": "ios-xe"}) is False
    # FortiGate has no SSH fallback — REST is the only strategy that matches it.
    assert [s.name for s in applicable_strategies({"os": "fortios"})] == ["rest"]


def test_missing_token_fails_clearly(monkeypatch, tmp_path):
    monkeypatch.delenv("NETCOPILOT_FORTIGATE_API_TOKEN", raising=False)
    result = RestAdapter().collect(DEVICE, [], str(tmp_path), {})
    assert result.success is False
    assert "NETCOPILOT_FORTIGATE_API_TOKEN" in result.error


def test_collect_success_writes_json_and_hostname(monkeypatch, tmp_path):
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok")

    def handler(url):
        if url.endswith("/monitor/system/status"):
            return _Resp(200, {"results": {"hostname": "real-fw-01"}})
        return _Resp(200, {"results": []})

    _patch(monkeypatch, handler)
    result = RestAdapter().collect(DEVICE, [], str(tmp_path), {})

    assert result.success is True
    assert result.strategy_name == "rest"
    assert result.hostname == "real-fw-01"
    assert (tmp_path / "edge-fw-01" / "fortigate_system_status.json").is_file()
    # all endpoints attempted
    assert len(result.commands) == len(FORTIGATE_ENDPOINTS)


def test_http_error_on_one_endpoint_is_soft(monkeypatch, tmp_path):
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok")

    def handler(url):
        if url.endswith("/monitor/system/status"):
            return _Resp(200, {"results": {"hostname": "real-fw-01"}})
        if url.endswith("/cmdb/ips/sensor"):
            return _Resp(403)
        return _Resp(200, {"results": []})

    _patch(monkeypatch, handler)
    result = RestAdapter().collect(DEVICE, [], str(tmp_path), {})

    assert result.success is True   # one 403 doesn't fail the device
    statuses = {c["command"]: c["status"] for c in result.commands}
    assert statuses["REST:GET /api/v2/cmdb/ips/sensor"] == "error"


def test_vdom_scopes_per_vdom_endpoints_only(monkeypatch, tmp_path):
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok")

    def handler(url):
        if url.endswith("/monitor/system/status"):
            return _Resp(200, {"results": {"hostname": "real-fw-01"}})
        return _Resp(200, {"results": []})

    holder = _patch(monkeypatch, handler)
    device = {**DEVICE, "vdom": "tenant-a"}
    RestAdapter().collect(device, [], str(tmp_path), {})

    calls = dict(holder["client"].calls)  # url -> params
    # Per-VDOM endpoint (firewall policy) is scoped...
    assert calls["https://192.0.2.254/api/v2/cmdb/firewall/policy"] == {"vdom": "tenant-a"}
    # ...global endpoint (HA config) is not.
    assert calls["https://192.0.2.254/api/v2/cmdb/system/ha"] is None


def test_no_vdom_means_no_scoping(monkeypatch, tmp_path):
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok")
    holder = _patch(monkeypatch, lambda url: _Resp(200, {"results": []}))
    RestAdapter().collect(DEVICE, [], str(tmp_path), {})  # no vdom field
    assert all(params is None for _url, params in holder["client"].calls)


def test_total_connection_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok")

    def handler(url):
        raise httpx.ConnectError("unreachable")

    _patch(monkeypatch, handler)
    result = RestAdapter().collect(DEVICE, [], str(tmp_path), {})

    assert result.success is False   # nothing collected
    assert "ConnectError" in result.error
    assert result.hostname == "edge-fw-01"
