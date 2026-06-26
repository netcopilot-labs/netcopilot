"""F2-3b: RESTCONF adapter (httpx). Transport mocked — no live devices."""

import httpx
import pytest

from netcopilot.collect import RestconfAdapter, SSHAdapter, applicable_strategies
from netcopilot.collect import restconf as restconf_mod

DEVICE = {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
CREDS = {"username": "u", "password": "p"}


class _Resp:
    def __init__(self, status_code, data=None, text=""):
        self.status_code = status_code
        self._data = data
        self.text = text

    def json(self):
        if self._data is None:
            raise ValueError("not json")
        return self._data


class _FakeClient:
    def __init__(self, handler):
        self._handler = handler

    def get(self, url):
        return self._handler(url)

    def close(self):
        pass


def _patch_client(monkeypatch, handler):
    monkeypatch.setattr(restconf_mod.httpx, "Client", lambda **kw: _FakeClient(handler))


def test_supports_iosxe_only():
    a = RestconfAdapter()
    assert a.supports({"os": "ios-xe"}) is True
    assert a.supports({"os": "ios-xr"}) is False    # XR uses NETCONF
    assert a.supports({"os": "fortios"}) is False
    assert a.supports({"os": "ios-xe", "ssh_only": True}) is False


def test_chain_restconf_between_netconf_and_ssh():
    # ignore the optional pyATS adapter that leads when the [pyats] extra is installed
    names = [s.name for s in applicable_strategies({"os": "ios-xe"}) if s.name != "pyats"]
    assert names == ["netconf", "restconf", "ssh"]


def test_collect_success_writes_json_and_extracts_hostname(monkeypatch, tmp_path):
    def handler(url):
        if "Cisco-IOS-XE-native:native" in url:
            return _Resp(200, {"Cisco-IOS-XE-native:native": {"hostname": "real-rc-01"}})
        return _Resp(200, {})

    _patch_client(monkeypatch, handler)
    result = RestconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is True
    assert result.strategy_name == "restconf"
    assert result.hostname == "real-rc-01"
    assert (tmp_path / "core-rtr-01" / "restconf_native.json").is_file()
    assert (tmp_path / "core-rtr-01" / "restconf_interfaces.json").is_file()


def test_404_is_soft_error_not_device_failure(monkeypatch, tmp_path):
    def handler(url):
        if "openconfig-lldp" in url:
            return _Resp(404, text="not found")
        if "Cisco-IOS-XE-native:native" in url:
            return _Resp(200, {"Cisco-IOS-XE-native:native": {"hostname": "real-rc-01"}})
        return _Resp(200, {})

    _patch_client(monkeypatch, handler)
    result = RestconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is True   # a 404 on one model doesn't fail the device
    statuses = {c["command"]: c["status"] for c in result.commands}
    assert statuses["RESTCONF:lldp"] == "error"
    assert statuses["RESTCONF:native"] == "success"


def test_connection_error_fails_device(monkeypatch, tmp_path):
    def handler(url):
        raise httpx.ConnectError("connection refused")

    _patch_client(monkeypatch, handler)
    result = RestconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is False
    assert "ConnectError" in result.error
    assert result.hostname == "core-rtr-01"   # fallback to inventory name
