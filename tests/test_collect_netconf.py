"""F2-3a: NETCONF adapter (ncclient). Transport mocked — no live devices."""

import pytest

from netcopilot.collect import NetconfAdapter, SSHAdapter, applicable_strategies
from netcopilot.collect import netconf as netconf_mod


class _Reply:
    def __init__(self, xml):
        self._xml = xml

    def __str__(self):
        return self._xml


_XE_SYSTEM = (
    '<rpc-reply><data><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">'
    "<hostname>real-xe-01</hostname></native></data></rpc-reply>"
)
_EMPTY = "<rpc-reply><data/></rpc-reply>"


class _FakeConn:
    """Stand-in for an ncclient NETCONF session (also its own context manager)."""

    session_id = "1"

    def __init__(self, fail_namespace=None):
        self.fail_namespace = fail_namespace

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def _maybe_fail(self, flt):
        if self.fail_namespace and self.fail_namespace in flt:
            raise RuntimeError("rpc-error")

    def get(self, filter=None):
        flt = filter[1]
        self._maybe_fail(flt)
        if "Cisco-IOS-XE-native" in flt:
            return _Reply(_XE_SYSTEM)
        return _Reply(_EMPTY)

    def get_config(self, source=None, filter=None):
        self._maybe_fail(filter[1])
        return _Reply(_EMPTY)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(netconf_mod.time, "sleep", lambda *_: None)


def _patch_connect(monkeypatch, conn_factory):
    monkeypatch.setattr(netconf_mod.manager, "connect", lambda **kw: conn_factory())


DEVICE = {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
CREDS = {"username": "u", "password": "p"}


def test_supports():
    a = NetconfAdapter()
    assert a.supports({"os": "ios-xe"}) is True
    assert a.supports({"os": "ios-xr"}) is True
    assert a.supports({"os": "fortios"}) is False
    assert a.supports({"os": "ios-xe", "ssh_only": True}) is False   # ssh_only opts out


def test_chain_puts_netconf_first_ssh_last():
    # ignore the optional pyATS adapter that leads when the [pyats] extra is installed
    strategies = [s for s in applicable_strategies({"os": "ios-xe"}) if s.name != "pyats"]
    assert isinstance(strategies[0], NetconfAdapter)
    assert isinstance(strategies[-1], SSHAdapter)


def test_collect_success_writes_xml_and_extracts_hostname(monkeypatch, tmp_path):
    _patch_connect(monkeypatch, _FakeConn)
    result = NetconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is True
    assert result.strategy_name == "netconf"
    assert result.hostname == "real-xe-01"                       # parsed from YANG
    assert (tmp_path / "core-rtr-01" / "netconf_system.xml").is_file()
    assert (tmp_path / "core-rtr-01" / "netconf_interfaces.xml").is_file()
    # commands param is ignored; entries are the YANG queries
    assert all(c["command"].startswith("NETCONF:") for c in result.commands)


def test_per_query_failure_is_soft(monkeypatch, tmp_path):
    # Fail only the stack_oper query; the rest succeed -> overall success.
    _patch_connect(monkeypatch, lambda: _FakeConn(fail_namespace="stack-oper"))
    result = NetconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is True
    statuses = {c["command"]: c["status"] for c in result.commands}
    assert statuses["NETCONF:stack_oper"] == "error"
    assert statuses["NETCONF:system"] == "success"


def test_connection_failure_after_retries(monkeypatch, tmp_path):
    def boom(**kw):
        raise ConnectionError("port 830 closed")

    monkeypatch.setattr(netconf_mod.manager, "connect", boom)
    result = NetconfAdapter().collect(DEVICE, [], str(tmp_path), CREDS)

    assert result.success is False
    assert "after 2 attempts" in result.error
    assert result.hostname == "core-rtr-01"                      # falls back to inventory name
