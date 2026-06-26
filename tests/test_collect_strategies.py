"""F2-2a: collection contracts, roles, profiles, SSH adapter, strategy chain.

No live devices — the SSH transport (Netmiko ConnectHandler) is mocked.
"""

import pytest

from netcopilot.collect import (
    CollectionResult,
    CollectionStrategy,
    SSHAdapter,
    applicable_strategies,
    default_chain,
)
from netcopilot.collect import ssh as ssh_mod
from netcopilot.collect.profiles import commands_for
from netcopilot.collect.roles import validate_role, validate_site


# ----------------------------- contracts ---------------------------------

def test_strategy_abc_cannot_be_instantiated():
    with pytest.raises(TypeError):
        CollectionStrategy()  # type: ignore[abstract]


def test_collection_result_defaults():
    r = CollectionResult(success=True, strategy_name="ssh", hostname="h")
    assert r.files_created == [] and r.commands == [] and r.error is None


# ------------------------------- roles -----------------------------------

def test_validate_role_known_unknown_missing():
    assert validate_role("core_router") == ("core_router", None)
    assert validate_role("CORE_ROUTER")[0] == "core_router"
    role, warn = validate_role("spine")
    assert role == "spine" and "not in KNOWN_ROLES" in warn
    assert validate_role(None) == ("unknown", "missing")
    assert validate_role("  ") == ("unknown", "missing")


def test_validate_site():
    assert validate_site("demo") == ("demo", None)
    assert validate_site(None) == ("unassigned", "missing")


# ------------------------------ profiles ---------------------------------

def test_commands_for_known_and_unknown():
    assert "show version" in commands_for("ios-xe")
    assert commands_for("ios-xr")[0] == "show version"
    assert commands_for("fortios") == []  # REST-collected, no CLI profile


# ------------------------------- chain -----------------------------------

def test_chain_routing_by_os():
    assert isinstance(default_chain()[-1], SSHAdapter)  # SSH is the universal fallback (last)
    # pyATS is prepended only when the optional [pyats] extra is installed; strip
    # it so the structured-transport ordering holds with or without the extra.
    def transports(device):
        return [s.name for s in applicable_strategies(device) if s.name != "pyats"]
    assert transports({"os": "ios-xe"}) == ["netconf", "restconf", "ssh"]
    assert transports({"os": "ios-xr"}) == ["netconf", "ssh"]  # no RESTCONF on XR
    assert transports({"os": "fortios"}) == ["rest"]  # FortiGate: REST only


def test_ssh_supports():
    a = SSHAdapter()
    assert a.supports({"os": "ios-xe"}) is True
    assert a.supports({"os": "ios-xr"}) is True
    assert a.supports({"os": "fortios"}) is False


# --------------------------- SSH adapter ---------------------------------

class _FakeConnection:
    """Stand-in for a Netmiko connection."""

    def __init__(self, hostname="core-rtr-01", fail_on=None):
        self._hostname = hostname
        self._fail_on = fail_on or set()
        self.disconnected = False

    def enable(self):
        pass

    def send_command(self, cmd):
        if cmd in self._fail_on:
            raise RuntimeError(f"boom: {cmd}")
        if "hostname" in cmd:
            return f"hostname {self._hostname}\n"
        return f"=== output of {cmd} ===\n"

    def disconnect(self):
        self.disconnected = True


def _patch_connect(monkeypatch, conn):
    captured = {}

    def fake_handler(**params):
        captured.update(params)
        return conn

    monkeypatch.setattr(ssh_mod, "ConnectHandler", fake_handler)
    return captured


def test_ssh_collect_success(monkeypatch, tmp_path):
    conn = _FakeConnection(hostname="real-name-01")
    params = _patch_connect(monkeypatch, conn)

    device = {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
    creds = {"username": "u", "password": "p", "enable_password": "e"}
    result = SSHAdapter().collect(device, ["show version", "show inventory"], str(tmp_path), creds)

    assert result.success is True
    assert result.strategy_name == "ssh"
    assert result.hostname == "real-name-01"          # read from device, not inventory
    assert params["host"] == "192.0.2.1"
    assert params["secret"] == "e"                    # enable secret wired for ios-xe
    assert len(result.files_created) == 2
    # Raw output written under <output_dir>/<inventory-name>/
    assert (tmp_path / "core-rtr-01" / "show_version.txt").is_file()
    assert conn.disconnected is True


def test_ssh_collect_command_error_is_captured_not_raised(monkeypatch, tmp_path):
    conn = _FakeConnection(fail_on={"show inventory"})
    _patch_connect(monkeypatch, conn)

    device = {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
    creds = {"username": "u", "password": "p"}
    result = SSHAdapter().collect(device, ["show version", "show inventory"], str(tmp_path), creds)

    assert result.success is False
    assert "boom" in result.error
    statuses = {c["command"]: c["status"] for c in result.commands}
    assert statuses == {"show version": "success", "show inventory": "error"}


def test_ssh_collect_connection_failure_is_captured(monkeypatch, tmp_path):
    def boom(**params):
        raise ConnectionError("unreachable")

    monkeypatch.setattr(ssh_mod, "ConnectHandler", boom)

    device = {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
    result = SSHAdapter().collect(device, ["show version"], str(tmp_path), {"username": "u", "password": "p"})

    assert result.success is False
    assert "unreachable" in result.error
    assert result.hostname == "core-rtr-01"           # falls back to inventory name
