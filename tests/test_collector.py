"""F2-2b: collection orchestrator (run_collection over an InventorySource).

No live devices — the SSH transport is mocked.
"""

import json

import pytest

from netcopilot.collect import (
    SSHAdapter,
    get_env_credentials,
    resolve_credentials,
    run_collection,
)
from netcopilot.collect import ssh as ssh_mod

# Orchestration tests pin an explicit SSH-only chain so they exercise the
# orchestrator without attempting a real NETCONF connect to a documentation IP.
SSH_CHAIN = [SSHAdapter()]
from netcopilot.inventory.base import InventorySource


class FakeInventory(InventorySource):
    def __init__(self, devices):
        self._devices = devices

    def get_devices(self):
        return list(self._devices)

    def get_device(self, name):
        return next((d for d in self._devices if d["name"] == name), None)


class _FakeConnection:
    def __init__(self, hostname):
        self._hostname = hostname

    def enable(self):
        pass

    def send_command(self, cmd):
        if "hostname" in cmd:
            return f"hostname {self._hostname}\n"
        return f"=== {cmd} ===\n"

    def disconnect(self):
        pass


@pytest.fixture
def mock_ssh(monkeypatch):
    """Patch Netmiko so SSHAdapter 'connects' to a fake device."""
    monkeypatch.setattr(
        ssh_mod, "ConnectHandler",
        lambda **p: _FakeConnection(hostname=f"real-{p['host'].replace('.', '-')}"),
    )


@pytest.fixture
def env_creds(monkeypatch):
    monkeypatch.setenv("NETCOPILOT_SSH_USERNAME", "operator")
    monkeypatch.setenv("NETCOPILOT_SSH_PASSWORD", "secret")
    monkeypatch.delenv("NETCOPILOT_ENABLE_PASSWORD", raising=False)


CISCO = [
    {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe", "role": "core_router", "site": "demo"},
    {"name": "dist-sw-01", "mgmt_ip": "192.0.2.2", "os": "ios-xr", "role": "distribution_switch", "site": "demo"},
]


# --------------------------- credentials ---------------------------------

def test_get_env_credentials_requires_user_and_pass(monkeypatch):
    monkeypatch.delenv("NETCOPILOT_SSH_USERNAME", raising=False)
    monkeypatch.delenv("NETCOPILOT_SSH_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="must be set"):
        get_env_credentials()


def test_get_env_credentials_reads_env(env_creds):
    creds = get_env_credentials()
    assert creds["username"] == "operator" and creds["password"] == "secret"
    assert creds["enable_password"] is None


def test_resolve_credentials_per_device_override_with_expandvars(monkeypatch):
    monkeypatch.setenv("FW_USER", "fwadmin")
    base = {"username": "operator", "password": "secret", "enable_password": None}
    device = {"username": "${FW_USER}", "password": "literal-pw"}
    out = resolve_credentials(device, base)
    assert out["username"] == "fwadmin"          # ${FW_USER} expanded
    assert out["password"] == "literal-pw"
    assert base["username"] == "operator"        # base untouched


# --------------------------- run_collection ------------------------------

def test_run_collection_writes_manifest_and_raw(mock_ssh, env_creds, tmp_path):
    run_id = run_collection(FakeInventory(CISCO), runs_dir=tmp_path, parallel=False, chain=SSH_CHAIN)
    assert run_id

    manifest = json.loads((tmp_path / run_id / "manifest.json").read_text())
    assert manifest["device_count"] == 2
    assert manifest["collection_mode"] == "sequential"
    assert {d["status"] for d in manifest["devices"]} == {"success"}
    assert {d["collection_strategy"] for d in manifest["devices"]} == {"ssh"}

    core = next(d for d in manifest["devices"] if d["inventory_name"] == "core-rtr-01")
    assert core["hostname"] == "real-192-0-2-1"  # read from device
    assert core["role"] == "core_router"
    assert (tmp_path / run_id / "raw" / "core-rtr-01" / "show_version.txt").is_file()


def test_manifest_carries_inventory_cluster(mock_ssh, env_creds, tmp_path):
    # Regression: the inventory cluster block must round-trip into the manifest.
    # model_builder derives cluster_declared_size from manifest cluster.size to
    # drive stack/HA member-id attribution; dropping it un-attributes every cable.
    devs = [
        {"name": "stk-sw-01", "mgmt_ip": "192.0.2.10", "os": "ios-xe",
         "role": "core_switch", "site": "demo",
         "cluster": {"name": "SW_CORE", "size": 2}},
        {"name": "solo-rtr-01", "mgmt_ip": "192.0.2.11", "os": "ios-xr",
         "role": "core_router", "site": "demo"},
    ]
    run_id = run_collection(FakeInventory(devs), runs_dir=tmp_path, parallel=False, chain=SSH_CHAIN)
    by_name = {d["inventory_name"]: d
               for d in json.loads((tmp_path / run_id / "manifest.json").read_text())["devices"]}
    assert by_name["stk-sw-01"]["cluster"] == {"name": "SW_CORE", "size": 2}
    assert by_name["solo-rtr-01"]["cluster"] is None  # no cluster declared


def test_run_collection_parallel(mock_ssh, env_creds, tmp_path):
    run_id = run_collection(FakeInventory(CISCO), runs_dir=tmp_path, parallel=True, chain=SSH_CHAIN)
    manifest = json.loads((tmp_path / run_id / "manifest.json").read_text())
    assert manifest["collection_mode"] == "parallel_threads"
    assert len(manifest["devices"]) == 2


def test_no_applicable_strategy_is_error_not_skip(env_creds, tmp_path):
    # A fortios device against an SSH-only chain has no applicable strategy:
    # the orchestrator records an error entry, it does not silently skip.
    inv = FakeInventory([{"name": "edge-fw-01", "mgmt_ip": "192.0.2.254", "os": "fortios"}])
    run_id = run_collection(inv, runs_dir=tmp_path, parallel=False, chain=SSH_CHAIN)
    entry = json.loads((tmp_path / run_id / "manifest.json").read_text())["devices"][0]
    assert entry["status"] == "error"
    assert entry["collection_strategy"] == "none"
    assert "no applicable collection strategy" in entry["error"]


def test_fortigate_only_run_needs_no_ssh_credentials(monkeypatch, tmp_path):
    # FortiGate authenticates with an API token, not SSH creds. A fortios-only
    # run must NOT require NETCOPILOT_SSH_USERNAME/PASSWORD.
    monkeypatch.delenv("NETCOPILOT_SSH_USERNAME", raising=False)
    monkeypatch.delenv("NETCOPILOT_SSH_PASSWORD", raising=False)
    monkeypatch.setenv("NETCOPILOT_FORTIGATE_API_TOKEN", "tok123")

    captured = {}

    def fake_client(**kw):
        captured["headers"] = kw.get("headers")

        class _C:
            def get(self, url, params=None):
                class _R:
                    status_code = 200

                    def raise_for_status(self):
                        pass

                    def json(self):
                        return {"results": {"hostname": "real-fw-01"}}
                return _R()

            def close(self):
                pass
        return _C()

    from netcopilot.collect import rest as rest_mod
    monkeypatch.setattr(rest_mod.httpx, "Client", fake_client)

    inv = FakeInventory([{"name": "edge-fw-01", "mgmt_ip": "192.0.2.254", "os": "fortios"}])
    run_id = run_collection(inv, runs_dir=tmp_path, parallel=False)  # default chain, no SSH creds

    entry = json.loads((tmp_path / run_id / "manifest.json").read_text())["devices"][0]
    assert entry["status"] == "success"
    assert entry["collection_strategy"] == "rest"
    assert entry["hostname"] == "real-fw-01"
    assert captured["headers"]["Authorization"] == "Bearer tok123"


def test_one_device_failure_does_not_abort_run(monkeypatch, env_creds, tmp_path):
    def connect(**p):
        if p["host"] == "192.0.2.2":
            raise ConnectionError("unreachable")
        return _FakeConnection(hostname="real-core")

    monkeypatch.setattr(ssh_mod, "ConnectHandler", connect)
    manifest_run = run_collection(FakeInventory(CISCO), runs_dir=tmp_path, parallel=False, chain=SSH_CHAIN)
    devices = json.loads((tmp_path / manifest_run / "manifest.json").read_text())["devices"]
    by_name = {d["inventory_name"]: d for d in devices}
    assert by_name["core-rtr-01"]["status"] == "success"
    assert by_name["dist-sw-01"]["status"] == "error"
    assert "unreachable" in by_name["dist-sw-01"]["error"]


def test_dry_run_creates_nothing(env_creds, tmp_path, capsys):
    out = run_collection(FakeInventory(CISCO), runs_dir=tmp_path, dry_run=True)
    assert out == ""
    assert list(tmp_path.iterdir()) == []      # no run folder written
    printed = capsys.readouterr().out
    assert "DRY-RUN" in printed and "core-rtr-01" in printed


def test_validation_rejects_duplicate_names(env_creds, tmp_path):
    dupes = [
        {"name": "x", "mgmt_ip": "192.0.2.1", "os": "ios-xe"},
        {"name": "x", "mgmt_ip": "192.0.2.2", "os": "ios-xe"},
    ]
    with pytest.raises(ValueError, match="duplicate device name"):
        run_collection(FakeInventory(dupes), runs_dir=tmp_path)


def test_validation_rejects_unknown_os(env_creds, tmp_path):
    bad = [{"name": "x", "mgmt_ip": "192.0.2.1", "os": "junos"}]
    with pytest.raises(ValueError, match="unsupported os"):
        run_collection(FakeInventory(bad), runs_dir=tmp_path)
