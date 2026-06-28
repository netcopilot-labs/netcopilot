"""Per-device secret indirection: a single ``${ENV_VAR}`` pattern for SSH creds
and the FortiGate ``api_token``, so multi-device / multi-tenant runs keep secrets
in ``.env`` rather than in the inventory file, and each device can carry its own."""

import pytest

from netcopilot.collect.base import expand_env_ref
from netcopilot.collect.collector import resolve_credentials
from netcopilot.collect.rest import RestAdapter


# ── the shared helper ────────────────────────────────────────────────────────
def test_expand_env_ref_resolves_set_var(monkeypatch):
    monkeypatch.setenv("TENANT_A_PW", "s3cret")
    assert expand_env_ref("${TENANT_A_PW}") == "s3cret"


def test_expand_env_ref_literal_passthrough():
    assert expand_env_ref("plain-value") == "plain-value"


def test_expand_env_ref_unset_raises():
    with pytest.raises(ValueError, match="unset environment variable"):
        expand_env_ref("${DEFINITELY_NOT_SET_XYZ}")


# ── SSH creds (resolve_credentials) ──────────────────────────────────────────
def test_resolve_credentials_per_device_env(monkeypatch):
    monkeypatch.setenv("FWUSER", "admin2")
    monkeypatch.setenv("FWPASS", "pw2")
    base = {"username": "global", "password": "globalpw", "enable_password": None}
    creds = resolve_credentials({"username": "${FWUSER}", "password": "${FWPASS}"}, base)
    assert creds["username"] == "admin2"
    assert creds["password"] == "pw2"


def test_resolve_credentials_falls_back_to_base():
    base = {"username": "global", "password": "globalpw", "enable_password": None}
    assert resolve_credentials({}, base)["username"] == "global"


def test_resolve_credentials_unset_ref_raises():
    base = {"username": "g", "password": "p", "enable_password": None}
    with pytest.raises(ValueError, match="unset environment variable"):
        resolve_credentials({"password": "${NOPE_NOT_SET}"}, base)


# ── FortiGate api_token (RestAdapter.collect, no HTTP — early returns) ────────
def _fw_device(**extra):
    return {"name": "edge-fw-01", "mgmt_ip": "192.0.2.99", "os": "fortios", **extra}


def test_rest_per_device_token_unset_ref_errors():
    res = RestAdapter().collect(_fw_device(api_token="${UNSET_FW_TOK}"), [], "/tmp", {})
    assert res.success is False
    assert "unset environment variable" in res.error


def test_rest_no_token_anywhere_errors(monkeypatch):
    monkeypatch.delenv("NETCOPILOT_FORTIGATE_API_TOKEN", raising=False)
    res = RestAdapter().collect(_fw_device(), [], "/tmp", {})
    assert res.success is False
    assert "api_token" in res.error or "API token" in res.error
