"""F2-5-final: testbed generator — inventory device dicts → pyATS Testbed.

Skipped entirely unless the optional ``[pyats]`` extra is installed.
"""

import pytest

pytest.importorskip("pyats")

from netcopilot.collect.testbed_generator import generate_testbed  # noqa: E402

CREDS = {"username": "admin", "password": "testpass"}

DEVICES = [
    {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xr"},
    {"name": "dist-sw-01", "mgmt_ip": "192.0.2.2", "os": "ios-xe"},
    {"name": "fw-01", "mgmt_ip": "192.0.2.3", "os": "fortios"},        # skipped: not Cisco
    {"name": "legacy-sw-01", "mgmt_ip": "192.0.2.4", "os": "ios-xe", "ssh_only": True},  # skipped
]


def test_includes_only_eligible_cisco_devices():
    tb = generate_testbed(DEVICES, CREDS)
    assert set(tb.devices) == {"core-rtr-01", "dist-sw-01"}


def test_os_and_platform_mapping():
    tb = generate_testbed(DEVICES, CREDS)
    assert tb.devices["core-rtr-01"].os == "iosxr"
    assert tb.devices["dist-sw-01"].os == "iosxe"
    # informational type hint
    assert tb.devices["core-rtr-01"].type == "router"
    assert tb.devices["dist-sw-01"].type == "switch"


def test_default_credentials_injected():
    tb = generate_testbed(DEVICES, CREDS)
    cred = tb.devices["dist-sw-01"].credentials["default"]
    assert str(cred.username) == "admin"


def test_enable_password_adds_enable_credential_for_iosxe_only():
    creds = {"username": "admin", "password": "testpass", "enable_password": "ena"}
    tb = generate_testbed(DEVICES, creds)
    assert "enable" in tb.devices["dist-sw-01"].credentials      # ios-xe
    assert "enable" not in tb.devices["core-rtr-01"].credentials  # ios-xr


def test_raises_when_no_eligible_devices():
    only_skipped = [
        {"name": "fw-01", "mgmt_ip": "192.0.2.3", "os": "fortios"},
        {"name": "legacy-sw-01", "mgmt_ip": "192.0.2.4", "os": "ios-xe", "ssh_only": True},
    ]
    with pytest.raises(ValueError, match="No Cisco devices eligible"):
        generate_testbed(only_skipped, CREDS)
