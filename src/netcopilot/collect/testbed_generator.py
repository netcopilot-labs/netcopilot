"""Testbed generator — NetCopilot inventory device dicts → a pyATS Testbed.

The pyATS adapter needs a ``Testbed`` object to connect; this module is the pure
translation from our inventory schema to pyATS's. Device dicts in, ``Testbed``
out — no network or file I/O. Only Cisco IOS XE / IOS XR devices are included;
FortiGate and ``ssh_only`` devices are skipped silently (they are handled by the
REST and SSH strategies respectively).

This module imports ``pyats`` at top level, so it is only importable when the
optional ``[pyats]`` extra is installed. The strategy chain imports the pyATS
adapter (and therefore this module) behind a ``try/except ImportError`` so a
plain install without pyATS still works.
"""
from __future__ import annotations

import logging
from typing import Any

from pyats.topology import loader

log = logging.getLogger(__name__)


#: Inventory ``os`` family → pyATS ``os`` string. The pyATS ``os`` selects the
#: Unicon connection plugin and the Genie parser set.
OS_FAMILY_TO_PYATS_OS: dict[str, str] = {
    "ios-xe": "iosxe",
    "ios-xr": "iosxr",
}

#: Inventory ``os`` family → pyATS ``platform`` hint. Helps Genie pick a
#: platform-specific parser variant where several exist (e.g. cat9k).
OS_FAMILY_TO_PYATS_PLATFORM: dict[str, str] = {
    "ios-xe": "cat9k",   # Catalyst 9000 series
    "ios-xr": "iosxr",   # platform string matches os for XR
}

#: Inventory ``os`` family → informational pyATS ``type`` (does not affect
#: parser selection).
OS_FAMILY_TO_PYATS_TYPE: dict[str, str] = {
    "ios-xe": "switch",
    "ios-xr": "router",
}

SSH_PORT = 22

#: Connect timeout (seconds). Matches the SSH strategy; virtual devices can be
#: slow to accept a session.
CONNECTION_TIMEOUT = 30

#: Exec timeout (seconds) — some show commands on virtual devices are slow.
EXEC_TIMEOUT = 60

#: SSH options for legacy-device compatibility. Older IOS (15.x) only advertises
#: the old DH key-exchange methods modern OpenSSH drops by default; the ``+``
#: prefix re-adds them without removing modern algorithms, so current IOS XE /
#: IOS XR negotiate a modern algorithm first and are unaffected.
#: ``UserKnownHostsFile=/dev/null`` avoids stale-host-key failures on devices that
#: regenerate their SSH host key on reboot — consistent with the read-only, no-PKI
#: posture of the NETCONF strategy (``hostkey_verify=False``).
SSH_OPTIONS = (
    "-o KexAlgorithms=+diffie-hellman-group1-sha1,"
    "diffie-hellman-group14-sha1,"
    "diffie-hellman-group-exchange-sha1"
    " -o HostKeyAlgorithms=+ssh-rsa"
    " -o PubkeyAcceptedAlgorithms=+ssh-rsa"
    " -o StrictHostKeyChecking=no"
    " -o UserKnownHostsFile=/dev/null"
)


def generate_testbed(
    devices: list[dict[str, Any]],
    credentials: dict[str, Any],
) -> Any:  # returns pyats.topology.Testbed (typed Any so callers need no pyATS import)
    """Build a pyATS ``Testbed`` from a NetCopilot inventory device list.

    Only Cisco devices pyATS can drive are included; FortiGate (``os`` not in
    the mapping) and ``ssh_only`` devices are skipped silently. The returned
    testbed opens no connections — the adapter connects later.

    Args:
        devices: Device dicts, each with at least ``{"name", "mgmt_ip", "os"}``.
            ``ssh_only: True`` excludes a device.
        credentials: ``{"username", "password"}`` and optionally
            ``"enable_password"`` (IOS XE enable secret).

    Returns:
        A ``pyats.topology.Testbed`` with every eligible Cisco device loaded.

    Raises:
        ValueError: If no eligible Cisco device is found (e.g. every device is
            ``ssh_only`` or FortiGate) — catches misconfiguration early.
    """
    included: list[str] = []
    skipped: list[tuple[str, str]] = []  # (name, reason)

    testbed_dict: dict[str, Any] = {
        "testbed": {"name": "netcopilot"},
        "devices": {},
    }

    for device in devices:
        device_name = device.get("name", device.get("mgmt_ip", "unknown"))
        os_family = device.get("os", "")

        # Skip non-Cisco OS families (FortiGate, Junos, ...).
        if os_family not in OS_FAMILY_TO_PYATS_OS:
            log.debug("Testbed: skipping %s — os %r not managed by pyATS", device_name, os_family)
            skipped.append((device_name, f"os={os_family!r} not supported"))
            continue

        # Skip ssh_only devices (no Genie parser support — handled by SSH strategy).
        if device.get("ssh_only", False):
            log.debug("Testbed: skipping %s — ssh_only=true", device_name)
            skipped.append((device_name, "ssh_only=true"))
            continue

        device_entry: dict[str, Any] = {
            "os": OS_FAMILY_TO_PYATS_OS[os_family],
            "platform": OS_FAMILY_TO_PYATS_PLATFORM[os_family],
            "type": OS_FAMILY_TO_PYATS_TYPE[os_family],
            # "default" credentials are what Unicon uses automatically on connect.
            "credentials": {
                "default": {
                    "username": credentials["username"],
                    "password": credentials["password"],
                },
            },
            "connections": {
                "cli": {
                    "protocol": "ssh",
                    "ip": device["mgmt_ip"],
                    "port": SSH_PORT,
                    "ssh_options": SSH_OPTIONS,
                    "settings": {
                        "CONNECTION_TIMEOUT": CONNECTION_TIMEOUT,
                        "EXEC_TIMEOUT": EXEC_TIMEOUT,
                    },
                },
            },
        }

        # IOS XE enable secret — add an "enable" credential set so Unicon can
        # enter privileged exec automatically during connect().
        if os_family == "ios-xe" and credentials.get("enable_password"):
            device_entry["credentials"]["enable"] = {
                "password": credentials["enable_password"],
            }

        testbed_dict["devices"][device_name] = device_entry
        included.append(device_name)
        log.debug("Testbed: added %s (os=%s, ip=%s)",
                  device_name, device_entry["os"], device["mgmt_ip"])

    if not testbed_dict["devices"]:
        reasons = "; ".join(f"{name}: {reason}" for name, reason in skipped)
        raise ValueError(
            f"No Cisco devices eligible for pyATS testbed. "
            f"All {len(skipped)} device(s) were skipped. Reasons: [{reasons}]. "
            f"Check that the inventory has ios-xe/ios-xr devices without ssh_only: true."
        )

    log.info("Testbed generated: %d Cisco device(s) included, %d skipped",
             len(included), len(skipped))

    # loader.load() accepts the dict directly (same schema as a YAML testbed
    # file) — no temp file needed.
    return loader.load(testbed_dict)
