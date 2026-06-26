"""Per-OS command profiles.

A *profile* is the list of read-only CLI commands NetCopilot runs on a device
of a given OS family. Keeping them here (rather than in scattered config files)
makes the supported command set explicit and removes any working-directory
dependency. Commands are deliberately conservative ``show`` commands — read-only,
present on stock images.

FortiGate (``fortios``) collects over its REST API, not a CLI command profile,
so it has no entry here.
"""
from __future__ import annotations

COMMAND_PROFILES: dict[str, list[str]] = {
    "ios-xe": [
        "show version",
        "show inventory",
        "show interfaces status",
        "show ip interface brief",
        "show cdp neighbors",
    ],
    "ios-xr": [
        "show version",
        "show inventory",
        "show interfaces brief",
        "show ipv4 interface brief",
        "show cdp neighbors",
    ],
}


def commands_for(os_family: str) -> list[str]:
    """Return the command profile for ``os_family`` (empty list if none)."""
    return list(COMMAND_PROFILES.get(os_family, []))
