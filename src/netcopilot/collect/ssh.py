"""SSH collection strategy (Netmiko).

The universal fallback: SSH into a Cisco device, run each command in its
profile, and save the raw output verbatim. It is the simplest strategy and the
one that works when structured transports (NETCONF/RESTCONF) are unavailable.

Raw output is written to ``<output_dir>/<inventory-name>/<command>.txt``. The
filename is derived deterministically from the command so downstream parsers can
locate it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from netcopilot.collect.base import CollectionResult, CollectionStrategy

#: Map NetCopilot OS families to Netmiko ``device_type`` driver names.
OS_TO_NETMIKO = {
    "ios-xe": "cisco_xe",
    "ios-xr": "cisco_xr",
}

SUPPORTED_OS_FAMILIES = frozenset(OS_TO_NETMIKO)

#: SSH connect timeout (seconds). Generous enough for slow virtual devices,
#: which can take far longer than Netmiko's ~10s default to accept a session,
#: while still failing reasonably fast on a genuinely unreachable host.
SSH_CONN_TIMEOUT = 30


def _command_to_filename(command: str) -> str:
    """Turn a CLI command into a filesystem-safe ``.txt`` filename.

    Deterministic — downstream parsers rely on this mapping to find raw output::

        "show ip interface brief" -> "show_ip_interface_brief.txt"
    """
    name = command.lower().replace(" ", "_")
    for ch in '/\\:*?"<>|':
        name = name.replace(ch, "")
    return f"{name}.txt"


def _determine_hostname(connection: Any, fallback: str) -> str:
    """Read the device's configured hostname (metadata only).

    The inventory name may be stale; recording what the device calls itself is
    more faithful. Falls back to ``fallback`` if it cannot be read.
    """
    output = connection.send_command("show running-config | include hostname")
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("hostname "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[-1]
            break
    return fallback


class SSHAdapter(CollectionStrategy):
    """Collect from a Cisco device over SSH using Netmiko."""

    name = "ssh"

    def supports(self, device: dict[str, Any]) -> bool:
        return device.get("os") in SUPPORTED_OS_FAMILIES

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        netmiko_type = OS_TO_NETMIKO.get(device["os"])
        if not netmiko_type:
            # supports() should have been checked first — guard anyway.
            return CollectionResult(
                success=False,
                strategy_name=self.name,
                hostname=device.get("name", device.get("mgmt_ip", "unknown")),
                error=f"No Netmiko device_type mapping for os '{device['os']}'",
            )

        inventory_name = device.get("name", device["mgmt_ip"])
        real_hostname = inventory_name
        success = True
        error: str | None = None
        command_entries: list[dict[str, Any]] = []
        files_created: list[str] = []

        connection = None
        try:
            params = {
                "device_type": netmiko_type,
                "host": device["mgmt_ip"],
                "username": credentials["username"],
                "password": credentials["password"],
                "conn_timeout": SSH_CONN_TIMEOUT,
            }
            if device["os"] == "ios-xe" and credentials.get("enable_password"):
                params["secret"] = credentials["enable_password"]

            connection = ConnectHandler(**params)
            if device["os"] == "ios-xe" and credentials.get("enable_password"):
                connection.enable()

            real_hostname = _determine_hostname(connection, fallback=inventory_name)

            host_path = Path(output_dir) / inventory_name
            host_path.mkdir(parents=True, exist_ok=True)

            for cmd in commands:
                output_file: Path | None = None
                cmd_status = "success"
                cmd_error: str | None = None
                try:
                    output = connection.send_command(cmd)
                    output_file = host_path / _command_to_filename(cmd)
                    output_file.write_text(output, encoding="utf-8")
                    files_created.append(str(output_file))
                except Exception as cmd_exc:  # noqa: BLE001 — per-command isolation
                    cmd_status = "error"
                    cmd_error = str(cmd_exc)
                    success = False
                    if error is None:
                        error = cmd_error

                command_entries.append({
                    "command": cmd,
                    "output_file": str(output_file) if output_file else None,
                    "status": cmd_status,
                    "error": cmd_error,
                })

        except Exception as dev_exc:  # noqa: BLE001 — device-level failure is data
            success = False
            error = str(dev_exc)
        finally:
            if connection:
                try:
                    connection.disconnect()
                except Exception:  # noqa: BLE001 — disconnect errors are not actionable
                    pass

        return CollectionResult(
            success=success,
            strategy_name=self.name,
            hostname=real_hostname,
            files_created=files_created,
            error=error,
            commands=command_entries,
        )
