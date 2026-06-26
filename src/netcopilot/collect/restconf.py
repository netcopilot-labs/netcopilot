"""RESTCONF collection strategy (httpx).

Fetches YANG-modeled JSON (RFC 8040) from Cisco IOS XE over HTTPS — the same
logical data as NETCONF, but over HTTP. It's the fallback for IOS XE devices
whose NETCONF subsystem is unavailable. IOS XR uses NETCONF, so RESTCONF here
is IOS-XE-only.

Read-only: GET requests only. Raw JSON is saved per endpoint as
``raw/<name>/restconf_<endpoint>.json`` for the parse layer.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from netcopilot.collect.base import CollectionResult, CollectionStrategy

logger = logging.getLogger(__name__)

SUPPORTED_OS_FAMILIES = frozenset({"ios-xe"})

RESTCONF_PORT = 443
RESTCONF_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

# (name, RESTCONF resource path) — same logical data as the NETCONF YANG queries.
IOSXE_RESTCONF_ENDPOINTS = [
    ("native", "Cisco-IOS-XE-native:native"),
    ("device_hardware", "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"),
    ("interfaces", "openconfig-interfaces:interfaces"),
    ("cdp", "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"),
    ("lldp", "openconfig-lldp:lldp"),
]


def _determine_hostname_from_json(json_responses: dict[str, Any], fallback: str) -> str:
    """Extract the hostname from the native RESTCONF JSON, else ``fallback``."""
    try:
        native_data = json_responses.get("native")
        if isinstance(native_data, dict):
            native = native_data.get("Cisco-IOS-XE-native:native", {})
            hostname = native.get("hostname")
            if hostname:
                return str(hostname).strip()
    except (AttributeError, TypeError) as exc:
        logger.warning("Failed to extract hostname from RESTCONF JSON: %s", exc)
    return fallback


class RestconfAdapter(CollectionStrategy):
    """Collect YANG-modeled JSON over RESTCONF (IOS XE) using httpx."""

    name = "restconf"

    def supports(self, device: dict[str, Any]) -> bool:
        if device.get("ssh_only", False):
            return False
        return device.get("os") in SUPPORTED_OS_FAMILIES

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """Collect via RESTCONF. ``commands`` is ignored (YANG paths are used)."""
        inventory_name = device.get("name", device["mgmt_ip"])
        base_url = f"https://{device['mgmt_ip']}:{RESTCONF_PORT}/restconf/data"
        status = True
        error: str | None = None
        command_entries: list[dict[str, Any]] = []
        files_created: list[str] = []
        json_responses: dict[str, Any] = {}

        # verify=False: device RESTCONF endpoints commonly present self-signed
        # certs; this is read-only collection. Use a CA bundle where you have one.
        client = httpx.Client(
            auth=(credentials["username"], credentials["password"]),
            headers=RESTCONF_HEADERS,
            verify=False,
            timeout=RESTCONF_TIMEOUT,
        )
        try:
            for endpoint_name, resource_path in IOSXE_RESTCONF_ENDPOINTS:
                cmd_status = "success"
                cmd_error: str | None = None
                try:
                    response = client.get(f"{base_url}/{resource_path}")
                    if response.status_code == 200:
                        json_responses[endpoint_name] = response.json()
                    elif response.status_code == 204:
                        json_responses[endpoint_name] = {}  # no data (valid)
                    elif response.status_code == 404:
                        # Device doesn't support this model — skip, not fatal.
                        cmd_status = "error"
                        cmd_error = f"HTTP 404: resource not found ({resource_path})"
                        logger.warning("RESTCONF '%s' not found on '%s'", endpoint_name, inventory_name)
                    else:
                        cmd_status = "error"
                        cmd_error = f"HTTP {response.status_code}: {response.text[:200]}"
                        status = False
                        if error is None:
                            error = cmd_error
                except httpx.RequestError as exc:
                    cmd_status = "error"
                    cmd_error = f"{type(exc).__name__}: {exc}"
                    status = False
                    if error is None:
                        error = cmd_error
                    logger.warning("RESTCONF request failed for '%s' endpoint '%s': %s",
                                   inventory_name, endpoint_name, exc)
                except ValueError as exc:  # JSON decode error
                    cmd_status = "error"
                    cmd_error = f"JSON decode error: {exc}"
                    status = False
                    if error is None:
                        error = cmd_error

                command_entries.append({
                    "command": f"RESTCONF:{endpoint_name}",
                    "output_file": None,
                    "status": cmd_status,
                    "error": cmd_error,
                })
        finally:
            client.close()

        real_hostname = _determine_hostname_from_json(json_responses, inventory_name)

        host_path = Path(output_dir) / inventory_name
        host_path.mkdir(parents=True, exist_ok=True)
        for i, (endpoint_name, _) in enumerate(IOSXE_RESTCONF_ENDPOINTS):
            data = json_responses.get(endpoint_name)
            if data is not None:
                output_file = host_path / f"restconf_{endpoint_name}.json"
                output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                files_created.append(str(output_file))
                command_entries[i]["output_file"] = str(output_file)

        return CollectionResult(
            success=status, strategy_name=self.name, hostname=real_hostname,
            files_created=files_created, error=error, commands=command_entries,
        )
