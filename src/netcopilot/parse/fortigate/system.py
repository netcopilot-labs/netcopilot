"""Parse FortiGate system status + HA peer REST JSON into device_info + members.

Builds the same device_info shape as the Cisco parsers (so the model layer needs
no vendor-specific logic), and cluster_members for HA pairs (master = the unit
the API connected to; others are slaves). Standalone FortiGate -> no members.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse(evidence_path: str) -> dict | None:
    """Parse FortiGate system identity + HA from a device's evidence directory."""
    evidence_dir = Path(evidence_path)
    status_data = _load_json(evidence_dir / "fortigate_system_status.json")
    if status_data is None:
        return {
            "_source": "fortigate_system_status.json", "_parse_status": "failed",
            "_warnings": ["fortigate_system_status.json not found or empty"],
            "os_family": "fortios", "hostname": None, "version": None,
            "platform": None, "serial": None, "uptime_text": None, "cluster_members": [],
        }

    results = status_data.get("results", {})
    warnings: list[str] = []
    hostname = results.get("hostname")
    version = status_data.get("version")
    serial = status_data.get("serial")

    # Platform: "FortiGate" + "601E" -> "FortiGate-601E".
    model_name = results.get("model_name", "")
    model_number = results.get("model_number", "")
    if model_name and model_number:
        platform = f"{model_name}-{model_number}"
    elif model_name:
        platform = model_name
    else:
        platform = results.get("model")
        if platform:
            warnings.append(f"Using raw model code '{platform}' — model_name not available")

    uptime_text = _calculate_uptime(_load_json(evidence_dir / "fortigate_web_ui_state.json"))

    for field, value in (("hostname", hostname), ("version", version),
                         ("serial", serial), ("platform", platform)):
        if not value:
            warnings.append(f"{field} not found in fortigate_system_status.json")

    device_info: dict[str, Any] = {
        "hostname": hostname, "version": version, "platform": platform, "serial": serial,
        "uptime_text": uptime_text, "os_family": "fortios",
        "_source": "fortigate_system_status.json",
        "_parse_status": "success" if not warnings else "partial",
    }
    if warnings:
        device_info["_warnings"] = warnings

    ha_data = _load_json(evidence_dir / "fortigate_ha_peer.json")
    if ha_data is not None:
        _enrich_ha_info(device_info, ha_data, serial)
        device_info["cluster_members"] = _build_ha_cluster_members(ha_data, serial, platform, version)
    else:
        device_info["cluster_members"] = []
    return device_info


def _calculate_uptime(state_data: dict | None) -> str:
    if not state_data:
        return "not available"
    try:
        results = state_data.get("results", {})
        snapshot_ms = results.get("snapshot_utc_time")
        reboot_ms = results.get("utc_last_reboot")
        if not snapshot_ms or not reboot_ms:
            return "not available"
        uptime_seconds = (int(snapshot_ms) - int(reboot_ms)) // 1000
        if uptime_seconds < 0:
            return "not available"
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        parts = []
        if days:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        return ", ".join(parts) if parts else "less than 1 minute"
    except (TypeError, ValueError, AttributeError):
        return "not available"


def _enrich_ha_info(device_info: dict[str, Any], ha_data: dict[str, Any], own_serial: str | None) -> None:
    peers = ha_data.get("results", [])
    if not isinstance(peers, list) or not peers:
        return
    if len(peers) >= 2:
        device_info["ha_status"] = "active"
        device_info["ha_cluster_size"] = len(peers)
        for peer in peers:
            peer_serial = peer.get("serial_no", "")
            if peer_serial and peer_serial != own_serial:
                device_info["ha_peer_serial"] = peer_serial
                device_info["ha_peer_hostname"] = peer.get("hostname")
                break
    elif len(peers) == 1:
        device_info["ha_status"] = "standalone"


def _build_ha_cluster_members(
    ha_data: dict[str, Any], own_serial: str | None, platform: str | None, version: str | None
) -> list[dict[str, Any]]:
    peers = ha_data.get("results", [])
    if not isinstance(peers, list) or len(peers) < 2:
        return []

    # Dedup by serial (Virtual Cluster HA reports each device once per vcluster).
    seen: dict[str, dict] = {}
    for peer in peers:
        serial = peer.get("serial_no", "")
        if serial not in seen or peer.get("master") or peer.get("primary"):
            seen[serial] = peer
    peers = list(seen.values())

    master: dict[str, Any] | None = None
    slaves: list[dict[str, Any]] = []
    for peer in peers:
        if peer.get("serial_no", "") == own_serial:
            master = peer
        else:
            slaves.append(peer)
    if master is None and peers:
        master, slaves = peers[0], peers[1:]

    members: list[dict[str, Any]] = []
    if master:
        members.append({
            "member_id": 0, "role": "master", "serial_number": master.get("serial_no"),
            "platform": platform, "version": version, "state": "HA synchronized",
            "priority": master.get("priority"), "member_type": "ha_active_passive",
        })
    for idx, slave in enumerate(slaves, start=1):
        members.append({
            "member_id": idx, "role": "slave", "serial_number": slave.get("serial_no"),
            "platform": platform, "version": version, "state": "HA synchronized",
            "priority": slave.get("priority"), "member_type": "ha_active_passive",
        })
    return members


def _load_json(file_path: Path) -> dict | None:
    if not file_path.is_file():
        return None
    try:
        text = file_path.read_text(encoding="utf-8")
        return json.loads(text) if text.strip() else None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load JSON from %s: %s", file_path, exc)
        return None
