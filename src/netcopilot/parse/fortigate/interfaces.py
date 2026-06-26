"""Parse FortiGate interface config + monitor REST JSON into interface records.

Merges CMDB config (name, IP, type, description) with monitor data (link state).
Emits the canonical interface shape (name/ip_address/status/protocol) plus
FortiGate extras (type, description, port_channel_int for aggregate members).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: FortiGate interface type -> vendor-neutral classification.
FORTIGATE_TYPE_MAP = {
    "physical": "physical", "vlan": "vlan", "aggregate": "aggregate",
    "loopback": "loopback", "tunnel": "tunnel",
    "redundant": "aggregate", "hard-switch": "physical",
}


def parse(evidence_path: str) -> dict | None:
    evidence_dir = Path(evidence_path)
    config_data = _load_json(evidence_dir / "fortigate_system_interface.json")
    if config_data is None:
        return None

    monitor_data = _load_json(evidence_dir / "fortigate_monitor_interface.json")
    monitor_by_name: dict[str, dict] = {}
    if monitor_data:
        results = monitor_data.get("results", {})
        if isinstance(results, dict):
            monitor_by_name = results
        elif isinstance(results, list):
            monitor_by_name = {i.get("name", ""): i for i in results if isinstance(i, dict)}

    config_interfaces = config_data.get("results", [])
    warnings: list[str] = []
    if not isinstance(config_interfaces, list):
        warnings.append("fortigate_system_interface.json 'results' is not a list")
        config_interfaces = []

    # Reverse map: physical member -> aggregate name.
    agg_reverse: dict[str, str] = {}
    for cfg in config_interfaces:
        if isinstance(cfg, dict) and cfg.get("type") == "aggregate":
            agg_name = cfg.get("name", "")
            for member in cfg.get("member", []):
                m_name = member.get("interface-name")
                if m_name and agg_name:
                    agg_reverse[m_name] = agg_name

    interfaces: list[dict[str, Any]] = []
    for iface in config_interfaces:
        if not isinstance(iface, dict):
            continue
        name = iface.get("name", "")
        if not name:
            continue
        intf: dict[str, Any] = {
            "name": name,
            "ip_address": _extract_ip(iface.get("ip", "")),
            "status": _normalize_status(iface.get("status", "")),          # admin
            "protocol": _oper_status(monitor_by_name.get(name, {})),       # oper (link)
            "type": FORTIGATE_TYPE_MAP.get(iface.get("type", ""), "other"),
            "description": iface.get("description", "") or iface.get("alias", ""),
        }
        if name in agg_reverse:
            intf["port_channel_int"] = agg_reverse[name]
        interfaces.append(intf)

    result: dict[str, Any] = {
        "interfaces": interfaces,
        "_source": "fortigate_system_interface.json + fortigate_monitor_interface.json",
        "_parse_status": "success" if not warnings else "partial",
    }
    if warnings:
        result["_warnings"] = warnings
    return result


def _extract_ip(ip_field: Any) -> str | None:
    """FortiGate 'addr mask' -> CIDR. '0.0.0.0 0.0.0.0' -> None."""
    if not ip_field or not isinstance(ip_field, str):
        return None
    parts = ip_field.strip().split()
    if len(parts) != 2:
        return None
    addr, mask = parts
    if addr == "0.0.0.0":
        return None
    prefix = _mask_to_prefix(mask)
    return f"{addr}/{prefix}" if prefix is not None else addr


def _mask_to_prefix(mask: str) -> int | None:
    try:
        octets = mask.split(".")
        if len(octets) != 4:
            return None
        mask_int = 0
        for octet in octets:
            mask_int = (mask_int << 8) | int(octet)
        binary = bin(mask_int)[2:].zfill(32)
        return binary.index("0") if "0" in binary else 32
    except (ValueError, IndexError):
        return None


def _normalize_status(status_value: Any) -> str:
    if not status_value:
        return "unknown"
    normalized = str(status_value).strip().lower()
    return normalized if normalized in ("up", "down") else "unknown"


def _oper_status(monitor_entry: dict) -> str:
    if not monitor_entry:
        return "unknown"
    link = monitor_entry.get("link")
    if link is True:
        return "up"
    if link is False:
        return "down"
    return "unknown"


def _load_json(file_path: Path) -> dict | None:
    if not file_path.is_file():
        return None
    try:
        text = file_path.read_text(encoding="utf-8")
        return json.loads(text) if text.strip() else None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load JSON from %s: %s", file_path, exc)
        return None
