"""Parse Cisco-native system RESTCONF JSON into device_info + cluster_members.

Same YANG models as the NETCONF system parser, JSON-encoded (RFC 7951). IOS-XE
only. RESTCONF does not collect stack-oper data, so stack members carry serial +
platform but no role/priority/state.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEY_NATIVE = "Cisco-IOS-XE-native:native"
KEY_HW_DATA = "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"


def parse(device_dir: str) -> dict | None:
    path = Path(device_dir)
    native_file = path / "restconf_native.json"
    hardware_file = path / "restconf_device_hardware.json"
    if not native_file.is_file():
        return None

    sources: list[str] = []
    warnings: list[str] = []
    result: dict = {
        "_parse_status": "success", "os_family": "ios-xe",
        "hostname": None, "version": None, "platform": None,
        "serial": None, "uptime_text": None,
    }

    _parse_native(native_file, result, sources, warnings)

    chassis_members: list[dict[str, Any]] = []
    if hardware_file.is_file():
        chassis_members = _parse_hardware(hardware_file, result, sources, warnings)
    else:
        warnings.append("restconf_device_hardware.json not found")

    result["cluster_members"] = _build_cluster_members(chassis_members, result.get("version"))
    result["_source"] = "+".join(sources) if sources else "restconf_native.json"
    if warnings:
        result["_parse_status"] = "partial"
        result["_warnings"] = warnings
    return result


def _parse_native(filepath: Path, result: dict, sources: list[str], warnings: list[str]) -> None:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        warnings.append("restconf_native.json is empty")
        return
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        warnings.append(f"restconf_native.json JSON parse error: {exc}")
        return
    sources.append("restconf_native.json")
    native = data.get(KEY_NATIVE, {})
    if not isinstance(native, dict):
        warnings.append("restconf_native.json: unexpected structure")
        return
    if native.get("hostname"):
        result["hostname"] = str(native["hostname"]).strip()
    if native.get("version"):
        result["version"] = str(native["version"]).strip()  # major.minor fallback


def _parse_hardware(filepath: Path, result: dict, sources: list[str], warnings: list[str]) -> list[dict[str, Any]]:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        warnings.append("restconf_device_hardware.json is empty")
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        warnings.append(f"restconf_device_hardware.json JSON parse error: {exc}")
        return []
    sources.append("restconf_device_hardware.json")

    device_hw = data.get(KEY_HW_DATA, {})
    device_hw = device_hw.get("device-hardware", {}) if isinstance(device_hw, dict) else {}
    if not isinstance(device_hw, dict):
        warnings.append("restconf_device_hardware.json: unexpected structure")
        return []

    inventory_list = device_hw.get("device-inventory", [])
    if not isinstance(inventory_list, list):
        inventory_list = []

    chassis_members: list[dict[str, Any]] = []
    first_chassis = True
    for inv in inventory_list:
        if not isinstance(inv, dict) or inv.get("hw-type") != "hw-type-chassis":
            continue
        part_number = _strip(inv.get("part-number"))
        serial_number = _strip(inv.get("serial-number"))
        chassis_members.append({
            "member_number": _extract_member_number(_strip(inv.get("dev-name"))),
            "serial": serial_number,
            "platform": part_number,
        })
        if first_chassis:
            if part_number:
                result["platform"] = part_number
            if serial_number:
                result["serial"] = serial_number
            first_chassis = False

    system_data = device_hw.get("device-system-data", {})
    if isinstance(system_data, dict):
        sw_version = system_data.get("software-version", "")
        if sw_version:
            match = re.search(r"Version\s+([\d.]+)", str(sw_version))
            if match:
                result["version"] = match.group(1)
        boot_time = system_data.get("boot-time", "")
        if boot_time:
            try:
                boot_dt = datetime.fromisoformat(str(boot_time).strip())
                delta = int((datetime.now(timezone.utc) - boot_dt).total_seconds())
                if delta >= 0:
                    result["uptime_text"] = _format_uptime(delta)
            except (ValueError, OSError):
                warnings.append("Could not parse boot-time for uptime calculation")
    return chassis_members


def _build_cluster_members(chassis_members: list[dict[str, Any]], device_version: str | None) -> list[dict[str, Any]]:
    if len(chassis_members) < 2:
        return []
    members = []
    for chassis in chassis_members:
        member_number = chassis.get("member_number")
        if member_number is None:
            continue
        members.append({
            "member_id": member_number,
            "role": None,  # RESTCONF has no stack-oper data
            "serial_number": chassis.get("serial"),
            "platform": chassis.get("platform"),
            "version": device_version,
            "state": None,
            "priority": None,
            "member_type": "stackwise",
        })
    members.sort(key=lambda m: m["member_id"])
    return members


def _strip(value: Any) -> str | None:
    return str(value).strip() if value else None


def _extract_member_number(dev_name: str | None) -> int | None:
    if not dev_name:
        return None
    match = re.match(r"Switch\s+(\d+)", dev_name)
    return int(match.group(1)) if match else None


def _format_uptime(total_seconds: int) -> str:
    weeks, rem = divmod(total_seconds, 604800)
    days, rem = divmod(rem, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if weeks:
        parts.append(f"{weeks} week{'s' if weeks != 1 else ''}")
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes or not parts:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return ", ".join(parts)
