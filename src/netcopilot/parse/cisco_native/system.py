"""Parse Cisco-native system NETCONF XML into device_info + cluster_members.

IOS XE combines native (hostname/version) + device-hardware (platform/serial/
uptime + per-chassis inventory) + stack-oper (per-member role/state/priority),
merged into cluster_members for stacks. IOS XR splits system info across four
single-purpose YANG files and is always standalone (no stack members).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

NS_XE_NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
NS_XE_HW_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper"
NS_XE_STACK_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-stack-oper"
NS_XR_SHELLUTIL_CFG = "http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-cfg"
NS_XR_INSTALL_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XR-install-oper"
NS_XR_SHELLUTIL_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-oper"
NS_XR_INVMGR_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XR-plat-chas-invmgr-ng-oper"


def parse_iosxe(device_dir: str) -> dict | None:
    """Parse IOS XE system + hardware + stack-oper XML from a device directory."""
    path = Path(device_dir)
    system_file = path / "netconf_system.xml"
    hardware_file = path / "netconf_device_hardware.xml"
    stack_oper_file = path / "netconf_stack_oper.xml"
    if not system_file.is_file():
        return None

    sources: list[str] = []
    warnings: list[str] = []
    result: dict = {
        "_parse_status": "success", "os_family": "ios-xe",
        "hostname": None, "version": None, "platform": None,
        "serial": None, "uptime_text": None,
    }

    _parse_xe_system(system_file, result, sources, warnings)

    chassis_members: list[dict[str, Any]] = []
    if hardware_file.is_file():
        chassis_members = _parse_xe_hardware(hardware_file, result, sources, warnings)
    else:
        warnings.append("netconf_device_hardware.xml not found")

    stack_oper: dict[int, dict[str, Any]] = {}
    if stack_oper_file.is_file():
        stack_oper = _parse_xe_stack_oper(stack_oper_file, sources, warnings)

    result["cluster_members"] = _build_cluster_members(
        chassis_members, stack_oper, result.get("version")
    )
    result["_source"] = "+".join(sources) if sources else "netconf_system.xml"
    if warnings:
        result["_parse_status"] = "partial"
        result["_warnings"] = warnings
    return result


def parse_iosxr(device_dir: str) -> dict | None:
    """Parse IOS XR system info from its four single-purpose YANG files."""
    path = Path(device_dir)
    files = {
        "hostname": path / "netconf_system_hostname.xml",
        "version": path / "netconf_system_version.xml",
        "uptime": path / "netconf_system_uptime.xml",
        "platform": path / "netconf_system_platform.xml",
    }
    if not any(f.is_file() for f in files.values()):
        return None

    sources: list[str] = []
    warnings: list[str] = []
    result: dict = {
        "_parse_status": "success", "os_family": "ios-xr",
        "hostname": None, "version": None, "platform": None,
        "serial": None, "uptime_text": None,
    }

    if files["hostname"].is_file():
        _parse_xr_hostname(files["hostname"], result, sources)
    else:
        warnings.append("netconf_system_hostname.xml not found")
    if files["version"].is_file():
        _parse_xr_version(files["version"], result, sources)
    else:
        warnings.append("netconf_system_version.xml not found")
    if files["uptime"].is_file():
        _parse_xr_uptime(files["uptime"], result, sources)
    else:
        warnings.append("netconf_system_uptime.xml not found")
    if files["platform"].is_file():
        _parse_xr_platform(files["platform"], result, sources)
    else:
        warnings.append("netconf_system_platform.xml not found")

    result["cluster_members"] = []  # IOS XR is standalone
    result["_source"] = "+".join(sources) if sources else "netconf_system_*.xml"
    if warnings:
        result["_parse_status"] = "partial"
        result["_warnings"] = warnings
    return result


# ----------------------------- IOS XE ------------------------------------

def _parse_xe_system(filepath: Path, result: dict, sources: list[str], warnings: list[str]) -> None:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        warnings.append("netconf_system.xml is empty")
        return
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        warnings.append(f"netconf_system.xml XML parse error: {exc}")
        return
    sources.append("netconf_system.xml")
    hostname_elem = root.find(f".//{{{NS_XE_NATIVE}}}hostname")
    if hostname_elem is not None and hostname_elem.text:
        result["hostname"] = hostname_elem.text.strip()
    version_elem = root.find(f".//{{{NS_XE_NATIVE}}}version")  # major.minor fallback
    if version_elem is not None and version_elem.text:
        result["version"] = version_elem.text.strip()


def _parse_xe_hardware(filepath: Path, result: dict, sources: list[str], warnings: list[str]) -> list[dict[str, Any]]:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        warnings.append("netconf_device_hardware.xml is empty")
        return []
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        warnings.append(f"netconf_device_hardware.xml XML parse error: {exc}")
        return []
    sources.append("netconf_device_hardware.xml")

    chassis_members: list[dict[str, Any]] = []
    first_chassis = True
    for inv in root.iter(f"{{{NS_XE_HW_OPER}}}device-inventory"):
        hw_type = inv.find(f"{{{NS_XE_HW_OPER}}}hw-type")
        if hw_type is None or hw_type.text != "hw-type-chassis":
            continue
        part_number = _text(inv, f"{{{NS_XE_HW_OPER}}}part-number")
        serial_number = _text(inv, f"{{{NS_XE_HW_OPER}}}serial-number")
        dev_name = _text(inv, f"{{{NS_XE_HW_OPER}}}dev-name")
        chassis_members.append({
            "member_number": _extract_member_number(dev_name),
            "serial": serial_number,
            "platform": part_number,
        })
        if first_chassis:
            if part_number:
                result["platform"] = part_number
            if serial_number:
                result["serial"] = serial_number
            first_chassis = False

    # Full version (with patch) from the software-version string.
    sw_version = root.find(f".//{{{NS_XE_HW_OPER}}}software-version")
    if sw_version is not None and sw_version.text:
        match = re.search(r"Version\s+([\d.]+)", sw_version.text)
        if match:
            result["version"] = match.group(1)

    # Uptime from boot-time (ISO 8601).
    boot_time = root.find(f".//{{{NS_XE_HW_OPER}}}boot-time")
    if boot_time is not None and boot_time.text:
        try:
            boot_dt = datetime.fromisoformat(boot_time.text.strip())
            delta = int((datetime.now(timezone.utc) - boot_dt).total_seconds())
            if delta >= 0:
                result["uptime_text"] = _format_uptime(delta)
        except (ValueError, OSError):
            warnings.append("Could not parse boot-time for uptime calculation")
    return chassis_members


def _parse_xe_stack_oper(filepath: Path, sources: list[str], warnings: list[str]) -> dict[int, dict[str, Any]]:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        return {}
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        warnings.append(f"netconf_stack_oper.xml XML parse error: {exc}")
        return {}
    sources.append("netconf_stack_oper.xml")

    members: dict[int, dict[str, Any]] = {}
    for node in root.iter(f"{{{NS_XE_STACK_OPER}}}stack-node"):
        chassis = node.find(f"{{{NS_XE_STACK_OPER}}}chassis-number")
        if chassis is None or not chassis.text:
            continue
        try:
            chassis_number = int(chassis.text.strip())
        except ValueError:
            continue
        priority_raw = node.findtext(f"{{{NS_XE_STACK_OPER}}}priority", "")
        try:
            priority = int(priority_raw) if priority_raw else None
        except ValueError:
            priority = None
        members[chassis_number] = {
            "role": _normalize_stack_role(node.findtext(f"{{{NS_XE_STACK_OPER}}}role", "")),
            "state": _normalize_stack_state(node.findtext(f"{{{NS_XE_STACK_OPER}}}node-state", "")),
            "priority": priority,
        }
    return members


def _build_cluster_members(
    chassis_members: list[dict[str, Any]],
    stack_oper: dict[int, dict[str, Any]],
    device_version: str | None,
) -> list[dict[str, Any]]:
    """Merge chassis (serial/platform) + stack-oper (role/state/priority) by member number."""
    if len(chassis_members) < 2:  # 0/1 chassis -> standalone, not a stack
        return []
    members: list[dict[str, Any]] = []
    for chassis in chassis_members:
        member_number = chassis.get("member_number")
        if member_number is None:
            continue
        oper = stack_oper.get(member_number, {})
        members.append({
            "member_id": member_number,
            "role": oper.get("role"),
            "serial_number": chassis.get("serial"),
            "platform": chassis.get("platform"),
            "version": device_version,  # shared image across the stack
            "state": oper.get("state"),
            "priority": oper.get("priority"),
            "member_type": "stackwise",
        })
    members.sort(key=lambda m: m["member_id"])
    return members


def _extract_member_number(dev_name: str | None) -> int | None:
    """'Switch 1' / 'Switch 2 Chassis' -> the 1-based member number."""
    if not dev_name:
        return None
    match = re.match(r"Switch\s+(\d+)", dev_name)
    return int(match.group(1)) if match else None


def _normalize_stack_role(role_raw: str) -> str | None:
    if not role_raw:
        return None
    return {"role-active": "Active", "role-standby": "Standby", "role-member": "Member"}.get(role_raw, role_raw)


def _normalize_stack_state(state_raw: str) -> str | None:
    if not state_raw:
        return None
    return {
        "state-ready": "Ready", "state-initializing": "Initializing",
        "state-ver-mismatch": "Version Mismatch", "state-progressing": "Progressing",
        "state-provisioned": "Provisioned", "state-invalid": "Invalid", "state-removed": "Removed",
    }.get(state_raw, state_raw)


# ----------------------------- IOS XR ------------------------------------

def _parse_xr_hostname(filepath: Path, result: dict, sources: list[str]) -> None:
    root = _xr_root(filepath)
    if root is None:
        return
    sources.append("netconf_system_hostname.xml")
    elem = root.find(f".//{{{NS_XR_SHELLUTIL_CFG}}}host-name")
    if elem is not None and elem.text:
        result["hostname"] = elem.text.strip()


def _parse_xr_version(filepath: Path, result: dict, sources: list[str]) -> None:
    root = _xr_root(filepath)
    if root is None:
        return
    sources.append("netconf_system_version.xml")
    elem = root.find(f".//{{{NS_XR_INSTALL_OPER}}}label")
    if elem is not None and elem.text:
        result["version"] = elem.text.strip()


def _parse_xr_uptime(filepath: Path, result: dict, sources: list[str]) -> None:
    root = _xr_root(filepath)
    if root is None:
        return
    sources.append("netconf_system_uptime.xml")
    for elem in root.iter(f"{{{NS_XR_SHELLUTIL_OPER}}}uptime"):
        if elem.text and elem.text.strip().isdigit():
            result["uptime_text"] = _format_uptime(int(elem.text.strip()))
            break


def _parse_xr_platform(filepath: Path, result: dict, sources: list[str]) -> None:
    root = _xr_root(filepath)
    if root is None:
        return
    sources.append("netconf_system_platform.xml")
    model = root.find(f".//{{{NS_XR_INVMGR_OPER}}}model-name")
    if model is not None and model.text:
        result["platform"] = model.text.strip()
    serial = root.find(f".//{{{NS_XR_INVMGR_OPER}}}serial-number")
    if serial is not None and serial.text:
        result["serial"] = serial.text.strip()


def _xr_root(filepath: Path) -> ElementTree.Element | None:
    content = filepath.read_text(encoding="utf-8")
    if not content.strip():
        return None
    try:
        return ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return None


# ------------------------------ shared -----------------------------------

def _text(parent: ElementTree.Element, tag: str) -> str | None:
    elem = parent.find(tag)
    if elem is not None and elem.text:
        return elem.text.strip()
    return None


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
