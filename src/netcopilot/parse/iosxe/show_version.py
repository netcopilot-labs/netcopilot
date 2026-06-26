"""Parse ``show version`` (IOS XE) into device_info + stack/SVL members."""
from __future__ import annotations

import re
from pathlib import Path


def parse(filepath: str) -> dict | None:
    """Parse ``show version`` text into a device_info dict (+ cluster_members
    for stacks/SVL). Returns ``None`` if the file is absent."""
    path = Path(filepath)
    if not path.is_file():
        return None

    content = path.read_text(encoding="utf-8")
    result: dict = {"_source": path.name, "_parse_status": "success", "os_family": "ios-xe"}
    warnings: list[str] = []

    # Hostname + uptime, e.g. "core-rtr-01 uptime is 31 weeks, 6 days"
    hostname_match = re.search(r"^(\S+)\s+uptime is\s+(.+)$", content, re.MULTILINE)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)
        result["uptime_text"] = hostname_match.group(2).strip()
    else:
        result["hostname"] = None
        result["uptime_text"] = None
        warnings.append("Could not extract hostname/uptime")

    # Version, e.g. "Cisco IOS XE Software, Version 17.12.05"
    version_match = re.search(r"Version\s+(\S+)", content)
    result["version"] = version_match.group(1).rstrip(",") if version_match else None
    if not version_match:
        warnings.append("Could not extract version")

    # Platform, e.g. "Model Number : C9500-32C"
    platform_match = re.search(r"Model Number\s*:\s*(\S+)", content)
    result["platform"] = platform_match.group(1) if platform_match else None
    if not platform_match:
        warnings.append("Could not extract platform")

    # Serial, e.g. "System Serial Number : FXX1234X5YZ"
    serial_match = re.search(r"System Serial Number\s*:\s*(\S+)", content)
    result["serial"] = serial_match.group(1) if serial_match else None
    if not serial_match:
        warnings.append("Could not extract serial")

    # --- Stack / SVL members from "Switch NN" sections ---------------------
    # C9500 SVL and C9300 stacks append "Switch NN" blocks, each with its own
    # Model Number / System Serial Number. A "Switch Ports Model" table marks
    # the active member with a leading "*"; otherwise member 1 is active.
    cluster_members: list[dict] = []
    active_member_id = 1
    is_svl = "C9500" in (result.get("platform") or "")
    member_type = "stackwise_virtual" if is_svl else "stackwise"

    table_rows = re.findall(
        r"^(\*?)\s+(\d+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s*$", content, re.MULTILINE
    )
    for star, num_str, _model in table_rows:
        if star == "*":
            active_member_id = int(num_str)

    switch_sections = re.split(r"^Switch\s+(\d+)\s*\n-{3,}", content, flags=re.MULTILINE)
    preamble = switch_sections[0] if switch_sections else ""
    m_active_mac = re.search(r"Base Ethernet MAC Address\s*:\s*(\S+)", preamble)
    active_mac = m_active_mac.group(1).lower() if m_active_mac else None
    if active_mac:
        result["mac_address"] = active_mac

    section_members: dict[int, dict] = {}
    for i in range(1, len(switch_sections), 2):
        if i + 1 >= len(switch_sections):
            break
        member_id = int(switch_sections[i])
        body = switch_sections[i + 1]
        m_model = re.search(r"Model Number\s*:\s*(\S+)", body)
        m_serial = re.search(r"System Serial Number\s*:\s*(\S+)", body)
        m_mac = re.search(r"Base Ethernet MAC Address\s*:\s*(\S+)", body)
        section_members[member_id] = {
            "serial": m_serial.group(1) if m_serial else None,
            "platform": m_model.group(1) if m_model else None,
            "mac": m_mac.group(1).lower() if m_mac else None,
        }

    if section_members:
        cluster_members.append({
            "member_id": active_member_id, "role": "active",
            "serial_number": result.get("serial"), "platform": result.get("platform"),
            "version": result.get("version"), "state": "ready",
            "member_type": member_type, "mac_address": active_mac,
        })
        for mid, info in sorted(section_members.items()):
            if info["serial"] == result.get("serial"):
                continue
            cluster_members.append({
                "member_id": mid, "role": "standby" if is_svl else "member",
                "serial_number": info["serial"],
                "platform": info["platform"] or result.get("platform"),
                "version": result.get("version"), "state": "ready",
                "member_type": member_type, "mac_address": info["mac"],
            })

    if cluster_members:
        result["cluster_members"] = cluster_members

    if warnings:
        result["_parse_status"] = "partial"
        result["_warnings"] = warnings
    return result
