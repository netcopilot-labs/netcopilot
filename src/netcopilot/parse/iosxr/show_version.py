"""Parse ``show version`` (IOS XR) into version/platform/uptime.

IOS XR ``show version`` carries no hostname or serial — hostname comes from the
inventory/manifest and the serial from ``show inventory``.
"""
from __future__ import annotations

import re
from pathlib import Path


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None

    content = path.read_text(encoding="utf-8")
    result: dict = {"_source": path.name, "_parse_status": "success", "os_family": "ios-xr"}
    warnings: list[str] = []

    # "Cisco IOS XR Software, Version 7.11.21" or "Version : 7.11.21"
    version_match = re.search(r"Version\s+[:\s]*(\d+\.\d+\.\d+)", content)
    result["version"] = version_match.group(1) if version_match else None
    if not version_match:
        warnings.append("Could not extract version")

    # "cisco NCS-5500 () processor"
    platform_match = re.search(r"cisco\s+(\S+)\s+.*processor", content, re.IGNORECASE)
    result["platform"] = platform_match.group(1) if platform_match else None
    if not platform_match:
        warnings.append("Could not extract platform")

    uptime_match = re.search(r"System uptime is\s+(.+)$", content, re.MULTILINE)
    result["uptime_text"] = uptime_match.group(1).strip() if uptime_match else None
    if not uptime_match:
        warnings.append("Could not extract uptime")

    result["hostname"] = None  # filled by facts_builder from the manifest
    result["serial"] = None    # comes from show inventory

    if warnings:
        result["_parse_status"] = "partial"
        result["_warnings"] = warnings
    return result
