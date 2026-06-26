"""Parse ``show cdp neighbors`` (IOS XR) into neighbor records.

IOS XR uses a single-line format; device IDs may be truncated with a trailing dot.
"""
from __future__ import annotations

from pathlib import Path


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    result: dict = {"_source": path.name, "_parse_status": "success", "neighbors": []}

    header_idx = next(
        (i for i, ln in enumerate(lines) if "Device ID" in ln and "Local Intrfce" in ln),
        None,
    )
    if header_idx is None:
        if "CDP is not enabled" in content:
            return result
        result["_parse_status"] = "partial"
        result["_warnings"] = ["Could not find CDP header"]
        return result

    header = lines[header_idx]
    cols = {
        "device_id": 0,
        "local_intf": header.find("Local Intrfce"),
        "holdtime": header.find("Holdtme"),
        "capability": header.find("Capability"),
        "platform": header.find("Platform"),
        "port_id": header.find("Port ID"),
    }

    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        device_id = _column(line, cols["device_id"], cols["local_intf"])
        local_intf = _column(line, cols["local_intf"], cols["holdtime"])
        if not device_id or not local_intf:
            continue
        hostname = device_id.rstrip(".")        # strip truncation dot
        if "." in hostname:
            hostname = hostname.split(".")[0]    # strip domain suffix
        result["neighbors"].append({
            "neighbor_hostname": hostname,
            "local_interface": local_intf,
            "neighbor_interface": _column(line, cols["port_id"], None),
            "neighbor_platform": _column(line, cols["platform"], cols["port_id"]),
            "capability": _column(line, cols["capability"], cols["platform"]),
        })
    return result


def _column(line: str, start: int, end: int | None) -> str:
    if start < 0 or start >= len(line):
        return ""
    if end is None or end < 0:
        return line[start:].strip()
    return line[start:end].strip()
