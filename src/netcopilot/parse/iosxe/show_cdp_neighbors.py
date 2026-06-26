"""Parse ``show cdp neighbors`` (IOS XE) into neighbor records.

Handles both single-line entries and the two-line form where a long device ID
overflows its column onto its own line.
"""
from __future__ import annotations

from pathlib import Path


def parse(filepath: str) -> dict | None:
    """Parse ``show cdp neighbors`` into ``{"neighbors": [...]}``.
    Returns ``None`` if the file is absent."""
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
        if "CDP is not enabled" in content or "Total cdp entries displayed : 0" in content:
            return result  # empty neighbor list is valid
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

    data_lines = lines[header_idx + 1:]
    i = 0
    while i < len(data_lines):
        line = data_lines[i]
        if not line.strip() or line.startswith("Total cdp entries"):
            i += 1
            continue

        # A line starting with a space, or whose local-intf column holds an
        # interface name ("Gi 1/0/1" → contains "/"), is a single-line entry.
        # A non-space line with no "/" there is a long device ID overflowing to
        # its own line, with the data on the next line.
        single_line = line.startswith(" ") or (
            len(line) > cols["local_intf"]
            and "/" in line[cols["local_intf"]:cols["holdtime"]]
        )
        if single_line:
            device_id = _column(line, 0, cols["local_intf"])
            neighbor = _data_line(line, cols, device_id)
            if neighbor:
                result["neighbors"].append(neighbor)
            i += 1
        else:
            device_id = line.strip()
            if i + 1 < len(data_lines):
                neighbor = _data_line(data_lines[i + 1], cols, device_id)
                if neighbor:
                    result["neighbors"].append(neighbor)
                i += 2
            else:
                i += 1
    return result


def _data_line(line: str, cols: dict, device_id: str) -> dict | None:
    if not line.strip():
        return None
    local_intf = _column(line, cols["local_intf"], cols["holdtime"])
    capability = _column(line, cols["capability"], cols["platform"])
    platform = _column(line, cols["platform"], cols["port_id"])
    port_id = _column(line, cols["port_id"], None)
    if not local_intf or not port_id:
        return None
    return {
        "neighbor_hostname": device_id.split(".")[0],  # strip domain suffix
        "local_interface": local_intf,
        "neighbor_interface": port_id,
        "neighbor_platform": platform,
        "capability": capability,
    }


def _column(line: str, start: int, end: int | None) -> str:
    if start < 0 or start >= len(line):
        return ""
    if end is None:
        return line[start:].strip()
    return line[start:end].strip()
