"""Parse ``show ipv4 interface brief`` (IOS XR) into interface records.

IOS XR's layout differs from IOS XE: no OK?/Method columns, a Vrf-Name column,
and "Shutdown" rather than "administratively down".
"""
from __future__ import annotations

from pathlib import Path


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None

    lines = path.read_text(encoding="utf-8").splitlines()
    result: dict = {"_source": path.name, "_parse_status": "success", "interfaces": []}

    header_idx = next(
        (i for i, ln in enumerate(lines) if ln.startswith("Interface") and "IP-Address" in ln),
        None,
    )
    if header_idx is None:
        result["_parse_status"] = "failed"
        result["_error"] = "Could not find header line"
        return result

    header = lines[header_idx]
    cols = {
        "interface": 0,
        "ip_address": header.find("IP-Address"),
        "status": header.find("Status"),
        "protocol": header.find("Protocol"),
        "vrf": header.find("Vrf-Name"),
    }

    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        interface = _column(line, cols["interface"], cols["ip_address"])
        if interface:
            result["interfaces"].append({
                "name": interface,
                "ip_address": _column(line, cols["ip_address"], cols["status"]),
                "status": _column(line, cols["status"], cols["protocol"]),
                "protocol": _column(line, cols["protocol"], cols["vrf"]),
            })
    return result


def _column(line: str, start: int, end: int | None) -> str:
    if start < 0 or start >= len(line):
        return ""
    if end is None or end < 0:
        return line[start:].strip()
    return line[start:end].strip()
