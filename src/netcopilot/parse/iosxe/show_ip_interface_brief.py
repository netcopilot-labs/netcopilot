"""Parse ``show ip interface brief`` (IOS XE) into interface records."""
from __future__ import annotations

from pathlib import Path


def parse(filepath: str) -> dict | None:
    """Parse ``show ip interface brief`` into ``{"interfaces": [...]}``.
    Returns ``None`` if the file is absent."""
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
        "ok": header.find("OK?"),
        "status": header.find("Status"),
        "protocol": header.find("Protocol"),
    }

    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        interface = _column(line, cols["interface"], cols["ip_address"])
        if interface:
            result["interfaces"].append({
                "name": interface,
                "ip_address": _column(line, cols["ip_address"], cols["ok"]),
                "status": _column(line, cols["status"], cols["protocol"]),
                "protocol": _column(line, cols["protocol"], None),
            })
    return result


def _column(line: str, start: int, end: int | None) -> str:
    """Slice a fixed-width column out of ``line``.

    e.g. for "Vlan10  192.0.2.1  YES NVRAM up up", _column(line, 0, 8) -> "Vlan10".
    """
    if start < 0:
        return ""
    if end is None:
        return line[start:].strip()
    return line[start:end].strip()
