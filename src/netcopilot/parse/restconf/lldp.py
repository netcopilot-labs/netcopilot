"""Parse openconfig-lldp RESTCONF JSON into LLDP neighbor records.

Output matches the CDP neighbor schema so the model layer treats them uniformly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

KEY_LLDP = "openconfig-lldp:lldp"


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return None

    result: dict = {"_source": path.name, "_parse_status": "success", "neighbors": []}
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        result["_parse_status"] = "failed"
        result["_error"] = f"JSON parse error: {exc}"
        return result

    lldp = data.get(KEY_LLDP, {})
    interfaces = lldp.get("interfaces", {}) if isinstance(lldp, dict) else {}
    interface_list = interfaces.get("interface", []) if isinstance(interfaces, dict) else []
    if not isinstance(interface_list, list):
        return result

    for iface in interface_list:
        if not isinstance(iface, dict) or not iface.get("name"):
            continue
        local_interface = str(iface["name"]).strip()
        neighbors = iface.get("neighbors", {})
        neighbor_list = neighbors.get("neighbor", []) if isinstance(neighbors, dict) else []
        if not isinstance(neighbor_list, list):
            continue
        for neighbor in neighbor_list:
            if isinstance(neighbor, dict):
                parsed = _parse_neighbor(neighbor, local_interface)
                if parsed:
                    result["neighbors"].append(parsed)
    return result


def _parse_neighbor(neighbor: dict[str, Any], local_interface: str) -> dict | None:
    state = neighbor.get("state", {})
    if not isinstance(state, dict):
        return None
    system_name = _strip(state.get("system-name"))
    if not system_name:
        return None
    system_desc = _strip(state.get("system-description"))
    return {
        "neighbor_hostname": system_name.split(".")[0] if "." in system_name else system_name,
        "local_interface": local_interface,
        "neighbor_interface": _strip(state.get("port-id")),
        "neighbor_platform": system_desc.split("\n")[0].strip() if system_desc else None,
        "capability": None,
    }


def _strip(value: Any) -> str | None:
    return str(value).strip() if value else None
