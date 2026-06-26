"""Parse Cisco-IOS-XE-cdp-oper RESTCONF JSON into CDP neighbor records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

KEY_CDP_DETAILS = "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"


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

    container = data.get(KEY_CDP_DETAILS, {})
    neighbor_list = container.get("cdp-neighbor-detail", []) if isinstance(container, dict) else []
    if not isinstance(neighbor_list, list):
        return result

    for detail in neighbor_list:
        if isinstance(detail, dict):
            neighbor = _parse_neighbor(detail)
            if neighbor:
                result["neighbors"].append(neighbor)
    return result


def _parse_neighbor(detail: dict[str, Any]) -> dict | None:
    device_name = _strip(detail.get("device-name"))
    if not device_name:
        return None
    return {
        "neighbor_hostname": device_name.split(".")[0] if "." in device_name else device_name,
        "local_interface": _strip(detail.get("local-intf-name")),
        "neighbor_interface": _strip(detail.get("port-id")),
        "neighbor_platform": _strip(detail.get("platform-name")),
        "capability": _strip(detail.get("capability")),
    }


def _strip(value: Any) -> str | None:
    return str(value).strip() if value else None
