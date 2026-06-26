"""Parse OpenConfig interfaces RESTCONF JSON into interface records.

Same OpenConfig model as the NETCONF parser, JSON-encoded (RFC 7951). IPv4 lives
under the cross-module ``openconfig-if-ip:ipv4`` key. Output matches the shared
interface schema.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

KEY_INTERFACES = "openconfig-interfaces:interfaces"
KEY_IPV4 = "openconfig-if-ip:ipv4"


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return None

    result: dict = {"_source": path.name, "_parse_status": "success", "interfaces": []}
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        result["_parse_status"] = "failed"
        result["_error"] = f"JSON parse error: {exc}"
        return result

    container = data.get(KEY_INTERFACES, {})
    interface_list = container.get("interface", []) if isinstance(container, dict) else []
    if not isinstance(interface_list, list):
        result["_parse_status"] = "partial"
        result["_warnings"] = ["No interface array found in JSON"]
        return result

    for iface in interface_list:
        if isinstance(iface, dict):
            parsed = _parse_interface(iface)
            if parsed:
                result["interfaces"].append(parsed)
    return result


def _parse_interface(iface: dict[str, Any]) -> dict | None:
    name = iface.get("name")
    if not name:
        return None
    admin_status = oper_status = "unknown"
    state = iface.get("state", {})
    if isinstance(state, dict):
        if state.get("admin-status"):
            admin_status = str(state["admin-status"]).strip().lower()
        if state.get("oper-status"):
            oper_status = str(state["oper-status"]).strip().lower()
    return {
        "name": str(name).strip(),
        "ip_address": _extract_ipv4(iface),
        "status": admin_status,
        "protocol": oper_status,
    }


def _extract_ipv4(iface: dict[str, Any]) -> str:
    subinterfaces = iface.get("subinterfaces", {})
    sub_list = subinterfaces.get("subinterface", []) if isinstance(subinterfaces, dict) else []
    if not isinstance(sub_list, list):
        return "unassigned"
    for sub in sub_list:
        if not isinstance(sub, dict):
            continue
        ipv4 = sub.get(KEY_IPV4, {})
        addresses = ipv4.get("addresses", {}) if isinstance(ipv4, dict) else {}
        addr_list = addresses.get("address", []) if isinstance(addresses, dict) else []
        if not isinstance(addr_list, list):
            continue
        for addr in addr_list:
            if isinstance(addr, dict) and addr.get("ip"):
                return str(addr["ip"]).strip()
    return "unassigned"
