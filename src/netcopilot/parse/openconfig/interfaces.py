"""Parse OpenConfig interfaces NETCONF XML into interface records.

OpenConfig is vendor-neutral, so this one parser serves IOS XE, IOS XR (and any
future device speaking the model). Output matches the SSH/text interface schema
so downstream layers are transport-agnostic.
"""
from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

NS_IF = "http://openconfig.net/yang/interfaces"
NS_IP = "http://openconfig.net/yang/interfaces/ip"


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return None

    result: dict = {"_source": path.name, "_parse_status": "success", "interfaces": []}
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        result["_parse_status"] = "failed"
        result["_error"] = f"XML parse error: {exc}"
        return result

    interfaces_elem = root.find(f".//{{{NS_IF}}}interfaces")
    if interfaces_elem is None:
        result["_parse_status"] = "partial"
        result["_warnings"] = ["No <interfaces> element found in XML"]
        return result

    for iface_elem in interfaces_elem.findall(f"{{{NS_IF}}}interface"):
        iface = _parse_interface(iface_elem)
        if iface:
            result["interfaces"].append(iface)
    return result


def _parse_interface(iface_elem: ElementTree.Element) -> dict | None:
    name_elem = iface_elem.find(f"{{{NS_IF}}}name")
    if name_elem is None or not name_elem.text:
        return None
    # OpenConfig admin-status -> status, oper-status -> protocol (matches text schema).
    admin_status = oper_status = "unknown"
    state_elem = iface_elem.find(f"{{{NS_IF}}}state")
    if state_elem is not None:
        admin = state_elem.find(f"{{{NS_IF}}}admin-status")
        if admin is not None and admin.text:
            admin_status = admin.text.strip().lower()
        oper = state_elem.find(f"{{{NS_IF}}}oper-status")
        if oper is not None and oper.text:
            oper_status = oper.text.strip().lower()
    return {
        "name": name_elem.text.strip(),
        "ip_address": _extract_ipv4(iface_elem),
        "status": admin_status,
        "protocol": oper_status,
    }


def _extract_ipv4(iface_elem: ElementTree.Element) -> str:
    """First IPv4 address under subinterfaces, or 'unassigned'."""
    subinterfaces = iface_elem.find(f"{{{NS_IF}}}subinterfaces")
    if subinterfaces is None:
        return "unassigned"
    for sub in subinterfaces.findall(f"{{{NS_IF}}}subinterface"):
        ipv4 = sub.find(f"{{{NS_IP}}}ipv4")
        if ipv4 is None:
            continue
        addresses = ipv4.find(f"{{{NS_IP}}}addresses")
        if addresses is None:
            continue
        for addr in addresses.findall(f"{{{NS_IP}}}address"):
            ip_elem = addr.find(f"{{{NS_IP}}}ip")
            if ip_elem is not None and ip_elem.text:
                return ip_elem.text.strip()
    return "unassigned"
