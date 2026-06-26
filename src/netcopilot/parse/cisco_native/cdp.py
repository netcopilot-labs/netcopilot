"""Parse Cisco-native CDP operational NETCONF XML into neighbor records.

IOS XE and IOS XR use different CDP YANG models (flat vs node-nested), so each
has its own entry point. Output matches the SSH CDP neighbor schema.
"""
from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

NS_XE_CDP = "http://cisco.com/ns/yang/Cisco-IOS-XE-cdp-oper"
NS_XR_CDP = "http://cisco.com/ns/yang/Cisco-IOS-XR-cdp-oper"


def _load(filepath: str) -> tuple[ElementTree.Element | None, dict]:
    path = Path(filepath)
    result: dict = {"_source": path.name, "_parse_status": "success", "neighbors": []}
    if not path.is_file():
        return None, result
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return None, result
    try:
        return ElementTree.fromstring(content), result
    except ElementTree.ParseError as exc:
        result["_parse_status"] = "failed"
        result["_error"] = f"XML parse error: {exc}"
        return None, result


def parse_iosxe(filepath: str) -> dict | None:
    """IOS XE: flat <cdp-neighbor-detail> list under <cdp-neighbor-details>."""
    if not Path(filepath).is_file():
        return None
    root, result = _load(filepath)
    if root is None:
        return result
    details = root.find(f".//{{{NS_XE_CDP}}}cdp-neighbor-details")
    if details is None:
        return result
    for detail in details.findall(f"{{{NS_XE_CDP}}}cdp-neighbor-detail"):
        neighbor = _xe_neighbor(detail)
        if neighbor:
            result["neighbors"].append(neighbor)
    return result


def parse_iosxr(filepath: str) -> dict | None:
    """IOS XR: per-node <neighbors>/<details>/<detail> (one node per line card)."""
    if not Path(filepath).is_file():
        return None
    root, result = _load(filepath)
    if root is None:
        return result
    for node in root.iter(f"{{{NS_XR_CDP}}}node"):
        neighbors = node.find(f"{{{NS_XR_CDP}}}neighbors")
        if neighbors is None:
            continue
        details = neighbors.find(f"{{{NS_XR_CDP}}}details")
        if details is None:
            continue
        for detail in details.findall(f"{{{NS_XR_CDP}}}detail"):
            neighbor = _xr_neighbor(detail)
            if neighbor:
                result["neighbors"].append(neighbor)
    return result


def _xe_neighbor(detail: ElementTree.Element) -> dict | None:
    device_name = _text(detail, f"{{{NS_XE_CDP}}}device-name")
    if not device_name:
        return None
    return {
        "neighbor_hostname": device_name.split(".")[0] if "." in device_name else device_name,
        "local_interface": _text(detail, f"{{{NS_XE_CDP}}}local-intf-name"),
        "neighbor_interface": _text(detail, f"{{{NS_XE_CDP}}}port-id"),
        "neighbor_platform": _text(detail, f"{{{NS_XE_CDP}}}platform-name"),
        "capability": _text(detail, f"{{{NS_XE_CDP}}}capability"),
    }


def _xr_neighbor(detail: ElementTree.Element) -> dict | None:
    local_intf = _text(detail, f"{{{NS_XR_CDP}}}interface-name")
    cdp_neighbor = detail.find(f"{{{NS_XR_CDP}}}cdp-neighbor")
    if cdp_neighbor is None:
        return None
    device_id = _text(cdp_neighbor, f"{{{NS_XR_CDP}}}device-id")
    if not device_id:
        return None
    return {
        "neighbor_hostname": device_id.split(".")[0] if "." in device_id else device_id,
        "local_interface": local_intf,
        "neighbor_interface": _text(cdp_neighbor, f"{{{NS_XR_CDP}}}port-id"),
        "neighbor_platform": _text(cdp_neighbor, f"{{{NS_XR_CDP}}}platform"),
        "capability": _text(cdp_neighbor, f"{{{NS_XR_CDP}}}capabilities"),
    }


def _text(parent: ElementTree.Element, tag: str) -> str | None:
    elem = parent.find(tag)
    if elem is not None and elem.text:
        return elem.text.strip()
    return None
