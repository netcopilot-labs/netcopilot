"""Parse OpenConfig LLDP NETCONF XML into neighbor records.

Output structure matches the CDP neighbor schema so the model layer treats CDP
and LLDP neighbors uniformly. Disabled/empty LLDP yields an empty list.
"""
from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

NS_LLDP = "http://openconfig.net/yang/lldp"


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return None

    result: dict = {"_source": path.name, "_parse_status": "success", "neighbors": []}
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        result["_parse_status"] = "failed"
        result["_error"] = f"XML parse error: {exc}"
        return result

    lldp_elem = root.find(f".//{{{NS_LLDP}}}lldp")
    if lldp_elem is None:
        return result
    interfaces_elem = lldp_elem.find(f"{{{NS_LLDP}}}interfaces")
    if interfaces_elem is None:
        return result

    for iface_elem in interfaces_elem.findall(f"{{{NS_LLDP}}}interface"):
        name_elem = iface_elem.find(f"{{{NS_LLDP}}}name")
        if name_elem is None or not name_elem.text:
            continue
        local_interface = name_elem.text.strip()
        neighbors_elem = iface_elem.find(f"{{{NS_LLDP}}}neighbors")
        if neighbors_elem is None:
            continue
        for neighbor_elem in neighbors_elem.findall(f"{{{NS_LLDP}}}neighbor"):
            neighbor = _parse_neighbor(neighbor_elem, local_interface)
            if neighbor:
                result["neighbors"].append(neighbor)
    return result


def _parse_neighbor(neighbor_elem: ElementTree.Element, local_interface: str) -> dict | None:
    state_elem = neighbor_elem.find(f"{{{NS_LLDP}}}state")
    if state_elem is None:
        return None
    system_name = _get_text(state_elem, "system-name")
    if not system_name:
        return None
    port_id = _get_text(state_elem, "port-id")
    system_desc = _get_text(state_elem, "system-description")
    hostname = system_name.split(".")[0] if "." in system_name else system_name
    platform = system_desc.split("\n")[0].strip() if system_desc else None
    return {
        "neighbor_hostname": hostname,
        "local_interface": local_interface,
        "neighbor_interface": port_id,
        "neighbor_platform": platform,
        "capability": None,  # not in the basic OpenConfig LLDP model
    }


def _get_text(parent: ElementTree.Element, tag: str) -> str | None:
    elem = parent.find(f"{{{NS_LLDP}}}{tag}")
    if elem is not None and elem.text:
        return elem.text.strip()
    return None
