"""
Stack Port Parser — normalize Genie stack data into a unified stack_ports schema.

Parses collected Genie output from:
  - C9300 ``show switch stack-ports summary`` → genie_stack_ports.json
  - C9500 ``show stackwise-virtual link`` → genie_svl_link.json
  - C9500 ``show stackwise-virtual dual-active-detection`` → genie_svl_dad.json

into a unified ``stack_ports[]`` array per device.

Unified Schema:

    C9300 cable entry::
        {"member_id": 1, "port_id": 1, "port_type": "cable", "status": "OK",
         "neighbor_member": 2, "cable_length": "50cm", "link_ok": true,
         "link_active": true, "sync_ok": true}

    C9500 SVL entry::
        {"member_id": 1, "port_type": "svl", "svl_id": 1,
         "interface": "HundredGigE1/0/25", "link_status": "Up",
         "protocol_status": "Ready"}

    C9500 DAD entry::
        {"member_id": 1, "port_type": "dad", "interface": "TwentyFiveGigE1/0/1",
         "link_status": "Up", "protocol_status": "Ready"}
"""

import logging
from typing import Any

log = logging.getLogger(__name__)


def parse_stack_ports(facts_dir_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse stack port data from Genie facts into a unified stack_ports list.

    Detects which stack data is available (C9300 vs C9500 SVL) and normalizes
    into the unified schema. Returns an empty list for non-stack devices.

    Args:
        facts_dir_data: The per-device facts dict containing a "genie" sub-dict
                        with stack_ports, svl_link, svl_dad, etc.

    Returns:
        List of normalized stack port entries, or an empty list.
    """
    genie = facts_dir_data.get("genie") or {}
    stack_ports: list[dict[str, Any]] = []

    # C9500 SVL takes priority (if present, device is SVL — not traditional)
    svl_link = genie.get("svl_link")
    if svl_link and isinstance(svl_link, dict):
        stack_ports.extend(_parse_svl_link(svl_link))
        # Also parse DAD if available
        svl_dad = genie.get("svl_dad")
        if svl_dad and isinstance(svl_dad, dict):
            stack_ports.extend(_parse_svl_dad(svl_dad))
        return stack_ports

    # C9300 traditional stack ports
    raw_stack = genie.get("stack_ports")
    if raw_stack and isinstance(raw_stack, dict):
        stack_ports.extend(_parse_c9300_stack_ports(raw_stack))

    return stack_ports


def _parse_c9300_stack_ports(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse C9300 Genie ShowSwitchStackPortsSummary output.

    Genie schema::
        {"stackports": {"1/1": {"stackport_id": "1/1", "port_status": "OK",
         "neighbor": 2 or "2/2", "cable_length": "50cm", ...}}}
    """
    result: list[dict[str, Any]] = []
    stackports = data.get("stackports", {})

    for port_key, port_data in stackports.items():
        # port_key is "member/port" e.g. "1/1", "2/1"
        parts = port_key.split("/")
        member_id = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
        port_id = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        # neighbor can be int (base parser) or str like "2/2" (C9300 parser)
        neighbor_raw = port_data.get("neighbor", 0)
        if isinstance(neighbor_raw, int):
            neighbor_member = neighbor_raw
        elif isinstance(neighbor_raw, str):
            # "2/2" → member 2, "NONE/NONE" → 0
            neighbor_parts = neighbor_raw.split("/")
            neighbor_member = (
                int(neighbor_parts[0])
                if neighbor_parts[0].isdigit()
                else 0
            )
        else:
            neighbor_member = 0

        entry = {
            "member_id": member_id,
            "port_id": port_id,
            "port_type": "cable",
            "status": port_data.get("port_status", "Unknown"),
            "neighbor_member": neighbor_member,
            "cable_length": port_data.get("cable_length", ""),
            "link_ok": port_data.get("link_ok", "No") == "Yes",
            "link_active": port_data.get("link_active", "No") == "Yes",
            "sync_ok": port_data.get("sync_ok", "No") == "Yes",
        }
        result.append(entry)

    return result


# SVL status code → human-readable mapping
_SVL_LINK_STATUS = {"U": "Up", "D": "Down"}
_SVL_PROTOCOL_STATUS = {"P": "Ready", "S": "Suspended"}


def _parse_svl_link(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse C9500 Genie ShowStackwiseVirtualLink output.

    Genie schema::
        {"switch": {1: {"svl": {1: {"ports": {"HundredGigE1/0/1":
         {"link_status": "U", "protocol_status": "P"}}}}}}}
    """
    result: list[dict[str, Any]] = []
    switches = data.get("switch", {})

    for switch_id, switch_data in switches.items():
        member_id = int(switch_id) if str(switch_id).isdigit() else 0
        svl_dict = switch_data.get("svl", {})

        for svl_id, svl_data in svl_dict.items():
            ports = svl_data.get("ports", {})
            for intf_name, port_data in ports.items():
                link_raw = port_data.get("link_status", "")
                proto_raw = port_data.get("protocol_status", "")
                entry = {
                    "member_id": member_id,
                    "port_type": "svl",
                    "svl_id": int(svl_id) if str(svl_id).isdigit() else 0,
                    "interface": intf_name,
                    "link_status": _SVL_LINK_STATUS.get(link_raw, link_raw),
                    "protocol_status": _SVL_PROTOCOL_STATUS.get(proto_raw, proto_raw),
                }
                result.append(entry)

    return result


def _parse_svl_dad(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse C9500 Genie ShowStackwiseVirtualDualActiveDetection output.

    The DAD parser output structure varies by Genie version. We handle the
    common format: per-switch, per-link entries with interface and status.
    """
    result: list[dict[str, Any]] = []
    switches = data.get("switch", {})

    for switch_id, switch_data in switches.items():
        member_id = int(switch_id) if str(switch_id).isdigit() else 0
        dad_links = switch_data.get("dad", switch_data.get("dual_active_detection", {}))

        for link_id, link_data in dad_links.items():
            ports = link_data.get("ports", {})
            if ports:
                for intf_name, port_data in ports.items():
                    entry = {
                        "member_id": member_id,
                        "port_type": "dad",
                        "interface": intf_name,
                        "link_status": _SVL_LINK_STATUS.get(
                            port_data.get("link_status", ""), port_data.get("link_status", "")
                        ),
                        "protocol_status": _SVL_PROTOCOL_STATUS.get(
                            port_data.get("protocol_status", ""), port_data.get("protocol_status", "")
                        ),
                    }
                    result.append(entry)

    return result
