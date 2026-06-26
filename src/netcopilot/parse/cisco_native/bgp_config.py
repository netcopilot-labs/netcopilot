"""Parse BGP process configuration from IOS XE / IOS XR running config.

Extracts process-level config and per-neighbor settings that Genie's
``learn('bgp')`` or ``parse('show bgp summary')`` do not capture: route
policies, BFD, password presence, maximum-prefix, network statements.

Supports both IOS XE (flat neighbor declarations + address-family block)
and IOS XR (indented neighbor blocks with nested address-family).

Used by the link builder for BGP adjacency enrichment.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_ROUTER_BGP_RE = re.compile(r"^router\s+bgp\s+(\d+)$")

# IOS XE flat neighbor lines (at 1-space indent inside router bgp block)
_XE_NEIGHBOR_REMOTE_AS = re.compile(
    r"^\s+neighbor\s+(\S+)\s+remote-as\s+(\d+)"
)
_XE_NEIGHBOR_DESC = re.compile(
    r"^\s+neighbor\s+(\S+)\s+description\s+(.*)"
)
_XE_NEIGHBOR_UPDATE_SRC = re.compile(
    r"^\s+neighbor\s+(\S+)\s+update-source\s+(\S+)"
)
_XE_NEIGHBOR_PASSWORD = re.compile(
    r"^\s+neighbor\s+(\S+)\s+password\s+"
)
_XE_NEIGHBOR_BFD = re.compile(
    r"^\s+neighbor\s+(\S+)\s+fall-over\s+bfd"
)

# IOS XR indented blocks
_XR_NEIGHBOR_RE = re.compile(r"^\s+neighbor\s+(\d+\.\d+\.\d+\.\d+)\s*$")
_XR_REMOTE_AS_RE = re.compile(r"^\s+remote-as\s+(\d+)")
_XR_DESC_RE = re.compile(r"^\s+description\s+(.*)")
_XR_BFD_RE = re.compile(r"^\s+bfd\s+fast-detect")
_XR_PASSWORD_RE = re.compile(r"^\s+password\s+encrypted\s+")
_XR_GRACEFUL_RE = re.compile(r"^\s+graceful-restart\s*$")
_XR_SEND_COMMUNITY_RE = re.compile(r"^\s+send-community-ebgp")
_XR_UPDATE_SOURCE_RE = re.compile(r"^\s+update-source\s+(\S+)")
_XR_ROUTE_POLICY_RE = re.compile(r"^\s+route-policy\s+(\S+)\s+(in|out)")
_XR_MAX_PREFIX_RE = re.compile(r"^\s+maximum-prefix\s+(\d+)")
_XR_NETWORK_RE = re.compile(r"^\s+network\s+(\S+)")

# IOS XE address-family block lines
_XE_AF_START = re.compile(r"^\s+address-family\s+(ipv4|ipv6)")
_XE_AF_NEIGHBOR_ACTIVATE = re.compile(
    r"^\s+neighbor\s+(\S+)\s+activate"
)
_XE_AF_NEIGHBOR_ROUTE_MAP = re.compile(
    r"^\s+neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)"
)
_XE_AF_NEIGHBOR_NEXT_HOP_SELF = re.compile(
    r"^\s+neighbor\s+(\S+)\s+next-hop-self"
)
_XE_AF_NEIGHBOR_SOFT_RECONFIG = re.compile(
    r"^\s+neighbor\s+(\S+)\s+soft-reconfiguration\s+inbound"
)
# R1-BGP-3: also capture the optional `route-map <name>` qualifier (was dropped).
_XE_AF_REDISTRIBUTE = re.compile(r"^\s+redistribute\s+(\S+)(?:.*\broute-map\s+(\S+))?")
_XE_AF_MAX_PATHS = re.compile(r"^\s+maximum-paths\s+(?:ibgp\s+)?(\d+)")
_XE_AF_NETWORK = re.compile(r"^\s+network\s+(\S+)")
# R1-BGP-2: allowas-in (eBGP loop-prevention override) was read by neither the
# parser nor the genie path. XE form is a flat AF neighbor line; XR is a bare
# line inside the neighbor's address-family block.
_XE_AF_NEIGHBOR_ALLOWAS = re.compile(r"^\s+neighbor\s+(\S+)\s+allowas-in(?:\s+(\d+))?")
_XR_ALLOWAS_RE = re.compile(r"^\s+allowas-in(?:\s+(\d+))?")

# Common
_BGP_ROUTER_ID_RE = re.compile(r"^\s+bgp\s+router-id\s+(\S+)")
_BGP_GRACEFUL_RE = re.compile(r"^\s+bgp\s+graceful-restart")
_BGP_LOG_NEIGHBOR_RE = re.compile(r"^\s+bgp\s+log[- ]neighbor")
_BGP_BESTPATH_RE = re.compile(r"^\s+bgp\s+bestpath\s+(.*)")
_NEXT_HOP_SELF_RE = re.compile(r"^\s+next-hop-self")
_SOFT_RECONFIG_RE = re.compile(r"^\s+soft-reconfiguration\s+inbound")

# Route-reflector — config-only attributes that Genie's operational `show bgp`
# output never exposes (route-reflector-client is per-neighbor policy; cluster-id
# is the RR cluster identifier). The running-config is the authoritative source.
_BGP_CLUSTER_ID_RE = re.compile(r"^\s+bgp\s+cluster-id\s+(\S+)")           # XE + XR process-level
_XE_AF_NEIGHBOR_RR_CLIENT = re.compile(
    r"^\s+neighbor\s+(\S+)\s+route-reflector-client"
)
_XR_RR_CLIENT_RE = re.compile(r"^\s+route-reflector-client\s*$")           # XR neighbor address-family


def _clean_description(desc: str) -> str:
    """Strip IOS XR ``** ... **`` or leading/trailing whitespace."""
    desc = desc.strip()
    if desc.startswith("**") and desc.endswith("**"):
        desc = desc[2:-2].strip()
    return desc


def _ensure_neighbor(neighbors: dict, ip: str) -> dict:
    """Get or create a neighbor entry."""
    if ip not in neighbors:
        neighbors[ip] = {
            "remote_as": None,
            "description": None,
            "bfd": False,
            "password_configured": False,
            "graceful_restart": False,
            "send_community": False,
            "update_source": None,
            "route_policy_in": None,
            "route_policy_out": None,
            "maximum_prefix": None,
            "next_hop_self": False,
            "soft_reconfiguration": False,
            "route_reflector_client": False,
        }
    return neighbors[ip]


def parse_bgp_process_config(
    config_text: str,
) -> dict[str, Any] | None:
    """Parse BGP process config from a running configuration.

    Handles both IOS XE (flat ``neighbor`` lines) and IOS XR (indented
    ``neighbor`` sub-blocks).

    Args:
        config_text: Full running-config text.

    Returns:
        Dict with process-level + per-neighbor config, or None if no
        ``router bgp`` block found::

            {
                "as_number": 65000,
                "router_id": "203.0.113.1",
                "graceful_restart": True,
                "log_neighbor_changes": False,
                "bestpath": "as-path multipath-relax",
                "network_statements": ["203.0.113.0/24", ...],
                "redistribute": ["static", "connected"],
                "neighbors": {
                    "198.51.100.2": {
                        "remote_as": 64500,
                        "description": "UPSTREAM-ISP",
                        "bfd": True,
                        "password_configured": True,
                        "graceful_restart": True,
                        "send_community": False,
                        "update_source": None,
                        "route_policy_in": "PEER-IN",
                        "route_policy_out": "ADVERTISE-PREFIXES",
                        "maximum_prefix": 1000000,
                        "next_hop_self": True,
                        "soft_reconfiguration": True,
                    },
                    ...
                },
            }
    """
    lines = config_text.splitlines()

    # --- Find the router bgp block ---
    bgp_start = None
    as_number = None
    for i, line in enumerate(lines):
        m = _ROUTER_BGP_RE.match(line)
        if m:
            bgp_start = i
            as_number = int(m.group(1))
            break

    if bgp_start is None:
        return None

    # --- Determine block end ---
    bgp_end = len(lines)
    for i in range(bgp_start + 1, len(lines)):
        line = lines[i]
        # Non-indented, non-empty line that isn't '!' ends the block
        if line and not line[0].isspace() and line != "!":
            bgp_end = i
            break
        # Standalone '!' at column 0 after at least some content → end
        if line == "!" and i > bgp_start + 1:
            # Check if next line is also not indented (true block end)
            if i + 1 >= len(lines) or (
                lines[i + 1] and not lines[i + 1][0].isspace()
                and not lines[i + 1].startswith("!")
            ):
                bgp_end = i
                break

    block_lines = lines[bgp_start + 1 : bgp_end]

    # --- Detect IOS XR vs IOS XE ---
    # IOS XR has standalone ``neighbor <ip>`` lines (just the IP, no keyword after)
    # IOS XE has ``neighbor <ip> remote-as <asn>`` on the same line
    is_xr = any(_XR_NEIGHBOR_RE.match(l) for l in block_lines)

    result: dict[str, Any] = {
        "as_number": as_number,
        "router_id": None,
        "cluster_id": None,
        "graceful_restart": False,
        "log_neighbor_changes": False,
        "bestpath": None,
        "network_statements": [],
        "redistribute": [],
        "neighbors": {},
    }

    if is_xr:
        _parse_xr_block(block_lines, result)
    else:
        _parse_xe_block(block_lines, result)

    return result


def _parse_xr_block(
    block_lines: list[str], result: dict[str, Any]
) -> None:
    """Parse IOS XR style BGP config (indented neighbor sub-blocks)."""
    neighbors = result["neighbors"]
    current_nbr: str | None = None
    in_af = False

    for line in block_lines:
        # Process-level settings
        m = _BGP_ROUTER_ID_RE.match(line)
        if m:
            result["router_id"] = m.group(1)
            continue

        m = _BGP_CLUSTER_ID_RE.match(line)
        if m and current_nbr is None:
            result["cluster_id"] = m.group(1)
            continue

        if _BGP_GRACEFUL_RE.match(line) and current_nbr is None:
            result["graceful_restart"] = True
            continue

        if _BGP_LOG_NEIGHBOR_RE.match(line):
            result["log_neighbor_changes"] = True
            continue

        m = _BGP_BESTPATH_RE.match(line)
        if m and current_nbr is None:
            result["bestpath"] = m.group(1).strip()
            continue

        # Network statements (process-level address-family)
        if current_nbr is None:
            m = _XR_NETWORK_RE.match(line)
            if m and not _XR_NEIGHBOR_RE.match(line):
                result["network_statements"].append(m.group(1))
                continue

        # Neighbor block start
        m = _XR_NEIGHBOR_RE.match(line)
        if m:
            current_nbr = m.group(1)
            _ensure_neighbor(neighbors, current_nbr)
            in_af = False
            continue

        # Block terminator for neighbor (IOS XR uses '!' at 1+ indent)
        if line.strip() == "!" and current_nbr is not None:
            if in_af:
                in_af = False  # End of address-family sub-block
            else:
                current_nbr = None  # End of neighbor block
            continue

        if current_nbr is None:
            continue

        nbr = neighbors[current_nbr]

        # Inside address-family sub-block
        if re.match(r"^\s+address-family\s+", line):
            in_af = True
            continue

        if in_af:
            m = _XR_ROUTE_POLICY_RE.match(line)
            if m:
                direction = m.group(2)
                if direction == "in":
                    nbr["route_policy_in"] = m.group(1)
                else:
                    nbr["route_policy_out"] = m.group(1)
                continue

            m = _XR_MAX_PREFIX_RE.match(line)
            if m:
                nbr["maximum_prefix"] = int(m.group(1))
                continue

            if _NEXT_HOP_SELF_RE.match(line):
                nbr["next_hop_self"] = True
                continue

            if _SOFT_RECONFIG_RE.match(line):
                nbr["soft_reconfiguration"] = True
                continue

            if _XR_RR_CLIENT_RE.match(line):
                nbr["route_reflector_client"] = True
                continue

            m = _XR_ALLOWAS_RE.match(line)
            if m:
                nbr["allowas_in"] = True
                if m.group(1):
                    nbr["allowas_in_number"] = int(m.group(1))
                continue
            continue

        # Neighbor-level (outside address-family)
        m = _XR_REMOTE_AS_RE.match(line)
        if m:
            nbr["remote_as"] = int(m.group(1))
            continue

        m = _XR_DESC_RE.match(line)
        if m:
            nbr["description"] = _clean_description(m.group(1))
            continue

        if _XR_BFD_RE.match(line):
            nbr["bfd"] = True
            continue

        if _XR_PASSWORD_RE.match(line):
            nbr["password_configured"] = True
            continue

        if _XR_GRACEFUL_RE.match(line):
            nbr["graceful_restart"] = True
            continue

        if _XR_SEND_COMMUNITY_RE.match(line):
            nbr["send_community"] = True
            continue

        m = _XR_UPDATE_SOURCE_RE.match(line)
        if m:
            nbr["update_source"] = m.group(1)
            continue


def _parse_xe_block(
    block_lines: list[str], result: dict[str, Any]
) -> None:
    """Parse IOS XE style BGP config (flat neighbor lines + AF blocks)."""
    neighbors = result["neighbors"]
    in_af = False

    for line in block_lines:
        # Process-level
        m = _BGP_ROUTER_ID_RE.match(line)
        if m:
            result["router_id"] = m.group(1)
            continue

        m = _BGP_CLUSTER_ID_RE.match(line)
        if m:
            result["cluster_id"] = m.group(1)
            continue

        if _BGP_GRACEFUL_RE.match(line):
            result["graceful_restart"] = True
            continue

        if _BGP_LOG_NEIGHBOR_RE.match(line):
            result["log_neighbor_changes"] = True
            continue

        m = _BGP_BESTPATH_RE.match(line)
        if m:
            result["bestpath"] = m.group(1).strip()
            continue

        # Address-family block
        if _XE_AF_START.match(line):
            in_af = True
            continue

        if re.match(r"^\s+exit-address-family", line):
            in_af = False
            continue

        if in_af:
            # AF-level neighbor commands
            m = _XE_AF_NEIGHBOR_ROUTE_MAP.match(line)
            if m:
                ip, rm_name, direction = m.group(1), m.group(2), m.group(3)
                nbr = _ensure_neighbor(neighbors, ip)
                if direction == "in":
                    nbr["route_policy_in"] = rm_name
                else:
                    nbr["route_policy_out"] = rm_name
                continue

            if _XE_AF_NEIGHBOR_NEXT_HOP_SELF.match(line):
                ip = _XE_AF_NEIGHBOR_NEXT_HOP_SELF.match(line).group(1)
                _ensure_neighbor(neighbors, ip)["next_hop_self"] = True
                continue

            if _XE_AF_NEIGHBOR_SOFT_RECONFIG.match(line):
                ip = _XE_AF_NEIGHBOR_SOFT_RECONFIG.match(line).group(1)
                _ensure_neighbor(neighbors, ip)["soft_reconfiguration"] = True
                continue

            m = _XE_AF_NEIGHBOR_RR_CLIENT.match(line)
            if m:
                _ensure_neighbor(neighbors, m.group(1))["route_reflector_client"] = True
                continue

            m = _XE_AF_NEIGHBOR_ALLOWAS.match(line)
            if m:
                nbr = _ensure_neighbor(neighbors, m.group(1))
                nbr["allowas_in"] = True
                if m.group(2):
                    nbr["allowas_in_number"] = int(m.group(2))
                continue

            m = _XE_AF_REDISTRIBUTE.match(line)
            if m:
                result["redistribute"].append(m.group(1))   # protocol (shape unchanged)
                if m.group(2):  # R1-BGP-3: keep the route-map binding (additive)
                    result.setdefault("redistribute_route_maps", {})[m.group(1)] = m.group(2)
                continue

            m = _XE_AF_NETWORK.match(line)
            if m:
                result["network_statements"].append(m.group(1))
                continue

            # Ignore activate, maximum-paths, etc.
            continue

        # Flat neighbor lines (outside AF)
        m = _XE_NEIGHBOR_REMOTE_AS.match(line)
        if m:
            ip = m.group(1)
            nbr = _ensure_neighbor(neighbors, ip)
            nbr["remote_as"] = int(m.group(2))
            continue

        m = _XE_NEIGHBOR_DESC.match(line)
        if m:
            ip = m.group(1)
            nbr = _ensure_neighbor(neighbors, ip)
            nbr["description"] = _clean_description(m.group(2))
            continue

        m = _XE_NEIGHBOR_UPDATE_SRC.match(line)
        if m:
            ip = m.group(1)
            nbr = _ensure_neighbor(neighbors, ip)
            nbr["update_source"] = m.group(2)
            continue

        if _XE_NEIGHBOR_PASSWORD.match(line):
            ip = _XE_NEIGHBOR_PASSWORD.match(line).group(1)
            _ensure_neighbor(neighbors, ip)["password_configured"] = True
            continue

        if _XE_NEIGHBOR_BFD.match(line):
            ip = _XE_NEIGHBOR_BFD.match(line).group(1)
            _ensure_neighbor(neighbors, ip)["bfd"] = True
            continue
