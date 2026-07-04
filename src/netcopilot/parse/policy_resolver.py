"""Firewall-policy and route-policy resolution — pure facts parsers.

Shared resolvers/parsers used by the graph loader (and, later, query tools):
FortiGate address/service/zone resolution, Cisco ACL parsing, and IOS XR
route-policy / prefix-set parsing. Stdlib only; no Neo4j, no network I/O.

Functions:
    fg_dst_to_cidr(dst)          — Convert FortiGate "IP MASK" to CIDR
    build_zone_map(facts_dir)    — Interface → zone reverse mapping
    build_address_resolver(facts_dir) — Address name → resolved CIDR/FQDN
    build_service_resolver(facts_dir) — Service name → resolved protocol/port
    parse_genie_acl(data)        — Cisco ACL parser (Genie nested → flat)
"""

import ipaddress
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


_ISDB_DST_FIELDS = ("internet-service-name", "internet-service-custom", "internet-service-group")
_ISDB_SRC_FIELDS = (
    "internet-service-src-name", "internet-service-src-custom", "internet-service-src-group",
)


def extract_isdb_refs(policy: dict) -> dict:
    """Extract the ISDB service names a FortiGate policy references.

    Returns ``{"dst": [names], "src": [names]}`` — the Internet Service Database
    references on the destination and source sides. Empty lists when the policy
    uses none. These names are otherwise invisible (an ISDB policy's ``dstaddr``
    is empty), so a path check that ignored them would report "no policy" for a
    policy that exists.
    """
    def _names(fields):
        out = []
        for field in fields:
            for ref in policy.get(field, []) or []:
                if isinstance(ref, dict) and ref.get("name"):
                    out.append(ref["name"])
        return out

    return {"dst": _names(_ISDB_DST_FIELDS), "src": _names(_ISDB_SRC_FIELDS)}


def service_allows(protocol: str | None, dst_port: int | None, service_str: str) -> bool:
    """Does a policy/ACE ``service`` string permit ``(protocol, dst_port)``?

    The shared 5-tuple service check, lenient across both grammars this codebase
    produces: FortiGate resolved services (``"TCP/443"``, ``"TCP/443-445"``,
    ``"ICMP"``, ``"ALL"``) and Cisco ACE services (``"tcp 443"``, ``"tcp 80-90"``,
    ``"tcp gt 1024"``, ``"ip"``, ``""``).

    Returns ``True`` when the flow is allowed by the service (including the
    permissive/unknown cases — ``ALL``/``any``/``ip``/empty, or a token whose
    port spec can't be parsed), so this never *invents* a block. When
    ``dst_port`` is ``None`` the check degrades to protocol-only; when
    ``protocol`` is also ``None`` it returns ``True`` (caller wanted IP-only).
    """
    if protocol is None:
        return True
    if not service_str:
        return True
    proto = protocol.lower()

    for raw in service_str.split(","):
        token = raw.strip()
        if not token:
            continue
        low = token.lower()
        if low in ("all", "any", "ip"):
            return True
        # Split proto from the port spec: "TCP/443" or "tcp 443" / "tcp gt 1024".
        if "/" in token:
            tproto, _, spec = token.partition("/")
        else:
            parts = token.split(None, 1)
            tproto, spec = parts[0], (parts[1] if len(parts) > 1 else "")
        tproto = tproto.strip().lower()
        if tproto in ("all", "any", "ip"):
            return True
        if tproto != proto:
            continue
        # Proto matches. Without a dst_port, proto-level match is enough.
        if dst_port is None or not spec:
            return True
        if _port_spec_matches(spec.strip().lower(), dst_port):
            return True
    return False


def _port_spec_matches(spec: str, port: int) -> bool:
    """Match a single port spec token (``"443"``, ``"80-90"``, ``"gt 1024"``,
    ``"lt 80"``, ``"src 53"``) against ``port``.

    ``src …`` is a source-port spec — irrelevant to a destination-port check,
    so it never matches here. Unparseable specs return ``True`` (permissive:
    don't fabricate a block from a spec we don't understand)."""
    try:
        if spec.startswith("src"):
            return False
        if spec.startswith("gt "):
            return port > int(spec[3:])
        if spec.startswith("lt "):
            return port < int(spec[3:])
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return int(lo) <= port <= int(hi)
        return int(spec) == port
    except (ValueError, TypeError):
        return True


def ip_in_isdb_ranges(ip: str, ranges: list[str]) -> bool:
    """Is ``ip`` within any ISDB range (``"start-end"`` or single-IP strings)?"""
    import ipaddress

    try:
        target = ipaddress.ip_address(ip.split("/")[0])
    except ValueError:
        return False
    for r in ranges or []:
        try:
            if "-" in r:
                lo, hi = r.split("-", 1)
                if ipaddress.ip_address(lo) <= target <= ipaddress.ip_address(hi):
                    return True
            elif ipaddress.ip_address(r) == target:
                return True
        except ValueError:
            continue
    return False


def fg_dst_to_cidr(dst: str) -> str:
    """Convert FortiGate ``IP MASK`` to CIDR.

    Example: ``'10.0.0.0 255.255.255.0'`` → ``'10.0.0.0/24'``.
    Also handles ``'0.0.0.0 0.0.0.0'`` → ``'0.0.0.0/0'``.
    """
    parts = dst.strip().split()
    if len(parts) == 2:
        try:
            net = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
            return str(net)
        except (ValueError, TypeError):
            pass
    return dst


def build_zone_map(facts_dir: Path) -> dict[str, str]:
    """Build interface-name → zone-name reverse map from fortigate_system_zone.json."""
    zone_path = facts_dir / "fortigate_system_zone.json"
    if not zone_path.exists():
        return {}
    try:
        data = json.loads(zone_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    mapping: dict[str, str] = {}
    for zone in data.get("results", []):
        zone_name = zone.get("name", "")
        for intf in zone.get("interface", []):
            intf_name = intf.get("interface-name", "")
            if intf_name:
                mapping[intf_name] = zone_name
    return mapping


def build_address_resolver(facts_dir: Path) -> dict[str, str]:
    """Build address-name → resolved-value map from FortiGate address/addrgrp files.

    Resolves subnet ("IP MASK" → CIDR), FQDN, and address groups (recursive,
    depth-limited to 3).  Returns empty dict if files are missing (graceful).
    """
    resolver: dict[str, str] = {"all": "0.0.0.0/0"}

    # Load address objects
    addr_path = facts_dir / "fortigate_firewall_address.json"
    if addr_path.exists():
        try:
            data = json.loads(addr_path.read_text())
            for obj in data.get("results", []):
                name = obj.get("name", "")
                if not name:
                    continue
                obj_type = obj.get("type", "")
                if obj_type in ("ipmask", "interface-subnet"):
                    subnet = obj.get("subnet", "")
                    if subnet:
                        resolver[name] = fg_dst_to_cidr(subnet)
                    else:
                        resolver[name] = name
                elif obj_type == "fqdn":
                    fqdn = obj.get("fqdn", "")
                    resolver[name] = fqdn if fqdn else name
                elif obj_type == "iprange":
                    start = obj.get("start-ip", "")
                    end = obj.get("end-ip", "")
                    if start and end:
                        resolver[name] = f"{start}-{end}"
                    else:
                        resolver[name] = name
                elif obj_type == "dynamic":
                    sub_type = obj.get("sub-type", "")
                    resolver[name] = f"dynamic:{sub_type}" if sub_type else "dynamic"
                else:
                    resolver[name] = name
        except (json.JSONDecodeError, OSError):
            pass

    # Load VIP (Virtual IP / DNAT) objects
    vip_path = facts_dir / "fortigate_firewall_vip.json"
    if vip_path.exists():
        try:
            data = json.loads(vip_path.read_text())
            for obj in data.get("results", []):
                name = obj.get("name", "")
                if not name or name in resolver:
                    continue
                extip = obj.get("extip", "")
                mappedip = obj.get("mappedip", [])
                mapped_str = ", ".join(
                    m.get("range", "") for m in mappedip if m.get("range")
                ) if mappedip else ""
                if extip and mapped_str:
                    resolver[name] = f"{extip} -> {mapped_str}"
                elif mapped_str:
                    resolver[name] = mapped_str
                elif extip:
                    resolver[name] = extip
                else:
                    resolver[name] = name
        except (json.JSONDecodeError, OSError):
            pass

    # Load address groups and expand (depth-limited recursion)
    grp_path = facts_dir / "fortigate_firewall_addrgrp.json"
    groups: dict[str, list[str]] = {}
    if grp_path.exists():
        try:
            data = json.loads(grp_path.read_text())
            for grp in data.get("results", []):
                grp_name = grp.get("name", "")
                members = [m.get("name", "") for m in grp.get("member", []) if m.get("name")]
                if grp_name and members:
                    groups[grp_name] = members
        except (json.JSONDecodeError, OSError):
            pass

    def _expand_group(name: str, depth: int = 0) -> str:
        if depth > 3 or name not in groups:
            return resolver.get(name, name)
        parts = []
        for member in groups[name]:
            if member in groups and depth < 3:
                parts.append(_expand_group(member, depth + 1))
            else:
                parts.append(resolver.get(member, member))
        resolved = ", ".join(parts)
        resolver[name] = resolved
        return resolved

    for grp_name in groups:
        if grp_name not in resolver:
            _expand_group(grp_name)

    return resolver


def build_service_resolver(facts_dir: Path) -> dict[str, str | None]:
    """Build service-name → resolved-value map from FortiGate service files.

    Resolves tcp-portrange/udp-portrange to "TCP/443" format.
    "ALL" → None (any).  Returns empty dict if files are missing.
    """
    resolver: dict[str, str | None] = {"ALL": None}

    svc_path = facts_dir / "fortigate_firewall_service_custom.json"
    if svc_path.exists():
        try:
            data = json.loads(svc_path.read_text())
            for obj in data.get("results", []):
                name = obj.get("name", "")
                if not name:
                    continue
                parts = []
                tcp = obj.get("tcp-portrange", "")
                udp = obj.get("udp-portrange", "")
                if tcp:
                    for seg in tcp.split():
                        port = seg.split(":")[0]
                        parts.append(f"TCP/{port}")
                if udp:
                    for seg in udp.split():
                        port = seg.split(":")[0]
                        parts.append(f"UDP/{port}")
                sctp = obj.get("sctp-portrange", "")
                if sctp:
                    # SF-SVC-1: a TCP/UDP/SCTP service whose ports live only in
                    # sctp-portrange used to fall through to the bare object name,
                    # silently dropping the ports.
                    for seg in sctp.split():
                        port = seg.split(":")[0]
                        parts.append(f"SCTP/{port}")
                if parts:
                    resolver[name] = ", ".join(parts)
                else:
                    protocol = obj.get("protocol", "")
                    if protocol in ("ICMP", "ICMP6"):
                        # SF-ICMP-1: keep the protocol (ICMP6 used to fall
                        # through to the bare object name) and append the
                        # icmptype when present (was collapsed to bare "ICMP").
                        icmptype = obj.get("icmptype", "")
                        resolver[name] = (
                            f"{protocol}/type:{icmptype}" if icmptype != "" and icmptype is not None
                            else protocol
                        )
                    elif protocol == "IP":
                        protocol_number = obj.get("protocol-number", "")
                        if protocol_number:
                            resolver[name] = f"IP/{protocol_number}"
                        else:
                            resolver[name] = name
                    else:
                        resolver[name] = name
        except (json.JSONDecodeError, OSError):
            pass

    # Service groups
    grp_path = facts_dir / "fortigate_firewall_service_group.json"
    if grp_path.exists():
        try:
            data = json.loads(grp_path.read_text())
            for grp in data.get("results", []):
                grp_name = grp.get("name", "")
                members = [m.get("name", "") for m in grp.get("member", []) if m.get("name")]
                if grp_name and members:
                    resolved_members = [resolver.get(m, m) for m in members]
                    resolver[grp_name] = ", ".join(
                        str(r) for r in resolved_members if r is not None
                    ) or None
        except (json.JSONDecodeError, OSError):
            pass

    return resolver


def parse_genie_acl(data: dict) -> list[dict]:
    """Parse genie_acl.json into structured ACL list.

    Flattens the deeply nested Genie ACL structure into a simpler format
    with permit/deny actions, source/destination, and L4 port info.
    """
    if "acls" in data and isinstance(data.get("acls"), dict):
        data = data["acls"]
    acls = []
    for acl_name, acl_data in sorted(data.items()):
        if not isinstance(acl_data, dict):
            continue
        acl_type = acl_data.get("type", "ipv4-acl-type")
        aces_raw = acl_data.get("aces", {})
        aces = []
        for seq_str, ace_data in sorted(aces_raw.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
            if not isinstance(ace_data, dict):
                continue
            actions = ace_data.get("actions", {})
            forwarding = actions.get("forwarding", "")
            action = "permit" if forwarding in ("accept", "permit") else "deny"
            logging_val = actions.get("logging", "log-none")

            source = "any"
            destination = "any"
            protocol = ""
            matches = ace_data.get("matches", {})
            l3 = matches.get("l3", {})
            ipv4 = l3.get("ipv4", {})

            # SF-ACE-1: keep ALL matched networks, sorted. next(iter(keys()))
            # dropped every network but the first on a multi-network ACE, and the
            # one it kept depended on genie's dict-insertion order.
            src_net = ipv4.get("source_ipv4_network", {})
            if src_net:
                source = ", ".join(sorted(src_net.keys()))

            dst_net = ipv4.get("destination_ipv4_network", {})
            if dst_net:
                destination = ", ".join(sorted(dst_net.keys()))

            prot = ipv4.get("protocol", "")
            if prot:
                protocol = prot

            l4_ports = ""
            l4 = matches.get("l4", {})
            for proto_key in ("tcp", "udp"):
                l4_proto = l4.get(proto_key, {})
                if l4_proto:
                    if not protocol:
                        protocol = proto_key
                    dst_port = l4_proto.get("destination_port", {})
                    op = dst_port.get("operator", {})
                    if op:
                        op_type = op.get("operator", "")
                        port = op.get("port", "")
                        if op_type == "eq":
                            l4_ports = str(port)
                        elif op_type == "range":
                            lower = op.get("lower_port", "")
                            upper = op.get("upper_port", "")
                            l4_ports = f"{lower}-{upper}"
                        elif op_type in ("lt", "gt"):
                            l4_ports = f"{op_type} {port}"
                    src_port = l4_proto.get("source_port", {})
                    src_op = src_port.get("operator", {})
                    if src_op and not l4_ports:
                        port = src_op.get("port", "")
                        l4_ports = f"src {port}"

            aces.append({
                "seq": int(seq_str) if seq_str.isdigit() else seq_str,
                "action": action,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "l4_ports": l4_ports,
                "log": logging_val != "log-none",
            })

        acls.append({
            "name": acl_name,
            "type": "IPv4" if "ipv4" in acl_type else "IPv6" if "ipv6" in acl_type else acl_type,
            "ace_count": len(aces),
            "aces": aces,
        })

    return acls


def parse_xr_route_policies(facts_dir):
    """Parse IOS XR route-policy and prefix-set blocks from running_config.txt.

    Shared by the graph loader and (later) query tools so both the Neo4j-load
    and render paths produce identical data from one parser.

    Returns (route_policies, prefix_sets) structured like IOS XE equivalents:
        route_policies: [{"name": str, "body": list[str]}]
        prefix_sets:    [{"name": str, "entries": [{"seq": int, "action": str, "prefix": str}, ...]}]
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return [], []

    try:
        text = config_path.read_text()
    except OSError:
        return [], []

    # Parse prefix-set blocks
    prefix_sets = []
    for m in re.finditer(
        r"^prefix-set\s+(\S+)\n(.*?)^end-set", text, re.MULTILINE | re.DOTALL
    ):
        name = m.group(1)
        body = m.group(2).strip()
        entries = []
        for i, line in enumerate(body.splitlines(), start=1):
            prefix = line.strip().rstrip(",")
            if prefix:
                entries.append({"seq": i * 5, "action": "permit", "prefix": prefix})
        prefix_sets.append({"name": name, "entries": entries})

    # Parse route-policy blocks
    route_policies = []
    for m in re.finditer(
        r"^route-policy\s+(\S+)\n(.*?)^end-policy", text, re.MULTILINE | re.DOTALL
    ):
        name = m.group(1)
        body = m.group(2).strip()
        body_lines = [l.strip() for l in body.splitlines() if l.strip()]
        route_policies.append({
            "name": name,
            "body": body_lines,
        })

    return route_policies, prefix_sets


def parse_acl_interface_bindings(facts_dir):
    """Parse running_config.txt for ACL-to-interface bindings.

    Returns ACL name → list of {interface, direction[, vrf]} dicts.
    Handles IOS XE ('ip access-group X in/out'), IOS XR ('ipv4/ipv6
    access-group X ingress/egress'), VTY lines ('access-class X in'),
    SSH server ACLs, and HTTP server ACLs.
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}

    bindings: dict = {}
    current_interface = None
    current_line = None
    current_vrf = None

    _INTF_RE = re.compile(r"^interface\s+(.+)")
    _LINE_RE = re.compile(r"^line\s+(vty|con|aux|default)\s*(.*)")
    _VRF_FWD_RE = re.compile(r"^\s+(?:ip\s+)?vrf\s+forwarding\s+(\S+)")
    _XE_ACL_RE = re.compile(r"^\s+ip\s+access-group\s+(\S+)\s+(in|out)")
    _XR_ACL_RE = re.compile(r"^\s+ipv[46]\s+access-group\s+(\S+)\s+(ingress|egress)")
    _VTY_XE_RE = re.compile(r"^\s+access-class\s+(\S+)\s+(in|out)")
    _VTY_XR_RE = re.compile(r"^\s+access-class\s+(ingress|egress)\s+(\S+)")
    _SSH_ACL_RE = re.compile(r"^ssh\s+server\s+.*access-list\s+(\S+)")
    _HTTP_ACL_RE = re.compile(r"^ip\s+http\s+access-class\s+\S+\s+(\S+)")

    dir_map = {"in": "inbound", "out": "outbound",
               "ingress": "inbound", "egress": "outbound"}

    for line in lines:
        m = _INTF_RE.match(line)
        if m:
            current_interface = m.group(1).strip()
            current_line = None
            current_vrf = None
            continue

        m = _LINE_RE.match(line)
        if m:
            suffix = m.group(2).strip()
            current_line = f"line {m.group(1)} {suffix}" if suffix else f"line {m.group(1)}"
            current_interface = None
            continue

        if line and not line[0].isspace():
            current_interface = None
            current_line = None

        if current_interface:
            m = _VRF_FWD_RE.match(line)
            if m:
                current_vrf = m.group(1)
                continue
            m = _XE_ACL_RE.match(line) or _XR_ACL_RE.match(line)
            if m:
                acl_name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
                entry = {"interface": current_interface, "direction": direction}
                if current_vrf:
                    entry["vrf"] = current_vrf
                bindings.setdefault(acl_name, []).append(entry)
                continue

        if current_line:
            m = _VTY_XE_RE.match(line)
            if m:
                acl_name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
                bindings.setdefault(acl_name, []).append(
                    {"interface": current_line, "direction": direction}
                )
                continue
            m = _VTY_XR_RE.match(line)
            if m:
                direction, acl_name = dir_map.get(m.group(1), m.group(1)), m.group(2)
                bindings.setdefault(acl_name, []).append(
                    {"interface": current_line, "direction": direction}
                )
                continue

        m = _SSH_ACL_RE.match(line)
        if m:
            bindings.setdefault(m.group(1), []).append(
                {"interface": "SSH server", "direction": "inbound"}
            )
            continue
        m = _HTTP_ACL_RE.match(line)
        if m:
            bindings.setdefault(m.group(1), []).append(
                {"interface": "HTTP server", "direction": "inbound"}
            )
            continue

    return bindings


def parse_bgp_neighbor_context(facts_dir):
    """Parse BGP neighbor route-map/route-policy bindings.

    Returns route-map/route-policy name → list of {context, direction[, vrf]}
    where context includes the neighbor IP and (if present) the description.
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}

    bindings: dict = {}
    in_bgp = False
    current_neighbor = None
    neighbor_desc = {}
    current_vrf = "default"

    dir_map = {"in": "inbound", "out": "outbound"}

    for line in lines:
        if re.match(r"^router\s+bgp\s+(\d+)", line):
            in_bgp = True
            current_vrf = "default"
            current_neighbor = None
            continue

        if in_bgp and line and not line[0].isspace() and not line.startswith("!"):
            in_bgp = False
            current_neighbor = None
            continue

        if not in_bgp:
            continue

        stripped = line.strip()

        m = re.match(r"^\s+vrf\s+(\S+)", line)
        if m:
            current_vrf = m.group(1)
            current_neighbor = None
            continue

        m = re.match(r"^\s+neighbor\s+(\S+)", line)
        if m:
            current_neighbor = m.group(1)
            continue

        if current_neighbor and stripped.startswith("description"):
            desc = stripped[len("description"):].strip().strip("*").strip()
            neighbor_desc[current_neighbor] = desc

        m = re.match(r"^\s+route-policy\s+(\S+)\s+(in|out)", line)
        if m and current_neighbor:
            name, direction = m.group(1), dir_map[m.group(2)]
            desc = neighbor_desc.get(current_neighbor, "")
            label = f"BGP {current_neighbor}"
            if desc:
                label += f" ({desc})"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": direction, "vrf": current_vrf}
            )
            continue

        m = re.match(r"^\s+neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)", line)
        if m:
            neighbor_ip, name, direction = m.group(1), m.group(2), dir_map[m.group(3)]
            desc = neighbor_desc.get(neighbor_ip, "")
            label = f"BGP {neighbor_ip}"
            if desc:
                label += f" ({desc})"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": direction, "vrf": current_vrf}
            )
            continue

        m = re.match(r"^\s+redistribute\s+(\S+).*\s+route-map\s+(\S+)", line)
        if m:
            proto, name = m.group(1), m.group(2)
            label = f"redistribute {proto}"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": "outbound", "vrf": current_vrf}
            )
            continue

    return bindings


def parse_route_policy_bindings(facts_dir):
    """Return (rm_bindings, pl_refs).

    rm_bindings: route-map/policy name → list of {context, direction} dicts
        (generic version — does NOT include neighbor IP, use
        parse_bgp_neighbor_context for that).
    pl_refs: prefix-list/set name → list of route-map/policy names that
        reference it.
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}, {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}, {}

    rm_bindings: dict = {}
    pl_refs: dict = {}

    _BGP_RM_RE = re.compile(r"^\s+(?:neighbor\s+\S+\s+)?route-map\s+(\S+)\s+(in|out)")
    _BGP_RP_RE = re.compile(r"^\s+route-policy\s+(\S+)\s+(in|out)")
    _REDIST_RM_RE = re.compile(r"^\s+redistribute\s+(\S+).*\s+route-map\s+(\S+)")
    _MATCH_PL_RE = re.compile(r"^\s+match\s+ip\s+address\s+prefix-list\s+(\S+)")
    _MATCH_PS_RE = re.compile(r"^\s+if\s+destination\s+in\s+(\S+)")

    dir_map = {"in": "inbound", "out": "outbound"}
    current_rm = None

    for line in lines:
        rm_def = re.match(r"^route-map\s+(\S+)", line) or re.match(r"^route-policy\s+(\S+)", line)
        if rm_def:
            current_rm = rm_def.group(1)
            continue

        if line and not line[0].isspace() and not line.startswith("!"):
            current_rm = None

        m = _BGP_RM_RE.match(line) or _BGP_RP_RE.match(line)
        if m:
            name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
            rm_bindings.setdefault(name, []).append(
                {"context": "BGP neighbor", "direction": direction}
            )
            continue

        m = _REDIST_RM_RE.match(line)
        if m:
            proto, name = m.group(1), m.group(2)
            rm_bindings.setdefault(name, []).append(
                {"context": f"redistribute {proto}", "direction": "outbound"}
            )
            continue

        if current_rm:
            m = _MATCH_PL_RE.match(line) or _MATCH_PS_RE.match(line)
            if m:
                pl_name = m.group(1)
                pl_refs.setdefault(pl_name, [])
                if current_rm not in pl_refs[pl_name]:
                    pl_refs[pl_name].append(current_rm)
                continue

    return rm_bindings, pl_refs


def build_firewall_policies(run_dir: Path, site: str, run_id: str) -> list[dict]:
    """Build the firewall-policy property dicts for a run — one shared source of
    truth for both the Neo4j loader (UNWIND into :FirewallPolicy nodes) and the
    ``policies.json`` pipeline artifact (diffable firewall-policy state).

    Reads FortiGate policy files (with address/service/zone resolution) and
    Cisco ACL files for every device under ``run_dir/facts``. Pure function of
    the facts — no Neo4j, no network I/O. None-valued properties are stripped
    (Neo4j doesn't store nulls; the artifact stays clean too).

    Returns:
        One dict per FortiGate policy / Cisco ACE, device-attributed. Empty when
        there is no ``facts`` dir or no policies at all.
    """
    def _strip_none(props: dict) -> dict:
        return {k: v for k, v in props.items() if v is not None}

    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return []

    policy_params: list[dict] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        # ── FortiGate policies ─────────────────────────────────────
        fg_policy_path = device_dir / "fortigate_firewall_policy.json"
        if fg_policy_path.exists():
            try:
                zone_map = build_zone_map(device_dir)
                addr_resolver = build_address_resolver(device_dir)
                svc_resolver = build_service_resolver(device_dir)

                data = json.loads(fg_policy_path.read_text())
                for idx, policy in enumerate(data.get("results", []), 1):
                    # Resolve source/dest interfaces with zones
                    srcintf = [
                        {"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""), "")}
                        for i in policy.get("srcintf", [])
                    ]
                    dstintf = [
                        {"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""), "")}
                        for i in policy.get("dstintf", [])
                    ]
                    # Resolve addresses
                    srcaddr = ", ".join(
                        addr_resolver.get(a.get("name", ""), a.get("name", ""))
                        for a in policy.get("srcaddr", [])
                    )
                    dstaddr = ", ".join(
                        addr_resolver.get(a.get("name", ""), a.get("name", ""))
                        for a in policy.get("dstaddr", [])
                    )
                    # Resolve services
                    services = []
                    for s in policy.get("service", []):
                        sname = s.get("name", "")
                        resolved = svc_resolver.get(sname, sname)
                        services.append(str(resolved) if resolved else sname)
                    service_str = ", ".join(services)

                    # Extract zone names for easy Cypher filtering
                    src_zones = [i["zone"] for i in srcintf if i["zone"]]
                    dst_zones = [i["zone"] for i in dstintf if i["zone"]]

                    # ISDB (Internet Service Database) references — otherwise
                    # invisible (an ISDB policy has an empty dstaddr).
                    isdb = extract_isdb_refs(policy)

                    policy_params.append(_strip_none({
                        "policyid": policy.get("policyid", 0),
                        "seq": idx,
                        "name": policy.get("name", ""),
                        "status": policy.get("status", ""),
                        "action": policy.get("action", ""),
                        "srcintf": json.dumps(srcintf),
                        "dstintf": json.dumps(dstintf),
                        "src_zones": src_zones,
                        "dst_zones": dst_zones,
                        "srcaddr": srcaddr,
                        "dstaddr": dstaddr,
                        "service": service_str,
                        "dst_isdb": ", ".join(isdb["dst"]),
                        "src_isdb": ", ".join(isdb["src"]),
                        # SF-NEGATE-1: an enabled *-negate inverts the policy
                        # (match everything EXCEPT the listed addr/service).
                        # Captured so it can't silently invert meaning downstream.
                        "src_negate": policy.get("srcaddr-negate", "") == "enable",
                        "dst_negate": policy.get("dstaddr-negate", "") == "enable",
                        "service_negate": policy.get("service-negate", "") == "enable",
                        "nat": policy.get("nat", ""),
                        "schedule": policy.get("schedule", ""),
                        "logtraffic": policy.get("logtraffic", ""),
                        "comments": policy.get("comments", ""),
                        "policy_type": "fortigate",
                        "device": device,
                        "site": site,
                        "run_id": run_id,
                    }))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse FortiGate policies for %s: %s", device, exc)

        # ── Cisco ACLs ─────────────────────────────────────────────
        acl_path = device_dir / "genie_acl.json"
        if acl_path.exists():
            # Compute interface bindings once per device and persist applied_to,
            # so query tools can't infer "not applied" from an empty/absent field.
            acl_bindings = parse_acl_interface_bindings(device_dir)
            try:
                data = json.loads(acl_path.read_text())
                acls = parse_genie_acl(data)
                for acl in acls:
                    applied_to = [
                        f"{b.get('interface','?')} {b.get('direction','?')}"
                        + (f" (vrf {b['vrf']})" if b.get("vrf") else "")
                        for b in acl_bindings.get(acl["name"], [])
                    ]
                    for ace in acl.get("aces", []):
                        policy_params.append(_strip_none({
                            "policyid": ace.get("seq", 0),
                            # seq = ACE evaluation order; mirrors the FortiGate
                            # block's seq so get_firewall_policies' ORDER BY
                            # p.device, p.seq is deterministic for ACL nodes too
                            # (without it ACL nodes have seq=NULL → scan order).
                            "seq": ace.get("seq", 0),
                            "name": acl["name"],
                            "status": "enable",
                            "action": ace.get("action", ""),
                            "srcaddr": ace.get("source", "any"),
                            "dstaddr": ace.get("destination", "any"),
                            "service": f"{ace.get('protocol', '')} {ace.get('l4_ports', '')}".strip() or "any",
                            "policy_type": "acl",
                            "acl_type": acl.get("type", ""),
                            "applied_to": applied_to,
                            "device": device,
                            "site": site,
                            "run_id": run_id,
                        }))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse Cisco ACLs for %s: %s", device, exc)

    return policy_params
