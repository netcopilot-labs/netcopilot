"""get_shared_services — VLAN, subnet, OSPF area, and BGP ASN membership.

Queries Neo4j SharedService nodes and MEMBER_OF relationships. Answers
questions like "which devices share VLAN 99?", "what subnets are in VRF X?",
"which devices are in OSPF area 0.0.0.102?".
"""

import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_shared_services(
    *,
    service_type: str | None = None,
    name: str | None = None,
    device: str | None = None,
    ip: str | None = None,
    context: dict,
) -> str:
    """Get shared service membership: VLANs, subnets, OSPF areas, BGP ASNs.

    Use ip parameter to find which device/interface/VLAN owns an IP address.
    """
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j unavailable."

    driver = get_driver()
    lines = []

    # ── IP lookup mode: find which interface/device/VLAN owns an IP ──
    if ip:
        return await _lookup_ip(ip, run_id, driver)

    # Resolve device name if provided
    if device:
        import re
        filt = device.lower()
        if '-' not in filt:
            filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt "
                "RETURN d.name AS name LIMIT 1",
                run_id=run_id, filt=filt,
            )
            rec = result.single()
            if rec:
                device = rec["name"]

    with driver.session() as session:
        # Build query based on filters
        if device:
            # Show all services for a specific device
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $device})"
                "-[:MEMBER_OF]->(s:SharedService) "
                "RETURN s.service_type AS stype, s.identifier AS ident, "
                "s.name AS name, s.vrf AS vrf, s.area_type AS area_type, "
                "s.process_id AS process_id "
                "ORDER BY s.service_type, s.identifier",
                run_id=run_id, device=device,
            )
            services = [dict(r) for r in result]

            lines.append(f"Shared services for {device}")
            lines.append(f"Total: {len(services)}")
            lines.append("")

            # Group by type
            by_type: dict[str, list] = {}
            for s in services:
                by_type.setdefault(s["stype"], []).append(s)

            for stype, items in sorted(by_type.items()):
                lines.append(f"{stype} ({len(items)}):")
                for item in items:
                    extra = ""
                    if item.get("vrf"):
                        extra += f" VRF:{item['vrf']}"
                    if item.get("area_type"):
                        extra += f" type:{item['area_type']}"
                    if item.get("name"):
                        extra += f" ({item['name']})"
                    lines.append(f"  {item['ident']}{extra}")
                lines.append("")

        elif name:
            # Show membership for a specific service (by identifier)
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->"
                "(s:SharedService {run_id: $run_id}) "
                "WHERE s.identifier = $name OR s.name = $name "
                "RETURN s.service_type AS stype, s.identifier AS ident, "
                "s.name AS sname, s.vrf AS vrf, s.area_type AS area_type, "
                "d.name AS device, d.role AS role "
                "ORDER BY d.name",
                run_id=run_id, name=name,
            )
            members = [dict(r) for r in result]

            if not members:
                # Try partial match — warn user it's approximate
                result = session.run(
                    "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->"
                    "(s:SharedService {run_id: $run_id}) "
                    "WHERE s.identifier CONTAINS $name OR s.name CONTAINS $name "
                    "RETURN s.service_type AS stype, s.identifier AS ident, "
                    "s.name AS sname, d.name AS device, d.role AS role "
                    "ORDER BY s.identifier, d.name",
                    run_id=run_id, name=name,
                )
                members = [dict(r) for r in result]
                if members:
                    # Check if multiple different services matched
                    unique_ids = set(m["ident"] for m in members)
                    if len(unique_ids) > 1:
                        lines.append(f"Note: partial match for '{name}' returned {len(unique_ids)} services.")
                        lines.append(f"Showing all. Use exact identifier for a specific service.")
                        lines.append("")

            if not members:
                return f"No shared service matching '{name}' found."

            stype = members[0].get("stype", "?")
            ident = members[0].get("ident", name)
            sname = members[0].get("sname", "")
            title = f"{stype}: {ident}"
            if sname:
                title += f" ({sname})"

            lines.append(f"Shared service — {title}")
            lines.append(f"Members ({len(members)}):")
            for m in members:
                lines.append(f"  {m['device']} ({m.get('role', '?')})")
            lines.append("")

        elif service_type:
            # Show all services of a type
            result = session.run(
                "MATCH (s:SharedService {service_type: $stype, run_id: $run_id}) "
                "OPTIONAL MATCH (d:Device)-[:MEMBER_OF]->(s) "
                "WITH s, collect(d.name) AS members "
                "RETURN s.identifier AS ident, s.name AS name, "
                "s.vrf AS vrf, s.area_type AS area_type, members "
                "ORDER BY s.identifier",
                stype=service_type, run_id=run_id,
            )
            services = [dict(r) for r in result]

            if not services:
                return f"No shared services of type '{service_type}' found."

            lines.append(f"Shared services — {service_type} ({len(services)})")
            lines.append("")
            for s in services:
                member_str = ", ".join(sorted(s.get("members", [])))
                extra = ""
                if s.get("vrf"):
                    extra += f" VRF:{s['vrf']}"
                if s.get("area_type"):
                    extra += f" {s['area_type']}"
                if s.get("name"):
                    extra += f" ({s['name']})"
                lines.append(f"  {s['ident']}{extra}")
                lines.append(f"    Members: {member_str}")
                lines.append("")

        else:
            # Overview — count by type
            result = session.run(
                "MATCH (s:SharedService {run_id: $run_id}) "
                "RETURN s.service_type AS stype, count(s) AS cnt "
                "ORDER BY count(s) DESC",
                run_id=run_id,
            )
            counts = [dict(r) for r in result]

            lines.append("Shared services overview")
            lines.append("")
            total = sum(c["cnt"] for c in counts)
            lines.append(f"Total: {total}")
            for c in counts:
                lines.append(f"  {c['stype']}: {c['cnt']}")
            lines.append("")
            lines.append("Use service_type filter for details (ospf_area, vlan, subnet, bgp_asn).")
            lines.append("Use name filter for specific service membership (e.g., name='0.0.0.8' for OSPF area).")
            lines.append("Use device filter for all services on a device.")

    return "\n".join(lines)


async def _lookup_ip(ip: str, run_id: str, driver) -> str:
    """Find which device, interface, and VLAN owns an IP address.

    Two strategies:
    1. Exact match: IP is directly assigned to an interface
    2. Subnet match: IP falls within a connected subnet (same broadcast domain)
    """
    import ipaddress

    ip = ip.strip()
    lines = [f"IP lookup: {ip}", ""]

    with driver.session() as session:
        # 1. Exact match — the IP is on an interface
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.ip IS NOT NULL AND (i.ip = $ip OR i.ip STARTS WITH $ip_slash) "
            "RETURN d.name AS device, d.role AS role, "
            "i.name AS interface, i.ip AS full_ip, i.description AS description, "
            "i.access_vlan AS vlan, i.vrf AS vrf, i.status AS status "
            "ORDER BY d.name",
            run_id=run_id, ip=ip, ip_slash=f"{ip}/",
        )
        exact = [dict(r) for r in result]

        if exact:
            lines.append(f"Exact match — {ip} is assigned to:")
            for m in exact:
                parts = [f"  {m['device']} {m['interface']}"]
                if m.get("full_ip"):
                    parts.append(f"({m['full_ip']})")
                if m.get("vlan"):
                    parts.append(f"VLAN:{m['vlan']}")
                if m.get("vrf"):
                    parts.append(f"VRF:{m['vrf']}")
                if m.get("status"):
                    parts.append(f"[{m['status']}]")
                if m.get("description"):
                    parts.append(f"— {m['description']}")
                lines.append(" ".join(parts))
            return "\n".join(lines)

        # 2. Subnet match — find interfaces whose subnet contains this IP
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return f"Invalid IP address: {ip}"

        # Query interfaces with IP and prefix_length (CIDR may be in ip field or separate)
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.ip IS NOT NULL "
            "RETURN d.name AS device, d.role AS role, "
            "i.name AS interface, i.ip AS raw_ip, i.prefix_length AS pfx, "
            "i.description AS description, "
            "i.access_vlan AS vlan, i.vrf AS vrf, i.status AS status "
            "ORDER BY d.name",
            run_id=run_id,
        )
        candidates = [dict(r) for r in result]

        subnet_matches = []
        for c in candidates:
            try:
                raw = c["raw_ip"]
                pfx = c.get("pfx")
                # Build CIDR: either "ip/prefix" from field, or "ip/prefix_length" from separate property
                if "/" in raw:
                    cidr = raw
                elif pfx:
                    cidr = f"{raw}/{pfx}"
                else:
                    continue
                net = ipaddress.ip_network(cidr, strict=False)
                if target in net:
                    c["subnet"] = str(net)
                    c["prefix_len"] = net.prefixlen
                    c["full_ip"] = cidr
                    subnet_matches.append(c)
            except ValueError:
                continue

        if subnet_matches:
            # Sort by most specific subnet (longest prefix)
            subnet_matches.sort(key=lambda x: -x["prefix_len"])
            lines.append(f"{ip} is not directly assigned but falls within:")
            for m in subnet_matches:
                parts = [f"  {m['device']} {m['interface']}"]
                parts.append(f"subnet:{m['subnet']}")
                own_ip = m["full_ip"].split("/")[0]
                parts.append(f"(interface IP: {own_ip})")
                if m.get("vlan"):
                    parts.append(f"VLAN:{m['vlan']}")
                if m.get("vrf"):
                    parts.append(f"VRF:{m['vrf']}")
                if m.get("description"):
                    parts.append(f"— {m['description']}")
                lines.append(" ".join(parts))
            lines.append("")
            lines.append(f"The IP {ip} is a peer/host in this subnet, reachable via these interfaces.")
            return "\n".join(lines)

        # 3. ARP fallback — check ArpEntry nodes for IP seen on device interfaces
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_ARP]->(a:ArpEntry {ip: $ip}) "
            "RETURN d.name AS device, d.role AS role, "
            "a.mac AS mac, a.interface AS interface, a.origin AS origin "
            "ORDER BY d.name",
            run_id=run_id, ip=ip,
        )
        arp_matches = [dict(r) for r in result]

        if arp_matches:
            lines.append(f"{ip} is not assigned to any interface but found in ARP tables:")
            for m in arp_matches:
                parts = [f"  {m['device']} {m['interface']}"]
                parts.append(f"MAC:{m['mac']}")
                if m.get("origin"):
                    parts.append(f"({m['origin']})")
                if m.get("role"):
                    parts.append(f"[{m['role']}]")
                lines.append(" ".join(parts))
            lines.append("")
            lines.append(f"This IP belongs to a host/endpoint reachable via these devices.")
            return "\n".join(lines)

        return f"No interface or ARP entry found matching IP {ip} in any device."
