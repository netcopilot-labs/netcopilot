"""get_routing_table — routing table per device and VRF.

Queries Route nodes from Neo4j (source of truth). Route nodes are created by the
graph loader from genie routing/static-routing facts, FortiGate routing, and BGP
full-table synthesis.
"""

import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_routing_table(
    *,
    device: str,
    vrf: str | None = None,
    protocol: str | None = None,
    context: dict,
) -> str:
    """Get routing table for a device, optionally filtered by VRF and protocol."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Cannot query routing table."

    driver = get_driver()

    # Resolve device name
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE toLower(d.name) CONTAINS toLower($name) "
            "RETURN d.name AS name LIMIT 1",
            run_id=run_id, name=device,
        )
        rec = result.single()
        if rec:
            device = rec["name"]
        else:
            return f"Device '{device}' not found. Use query_topology to list devices."

    # Query Route nodes from Neo4j
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_ROUTE]->(r:Route) "
            "RETURN r.prefix AS prefix, r.vrf AS vrf, r.protocol AS protocol, "
            "r.next_hop AS next_hop, r.interface AS interface, "
            "r.ad AS ad, r.metric AS metric, r.active AS active, "
            "r.source AS source, r.note AS note",
            run_id=run_id, device=device,
        )
        routes = [dict(r) for r in result]

    if not routes:
        return f"No routing data found for device '{device}'."

    # Build IP → device name lookup for next-hop resolution
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.ip IS NOT NULL "
            "RETURN i.ip AS ip, d.name AS device",
            run_id=run_id,
        )
        ip_to_device: dict[str, str] = {}
        for rec in result:
            ip = rec["ip"]
            if "/" in ip:
                ip = ip.split("/")[0]
            ip_to_device[ip] = rec["device"]

    # Resolve next-hop IPs to device names
    for r in routes:
        nh = r.get("next_hop", "")
        if nh and nh in ip_to_device:
            r["next_hop_device"] = ip_to_device[nh]

    # Filter by VRF
    if vrf:
        routes = [r for r in routes if (r.get("vrf") or "").lower() == vrf.lower()]
        if not routes:
            return f"No routes in VRF '{vrf}' on device '{device}'."

    # Filter by protocol
    if protocol:
        proto_lower = protocol.lower()
        routes = [r for r in routes if proto_lower in (r.get("protocol") or "").lower()]
        if not routes:
            return f"No {protocol} routes on device '{device}'" + (f" in VRF '{vrf}'" if vrf else "") + "."

    # Get unique VRFs
    vrfs = sorted(set(r.get("vrf") or "default" for r in routes))

    # Build output
    lines = [
        f"Routing table — {device}",
        f"Total routes: {len(routes)} across {len(vrfs)} VRF(s): {', '.join(vrfs)}",
        "",
    ]

    for v in vrfs:
        vrf_routes = [r for r in routes if (r.get("vrf") or "default") == v]
        lines.append(f"VRF: {v} ({len(vrf_routes)} routes)")

        by_proto: dict[str, list] = {}
        for r in vrf_routes:
            p = r.get("protocol") or "?"
            by_proto.setdefault(p, []).append(r)

        for p, p_routes in sorted(by_proto.items()):
            lines.append(f"  {p} ({len(p_routes)}):")
            for r in p_routes[:20]:
                nh = r.get("next_hop") or ""
                intf = r.get("interface") or ""
                ad = r.get("ad") or ""
                metric = r.get("metric") or ""
                nh_dev = r.get("next_hop_device", "")
                via = f" via {nh}" if nh else ""
                if nh_dev:
                    via += f" ({nh_dev})"
                out = f" {intf}" if intf else ""
                meta = f" [AD:{ad}/M:{metric}]" if ad else ""
                lines.append(f"    {r.get('prefix', '?')}{via}{out}{meta}")
            if len(p_routes) > 20:
                lines.append(f"    ... and {len(p_routes) - 20} more")
        lines.append("")

    return "\n".join(lines)
