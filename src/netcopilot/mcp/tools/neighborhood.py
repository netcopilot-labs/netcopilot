"""get_network_neighborhood — N-hop graph traversal from a device.

Returns direct neighbors (link types, roles), shared VLANs, shared OSPF
areas, BGP sessions, and finding counts.  Max hops capped at 4.

C1S5-US9.
"""

import logging

from netcopilot.findings import device_from_finding, load_findings_enriched
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)

_MAX_HOPS_CAP = 4


async def get_network_neighborhood(
    *,
    device: str,
    hops: int = 1,
    context: dict,
) -> str:
    """Return the network neighborhood for *device* up to *hops* hops away."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Neighborhood analysis requires the topology graph."

    hops = max(1, min(hops, _MAX_HOPS_CAP))
    driver = get_driver()

    # ── Resolve device ──────────────────────────────────────────────
    with driver.session() as session:
        rec = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $name}) "
            "RETURN d.name AS name, d.role AS role, d.building AS building, "
            "d.os_type AS os_type, d.cluster_size AS cluster_size",
            run_id=run_id, name=device,
        ).single()
        if not rec:
            rec = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS toLower($name) "
                "RETURN d.name AS name, d.role AS role, d.building AS building, "
                "d.os_type AS os_type, d.cluster_size AS cluster_size LIMIT 1",
                run_id=run_id, name=device,
            ).single()
            if not rec:
                return (
                    f"Device '{device}' not found in run {run_id}. "
                    "Use query_topology to list available devices."
                )
        device = rec["name"]
        dev_role = rec["role"] or ""
        dev_building = rec["building"] or ""
        dev_os = rec["os_type"] or ""
        dev_cluster = rec["cluster_size"] or 1

    # ── 1. Direct neighbors (all link types) ────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id, name: $name})-[link]-(n:Device)
            WHERE type(link) IN [
                'PHYSICAL_CABLE', 'MGMT_LINK', 'L3_REACHABILITY',
                'INFRASTRUCTURE_LINK', 'INFERRED_LINK', 'ROUTING_ADJACENCY'
            ]
            RETURN n.name AS neighbor, n.role AS role, n.building AS building,
                   n.collected AS collected, n.device_type AS device_type,
                   type(link) AS link_type,
                   link.local_interface AS local_port,
                   link.remote_interface AS remote_port,
                   link.protocol AS protocol,
                   link.bgp_type AS bgp_type,
                   link.local_as AS local_as,
                   link.remote_as AS remote_as,
                   link.area AS area
            ORDER BY n.name, type(link)
            """,
            run_id=run_id, name=device,
        )
        all_links = [dict(r) for r in result]

    # ── 2. N-hop expansion (hops > 1) ───────────────────────────────
    hop_layers: dict[int, set[str]] = {0: {device}}
    hop_devices: dict[str, dict] = {}  # name → {role, building, hop}

    # 1-hop neighbors from the query above
    for link in all_links:
        n = link["neighbor"]
        if n not in hop_devices:
            hop_devices[n] = {
                "role": link["role"] or "",
                "building": link["building"] or "",
                "hop": 1,
            }
    hop_layers[1] = set(hop_devices.keys())

    if hops > 1:
        with driver.session() as session:
            for hop in range(2, hops + 1):
                prev_layer = hop_layers.get(hop - 1, set())
                if not prev_layer:
                    break
                seen = set()
                for h in hop_layers.values():
                    seen |= h
                result = session.run(
                    """
                    MATCH (d:Device {run_id: $run_id})-[link]-(n:Device {run_id: $run_id})
                    WHERE d.name IN $sources
                      AND NOT n.name IN $seen
                      AND type(link) IN [
                          'PHYSICAL_CABLE', 'MGMT_LINK', 'L3_REACHABILITY',
                          'INFRASTRUCTURE_LINK', 'ROUTING_ADJACENCY'
                      ]
                    RETURN DISTINCT n.name AS name, n.role AS role, n.building AS building
                    """,
                    run_id=run_id, sources=list(prev_layer), seen=list(seen),
                )
                new_layer = set()
                for r in result:
                    n = r["name"]
                    new_layer.add(n)
                    if n not in hop_devices:
                        hop_devices[n] = {
                            "role": r["role"] or "",
                            "building": r["building"] or "",
                            "hop": hop,
                        }
                hop_layers[hop] = new_layer

    # ── 3. Shared VLANs ────────────────────────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id, name: $name})
                  -[:MEMBER_OF]->(ss:SharedService {service_type: 'vlan'})
                  <-[:MEMBER_OF]-(n:Device)
            WHERE n.name <> $name
            RETURN ss.identifier AS vlan_id, ss.name AS vlan_name,
                   collect(DISTINCT n.name) AS members
            ORDER BY ss.identifier
            """,
            run_id=run_id, name=device,
        )
        shared_vlans = [dict(r) for r in result]

    # ── 4. Shared OSPF areas ────────────────────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id, name: $name})
                  -[:MEMBER_OF]->(ss:SharedService {service_type: 'ospf_area'})
                  <-[:MEMBER_OF]-(n:Device)
            WHERE n.name <> $name
            RETURN ss.identifier AS area_id, ss.name AS area_name,
                   collect(DISTINCT n.name) AS members
            ORDER BY ss.identifier
            """,
            run_id=run_id, name=device,
        )
        shared_ospf = [dict(r) for r in result]

    # ── 5. BGP sessions ────────────────────────────────────────────
    bgp_sessions = [
        link for link in all_links
        if link.get("protocol") == "bgp" or link.get("bgp_type")
    ]

    # ── 6. Finding counts ──────────────────────────────────────────
    finding_counts = _load_finding_counts(context, device, hop_devices)

    # ── Format output ──────────────────────────────────────────────
    return _format_output(
        device, dev_role, dev_building, dev_os, dev_cluster,
        hops, all_links, hop_layers, hop_devices,
        shared_vlans, shared_ospf, bgp_sessions, finding_counts,
    )


def _load_finding_counts(
    context: dict, device: str, hop_devices: dict[str, dict],
) -> dict[str, dict]:
    """Load finding counts per device — uses canonical Neo4j-first loader."""
    counts: dict[str, dict] = {}
    run_id = context.get("run_id", "")
    if not run_id:
        return counts

    findings = load_findings_enriched(run_id) or []
    target_devices = {device} | set(hop_devices.keys())
    for f in findings:
        d = device_from_finding(f)
        if d is None or d not in target_devices:
            continue
        sev = f.get("severity", "info")
        if d not in counts:
            counts[d] = {"total": 0, "critical": 0, "high": 0, "low": 0, "info": 0}
        counts[d]["total"] += 1
        if sev in counts[d]:
            counts[d][sev] += 1

    return counts


def _format_output(
    device: str,
    role: str,
    building: str,
    os_type: str,
    cluster_size: int,
    hops: int,
    all_links: list[dict],
    hop_layers: dict[int, set[str]],
    hop_devices: dict[str, dict],
    shared_vlans: list[dict],
    shared_ospf: list[dict],
    bgp_sessions: list[dict],
    finding_counts: dict[str, dict],
) -> str:
    lines: list[str] = []

    # Header
    cluster_tag = f", {cluster_size}-member cluster" if cluster_size > 1 else ""
    lines.append(f"Network neighborhood — {device}")
    lines.append(f"  Role: {role or 'unknown'} | Building: {building or 'unknown'} "
                 f"| OS: {os_type or 'unknown'}{cluster_tag}")

    dev_findings = finding_counts.get(device)
    if dev_findings:
        lines.append(f"  Findings: {dev_findings['total']} "
                      f"({dev_findings['critical']} critical, {dev_findings['high']} high)")

    # ── Direct neighbors ────────────────────────────────────────────
    # Group links by neighbor
    by_neighbor: dict[str, dict] = {}
    for link in all_links:
        n = link["neighbor"]
        if n not in by_neighbor:
            by_neighbor[n] = {
                "role": link["role"] or "",
                "building": link["building"] or "",
                "collected": link.get("collected", False),
                "device_type": link.get("device_type", ""),
                "link_types": set(),
                "cables": 0,
                "routing_protocols": set(),
                "bgp_type": None,
                "remote_as": None,
            }
        by_neighbor[n]["link_types"].add(link["link_type"])
        if link["link_type"] in ("PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"):
            by_neighbor[n]["cables"] += 1
        if link.get("protocol"):
            by_neighbor[n]["routing_protocols"].add(link["protocol"])
        if link.get("bgp_type"):
            by_neighbor[n]["bgp_type"] = link["bgp_type"]
            by_neighbor[n]["remote_as"] = link.get("remote_as") or link.get("local_as")

    lines.extend(["", f"Direct neighbors ({len(by_neighbor)}):"])
    for n, info in sorted(by_neighbor.items()):
        role_str = f" ({info['role']})" if info["role"] else ""
        bldg_str = f" [{info['building']}]" if info["building"] else ""
        link_str = ", ".join(sorted(info["link_types"]))
        cable_str = f", {info['cables']} cable(s)" if info["cables"] else ""

        bgp_label = ""
        if info["bgp_type"] == "transit":
            bgp_label = f" [eBGP TRANSIT AS{info['remote_as']}]"
        elif info["bgp_type"] == "peering":
            bgp_label = f" [eBGP PEERING AS{info['remote_as']}]"
        elif "bgp" in info["routing_protocols"]:
            bgp_label = " [iBGP]" if not info["bgp_type"] else ""

        n_findings = finding_counts.get(n)
        finding_str = ""
        if n_findings and n_findings["total"] > 0:
            finding_str = f" — {n_findings['total']} findings"
            if n_findings["critical"]:
                finding_str += f" ({n_findings['critical']} critical)"

        lines.append(
            f"  {n}{role_str}{bldg_str} — {link_str}{cable_str}{bgp_label}{finding_str}"
        )

    # ── N-hop layers (if hops > 1) ──────────────────────────────────
    if hops > 1:
        for hop in range(2, hops + 1):
            layer = hop_layers.get(hop, set())
            if not layer:
                break
            lines.extend(["", f"Hop {hop} ({len(layer)} devices):"])
            for n in sorted(layer):
                info = hop_devices.get(n, {})
                role_str = f" ({info.get('role', '')})" if info.get("role") else ""
                bldg_str = f" [{info.get('building', '')}]" if info.get("building") else ""
                n_findings = finding_counts.get(n)
                finding_str = ""
                if n_findings and n_findings["total"] > 0:
                    finding_str = f" — {n_findings['total']} findings"
                lines.append(f"  {n}{role_str}{bldg_str}{finding_str}")

    # ── Shared VLANs ────────────────────────────────────────────────
    if shared_vlans:
        lines.extend(["", f"Shared VLANs ({len(shared_vlans)}):"])
        for v in shared_vlans[:20]:
            name = f" ({v['vlan_name']})" if v.get("vlan_name") else ""
            members = v.get("members", [])
            member_str = ", ".join(sorted(members)[:5])
            if len(members) > 5:
                member_str += f" +{len(members) - 5} more"
            lines.append(f"  VLAN {v['vlan_id']}{name}: {member_str}")
        if len(shared_vlans) > 20:
            lines.append(f"  ... +{len(shared_vlans) - 20} more VLANs")

    # ── Shared OSPF areas ───────────────────────────────────────────
    if shared_ospf:
        lines.extend(["", f"Shared OSPF areas ({len(shared_ospf)}):"])
        for a in shared_ospf:
            members = a.get("members", [])
            member_str = ", ".join(sorted(members)[:5])
            if len(members) > 5:
                member_str += f" +{len(members) - 5} more"
            lines.append(f"  Area {a['area_id']}: {member_str}")

    # ── BGP sessions ────────────────────────────────────────────────
    if bgp_sessions:
        # Deduplicate (bidirectional edges)
        seen_peers = set()
        unique_bgp: list[dict] = []
        for s in bgp_sessions:
            peer = s["neighbor"]
            if peer not in seen_peers:
                seen_peers.add(peer)
                unique_bgp.append(s)

        lines.extend(["", f"BGP sessions ({len(unique_bgp)}):"])
        for s in unique_bgp:
            bgp_type = s.get("bgp_type", "")
            remote_as = s.get("remote_as") or s.get("local_as") or "?"
            label = bgp_type.upper() if bgp_type else "iBGP"
            lines.append(f"  {s['neighbor']} — {label} (AS {remote_as})")

    # ── Summary ─────────────────────────────────────────────────────
    total_devices = len(hop_devices)
    total_findings = sum(c["total"] for c in finding_counts.values() if c)
    lines.extend(["", f"Summary: {total_devices} device(s) within {hops} hop(s), "
                  f"{total_findings} total findings in neighborhood"])

    return "\n".join(lines)
