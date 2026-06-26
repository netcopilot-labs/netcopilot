"""get_site_summary — per-building operational summary.

Device count by role, redundancy status (HA/LAG), OSPF areas, BGP sessions,
finding counts by severity, and uplinks to other buildings.

C1S5-US10.
"""

import logging

from netcopilot.findings import device_from_finding, load_findings_enriched
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_site_summary(
    *,
    building: str | None = None,
    context: dict,
) -> str:
    """Return an operational summary for a building or all buildings."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Site summary requires the topology graph."

    driver = get_driver()

    # ── 1. Devices by building ──────────────────────────────────────
    with driver.session() as session:
        if building:
            result = session.run(
                """
                MATCH (d:Device {run_id: $run_id})
                WHERE d.collected = true
                  AND toLower(d.building) = toLower($building)
                RETURN d.name AS name, d.role AS role, d.building AS building,
                       d.os_type AS os_type, d.cluster_size AS cluster_size
                ORDER BY d.role, d.name
                """,
                run_id=run_id, building=building,
            )
        else:
            result = session.run(
                """
                MATCH (d:Device {run_id: $run_id})
                WHERE d.collected = true
                RETURN d.name AS name, d.role AS role, d.building AS building,
                       d.os_type AS os_type, d.cluster_size AS cluster_size
                ORDER BY d.building, d.role, d.name
                """,
                run_id=run_id,
            )
        devices = [dict(r) for r in result]

    if not devices:
        if building:
            return (
                f"No devices found in building '{building}'. "
                "Use query_topology to list available buildings."
            )
        return f"No devices found in run {run_id}."

    # Group by building
    by_building: dict[str, list[dict]] = {}
    for d in devices:
        b = d.get("building") or "unknown"
        by_building.setdefault(b, []).append(d)

    # ── 2. Inter-building links ─────────────────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (a:Device {run_id: $run_id})-[link:PHYSICAL_CABLE]-(b:Device {run_id: $run_id})
            WHERE a.building IS NOT NULL AND b.building IS NOT NULL
              AND a.building <> b.building AND a.name < b.name
            RETURN a.building AS bldg_a, a.name AS dev_a,
                   b.building AS bldg_b, b.name AS dev_b,
                   count(link) AS cables
            ORDER BY a.building, b.building
            """,
            run_id=run_id,
        )
        uplinks = [dict(r) for r in result]

    # ── 3. OSPF areas per building ──────────────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->(ss:SharedService {service_type: 'ospf_area'})
            WHERE d.collected = true
            RETURN d.building AS building,
                   collect(DISTINCT ss.identifier) AS areas
            ORDER BY d.building
            """,
            run_id=run_id,
        )
        ospf_by_building = {r["building"]: r["areas"] for r in result}

    # ── 4. BGP sessions per building ────────────────────────────────
    with driver.session() as session:
        result = session.run(
            """
            MATCH (a:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]-(b:Device {run_id: $run_id})
            WHERE r.protocol = 'bgp' AND a.collected = true
            RETURN a.building AS building, a.name AS device,
                   b.name AS peer, r.bgp_type AS bgp_type,
                   r.local_as AS local_as, r.remote_as AS remote_as
            ORDER BY a.building, a.name
            """,
            run_id=run_id,
        )
        bgp_by_building: dict[str, list[dict]] = {}
        for r in result:
            b = r["building"] or "unknown"
            bgp_by_building.setdefault(b, []).append(dict(r))

    # ── 5. Finding counts ───────────────────────────────────────────
    finding_counts = _load_finding_counts(context)

    # ── Format ──────────────────────────────────────────────────────
    buildings_to_show = (
        [building.upper()] if building else sorted(by_building.keys())
    )
    # Handle case-insensitive match
    if building:
        matched = [b for b in by_building if b.upper() == building.upper()]
        buildings_to_show = matched if matched else [building]

    lines: list[str] = []

    for bldg in buildings_to_show:
        devs = by_building.get(bldg, [])
        if not devs:
            continue

        lines.append(f"=== Building {bldg} ({len(devs)} devices) ===")

        # Devices by role
        by_role: dict[str, list[dict]] = {}
        for d in devs:
            by_role.setdefault(d["role"] or "unknown", []).append(d)

        lines.append("")
        lines.append("Devices:")
        for role, role_devs in sorted(by_role.items()):
            for d in role_devs:
                cluster_tag = ""
                if d.get("cluster_size") and d["cluster_size"] > 1:
                    cluster_tag = f" [{d['cluster_size']}-member HA]"
                lines.append(f"  {d['name']} — {role} ({d.get('os_type', '?')}){cluster_tag}")

        # Redundancy summary
        ha_devices = [d for d in devs if d.get("cluster_size") and d["cluster_size"] > 1]
        standalone = [d for d in devs if not d.get("cluster_size") or d["cluster_size"] <= 1]
        lines.append("")
        lines.append("Redundancy:")
        if ha_devices:
            lines.append(f"  HA clusters: {len(ha_devices)} device(s) in clusters")
            for d in ha_devices:
                lines.append(f"    {d['name']} — {d['cluster_size']}-member cluster")
        if standalone:
            lines.append(f"  Standalone: {len(standalone)} device(s)")

        # OSPF areas
        areas = ospf_by_building.get(bldg, [])
        if areas:
            lines.append("")
            lines.append(f"OSPF areas ({len(areas)}): {', '.join(sorted(areas))}")

        # BGP sessions
        bgp_sessions = bgp_by_building.get(bldg, [])
        if bgp_sessions:
            # Deduplicate bidirectional
            seen = set()
            unique_bgp: list[dict] = []
            for s in bgp_sessions:
                key = tuple(sorted([s["device"], s["peer"]]))
                if key not in seen:
                    seen.add(key)
                    unique_bgp.append(s)
            lines.append("")
            lines.append(f"BGP sessions ({len(unique_bgp)}):")
            for s in unique_bgp:
                bgp_type = (s.get("bgp_type") or "iBGP").upper()
                remote_as = s.get("remote_as") or s.get("local_as") or "?"
                lines.append(f"  {s['device']} ↔ {s['peer']} — {bgp_type} (AS {remote_as})")

        # Uplinks to other buildings
        bldg_uplinks = [
            u for u in uplinks
            if u["bldg_a"] == bldg or u["bldg_b"] == bldg
        ]
        if bldg_uplinks:
            lines.append("")
            lines.append("Uplinks to other buildings:")
            for u in bldg_uplinks:
                remote_bldg = u["bldg_b"] if u["bldg_a"] == bldg else u["bldg_a"]
                lines.append(
                    f"  → {remote_bldg}: {u['dev_a']} ↔ {u['dev_b']} ({u['cables']} cable(s))"
                )

        # Findings
        bldg_device_names = {d["name"] for d in devs}
        bldg_findings = {
            d: finding_counts[d]
            for d in bldg_device_names
            if d in finding_counts
        }
        if bldg_findings:
            total = sum(c["total"] for c in bldg_findings.values())
            critical = sum(c["critical"] for c in bldg_findings.values())
            high = sum(c["high"] for c in bldg_findings.values())
            lines.append("")
            lines.append(f"Findings: {total} total ({critical} critical, {high} high)")
            # Show per-device if any have critical
            devices_with_critical = [
                (d, c) for d, c in bldg_findings.items() if c["critical"] > 0
            ]
            if devices_with_critical:
                for d, c in sorted(devices_with_critical, key=lambda x: -x[1]["critical"]):
                    lines.append(f"  {d}: {c['total']} findings ({c['critical']} critical)")

        lines.append("")

    # ── Network-wide summary (when no building filter) ──────────────
    if not building and len(by_building) > 1:
        total_devices = len(devices)
        total_buildings = len(by_building)
        total_findings = sum(c["total"] for c in finding_counts.values())
        total_critical = sum(c["critical"] for c in finding_counts.values())
        lines.append(f"Network summary: {total_buildings} buildings, {total_devices} devices, "
                      f"{total_findings} findings ({total_critical} critical)")

    return "\n".join(lines)


def _load_finding_counts(context: dict) -> dict[str, dict]:
    """Load finding counts per device — uses canonical Neo4j-first loader."""
    counts: dict[str, dict] = {}
    run_id = context.get("run_id", "")
    if not run_id:
        return counts

    findings = load_findings_enriched(run_id) or []
    for f in findings:
        d = device_from_finding(f)
        if not d:
            continue
        sev = f.get("severity", "info")
        if d not in counts:
            counts[d] = {"total": 0, "critical": 0, "high": 0, "low": 0, "info": 0}
        counts[d]["total"] += 1
        if sev in counts[d]:
            counts[d][sev] += 1

    return counts
