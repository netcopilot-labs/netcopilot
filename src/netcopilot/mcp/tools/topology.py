"""query_topology — network structure from Neo4j.

First tool called in most conversations. Returns devices, physical links,
and routing adjacencies for a site/run.
"""

import logging

from netcopilot.graph.client import get_driver, get_site_for_run, is_available

log = logging.getLogger(__name__)


async def query_topology(
    *,
    site: str | None = None,
    device_filter: str | None = None,
    include_links: bool = True,
    include_services: bool = False,
    context: dict,
) -> str:
    """Get network topology: devices, physical links, routing adjacencies."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Cannot query topology."

    driver = get_driver()

    # Resolve site from run_id if not provided
    if not site and run_id:
        site = get_site_for_run(run_id)

    with driver.session() as session:
        # ── Devices ──────────────────────────────────────────────────────
        device_query = (
            "MATCH (d:Device {run_id: $run_id}) "
            "RETURN d.name AS name, d.role AS role, d.platform AS platform, "
            "d.os_type AS os_type, d.os_version AS os_version, d.site AS site, "
            "d.collected AS collected "
            "ORDER BY d.name"
        )
        result = session.run(device_query, run_id=run_id)
        all_devices = [dict(r) for r in result]

        # Classify devices
        managed = [d for d in all_devices if d.get("role")]
        external = [d for d in all_devices if not d.get("role")]
        reachable = [d for d in managed if d.get("collected") is not False]
        unreachable = [d for d in managed if d.get("collected") is False]

        # Apply device_filter if provided
        devices = managed  # default: show managed devices
        if device_filter:
            import re
            filt = device_filter.lower()
            # Normalize shorthand: "SW01" → "sw-01"
            if '-' not in filt:
                filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
            devices = [d for d in managed if filt in (d["name"] or "").lower()]
            # Warn if filter is too broad (single char matches too many)
            if len(devices) > 5 and len(filt) <= 2:
                devices = devices[:5]
                log.info("Device filter '%s' too broad (%d matches), limited to 5", device_filter, len(devices))

        if not devices and not external:
            # Not a device — check if it's a service/customer name
            if device_filter:
                svc_result = session.run(
                    "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                    "WHERE toLower(i.description) CONTAINS toLower($name) "
                    "AND i.status = 'up' "
                    "RETURN DISTINCT d.name AS device, i.name AS intf, i.description AS desc "
                    "ORDER BY d.name LIMIT 10",
                    run_id=run_id, name=device_filter,
                )
                svc_matches = [dict(r) for r in svc_result]
                if svc_matches:
                    svc_lines = [
                        f"'{device_filter}' is not a device — it's a service/customer found on:",
                    ]
                    for m in svc_matches:
                        svc_lines.append(f"  {m['device']} — {m['intf']}: {m['desc']}")
                    svc_lines.append("")
                    svc_lines.append(f"Use trace_path(service=\"{device_filter}\") to trace the traffic path.")
                    return "\n".join(svc_lines)
            return f"No devices found for run {run_id}" + (
                f" matching '{device_filter}'" if device_filter else ""
            )

        # ── Build output ─────────────────────────────────────────────────
        if device_filter:
            lines = [
                f"Topology — site: {site or 'unknown'} | run: {run_id}",
                f"Matching devices: {len(devices)}",
                "",
                "Devices:",
            ]
        else:
            lines = [
                f"Topology — site: {site or 'unknown'} | run: {run_id}",
                f"Managed devices: {len(managed)} ({len(reachable)} reachable, "
                f"{len(unreachable)} unreachable) | "
                f"External peers: {len(external)}",
                "",
                "Devices:",
            ]
        for d in devices:
            parts = [f"  {d['name']:<25}"]
            if d.get("role"):
                parts.append(f"{d['role']:<20}")
            if d.get("platform"):
                parts.append(d["platform"])
            if d.get("os_version"):
                parts.append(f"({d['os_version']})")
            lines.append(" ".join(parts))

        if unreachable and not device_filter:
            lines.extend(["", "Unreachable devices:"])
            for d in unreachable:
                parts = [f"  {d['name']:<25}"]
                if d.get("role"):
                    parts.append(f"{d['role']:<20}")
                parts.append("(collection failed)")
                lines.append(" ".join(parts))

        if external and not device_filter:  # External peers only shown without filter
            lines.extend(["", "External BGP peers:"])
            for d in external:
                lines.append(f"  {d['name']}")

        # ── Physical links ───────────────────────────────────────────────
        if include_links:
            # Physical cables only (confirmed discovery methods)
            # Use CASE to canonicalize direction (alphabetical) for dedup
            cable_query = (
                "MATCH (d1:Device {run_id: $run_id})-[r]->(d2:Device {run_id: $run_id}) "
                "WHERE type(r) IN ['PHYSICAL_CABLE', 'INFRASTRUCTURE_LINK'] "
                "WITH CASE WHEN d1.name < d2.name THEN d1.name ELSE d2.name END AS src, "
                "     CASE WHEN d1.name < d2.name THEN d2.name ELSE d1.name END AS dst, "
                "     r, type(r) AS link_type "
                "RETURN DISTINCT src, dst, link_type, "
                "r.discovery_method AS discovery, r.confidence AS confidence, "
                "r.local_interface AS local_port, r.remote_interface AS remote_port "
                "ORDER BY src, dst"
            )
            result = session.run(cable_query, run_id=run_id)
            cables = [dict(r) for r in result]

            # Filter cables to only those involving filtered devices
            if device_filter:
                cables = [c for c in cables
                          if filt in (c["src"] or "").lower()
                          or filt in (c["dst"] or "").lower()]

            # Build interface media_type lookup
            media_result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                "WHERE i.media_type IS NOT NULL "
                "RETURN d.name + ':' + i.name AS key, i.media_type AS media",
                run_id=run_id,
            )
            media_map = {r["key"]: r["media"] for r in media_result}

            if cables:
                lines.extend(["", f"Physical cables ({len(cables)}):"])
                for lk in cables:
                    disc = f" [{lk.get('discovery', '?')}]" if lk.get("discovery") else ""
                    ports = ""
                    media = ""
                    lp = lk.get("local_port", "")
                    rp = lk.get("remote_port", "")
                    if lp and rp:
                        ports = f" ({lp} ↔ {rp})"
                    # Lookup media type — try all 4 combinations since
                    # CASE WHEN canonicalization may swap src/dst vs port direction
                    m = (media_map.get(f"{lk['src']}:{lp}", "")
                         or media_map.get(f"{lk['dst']}:{rp}", "")
                         or media_map.get(f"{lk['dst']}:{lp}", "")
                         or media_map.get(f"{lk['src']}:{rp}", ""))
                    if m:
                        media = f" [{m}]"
                    lines.append(
                        f"  {lk['src']} <-> {lk['dst']}{ports}{disc}{media}"
                    )

            # Management OOB cables: confirmed methods OR mgmt_port ↔ mgmt_switch
            # Note: 'mgmt_switch' role comes from inventory YAML, not hardcoded.
            # Different networks may use different role names — update query if needed.
            # IOS XR mgmt ports don't run CDP, so the anti-orphan rescue in
            # topology.py uses the same rule: arp_subnet from a mgmt port to
            # a mgmt_switch proves a cable exists.
            # Confirmed mgmt cables (CDP/LACP/FDB)
            mgmt_confirmed_query = (
                "MATCH (d1:Device {run_id: $run_id})-[r:MGMT_LINK]->(d2:Device {run_id: $run_id}) "
                "WHERE r.mgmt_type = 'oob' "
                "AND r.discovery_method IN ['cdp_bilateral', 'cdp_unilateral', "
                "  'lacp_bilateral', 'fdb_mgmt'] "
                "WITH CASE WHEN d1.name < d2.name THEN d1.name ELSE d2.name END AS src, "
                "     CASE WHEN d1.name < d2.name THEN d2.name ELSE d1.name END AS dst, "
                "     r "
                "RETURN DISTINCT src, dst, "
                "r.discovery_method AS discovery, "
                "r.local_interface AS local_port, r.remote_interface AS remote_port "
                "ORDER BY src, dst"
            )
            result = session.run(mgmt_confirmed_query, run_id=run_id)
            raw_mgmt = [dict(r) for r in result]

            # Deduplicate by device pair
            seen_pairs = set()
            mgmt_cables = []
            for lk in raw_mgmt:
                pair = tuple(sorted([lk["src"], lk["dst"]]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    mgmt_cables.append(lk)

            # IOS XR mgmt ports don't run CDP — add probable cables
            # where a mgmt port has ARP to a mgmt_switch and no confirmed cable exists
            mgmt_probable_query = (
                "MATCH (d1:Device {run_id: $run_id})-[r:MGMT_LINK]->(d2:Device {run_id: $run_id}) "
                "WHERE r.mgmt_type = 'oob' "
                "AND r.discovery_method IN ['arp_subnet', 'mac_subnet'] "
                "AND d2.role = 'mgmt_switch' "
                "AND (r.local_interface STARTS WITH 'Mgmt' "
                "  OR r.local_interface STARTS WITH 'mgmt' "
                "  OR r.local_interface STARTS WITH 'Gi0/0' "
                "  OR r.local_interface STARTS WITH 'GigabitEthernet0/0' "
                "  OR r.local_interface STARTS WITH 'Management') "
                "RETURN d1.name AS src, d2.name AS dst, "
                "r.local_interface AS local_port, r.remote_interface AS remote_port "
                "ORDER BY d1.name"
            )
            result = session.run(mgmt_probable_query, run_id=run_id)
            for rec in result:
                pair = tuple(sorted([rec["src"], rec["dst"]]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    mgmt_cables.append({
                        **dict(rec), "discovery": "arp_inferred",
                    })

            # Filter mgmt cables to device_filter — reuse the normalized `filt` from the
            # device block above. (The source reset it to the un-normalized value here, a
            # latent shorthand-filter bug; fixed in this extraction.)
            if device_filter:
                mgmt_cables = [c for c in mgmt_cables
                               if filt in (c["src"] or "").lower()
                               or filt in (c["dst"] or "").lower()]

            if mgmt_cables:
                lines.extend(["", f"Management OOB cables ({len(mgmt_cables)}):"])
                for lk in mgmt_cables:
                    lp = lk.get("local_port", "")
                    rp = lk.get("remote_port", "")
                    ports = f" ({lp} ↔ {rp})" if lp and rp else ""
                    m = (media_map.get(f"{lk['src']}:{lp}", "")
                         or media_map.get(f"{lk['dst']}:{rp}", "")
                         or media_map.get(f"{lk['dst']}:{lp}", "")
                         or media_map.get(f"{lk['src']}:{rp}", ""))
                    media = f" [{m}]" if m else ""
                    lines.append(f"  {lk['src']} <-> {lk['dst']}{ports}{media}")

            # ── Routing adjacencies ──────────────────────────────────────
            adj_query = (
                "MATCH (d1:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]->"
                "(d2:Device {run_id: $run_id}) "
                "RETURN d1.name AS src, d2.name AS dst, "
                "r.protocol AS protocol, r.state AS state, r.area AS area, "
                "r.local_as AS local_as, r.remote_as AS remote_as "
                "ORDER BY r.protocol, d1.name"
            )
            result = session.run(adj_query, run_id=run_id)
            adjs = [dict(r) for r in result]

            # Filter adjacencies to device_filter
            if device_filter:
                adjs = [a for a in adjs
                        if filt in (a["src"] or "").lower()
                        or filt in (a["dst"] or "").lower()]

            if adjs:
                lines.extend(["", f"Routing adjacencies ({len(adjs)}):"])
                for adj in adjs:
                    proto = (adj.get("protocol") or "?").upper()
                    state = adj.get("state", "?")
                    extra = ""
                    if adj.get("area"):
                        extra = f" area {adj['area']}"
                    if adj.get("local_as") and adj.get("remote_as"):
                        extra += f" AS{adj['local_as']}→AS{adj['remote_as']}"
                    lines.append(
                        f"  {proto}: {adj['src']} → {adj['dst']}  {state}{extra}"
                    )

        # ── Shared services ──────────────────────────────────────────────
        if include_services:
            svc_query = (
                "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->(s:SharedService) "
                "RETURN s.service_type AS type, s.name AS name, "
                "collect(d.name) AS members "
                "ORDER BY s.service_type, s.name"
            )
            result = session.run(svc_query, run_id=run_id)
            services = [dict(r) for r in result]

            if services:
                lines.extend(["", f"Shared services ({len(services)}):"])
                for svc in services:
                    members = ", ".join(sorted(svc["members"]))
                    lines.append(f"  [{svc['type']}] {svc['name']}: {members}")

    return "\n".join(lines)
