"""get_redundancy_assessment — network-wide redundancy and SPOF analysis.

Checks every device for HA/cluster status and path redundancy.
Identifies real single points of failure — devices with no HA AND
no redundant upstream path. Shows what gets isolated if each SPOF fails.
"""

import logging

from netcopilot.graph.client import get_driver, is_available

from netcopilot.mcp.result import ToolResult

log = logging.getLogger(__name__)


def _fhrp_gateway_block(driver, run_id: str) -> tuple[list[str], dict]:
    """Gateway (FHRP) redundancy section for the network-wide assessment.

    Reads the fhrp_group SharedServices; a group with fewer than 2 members (or no
    active router) is an unprotected gateway. Members are ENUMERATED (hostname,
    real IP, role, priority) so "how is VRRP configured?" is answered completely
    in one call — the 2026-07-11 edge audit measured the summary-only version
    costing a 9-call drill-down for detail the graph already held (s22-1).
    """
    import json

    with driver.session() as session:
        result = session.run(
            "MATCH (svc:SharedService {service_type: 'fhrp_group', run_id: $run_id}) "
            "OPTIONAL MATCH (d:Device)-[:MEMBER_OF]->(svc) "
            "WITH svc, count(d) AS members "
            "RETURN svc.protocol AS proto, svc.group_number AS grp, svc.vip AS vip, "
            "svc.interface AS intf, svc.active_device AS active, members, "
            "svc.members_json AS members_json "
            "ORDER BY svc.vip",
            run_id=run_id,
        )
        rows = [dict(r) for r in result]
    if not rows:
        return [], {"fhrp_groups": 0, "fhrp_unprotected": 0, "fhrp_members": 0}

    unprotected = [r for r in rows if (r["members"] or 0) < 2 or not r["active"]]
    total_members = 0
    lines = ["", f"Gateway redundancy (FHRP) — {len(rows)} group(s):"]
    for r in rows:
        proto = (r["proto"] or "fhrp").upper()
        if (r["members"] or 0) < 2:
            status = "⚠ UNPROTECTED (no standby peer)"
        elif not r["active"]:
            status = "⚠ no active router"
        else:
            status = f"redundant (active {r['active']})"
        lines.append(f"  {r['intf']} {proto} grp {r['grp']} VIP {r['vip']} — {status}")
        try:
            member_detail = json.loads(r["members_json"]) if r.get("members_json") else []
        except (json.JSONDecodeError, TypeError):
            member_detail = []
        total_members += len(member_detail)
        for m in member_detail:
            role = m.get("state") or "participant"
            ip = f" {m.get('ip')}" if m.get("ip") else ""
            pri = f" pri {m.get('priority')}" if m.get("priority") is not None else ""
            marker = "→" if m.get("hostname") == r["active"] else " "
            lines.append(f"    {marker} {m.get('hostname')}{ip} — {role}{pri}")
    return lines, {"fhrp_groups": len(rows), "fhrp_unprotected": len(unprotected),
                   "fhrp_members": total_members}


def _lag_uplink_block(driver, run_id: str) -> tuple[list[str], dict, list[dict]]:
    """Link-aggregation (LACP) state for the network-wide assessment (s22).

    Reads the first-class bundle state off the Port-channel Interface nodes.
    A single-member bundle is aggregation WITHOUT member redundancy — said
    aloud as narrative (deliberately not invented as a rule; not in the
    catalog). Returns the rows too so the caller can cross-reference the
    FHRP peer interconnect without a second query.
    """
    import json

    with driver.session() as session:
        # Peer resolution is member-based and direction-aware: the physical
        # link is stored between the MEMBER interfaces (Gi1/0/1↔Gi1/0/5, CDP/
        # LACP), not Po↔Po — and l.local_interface names the startNode's side,
        # so the member-list match must check which end of the relationship
        # this device is (a plain OR over both sides can pick a wrong peer
        # whose port happens to share a name like Gi1/0/1).
        rows = [dict(r) for r in session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.lag_protocol IS NOT NULL "
            "OPTIONAL MATCH (d)-[l]-(p:Device {run_id: $run_id}) "
            "WHERE type(l) IN ['PHYSICAL_CABLE', 'INFRASTRUCTURE_LINK'] "
            "AND ((startNode(l) = d AND (l.local_interface IN i.port_channel_members "
            "                            OR l.local_interface = i.name)) "
            "  OR (startNode(l) = p AND (l.remote_interface IN i.port_channel_members "
            "                            OR l.remote_interface = i.name))) "
            "RETURN d.name AS device, i.name AS po, i.lag_protocol AS protocol, "
            "i.lag_oper_status AS status, i.lag_members_json AS members_json, "
            "collect(DISTINCT p.name) AS peers "
            "ORDER BY d.name, i.name",
            run_id=run_id,
        )]
    if not rows:
        return [], {"lag_bundles": 0, "lag_degraded": 0, "lag_single_member": 0}, []

    degraded = single = 0
    lines = ["", f"Link aggregation (LACP) — {len(rows)} bundle end(s):"]
    for r in rows:
        try:
            members = json.loads(r["members_json"]) if r.get("members_json") else []
        except (json.JSONDecodeError, TypeError):
            members = []
        r["_members"] = members
        bundled = [m for m in members if m.get("bundled")]
        peer = f" → {', '.join(p for p in r['peers'] if p)}" if any(r["peers"]) else ""
        detail = ", ".join(m["name"] for m in bundled) or "none"
        line = (f"  {r['device']} {r['po']} [{r['protocol']}, {r['status'] or '?'}] — "
                f"{len(bundled)}/{len(members)} member(s) bundled ({detail}){peer}")
        notes = []
        if r["status"] not in ("up", None) or len(bundled) < len(members):
            degraded += 1
            notes.append("⚠ DEGRADED")
        if len(members) == 1:
            single += 1
            notes.append("⚠ single member — no member redundancy")
        if notes:
            line += "  " + " ".join(notes)
        lines.append(line)
    return lines, {"lag_bundles": len(rows), "lag_degraded": degraded,
                   "lag_single_member": single}, rows


async def get_redundancy_assessment(
    *,
    device: str | None = None,
    context: dict,
) -> ToolResult:
    """Assess network redundancy — identify real single points of failure."""
    run_id = context.get("run_id", "")

    if not is_available():
        return ToolResult("error", "Neo4j unavailable.")

    driver = get_driver()

    # Resolve device if provided
    if device:
        import re
        filt = device.lower()
        if '-' not in filt:
            filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt AND d.role IS NOT NULL "
                "RETURN d.name AS name LIMIT 1",
                run_id=run_id, filt=filt,
            )
            rec = result.single()
            if rec:
                device = rec["name"]
            else:
                return ToolResult("not_found", f"Device '{device}' not found.")

    # ── Gather all device data from Neo4j ──────────────────────────
    with driver.session() as session:
        # Device properties
        result = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE d.role IS NOT NULL "
            "RETURN d.name AS name, d.role AS role, d.cluster_size AS cluster_size, "
            "d.building AS building, d.collected AS collected, d.os_type AS os_type "
            "ORDER BY d.name",
            run_id=run_id,
        )
        devices = {r["name"]: dict(r) for r in result}

        # Physical cable neighbors per device with cable count (for LAG detection)
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[link:PHYSICAL_CABLE]-(n:Device) "
            "WHERE d.role IS NOT NULL AND n.role IS NOT NULL "
            "RETURN d.name AS dev, n.name AS neighbor, count(link) AS cables",
            run_id=run_id,
        )
        # neighbors: {dev: [neighbor_names]}
        # cables_per_pair: {(dev, neighbor): cable_count}
        neighbors: dict[str, list[str]] = {}
        cables_per_pair: dict[tuple[str, str], int] = {}
        for r in result:
            neighbors.setdefault(r["dev"], [])
            if r["neighbor"] not in neighbors[r["dev"]]:
                neighbors[r["dev"]].append(r["neighbor"])
            cables_per_pair[(r["dev"], r["neighbor"])] = r["cables"]

        # HA member affinity: for cables to HA devices, which member does each
        # stack member connect to? (expert case: stacked device → single HA member)
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[link:PHYSICAL_CABLE]-(n:Device) "
            "WHERE d.cluster_size >= 2 AND n.cluster_size >= 2 "
            "AND link.source_member_id IS NOT NULL "
            "AND link.target_member_id IS NOT NULL "
            "RETURN d.name AS dev, n.name AS neighbor, "
            "link.source_member_id AS src_mid, link.target_member_id AS tgt_mid",
            run_id=run_id,
        )
        # ha_affinity: {(stacked_dev, ha_neighbor): {src_member: set(tgt_members)}}
        ha_affinity: dict[tuple[str, str], dict[int, set[int]]] = {}
        for r in result:
            key = (r["dev"], r["neighbor"])
            ha_affinity.setdefault(key, {})
            ha_affinity[key].setdefault(r["src_mid"], set()).add(r["tgt_mid"])

    # ── Classify each device ───────────────────────────────────────
    assessments = []
    for name, dev in devices.items():
        role = dev["role"] or ""
        cluster_size = dev["cluster_size"] or 1
        building = dev["building"] or "unknown"
        collected = dev["collected"]
        phys_neighbors = neighbors.get(name, [])

        has_ha = cluster_size >= 2
        ha_type = None
        if has_ha:
            if "fortios" in (dev.get("os_type") or ""):
                ha_type = "FortiGate HA"
            else:
                ha_type = "StackWise Virtual"

        # Determine upstream devices (devices this one depends on)
        # and downstream devices (devices that depend on this one)
        upstream = []
        downstream = []
        for nbr_name in phys_neighbors:
            nbr = devices.get(nbr_name, {})
            nbr_role = nbr.get("role", "")
            # Upstream: core > distribution > TOC > access
            if _is_upstream(role, nbr_role):
                upstream.append(nbr_name)
            else:
                downstream.append(nbr_name)

        # Check LAG protection: single neighbor but multiple cables = LAG
        has_lag_uplink = False
        if len(upstream) == 1:
            cable_count = cables_per_pair.get((name, upstream[0]), 0)
            if cable_count >= 2:
                has_lag_uplink = True

        # Check HA member affinity (expert case):
        # If this device is stacked and connects to an HA device,
        # check if each stack member reaches BOTH HA members.
        ha_affinity_risk = None
        if has_ha and cluster_size >= 2:
            for nbr_name in phys_neighbors:
                nbr = devices.get(nbr_name, {})
                nbr_cluster = nbr.get("cluster_size") or 1
                if nbr_cluster >= 2:
                    affinity = ha_affinity.get((name, nbr_name), {})
                    for src_mid, tgt_mids in affinity.items():
                        if len(tgt_mids) < 2:
                            # This stack member connects to only one HA member
                            ha_affinity_risk = {
                                "device": name,
                                "src_member": src_mid,
                                "neighbor": nbr_name,
                                "tgt_member": next(iter(tgt_mids)),
                            }

        # Determine redundancy status
        if not collected:
            status = "unreachable"
            risk = "unknown"
        elif has_ha and len(upstream) >= 2:
            status = "fully_redundant"
            risk = "low"
        elif has_ha:
            status = "ha_protected"
            risk = "low"
        elif len(upstream) >= 2:
            status = "path_redundant"
            risk = "moderate"
        elif len(upstream) == 1 and has_lag_uplink:
            status = "lag_protected"
            risk = "moderate"
        elif len(upstream) == 1:
            status = "single_uplink"
            risk = "high"
        elif len(upstream) == 0 and len(downstream) > 0:
            if len(phys_neighbors) >= 2:
                status = "multi_connected"
                risk = "moderate"
            else:
                status = "single_connected"
                risk = "high"
        else:
            status = "isolated"
            risk = "critical"

        # What gets isolated if this device fails
        isolated = []
        if downstream:
            for ds_name in downstream:
                ds_neighbors = neighbors.get(ds_name, [])
                # If downstream device's ONLY upstream is this device
                ds_upstreams = [n for n in ds_neighbors
                                if n != name and _is_upstream(
                                    devices.get(ds_name, {}).get("role", ""),
                                    devices.get(n, {}).get("role", "")
                                )]
                if not ds_upstreams:
                    isolated.append(ds_name)

        assessments.append({
            "name": name,
            "role": role,
            "building": building,
            "cluster_size": cluster_size,
            "has_ha": has_ha,
            "ha_type": ha_type,
            "has_lag_uplink": has_lag_uplink,
            "ha_affinity_risk": ha_affinity_risk,
            "upstream": upstream,
            "downstream": downstream,
            "status": status,
            "risk": risk,
            "isolated_on_failure": isolated,
        })

    # ── Filter to specific device if requested ─────────────────────
    if device:
        a = next((a for a in assessments if a["name"] == device), None)
        if not a:
            return ToolResult("not_found", f"No assessment for '{device}'.")
        return ToolResult(
            "ok",
            _format_device_assessment(a, devices, neighbors),
            verdict={"status": a["status"], "risk": a["risk"]},
        )

    # ── Network-wide assessment ────────────────────────────────────
    verdict = {
        "devices": len(assessments),
        "ha_protected": sum(1 for a in assessments if a["has_ha"]),
        "spof_no_ha": sum(
            1 for a in assessments
            if a["isolated_on_failure"] and not a["has_ha"]
            and a["status"] != "unreachable"
        ),
        "single_uplink": sum(1 for a in assessments if a["status"] == "single_uplink"),
        "unreachable": sum(1 for a in assessments if a["status"] == "unreachable"),
    }
    fhrp_lines, fhrp_verdict = _fhrp_gateway_block(driver, run_id)
    verdict.update(fhrp_verdict)
    lag_lines, lag_verdict, lag_rows = _lag_uplink_block(driver, run_id)
    verdict.update(lag_verdict)

    # ── FHRP-over-LAG correlation (s22-5) ────────────────────────────────
    # The gateway peers usually interconnect over a bundle; if that bundle
    # has a single member, the whole gateway redundancy rides ONE cable —
    # exactly the "is the active gateway's uplink itself redundant?"
    # question (2026-07-10). Cross-referenced from data already fetched.
    if fhrp_lines and lag_rows:
        noted_pairs: set[tuple] = set()   # both bundle ends describe ONE interconnect
        for r in lag_rows:
            peers = [p for p in r["peers"] if p]
            if len(r.get("_members", [])) == 1 and peers:
                pair = tuple(sorted([r["device"], *peers]))
                if pair in noted_pairs:
                    continue
                noted_pairs.add(pair)
                fhrp_lines.append(
                    f"  ⚠ note: {' ↔ '.join(pair)} interconnect via {r['po']} "
                    f"(single-member bundle) — gateway failover between them "
                    f"depends on one physical link")

    text = _format_network_assessment(assessments)
    if fhrp_lines:
        text += "\n" + "\n".join(fhrp_lines)
    if lag_lines:
        text += "\n" + "\n".join(lag_lines)
    return ToolResult("ok", text, verdict=verdict)


def _is_upstream(device_role: str, neighbor_role: str) -> bool:
    """Determine if neighbor is upstream (higher in the hierarchy)."""
    # Standard access/aggregation hierarchy. Unknown roles default to the
    # access tier (5), so any site-specific role names degrade gracefully.
    hierarchy = {
        "border_router": 1,
        "core_switch": 2,
        "firewall": 2,
        "distribution_switch": 3,
        "dmz_switch": 4,
        "mgmt_switch": 4,
        "access_switch": 5,
    }
    dev_level = hierarchy.get(device_role, 5)
    nbr_level = hierarchy.get(neighbor_role, 5)
    return nbr_level < dev_level


def _format_device_assessment(a: dict, devices: dict, neighbors: dict) -> str:
    """Format a single device's redundancy assessment."""
    lines = [f"Redundancy assessment — {a['name']}"]
    lines.append(f"  Role: {a['role']} | Building: {a['building']}")

    if a["has_ha"]:
        lines.append(f"  HA: {a['ha_type']} ({a['cluster_size']} members)")
    else:
        lines.append(f"  HA: none")

    lines.append(f"  Upstream paths: {len(a['upstream'])}")
    for u in a["upstream"]:
        dev = devices.get(u, {})
        ha = f" [{dev.get('cluster_size', 1) or 1}-member HA]" if (dev.get("cluster_size") or 1) >= 2 else ""
        lines.append(f"    → {u} ({dev.get('role', '?')}){ha}")

    lines.append(f"  Downstream devices: {len(a['downstream'])}")
    for d in a["downstream"]:
        lines.append(f"    ← {d} ({devices.get(d, {}).get('role', '?')})")

    lines.append(f"  Status: {a['status']} (risk: {a['risk']})")

    if a["isolated_on_failure"]:
        lines.append(f"  ⚠ If {a['name']} fails, {len(a['isolated_on_failure'])} device(s) lose ALL connectivity:")
        for iso in a["isolated_on_failure"]:
            lines.append(f"    ✗ {iso} ({devices.get(iso, {}).get('role', '?')})")

    return "\n".join(lines)


def _format_network_assessment(assessments: list[dict]) -> str:
    """Format network-wide redundancy assessment."""
    lines = ["Redundancy assessment — Network overview", ""]

    # HA-protected devices
    ha_devices = [a for a in assessments if a["has_ha"]]
    no_ha = [a for a in assessments if not a["has_ha"] and a["status"] != "unreachable"]
    unreachable = [a for a in assessments if a["status"] == "unreachable"]

    lines.append(f"HA-protected devices ({len(ha_devices)}):")
    for a in ha_devices:
        lines.append(f"  ✓ {a['name']} ({a['role']}) — {a['ha_type']}, {a['cluster_size']} members")
    lines.append("")

    # Real SPOFs: devices whose failure isolates downstream devices
    spofs = [a for a in assessments if a["isolated_on_failure"] and a["status"] != "unreachable"]
    spofs.sort(key=lambda x: -len(x["isolated_on_failure"]))

    # Split SPOFs: devices WITH HA that still isolate downstream vs devices WITHOUT HA
    spofs_no_ha = [a for a in spofs if not a["has_ha"]]
    spofs_with_ha = [a for a in spofs if a["has_ha"]]

    if spofs_no_ha:
        lines.append(f"Single points of failure — no HA ({len(spofs_no_ha)}):")
        for a in spofs_no_ha:
            isolated_names = ", ".join(a["isolated_on_failure"])
            lines.append(
                f"  ⚠ {a['name']} ({a['role']}, {a['building']}) — "
                f"failure isolates {len(a['isolated_on_failure'])} device(s): "
                f"{isolated_names}"
            )
        lines.append("")

    if spofs_with_ha:
        lines.append(f"Devices with HA but downstream SPOFs ({len(spofs_with_ha)}):")
        for a in spofs_with_ha:
            isolated_names = ", ".join(a["isolated_on_failure"])
            lines.append(
                f"  ~ {a['name']} ({a['role']}, {a['ha_type']}) — "
                f"HA protects this device, but full stack failure "
                f"isolates {len(a['isolated_on_failure'])} device(s): "
                f"{isolated_names}"
            )
        lines.append("")

    # Devices with no HA but path redundancy
    path_redundant = [a for a in no_ha if a["status"] == "path_redundant"]
    if path_redundant:
        lines.append(f"No HA but path-redundant ({len(path_redundant)}):")
        for a in path_redundant:
            lines.append(f"  ~ {a['name']} ({a['role']}) — {len(a['upstream'])} upstream paths")
        lines.append("")

    # LAG-protected devices (single neighbor but multiple cables)
    lag_protected = [a for a in no_ha if a["status"] == "lag_protected"]
    if lag_protected:
        lines.append(f"LAG-protected (single neighbor, multiple cables) ({len(lag_protected)}):")
        for a in lag_protected:
            upstream_name = a["upstream"][0] if a["upstream"] else "?"
            lines.append(f"  {a['name']} ({a['role']}, {a['building']}) → {upstream_name} (LAG)")
        lines.append("")

    # Truly single-uplink devices
    single = [a for a in no_ha if a["status"] == "single_uplink" and not a["isolated_on_failure"]]
    if single:
        lines.append(f"Single uplink — no LAG ({len(single)}):")
        for a in single:
            upstream_name = a["upstream"][0] if a["upstream"] else "?"
            lines.append(f"  ⚠ {a['name']} ({a['role']}, {a['building']}) → {upstream_name}")
        lines.append("")

    # HA member affinity risks (expert case)
    affinity_risks = [a for a in assessments if a.get("ha_affinity_risk")]
    if affinity_risks:
        lines.append(f"HA member affinity risk ({len(affinity_risks)}):")
        for a in affinity_risks:
            ar = a["ha_affinity_risk"]
            lines.append(
                f"  ⚠ {a['name']} member {ar['src_member']} connects only to "
                f"{ar['neighbor']} member {ar['tgt_member']} — if that HA member "
                f"fails, this stack member loses connectivity despite HA"
            )
        lines.append("")

    if unreachable:
        lines.append(f"Unreachable ({len(unreachable)}):")
        for a in unreachable:
            lines.append(f"  ? {a['name']} ({a['role']}, {a['building']})")
        lines.append("")

    # Summary
    total = len(assessments)
    lines.append("Summary:")
    lines.append(f"  Total devices: {total}")
    lines.append(f"  HA-protected: {len(ha_devices)}")
    lines.append(f"  Single points of failure: {len(spofs_no_ha)}")
    lines.append(f"  HA with downstream risk: {len(spofs_with_ha)}")
    lines.append(f"  Path-redundant (no HA): {len(path_redundant)}")
    lines.append(f"  LAG-protected: {len(lag_protected)}")
    lines.append(f"  Single-uplink (no LAG): {len(single)}")
    lines.append(f"  HA affinity risks: {len(affinity_risks)}")
    lines.append(f"  Unreachable: {len(unreachable)}")

    return "\n".join(lines)
