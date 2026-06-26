"""get_redundancy_assessment — network-wide redundancy and SPOF analysis.

Checks every device for HA/cluster status and path redundancy.
Identifies real single points of failure — devices with no HA AND
no redundant upstream path. Shows what gets isolated if each SPOF fails.
"""

import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_redundancy_assessment(
    *,
    device: str | None = None,
    context: dict,
) -> str:
    """Assess network redundancy — identify real single points of failure."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j unavailable."

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
                return f"Device '{device}' not found."

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
            return f"No assessment for '{device}'."
        return _format_device_assessment(a, devices, neighbors)

    # ── Network-wide assessment ────────────────────────────────────
    return _format_network_assessment(assessments)


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
