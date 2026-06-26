"""get_device_detail — full state for one device.

Queries Neo4j for device metadata, interfaces, routing adjacencies.
Reads the run's findings for device-specific findings.
"""

import json
import logging
from pathlib import Path

from netcopilot.findings import SEVERITY_ORDER, device_from_finding, load_findings_enriched
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)

VALID_SECTIONS = {"interfaces", "routing", "bgp", "ospf", "findings", "security"}


async def get_device_detail(
    *,
    device: str,
    sections: list[str] | None = None,
    context: dict,
) -> str:
    """Get full state for one device: interfaces, routing, BGP/OSPF, findings."""
    run_id = context.get("run_id", "")
    data_dir = context.get("data_dir")

    if not is_available():
        return "Neo4j is unavailable. Device detail requires the topology graph."

    driver = get_driver()

    # Validate and resolve device name
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $name}) "
            "RETURN d.name AS name, d.role AS role, d.platform AS platform, "
            "d.os_type AS os_type, d.os_version AS os_version, d.site AS site, "
            "d.cluster_size AS cluster_size, d.cluster_declared_size AS cluster_declared, "
            "d.cluster_members AS cluster_members, d.serial AS serial, "
            "d.is_route_reflector AS is_route_reflector, d.rr_cluster_id AS rr_cluster_id, "
            "d.collected AS collected",
            run_id=run_id, name=device,
        )
        record = result.single()
        if not record:
            # Try substring match with device name normalization
            import re
            filt = device.lower()
            if '-' not in filt:
                filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt "
                "RETURN d.name AS name, d.role AS role, d.platform AS platform, "
                "d.os_type AS os_type, d.os_version AS os_version, d.site AS site, "
                "d.cluster_size AS cluster_size, d.cluster_declared_size AS cluster_declared, "
                "d.cluster_members AS cluster_members, d.serial AS serial, "
                "d.is_route_reflector AS is_route_reflector, d.rr_cluster_id AS rr_cluster_id, "
                "d.collected AS collected "
                "LIMIT 1",
                run_id=run_id, filt=filt,
            )
            record = result.single()
            if not record:
                # Not a device — check if it's a service/customer name
                svc_result = session.run(
                    "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                    "WHERE toLower(i.description) CONTAINS toLower($name) "
                    "AND i.status = 'up' "
                    "RETURN DISTINCT d.name AS device, i.name AS intf, i.description AS desc "
                    "ORDER BY d.name LIMIT 10",
                    run_id=run_id, name=device,
                )
                svc_matches = [dict(r) for r in svc_result]
                if svc_matches:
                    devices_found = sorted(set(m["device"] for m in svc_matches))
                    lines = [
                        f"'{device}' is not a device — it's a service/customer found on {len(devices_found)} device(s):",
                    ]
                    for m in svc_matches:
                        lines.append(f"  {m['device']} — {m['intf']}: {m['desc']}")
                    lines.append("")
                    lines.append(f"Use trace_path(service=\"{device}\") to trace the traffic path.")
                    lines.append(f"Use get_device_detail(device=\"{devices_found[0]}\") for device details.")
                    return "\n".join(lines)
                return (
                    f"'{device}' not found as a device or service in run {run_id}. "
                    "Use query_topology to list available devices."
                )

    dev_data = dict(record)
    device = dev_data["name"]  # Use canonical name

    # Determine which sections to include
    requested = set(sections) & VALID_SECTIONS if sections else VALID_SECTIONS

    lines = [
        f"Device: {device}",
        f"  Role: {dev_data.get('role', '?')}",
        f"  Platform: {dev_data.get('platform', '?')}",
        f"  OS: {dev_data.get('os_type', '?')} {dev_data.get('os_version', '')}",
        f"  Site: {dev_data.get('site', '?')}",
    ]

    # BGP route-reflector role (config-only fact; genie's operational BGP omits it).
    if dev_data.get("is_route_reflector"):
        cid = dev_data.get("rr_cluster_id")
        lines.append("  BGP role: Route Reflector" + (f" (cluster-id {cid})" if cid else ""))

    # Cluster/HA information
    cluster_size = dev_data.get("cluster_size")
    if cluster_size and cluster_size > 1:
        lines.append(f"  Cluster: {cluster_size} members (StackWise Virtual / HA)")
        members_json = dev_data.get("cluster_members")
        if members_json:
            try:
                members = json.loads(members_json) if isinstance(members_json, str) else members_json
                for m in members:
                    role = m.get("role", "?")
                    serial = m.get("serial_number", "?")
                    state = m.get("state", "?")
                    mtype = m.get("member_type", "?")
                    lines.append(f"    Member {m.get('member_id', '?')}: {role} | {state} | {mtype} | SN: {serial}")
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning("Failed to parse cluster members for %s: %s", device, exc)
    elif dev_data.get("collected") is False:
        lines.append("  Status: UNREACHABLE (collection failed)")

    with driver.session() as session:
        # ── Interfaces ───────────────────────────────────────────────────
        if "interfaces" in requested:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $name})"
                "-[:HAS_INTERFACE]->(i:Interface) "
                "RETURN i.name AS name, i.status AS status, "
                "i.speed AS speed, i.ip AS ip, i.description AS description, "
                "i.access_vlan AS vlan, i.vrf AS vrf, "
                "i.port_channel_int AS lag_parent, i.port_channel_members AS lag_members "
                "ORDER BY i.name",
                run_id=run_id, name=device,
            )
            intfs = [dict(r) for r in result]

            lines.extend(["", f"Interfaces ({len(intfs)}):"])
            if intfs:
                for i in intfs:
                    status = i.get("status", "?")
                    ip_str = f" {i['ip']}" if i.get("ip") else ""
                    desc = f" — {i['description']}" if i.get("description") else ""
                    speed = f" {i['speed']}" if i.get("speed") else ""
                    vlan = f" VLAN:{i['vlan']}" if i.get("vlan") else ""
                    vrf = f" VRF:{i['vrf']}" if i.get("vrf") else ""
                    lag = ""
                    if i.get("lag_parent"):
                        lag = f" member-of:{i['lag_parent']}"
                    elif i.get("lag_members"):
                        lag = f" members:[{i['lag_members']}]"
                    lines.append(
                        f"  {i['name']:<30} {status:<6}{speed}{ip_str}{vlan}{vrf}{lag}{desc}"
                    )
            else:
                lines.append("  No interface data in graph.")

        # ── BGP ──────────────────────────────────────────────────────────
        if "bgp" in requested:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $name})"
                "-[r:ROUTING_ADJACENCY]-(peer:Device) "
                "WHERE r.protocol = 'bgp' "
                "RETURN DISTINCT peer.name AS peer, r.state AS state, "
                "r.local_as AS local_as, r.remote_as AS remote_as, "
                "r.peer_address AS peer_address, r.bgp_type AS bgp_type, "
                "r.session_type AS session_type, "
                "r.rr_client AS rr_client, r.rr_reflector AS rr_reflector "
                "ORDER BY peer.name",
                run_id=run_id, name=device,
            )
            bgp_sessions = [dict(r) for r in result]

            lines.extend(["", f"BGP sessions ({len(bgp_sessions)}):"])
            if bgp_sessions:
                for s in bgp_sessions:
                    state = s.get("state", "?")
                    peer_addr = f" ({s['peer_address']})" if s.get("peer_address") else ""
                    as_info = ""
                    if s.get("local_as") and s.get("remote_as"):
                        # Prefer the stored session_type; fall back to AS comparison.
                        stype = s.get("session_type")
                        label = (
                            ("iBGP" if stype == "ibgp" else "eBGP") if stype
                            else ("iBGP" if s["local_as"] == s["remote_as"] else "eBGP")
                        )
                        as_info = f" {label} AS{s['local_as']}→AS{s['remote_as']}"
                    # Show transit/peering for eBGP sessions
                    type_label = ""
                    if s.get("bgp_type"):
                        type_label = f" [{s['bgp_type']}]"
                    # Route-reflector role of this session (config-only fact).
                    rr_label = ""
                    if s.get("rr_client"):
                        if s.get("rr_reflector") == device:
                            rr_label = " [RR-client]"          # this device reflects to the peer
                        elif s.get("rr_reflector") == s.get("peer"):
                            rr_label = " [via route-reflector]"  # peer is this device's reflector
                        else:
                            rr_label = " [RR session]"
                    lines.append(
                        f"  {s['peer']}{peer_addr}  {state}{as_info}{type_label}{rr_label}"
                    )
            else:
                lines.append("  No BGP sessions.")

        # ── OSPF ─────────────────────────────────────────────────────────
        if "ospf" in requested:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $name})"
                "-[r:ROUTING_ADJACENCY]-(peer:Device) "
                "WHERE r.protocol = 'ospf' "
                "RETURN DISTINCT peer.name AS peer, r.state AS state, r.area AS area, "
                "r.vrf AS vrf "
                "ORDER BY peer.name",
                run_id=run_id, name=device,
            )
            ospf_adjs = [dict(r) for r in result]

            lines.extend(["", f"OSPF adjacencies ({len(ospf_adjs)}):"])
            if ospf_adjs:
                for a in ospf_adjs:
                    area = f" area {a['area']}" if a.get("area") else ""
                    # Show VRF only when non-default, mirroring the interface rows.
                    vrf = f" VRF:{a['vrf']}" if a.get("vrf") and a["vrf"] != "default" else ""
                    lines.append(f"  {a['peer']}  {a.get('state', '?')}{area}{vrf}")
            else:
                lines.append("  No OSPF adjacencies.")

    # ── Routing (from facts) ─────────────────────────────────────────
    if "routing" in requested and data_dir:
        routing_path = Path(data_dir) / "facts" / device / "genie_routing.json"
        if routing_path.exists():
            try:
                routing_data = json.loads(routing_path.read_text())
                vrfs = routing_data.get("vrf", routing_data)
                lines.extend(["", "Routing:"])
                for vrf_name, vrf_data in vrfs.items():
                    af = vrf_data.get("address_family", {})
                    for af_name, af_data in af.items():
                        routes = af_data.get("routes", {})
                        lines.append(
                            f"  VRF {vrf_name} ({af_name}): {len(routes)} routes"
                        )
            except (json.JSONDecodeError, OSError):
                lines.extend(["", "Routing: data unavailable"])
        else:
            lines.extend(["", "Routing: no routing data collected"])

    # ── Findings ─────────────────────────────────────────────────────
    if "findings" in requested:
        all_findings = load_findings_enriched(run_id) or []
        dev_findings = [f for f in all_findings if device_from_finding(f) == device]

        lines.extend(["", f"Findings ({len(dev_findings)}):"])
        if dev_findings:
            sev_order = SEVERITY_ORDER
            dev_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))
            for f in dev_findings[:15]:
                sev = f.get("severity", "info").upper()
                rule = f.get("rule_id", "?")
                ack = " [ACK]" if f.get("acknowledged") else ""
                lines.append(f"  [{sev}] {rule}{ack}")
            if len(dev_findings) > 15:
                lines.append(f"  ... and {len(dev_findings) - 15} more (use get_findings(device='{device}') for full list)")
        else:
            lines.append("  No findings for this device.")

    # ── Security ─────────────────────────────────────────────────────
    if "security" in requested and data_dir:
        sec_path = Path(data_dir) / "facts" / device / "security_config.json"
        if sec_path.exists():
            try:
                sec_data = json.loads(sec_path.read_text())
                lines.extend(["", "Security config:"])
                for key, val in list(sec_data.items())[:10]:
                    lines.append(f"  {key}: {val}")
            except (json.JSONDecodeError, OSError):
                lines.extend(["", "Security: data unavailable"])

    return "\n".join(lines)
