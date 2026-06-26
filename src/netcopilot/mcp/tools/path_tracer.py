"""trace_path — universal network path tracer with service resolution.

Traces traffic hop-by-hop through L2 trunks, L3 routing, VRF boundaries,
firewalls, and BGP exits. Works on any network — no hardcoded topology
knowledge. Service resolution searches interface descriptions generically.

Algorithm:
  1. Resolve source (device name or service keyword → device + VRF)
  2. Load routing table for source device
  3. Longest prefix match for destination
  4. Resolve next-hop IP → device name (Neo4j Interface.ip)
  5. Classify boundary (L2 trunk, L3 forward, firewall, VRF, eBGP)
  6. Repeat on next device until exit or dead end
"""

import logging
from pathlib import Path

from netcopilot.graph.client import get_driver, is_available
from netcopilot.findings import resolve_device as _shared_resolve, suggest_devices, get_device_role, is_security_device, is_default_route

log = logging.getLogger(__name__)


def _explain_bgp_selection(device: str, selected_peer: str, run_id: str) -> str | None:
    """Explain why a BGP next-hop was selected over alternatives.

    Checks if multiple iBGP peers advertise a default route to this device,
    and if their local-preference values differ. Returns an explanation
    string or None if no useful explanation is available.
    """
    if not is_available():
        return None

    try:
        driver = get_driver()
        with driver.session() as session:
            # Find all iBGP peers of this device that have default_originate_local_pref
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $device})"
                "-[r:ROUTING_ADJACENCY]-(peer:Device {run_id: $run_id}) "
                "WHERE r.protocol = 'bgp' AND r.default_originate_local_pref IS NOT NULL "
                "RETURN peer.name AS peer, r.default_originate_local_pref AS lp, "
                "r.default_originate AS do, r.default_originate_policy AS policy",
                run_id=run_id, device=device,
            )
            peers = [dict(r) for r in result]

        if len(peers) < 2:
            # No alternatives or no local-pref data
            if peers and peers[0].get("lp"):
                return f"{selected_peer} sends default with local-pref {peers[0]['lp']} (policy: {peers[0].get('policy', '?')})"
            return None

        # Sort by local-pref descending
        peers.sort(key=lambda p: -(p.get("lp") or 0))
        winner = peers[0]
        others = peers[1:]

        # Check if all peers have equal local-pref
        all_equal = all(p.get("lp") == winner.get("lp") for p in peers)

        if all_equal:
            peer_list = ", ".join(f"{p['peer']} (LP={p['lp']})" for p in peers)
            return (
                f"equal local-pref ({winner['lp']}) across {len(peers)} peers: "
                f"{peer_list} — tie-broken by BGP best-path (router-id or arrival order)"
            )
        elif winner["peer"] == selected_peer:
            other_lps = ", ".join(f"{p['peer']}={p['lp']}" for p in others)
            return (
                f"{selected_peer} selected — local-pref {winner['lp']} "
                f"(policy: {winner.get('policy', '?')}) beats {other_lps}"
            )
        else:
            selected_lp = next((p["lp"] for p in peers if p["peer"] == selected_peer), "?")
            return (
                f"{selected_peer} selected (LP={selected_lp}) but {winner['peer']} "
                f"has higher local-pref ({winner['lp']}) — check BGP best-path"
            )

    except Exception as exc:
        log.debug("BGP selection explanation failed: %s", exc)
        return None


def _check_firewall_policy(
    fw_device: str, src_ip: str, dst_ip: str, src_intf: str, dst_intf: str, run_id: str,
) -> str | None:
    """Check FirewallPolicy nodes for a matching policy at a firewall crossing.

    Tries two match strategies:
    1. IP-based: source/destination IPs against resolved srcaddr/dstaddr CIDRs
    2. Interface-based: interface names against srcintf/dstintf (fallback)

    Returns a description string or None if no match or Neo4j unavailable.
    """
    import ipaddress
    import json

    if not is_available():
        return None

    try:
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:HAS_POLICY]->(p:FirewallPolicy) "
                "WHERE toLower(d.name) = toLower($device) AND p.status <> 'disable' "
                "RETURN p.policyid AS id, p.name AS name, p.action AS action, "
                "p.srcintf AS srcintf, p.dstintf AS dstintf, "
                "p.srcaddr AS srcaddr, p.dstaddr AS dstaddr, "
                "p.service AS service, p.policy_type AS ptype "
                "ORDER BY p.seq",
                run_id=run_id, device=fw_device,
            )
            policies = [dict(r) for r in result]

        if not policies:
            return None

        # Strategy 1: IP-based match — find first PERMIT policy matching dest IP
        # Skip deny-all rules (like blacklists) that match on 0.0.0.0/0 without
        # verifying source — we don't have the source IP of the actual traffic.
        try:
            dst_addr = ipaddress.ip_address(dst_ip) if dst_ip and dst_ip != "0.0.0.0" else None
        except ValueError:
            dst_addr = None

        if dst_addr:
            for p in policies:
                action = (p.get("action") or "").lower()
                dstaddr_str = p.get("dstaddr", "") or ""

                # Check specific destination CIDRs (skip 0.0.0.0/0 "any" on deny rules)
                for cidr in dstaddr_str.replace(",", " ").split():
                    cidr = cidr.strip()
                    if not cidr or "/" not in cidr:
                        continue
                    # Skip "any" destination on deny rules — too broad without source check
                    if cidr == "0.0.0.0/0" and action in ("deny",):
                        continue
                    try:
                        if dst_addr in ipaddress.ip_network(cidr, strict=False):
                            act = action.upper()
                            name = p.get("name") or f"id:{p.get('id', '?')}"
                            svc = p.get("service") or "ALL"
                            return (
                                f"Firewall policy: '{name}' (id:{p.get('id', '?')}) "
                                f"{act}S traffic (match by address, service: {svc})"
                            )
                    except ValueError:
                        continue

        # For default route traces (0.0.0.0/0), find first ACCEPT policy with dst "any"
        permit_any = None
        for p in policies:
            action = (p.get("action") or "").lower()
            dstaddr_str = p.get("dstaddr", "") or ""
            if action in ("accept", "permit") and "0.0.0.0/0" in dstaddr_str:
                name = p.get("name") or f"id:{p.get('id', '?')}"
                svc = p.get("service") or "ALL"
                permit_any = (
                    f"Firewall policy: '{name}' (id:{p.get('id', '?')}) "
                    f"PERMITS traffic (match by address, service: {svc})"
                )
                break

        # Strategy 2: Interface name substring match — prefer PERMIT (fallback)
        src_intf_lower = (src_intf or "").lower()
        dst_intf_lower = (dst_intf or "").lower()
        for p in policies:
            action = (p.get("action") or "").lower()
            if action not in ("accept", "permit"):
                continue  # Skip deny rules in interface match — too imprecise
            srcintf_json = p.get("srcintf") or "[]"
            dstintf_json = p.get("dstintf") or "[]"
            try:
                src_intfs = json.loads(srcintf_json) if srcintf_json.startswith("[") else []
                dst_intfs = json.loads(dstintf_json) if dstintf_json.startswith("[") else []
            except (json.JSONDecodeError, TypeError):
                continue

            src_match = any(
                src_intf_lower in (i.get("name", "").lower()) or i.get("name", "") == "any"
                for i in src_intfs
            ) if src_intf_lower else True
            dst_match = any(
                dst_intf_lower in (i.get("name", "").lower()) or i.get("name", "") == "any"
                for i in dst_intfs
            ) if dst_intf_lower else True

            if src_match and dst_match:
                name = p.get("name") or f"id:{p.get('id', '?')}"
                svc = p.get("service") or "ALL"
                return (
                    f"Firewall policy: '{name}' (id:{p.get('id', '?')}) "
                    f"PERMITS traffic (match by interface, verify manually, service: {svc})"
                )

        # Return permit_any if found earlier, otherwise no match
        if permit_any:
            return permit_any

        return "⚠ No matching firewall policy found for this traffic flow"

    except Exception as exc:
        log.debug("Firewall policy check failed for %s: %s", fw_device, exc)
        return None


def _build_ip_to_device(run_id: str) -> dict[str, str]:
    """Build IP → device name lookup from Neo4j."""
    ip_map: dict[str, str] = {}
    if not is_available():
        return ip_map
    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.ip IS NOT NULL "
            "RETURN i.ip AS ip, d.name AS device",
            run_id=run_id,
        )
        for rec in result:
            ip = rec["ip"]
            if "/" in ip:
                ip = ip.split("/")[0]
            ip_map[ip] = rec["device"]
    return ip_map


# Device resolution and suggestions now in agent.shared


def _load_routes(device: str, data_dir: str | Path) -> dict[str, list[dict]]:
    """Load routing table grouped by VRF from Neo4j Route nodes."""
    routes_by_vrf: dict[str, list[dict]] = {}

    if not is_available():
        return routes_by_vrf

    # Extract run_id from data_dir path
    run_id = Path(data_dir).name

    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_ROUTE]->(r:Route) "
            "RETURN r.prefix AS prefix, r.vrf AS vrf, r.protocol AS protocol, "
            "r.next_hop AS next_hop, r.interface AS interface, "
            "r.ad AS ad, r.metric AS metric, r.active AS active, "
            "r.source AS source, r.note AS note",
            run_id=run_id, device=device,
        )
        for rec in result:
            vrf = rec["vrf"] or "default"
            routes_by_vrf.setdefault(vrf, []).append({
                "prefix": rec["prefix"] or "",
                "vrf": vrf,
                "protocol": rec["protocol"] or "?",
                "next_hop": rec["next_hop"] or "",
                "interface": rec["interface"] or "",
                "ad": rec["ad"] or 0,
                "metric": rec["metric"] or 0,
                "active": rec["active"] if rec["active"] is not None else True,
                "source": rec["source"] or "dynamic",
                "note": rec["note"] or "",
            })

    return routes_by_vrf


def _find_default_route(routes: list[dict]) -> dict | None:
    """Find the best active default route (0.0.0.0/0) in a route list.

    Skips routes marked inactive (next-hop unreachable). Among active
    routes, prefers lowest AD.
    """
    defaults = [r for r in routes if is_default_route(r.get("prefix", ""))]
    if not defaults:
        return None
    # Filter out inactive routes (next-hop unreachable)
    active = [r for r in defaults if r.get("active", True) is not False]
    if not active:
        # All defaults are inactive — return best inactive with a warning flag
        defaults.sort(key=lambda r: r.get("ad", 999) or 999)
        best = defaults[0]
        best["_inactive"] = True
        return best
    # Prefer lowest AD (ignore 0 which means unset)
    active.sort(key=lambda r: r.get("ad", 999) or 999)
    return active[0]


def _pick_best_vrf(device_routes: dict[str, list[dict]]) -> str | None:
    """Pick the best VRF to trace through.

    Priority:
    1. VRF with BGP routes (likely the internet-facing VRF)
    2. "default" VRF if it has a default route
    3. Any non-management VRF with a default route
    4. Management VRF as last resort
    """
    # Check for BGP routes first. Use prefix match so a device with only a
    # synthesized BGP route (protocol="bgp (synthesized)" for full-Internet-
    # table devices) is still detected as a BGP-VRF rather than falling
    # through to default-route heuristics.
    for v, routes in device_routes.items():
        if any((r.get("protocol") or "").lower().startswith("bgp") for r in routes):
            return v

    # Check "default" explicitly
    if "default" in device_routes and _find_default_route(device_routes["default"]):
        return "default"

    # Non-management VRFs
    for v, routes in device_routes.items():
        if _find_default_route(routes):
            v_lower = v.lower()
            if "mgmt" not in v_lower and "management" not in v_lower:
                return v

    # Any VRF with a default route (including management)
    for v, routes in device_routes.items():
        if _find_default_route(routes):
            return v

    return None


def _get_bgp_exit(device: str, run_id: str) -> list[dict] | None:
    """Check if device has eBGP sessions (internet exit).

    Uses two directed queries instead of undirected match to avoid
    false positives from unrelated adjacencies.
    """
    if not is_available():
        return None
    driver = get_driver()
    peers = []
    with driver.session() as session:
        # Bidirectional: both directions (eBGP may be stored either way)
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $name})"
            "-[r:ROUTING_ADJACENCY]-(peer:Device) "
            "WHERE r.protocol = 'bgp' AND r.local_as <> r.remote_as "
            "RETURN DISTINCT peer.name AS peer, r.local_as AS local_as, "
            "r.remote_as AS remote_as, r.state AS state, "
            "r.bgp_type AS bgp_type",
            run_id=run_id, name=device,
        )
        seen = set()
        for rec in result:
            if rec["peer"] not in seen:
                seen.add(rec["peer"])
                peers.append(dict(rec))

    return peers if peers else None


# Device role lookup now in agent.shared (cached)


def _resolve_vrf_from_service_vlan(
    intf_matches: list[dict],
    run_id: str,
    source_device: str | None = None,
) -> str | None:
    """Find the VRF for a service by looking up its VLAN's SVI.

    Chain: service interfaces → access_vlan → find SVI (VlN) on any device
    → read SVI's vrf property. Prefers non-management VRFs.

    If the source device has access ports for the service, uses THAT
    device's VLAN (which may differ between sites — the same service can
    be VLAN 326 at one site and VLAN 1904 at another).
    """
    if not is_available():
        return None

    # Get VLAN IDs from the service interfaces
    # Prefer VLANs from the source device if specified
    vlan_ids = set()
    source_vlans = set()
    for m in intf_matches:
        v = m.get("vlan")
        if v:
            vlan_ids.add(int(v))
            if source_device and m.get("device") == source_device:
                source_vlans.add(int(v))

    # Prefer source device VLANs (the actual VLAN at the endpoint)
    check_vlans = source_vlans if source_vlans else vlan_ids
    if not check_vlans:
        return None

    driver = get_driver()
    with driver.session() as session:
        for vlan_id in sorted(check_vlans):
            # Find ALL SVIs for this VLAN across all devices
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                "WHERE i.name = $svi OR i.name = $svi2 "
                "RETURN i.vrf AS vrf, d.name AS device, i.ip AS ip",
                run_id=run_id, svi=f"Vl{vlan_id}", svi2=f"Vlan{vlan_id}",
            )
            svis = [dict(r) for r in result]

            # Prefer non-management VRF SVIs
            for svi in svis:
                resolved_vrf = svi["vrf"] or "default"
                if "mgmt" not in resolved_vrf.lower() and "management" not in resolved_vrf.lower():
                    log.info("Service VLAN %d → SVI on %s → VRF %s",
                             vlan_id, svi["device"], resolved_vrf)
                    return resolved_vrf

            # Fallback: any SVI VRF
            if svis:
                resolved_vrf = svis[0]["vrf"] or "default"
                log.info("Service VLAN %d → SVI on %s → VRF %s (fallback)",
                         vlan_id, svis[0]["device"], resolved_vrf)
                return resolved_vrf

    return None


def _get_l2_trunk_neighbor(device: str, vrf: str, run_id: str, data_dir: str | Path) -> str | None:
    """Detect L2 trunk neighbor when no L3 route exists.

    If the device has no routes in this VRF but shares VLANs with another
    device via a physical trunk, the traffic is L2-switched.
    """
    if not is_available():
        return None
    driver = get_driver()
    with driver.session() as session:
        # Find devices sharing VLANs with this device via physical cables
        result = session.run(
            "MATCH (d1:Device {run_id: $run_id, name: $name})"
            "-[r:PHYSICAL_CABLE]-(d2:Device) "
            "WHERE r.l2_local_vlans_carried IS NOT NULL "
            "RETURN DISTINCT d2.name AS neighbor, d2.role AS role "
            "ORDER BY d2.role",
            run_id=run_id, name=device,
        )
        for rec in result:
            neighbor = rec["neighbor"]
            # Check if the neighbor has routes in this VRF or a data VRF
            neighbor_routes = _load_routes(neighbor, data_dir)
            if vrf in neighbor_routes or _pick_best_vrf(neighbor_routes):
                return neighbor
    return None


async def trace_path(
    *,
    source_device: str | None = None,
    service: str | None = None,
    destination: str = "internet",
    vrf: str | None = None,
    max_hops: int = 10,
    context: dict,
) -> str:
    """Trace network path from source to destination across L2/L3/VRF boundaries."""
    run_id = context.get("run_id", "")
    data_dir = context.get("data_dir", "")

    lines = []

    # ── Service Resolution ──────────────────────────────────────────
    if service:
        if not is_available():
            return "Neo4j unavailable for service resolution."
        driver = get_driver()

        # 1. Search interface descriptions for service keyword (all statuses)
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                "WHERE (toLower(i.description) CONTAINS toLower($service) "
                "  OR toLower(i.name) CONTAINS toLower($service)) "
                "RETURN d.name AS device, i.name AS interface, i.description AS desc, "
                "i.access_vlan AS vlan, i.speed AS speed, i.status AS status "
                "ORDER BY d.name, i.name",
                run_id=run_id, service=service,
            )
            intf_matches = [dict(r) for r in result]

        # 2. Search SharedService (VLAN) names for service keyword
        vlan_members: dict[str, list[str]] = {}  # vlan_name → [devices]
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->"
                "(s:SharedService {run_id: $run_id}) "
                "WHERE s.service_type = 'vlan' "
                "AND toLower(s.name) CONTAINS toLower($service) "
                "RETURN s.name AS vlan_name, s.identifier AS vlan_id, "
                "d.name AS device, d.role AS role "
                "ORDER BY s.name, d.name",
                run_id=run_id, service=service,
            )
            for rec in result:
                key = f"{rec['vlan_name']} (VLAN {rec['vlan_id']})"
                vlan_members.setdefault(key, []).append(
                    f"{rec['device']} ({rec['role']})"
                )

        if not intf_matches and not vlan_members:
            return (
                f"No interfaces or VLANs matching service '{service}' found. "
                "Interface descriptions and VLAN names are searched. "
                "Try a different term or use source_device parameter instead."
            )

        # Group interface matches by device
        devices_with_intfs = {}
        for m in intf_matches:
            devices_with_intfs.setdefault(m["device"], []).append(m)

        # Pick source device: prefer device with physical access ports
        # (endpoint), not SVIs (gateway) or port-channels (trunk)
        def _is_endpoint_port(intf_name: str) -> bool:
            """True if this is a physical access port, not an SVI or LAG."""
            name = intf_name or ""
            if name.startswith("Vl") or name.startswith("Vlan"):
                return False  # SVI — gateway, not endpoint
            if name.startswith("Po") or name.startswith("Port-channel"):
                return False  # LAG — trunk, not endpoint
            if name.startswith("Lo") or name.startswith("Loopback"):
                return False
            return True

        # Find devices with physical access ports (the real endpoints)
        endpoint_devices = []
        gateway_devices = []
        for dev, intfs in devices_with_intfs.items():
            has_endpoint = any(_is_endpoint_port(m["interface"]) for m in intfs)
            if has_endpoint:
                endpoint_devices.append(dev)
            else:
                gateway_devices.append(dev)

        # ── Group endpoints by building ─────────────────────────────
        by_building: dict[str, list[str]] = {}
        if endpoint_devices:
            with driver.session() as session:
                for dev in endpoint_devices:
                    result = session.run(
                        "MATCH (d:Device {run_id: $run_id, name: $name}) "
                        "RETURN d.building AS building",
                        run_id=run_id, name=dev,
                    )
                    rec = result.single()
                    building = rec["building"] if rec and rec["building"] else "unknown"
                    by_building.setdefault(building, []).append(dev)

        # ── Multiple buildings: ask the user which location ─────────
        if len(by_building) > 1 and not source_device:
            lines.append(f"Service '{service}' is connected at multiple locations:")
            lines.append("")
            for building, devs in sorted(by_building.items()):
                lines.append(f"  {building}:")
                for dev in devs:
                    intfs = devices_with_intfs[dev]
                    ep_intfs = [m for m in intfs if _is_endpoint_port(m["interface"])]
                    for m in ep_intfs[:3]:
                        status = m.get("status", "?")
                        status_tag = f" [{status}]" if status != "up" else ""
                        lines.append(f"    {dev} {m['interface']}{status_tag}: {m.get('desc', '')}")
            lines.append("")
            buildings = sorted(by_building.keys())
            lines.append(f"Which location? Call trace_path(service=\"{service}\", "
                         f"source_device=\"<device>\") with a specific device.")
            lines.append(f"Available buildings: {', '.join(buildings)}")
            return "\n".join(lines)

        # ── Single building or source_device specified: pick endpoint ─
        if not source_device:
            if endpoint_devices:
                source_device = endpoint_devices[0]
            elif gateway_devices:
                source_device = gateway_devices[0]

        # ── Resolve VRF from service VLAN ───────────────────────────
        service_vrf = _resolve_vrf_from_service_vlan(intf_matches, run_id, source_device)

        # ── Check if device has multiple traffic types (mgmt vs data) ─
        if not vrf and source_device:
            device_vrfs = set()
            # Get all VRFs from VLANs on this device's access ports
            for m in intf_matches:
                if m.get("device") == source_device and m.get("vlan"):
                    vlan_vrf = _resolve_vrf_from_service_vlan(
                        [m], run_id, source_device)
                    if vlan_vrf:
                        device_vrfs.add(vlan_vrf)
            # Also check route VRFs on this device
            routes_by_vrf = _load_routes(source_device, data_dir)
            for v in routes_by_vrf:
                if _find_default_route(routes_by_vrf[v]):
                    device_vrfs.add(v)

            # Filter out VRFs with only IPv6/multicast routes
            real_vrfs = set()
            for v in device_vrfs:
                vrf_routes = routes_by_vrf.get(v, [])
                has_ipv4 = any(not r.get("prefix", "").startswith("FF")
                              and ":" not in r.get("prefix", "")
                              for r in vrf_routes)
                if has_ipv4 or v == service_vrf:
                    real_vrfs.add(v)

            if len(real_vrfs) > 1 and not service_vrf:
                # Multiple VRFs — ask the user
                lines.append(f"Service '{service}' on {source_device} can use multiple traffic paths:")
                lines.append("")
                for v in sorted(real_vrfs):
                    vrf_type = "management" if "mgmt" in v.lower() or "management" in v.lower() else "data"
                    lines.append(f"  {v} ({vrf_type})")
                lines.append("")
                lines.append(f"Which traffic type? Call trace_path(service=\"{service}\", "
                             f"source_device=\"{source_device}\", vrf=\"<vrf_name>\")")
                return "\n".join(lines)

            # Use the service VRF if resolved, otherwise the only real VRF
            if service_vrf:
                vrf = service_vrf
            elif len(real_vrfs) == 1:
                vrf = real_vrfs.pop()

        if vrf is None and service_vrf:
            vrf = service_vrf

        # Build service resolution output
        lines.append(f"Service resolution: '{service}'")

        if endpoint_devices:
            lines.append(f"  Endpoints (physical access ports):")
            for dev in endpoint_devices:
                intfs = devices_with_intfs[dev]
                ep_intfs = [m for m in intfs if _is_endpoint_port(m["interface"])]
                for m in ep_intfs[:5]:
                    status = m.get("status", "?")
                    status_tag = f" [{status}]" if status != "up" else ""
                    lines.append(f"    {dev} {m['interface']}{status_tag}: {m.get('desc', '')}")
                if len(ep_intfs) > 5:
                    lines.append(f"    ... and {len(ep_intfs) - 5} more")

        if gateway_devices:
            lines.append(f"  Gateways (SVIs/trunks):")
            for dev in gateway_devices:
                intfs = devices_with_intfs[dev]
                for m in intfs[:3]:
                    lines.append(f"    {dev} {m['interface']}: {m.get('desc', '')}")

        if vlan_members:
            for vlan_name, members in vlan_members.items():
                lines.append(f"  VLAN membership — {vlan_name}:")
                for member in members:
                    lines.append(f"    {member}")

        lines.append("")

    # ── Resolve source device ───────────────────────────────────────
    if not source_device:
        return "Specify source_device or service parameter."

    resolved = _shared_resolve(source_device, run_id)
    if not resolved:
        suggestion = suggest_devices(source_device, run_id)
        return f"Device '{source_device}' not found.{suggestion}"
    source_device = resolved

    # ── Build IP lookup ─────────────────────────────────────────────
    ip_to_device = _build_ip_to_device(run_id)

    # ── Determine destination ───────────────────────────────────────
    dest_ip = "0.0.0.0/0"
    if destination.lower() != "internet":
        dest_ip = destination

    # ── Load source routing table ───────────────────────────────────
    routes_by_vrf = _load_routes(source_device, data_dir)
    if not routes_by_vrf:
        return f"No routing data for {source_device}."

    # ── If no VRF specified, pick best ──────────────────────────────
    if not vrf:
        available_vrfs = sorted(routes_by_vrf.keys())
        vrf = _pick_best_vrf(routes_by_vrf)

        if not vrf:
            lines.append(f"Device {source_device} has VRFs: {', '.join(available_vrfs)}")
            lines.append("None have a default route to trace.")
            return "\n".join(lines)

        traceable = [v for v in available_vrfs if _find_default_route(routes_by_vrf[v])]
        if len(traceable) > 1:
            lines.append(f"VRFs with default routes: {', '.join(traceable)}")
            lines.append(f"Tracing: {vrf}")
            lines.append("")

    # ── Trace path ──────────────────────────────────────────────────
    current_device = source_device
    current_vrf = vrf
    visited: set[tuple[str, str]] = set()
    hops: list[dict] = []
    max_hops = min(max_hops, 20)  # Cap at 20 to prevent runaway traces

    lines.append(f"Path: {source_device} ({current_vrf}) → {destination}")
    lines.append("")

    for hop_num in range(1, max_hops + 1):
        # Loop detection — track (device, vrf) pairs
        key = (current_device, current_vrf)
        if key in visited:
            lines.append(f"  ⚠ Loop detected at {current_device} [{current_vrf}]")
            break
        visited.add(key)

        role = get_device_role(current_device, run_id)

        # Check for eBGP exit BEFORE loading routes
        ebgp_peers = _get_bgp_exit(current_device, run_id)
        if ebgp_peers:
            lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
            transit_peers = [p for p in ebgp_peers if p.get("bgp_type") != "peering"]
            peering_peers = [p for p in ebgp_peers if p.get("bgp_type") == "peering"]
            if transit_peers:
                lines.append(f"  Exit: eBGP internet transit")
                for peer in transit_peers:
                    lines.append(f"    → {peer['peer']} AS{peer['local_as']}→AS{peer['remote_as']} ({peer.get('state', '?')}) [transit]")
            if peering_peers:
                lines.append(f"  Direct peering (not internet transit):")
                for peer in peering_peers:
                    lines.append(f"    → {peer['peer']} AS{peer['local_as']}→AS{peer['remote_as']} ({peer.get('state', '?')}) [peering, {peer.get('prefix_count', '?')} prefixes]")
            hops.append({"device": current_device, "vrf": current_vrf, "type": "ebgp_exit", "role": role})
            break

        # Load routing table
        device_routes = _load_routes(current_device, data_dir)
        vrf_routes = device_routes.get(current_vrf, [])

        # VRF not found — try L2 trunk FIRST (device L2-switches this VRF upstream)
        if not vrf_routes:
            l2_neighbor = _get_l2_trunk_neighbor(current_device, current_vrf, run_id, data_dir)
            if l2_neighbor:
                lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
                lines.append(f"  Boundary: L2 trunk (no routes in {current_vrf}, VLAN-switched)")
                hops.append({
                    "device": current_device, "vrf": current_vrf,
                    "next_device": l2_neighbor, "protocol": "L2",
                    "boundary": "L2 trunk", "role": role,
                })
                current_device = l2_neighbor
                next_routes = _load_routes(current_device, data_dir)
                if current_vrf not in next_routes:
                    best = _pick_best_vrf(next_routes)
                    if best:
                        current_vrf = best
                continue

            # No L2 trunk — fall back to best VRF with routes
            best = _pick_best_vrf(device_routes)
            if best:
                current_vrf = best
                vrf_routes = device_routes[best]

        # Still no routes — try L2 trunk detection
        if not vrf_routes:
            l2_neighbor = _get_l2_trunk_neighbor(current_device, current_vrf, run_id, data_dir)
            if l2_neighbor:
                lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
                lines.append(f"  Boundary: L2 trunk (no L3 routes, VLAN-switched)")
                hops.append({
                    "device": current_device, "vrf": current_vrf,
                    "next_device": l2_neighbor, "protocol": "L2",
                    "boundary": "L2 trunk", "role": role,
                })
                current_device = l2_neighbor
                # Keep current VRF if next device has it; otherwise pick best
                next_routes = _load_routes(current_device, data_dir)
                if current_vrf not in next_routes:
                    best = _pick_best_vrf(next_routes)
                    if best:
                        current_vrf = best
                continue

            lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
            lines.append(f"  ⚠ No routes in any VRF")
            break

        # Find route to destination
        default = _find_default_route(vrf_routes)
        if not default:
            # No default route — try L2 trunk as fallback
            l2_neighbor = _get_l2_trunk_neighbor(current_device, current_vrf, run_id, data_dir)
            if l2_neighbor:
                lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
                lines.append(f"  Boundary: L2 trunk (no default route, VLAN-switched to upstream)")
                hops.append({
                    "device": current_device, "vrf": current_vrf,
                    "next_device": l2_neighbor, "protocol": "L2",
                    "boundary": "L2 trunk", "role": role,
                })
                current_device = l2_neighbor
                next_routes = _load_routes(current_device, data_dir)
                if current_vrf not in next_routes:
                    best = _pick_best_vrf(next_routes)
                    if best:
                        current_vrf = best
                continue
            lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
            lines.append(f"  ⚠ No default route or L2 trunk path in VRF '{current_vrf}'")
            break

        # If route is inactive (next-hop unreachable), try L2 trunk as fallback
        if default.get("_inactive"):
            l2_neighbor = _get_l2_trunk_neighbor(current_device, current_vrf, run_id, data_dir)
            if l2_neighbor:
                lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
                lines.append(f"  Boundary: L2 trunk (default route inactive, VLAN-switched to upstream)")
                hops.append({
                    "device": current_device, "vrf": current_vrf,
                    "next_device": l2_neighbor, "protocol": "L2",
                    "boundary": "L2 trunk (inactive route fallback)", "role": role,
                })
                current_device = l2_neighbor
                next_routes = _load_routes(current_device, data_dir)
                if current_vrf not in next_routes:
                    best = _pick_best_vrf(next_routes)
                    if best:
                        current_vrf = best
                continue
            # No L2 fallback — report inactive route and stop
            lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
            nh = default.get("next_hop", "?")
            proto = default.get("protocol", "?")
            lines.append(f"  ⚠ Default route {dest_ip} via {nh} [{proto}] — INACTIVE (next-hop unreachable)")
            lines.append(f"  No active default route or L2 trunk path in VRF '{current_vrf}'")
            break

        next_hop = default.get("next_hop", "")
        protocol = default.get("protocol", "unknown")
        ad = default.get("ad", 0)
        interface = default.get("interface", "")

        # Resolve next-hop to device
        next_device = ip_to_device.get(next_hop, "")

        # Classify boundary
        if not next_device:
            boundary = "exits collection scope"
        elif next_device == current_device:
            boundary = "VRF boundary (inter-VRF routing)"
        elif is_security_device(current_device, run_id) or is_security_device(next_device, run_id):
            fw_dev = current_device if is_security_device(current_device, run_id) else next_device
            policy_result = _check_firewall_policy(
                fw_dev, next_hop, dest_ip, interface, "", run_id,
            )
            boundary = "firewall crossing"
            if policy_result:
                boundary += f" — {policy_result}"
        else:
            boundary = f"L3 forwarding ({protocol})"

        lines.append(f"Hop {hop_num}: {current_device} [{current_vrf}] ({role})")
        via = f"via {next_hop}"
        if next_device:
            via += f" ({next_device})"
        lines.append(f"  Route: {dest_ip} {via} [{protocol}, AD:{ad}]")

        # BGP path selection explanation — check if alternative BGP next-hops exist.
        # Match "bgp" prefix so synthesized BGP routes ("bgp (synthesized)") also
        # trigger the explanation.
        if (protocol or "").startswith("bgp") and next_device:
            bgp_explanation = _explain_bgp_selection(
                current_device, next_device, run_id,
            )
            if bgp_explanation:
                lines.append(f"  BGP selection: {bgp_explanation}")
        if default.get("note"):
            lines.append(f"  Note: {default['note']}")
        lines.append(f"  Boundary: {boundary}")

        hops.append({
            "device": current_device,
            "vrf": current_vrf,
            "next_hop": next_hop,
            "next_device": next_device,
            "protocol": protocol,
            "boundary": boundary,
            "role": role,
        })

        # Move to next device
        if not next_device:
            lines.append(f"  ⚠ Next-hop {next_hop} is outside collected topology")
            break

        current_device = next_device
        # Resolve VRF on next device
        next_routes = _load_routes(current_device, data_dir)
        if current_vrf not in next_routes:
            best = _pick_best_vrf(next_routes)
            if best:
                current_vrf = best

    # ── Summary ─────────────────────────────────────────────────────
    if hops:
        lines.append("")
        lines.append("Summary:")
        protocols = [h.get("protocol", "?") for h in hops if h.get("protocol") and h.get("protocol") != "?"]
        lines.append(f"  Total hops: {len(hops)}")
        if protocols:
            lines.append(f"  Protocols: {' → '.join(protocols)}")

        fw_hops = [h for h in hops if "firewall" in h.get("boundary", "")]
        if fw_hops:
            fw_names = set()
            for h in fw_hops:
                if is_security_device(h["device"], run_id):
                    fw_names.add(h["device"])
                elif h.get("next_device") and is_security_device(h["next_device"], run_id):
                    fw_names.add(h["next_device"])
            lines.append(f"  Firewall: YES (crosses {', '.join(sorted(fw_names))})")
        else:
            lines.append(f"  Firewall: NO")

        exit_hops = [h for h in hops if h.get("type") == "ebgp_exit"]
        if exit_hops:
            lines.append(f"  Internet exit: {exit_hops[0]['device']}")

        # SPOF: devices that appear exactly once (excluding border routers which have eBGP redundancy)
        device_counts: dict[str, int] = {}
        for h in hops:
            device_counts[h["device"]] = device_counts.get(h["device"], 0) + 1
        spofs = [d for d, c in device_counts.items()
                 if c == 1 and "border" not in get_device_role(d, run_id).lower()]
        if spofs:
            lines.append(f"  Single points of failure: {', '.join(spofs)}")

    return "\n".join(lines)
