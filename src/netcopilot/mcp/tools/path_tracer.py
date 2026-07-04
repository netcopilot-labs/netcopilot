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
from netcopilot.findings import load_findings_enriched, device_from_finding

from netcopilot.mcp.result import ToolResult

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


def _load_isdb_services_for(device: str, run_id: str) -> dict[str, dict]:
    """ISDB services referenced by ``device``'s policies → ``{name: {ranges, truncated}}``."""
    services: dict[str, dict] = {}
    if not is_available():
        return services
    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:REFERENCES_ISDB]->(s:ISDBService) "
            "WHERE toLower(d.name) = toLower($device) "
            "RETURN s.name AS name, s.ranges AS ranges, s.truncated AS truncated",
            run_id=run_id, device=device,
        )
        for rec in result:
            services[rec["name"]] = {
                "ranges": rec["ranges"] or [],
                "truncated": bool(rec["truncated"]),
            }
    return services


def _findings_on_path(path_devices: list[str], run_id: str) -> list[dict]:
    """Open findings on the devices a trace traversed (findings overlay).

    Reuses the deterministic rule-engine findings (no new analysis): a path may
    be reachable yet cross a device/link with an open problem. Returns compact
    ``{severity, title, device, finding_id}`` for HIGH/critical/medium findings
    on traversed devices, so a "reachable" verdict can carry its caveats.
    """
    findings = load_findings_enriched(run_id)
    if not findings:
        return []
    on_path = set(path_devices)
    risks: list[dict] = []
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev not in ("critical", "high", "medium"):
            continue
        dev = device_from_finding(f)
        if dev not in on_path:
            continue
        risks.append({
            "severity": sev,
            "title": f.get("title") or f.get("rule_id") or "finding",
            "device": dev,
            "finding_id": f.get("finding_id") or f.get("evidence", {}).get("element_id", ""),
        })
    return risks


def _check_firewall_policy(
    fw_device: str, src_ip: str, dst_ip: str, src_intf: str, dst_intf: str, run_id: str,
    protocol: str | None = None, dst_port: int | None = None,
) -> dict | None:
    """Check FirewallPolicy nodes for the policy governing a flow at a crossing.

    Match strategies, in order: ISDB references (dst_isdb resolved to ranges),
    resolved destination CIDRs, and interface-name fallback — all gated by the
    5-tuple ``service`` check when ``protocol``/``dst_port`` are supplied. Names
    the deciding policy and whether it permits/denies.

    Returns a dict ``{text, decision, policy, id, via}`` (decision ∈
    permit/deny/unknown/no_policy) or ``None`` when Neo4j is unavailable or the
    device has no policies. The three-state honesty ladder: a resolved ISDB or
    address match yields permit/deny; an ISDB reference whose feed wasn't
    resolved yields ``unknown`` with a manual-review note; only a genuine
    absence of any matching policy yields ``no_policy``.
    """
    import ipaddress
    import json
    from netcopilot.parse.policy_resolver import ip_in_isdb_ranges, service_allows

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
                "p.dst_isdb AS dst_isdb, p.service AS service, p.policy_type AS ptype "
                "ORDER BY p.seq",
                run_id=run_id, device=fw_device,
            )
            policies = [dict(r) for r in result]

        if not policies:
            return None

        isdb_services = _load_isdb_services_for(fw_device, run_id)

        def _decision(p, via, via_display=None):
            action = (p.get("action") or "").lower()
            decision = "deny" if action in ("deny", "drop") else "permit"
            name = p.get("name") or f"id:{p.get('id', '?')}"
            svc = p.get("service") or "ALL"
            verb = "DENIES" if decision == "deny" else "PERMITS"
            text = (f"Firewall policy: '{name}' (id:{p.get('id', '?')}) "
                    f"{verb} traffic (match by {via_display or via}, service: {svc})")
            return {"text": text, "decision": decision, "policy": name,
                    "id": p.get("id"), "via": via}

        try:
            dst_addr = ipaddress.ip_address(dst_ip) if dst_ip and dst_ip != "0.0.0.0" else None
        except ValueError:
            dst_addr = None

        # Ladder rung 1 — ISDB references. Remember an unresolved-feed candidate
        # so it beats a false "no policy" but loses to a concrete match.
        isdb_manual = None
        if dst_addr:
            for p in policies:
                names = [n.strip() for n in (p.get("dst_isdb") or "").split(",") if n.strip()]
                if not names:
                    continue
                if not service_allows(protocol, dst_port, p.get("service") or ""):
                    continue
                resolved_hit = any(
                    ip_in_isdb_ranges(str(dst_addr), isdb_services.get(n, {}).get("ranges", []))
                    for n in names
                )
                if resolved_hit:
                    return _decision(p, "Internet-Service",
                                     f"Internet-Service[{', '.join(names)}]")
                have_ranges = any(isdb_services.get(n, {}).get("ranges") for n in names)
                if not have_ranges and isdb_manual is None:
                    nm = p.get("name") or f"id:{p.get('id', '?')}"
                    isdb_manual = {
                        "text": (f"Firewall policy '{nm}' matches via Internet-Service"
                                 f"[{', '.join(names)}] — ISDB feed not resolved in this run "
                                 f"(manual review)"),
                        "decision": "unknown", "policy": nm, "id": p.get("id"), "via": "isdb-unresolved",
                    }

        # Ladder rung 2 — resolved destination CIDRs (service-gated).
        if dst_addr:
            for p in policies:
                action = (p.get("action") or "").lower()
                if not service_allows(protocol, dst_port, p.get("service") or ""):
                    continue
                for cidr in (p.get("dstaddr", "") or "").replace(",", " ").split():
                    cidr = cidr.strip()
                    if not cidr or "/" not in cidr:
                        continue
                    if cidr == "0.0.0.0/0" and action in ("deny", "drop"):
                        continue  # deny-any without a source check is too broad
                    try:
                        if dst_addr in ipaddress.ip_network(cidr, strict=False):
                            return _decision(p, "address")
                    except ValueError:
                        continue

        # For default-route traces (internet), first ACCEPT policy with dst "any".
        permit_any = None
        for p in policies:
            action = (p.get("action") or "").lower()
            if (action in ("accept", "permit")
                    and "0.0.0.0/0" in (p.get("dstaddr", "") or "")
                    and service_allows(protocol, dst_port, p.get("service") or "")):
                permit_any = _decision(p, "address")
                break

        # Ladder rung 3 — interface-name fallback (permit only).
        src_intf_lower = (src_intf or "").lower()
        dst_intf_lower = (dst_intf or "").lower()
        for p in policies:
            action = (p.get("action") or "").lower()
            if action not in ("accept", "permit"):
                continue
            if not service_allows(protocol, dst_port, p.get("service") or ""):
                continue
            try:
                src_intfs = json.loads(p.get("srcintf") or "[]")
                dst_intfs = json.loads(p.get("dstintf") or "[]")
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
                return _decision(p, "interface, verify manually")

        if permit_any:
            return permit_any
        if isdb_manual:
            return isdb_manual

        return {"text": "⚠ No matching firewall policy found for this traffic flow",
                "decision": "no_policy", "policy": None, "id": None, "via": None}

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


def _resolve_in_interface(next_device: str, next_hop: str, run_id: str) -> str | None:
    """Best-effort: the interface on ``next_device`` that receives ``next_hop``.

    Finds the interface whose configured subnet contains ``next_hop`` (the
    address the current hop forwards to). Returns ``None`` when the model can't
    resolve it — callers must treat that as an explicit unknown, never a match.
    """
    import ipaddress

    if not next_device or not next_hop or not is_available():
        return None
    try:
        target = ipaddress.ip_address(next_hop.split("/")[0])
    except ValueError:
        return None
    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_INTERFACE]->(i:Interface) "
            "WHERE i.ip IS NOT NULL "
            "RETURN i.name AS name, i.ip AS ip",
            run_id=run_id, device=next_device,
        )
        for rec in result:
            ip = rec["ip"]
            if "/" not in ip:
                continue
            try:
                net = ipaddress.ip_network(ip, strict=False)
            except ValueError:
                continue
            if target.version == net.version and target in net:
                return rec["name"]
    return None


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


def _find_route_to(routes: list[dict], dest_ip: str) -> dict | None:
    """Longest-prefix-match route for ``dest_ip``; fall back to the default route.

    Destination-aware selection: among routes whose prefix contains ``dest_ip``
    (excluding the default, handled as the fallback), return the most specific
    active one, breaking ties by lowest AD. When nothing more specific matches
    — or ``dest_ip`` is the internet placeholder / not an address — delegate to
    :func:`_find_default_route`, so external-destination traces are unchanged.
    """
    import ipaddress

    if not dest_ip or dest_ip in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0"):
        return _find_default_route(routes)
    try:
        target = ipaddress.ip_address(dest_ip.split("/")[0])
    except ValueError:
        return _find_default_route(routes)

    matches: list[tuple[int, dict]] = []
    for r in routes:
        prefix = r.get("prefix", "")
        if not prefix or is_default_route(prefix):
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if target.version == net.version and target in net:
            matches.append((net.prefixlen, r))

    if not matches:
        return _find_default_route(routes)

    active = [(pl, r) for pl, r in matches if r.get("active", True) is not False]
    if active:
        active.sort(key=lambda x: (-x[0], x[1].get("ad", 999) or 999))
        return active[0][1]
    # All specific matches inactive — return the most specific, flagged.
    matches.sort(key=lambda x: (-x[0], x[1].get("ad", 999) or 999))
    best = dict(matches[0][1])
    best["_inactive"] = True
    return best


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
    src_ip: str | None = None,
    protocol: str | None = None,
    dst_port: int | None = None,
    vrf: str | None = None,
    run_id: str | None = None,
    max_hops: int = 10,
    context: dict,
) -> ToolResult:
    """Trace network path from source to destination across L2/L3/VRF boundaries."""
    # ``run_id`` arg pins the trace to a specific run (pre/post-change
    # comparison); otherwise use the context's current run.
    run_id = run_id or context.get("run_id", "")
    data_dir = context.get("data_dir", "")
    if run_id and data_dir:
        # data_dir is <runs>/<run_id>; repoint it when a different run is pinned.
        from pathlib import Path as _P
        data_dir = str(_P(data_dir).parent / run_id)

    # Capture the flow's L4 tuple before the walk loop — inside the loop
    # ``protocol`` is reused for the per-hop *routing* protocol (ospf/bgp/...).
    flow_protocol = protocol
    flow_dst_port = dst_port

    lines = []

    # ── Service Resolution ──────────────────────────────────────────
    if service:
        if not is_available():
            return ToolResult("error", "Neo4j unavailable for service resolution.")
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
            return ToolResult("not_found", (
                f"No interfaces or VLANs matching service '{service}' found. "
                "Interface descriptions and VLAN names are searched. "
                "Try a different term or use source_device parameter instead."
            ))

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
            return ToolResult("ambiguous", "\n".join(lines))

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
                return ToolResult("ambiguous", "\n".join(lines))

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
        return ToolResult("error", "Specify source_device or service parameter.")

    resolved = _shared_resolve(source_device, run_id)
    if not resolved:
        suggestion = suggest_devices(source_device, run_id)
        return ToolResult("not_found", f"Device '{source_device}' not found.{suggestion}")
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
        return ToolResult("no_data", f"No routing data for {source_device}.")

    # ── If no VRF specified, pick best ──────────────────────────────
    if not vrf:
        available_vrfs = sorted(routes_by_vrf.keys())
        vrf = _pick_best_vrf(routes_by_vrf)

        if not vrf:
            lines.append(f"Device {source_device} has VRFs: {', '.join(available_vrfs)}")
            lines.append("None have a default route to trace.")
            return ToolResult("no_data", "\n".join(lines))

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

        # Load routing table up front — needed both to decide whether an eBGP
        # exit is the right move and to select the forwarding route.
        device_routes = _load_routes(current_device, data_dir)
        vrf_routes = device_routes.get(current_vrf, [])

        # A concrete destination reachable by a more-specific (non-default)
        # active route stays inside the collected topology — don't shortcut it
        # out via eBGP. For an internet/external destination there is never a
        # more-specific-than-default match, so the exit fires exactly as before.
        specific_route = _find_route_to(vrf_routes, dest_ip) if vrf_routes else None
        dest_is_internal = (
            specific_route is not None
            and not is_default_route(specific_route.get("prefix", ""))
        )

        # Check for eBGP exit (external destinations only)
        ebgp_peers = _get_bgp_exit(current_device, run_id)
        if ebgp_peers and not dest_is_internal:
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

        # Find route to destination (longest-prefix-match; default fallback)
        default = _find_route_to(vrf_routes, dest_ip)
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
        hop_policy = None
        if not next_device:
            boundary = "exits collection scope"
        elif next_device == current_device:
            boundary = "VRF boundary (inter-VRF routing)"
        elif is_security_device(current_device, run_id) or is_security_device(next_device, run_id):
            fw_dev = current_device if is_security_device(current_device, run_id) else next_device
            policy_result = _check_firewall_policy(
                fw_dev, src_ip or next_hop, dest_ip, interface, "", run_id,
                protocol=flow_protocol, dst_port=flow_dst_port,
            )
            boundary = "firewall crossing"
            if policy_result:
                boundary += f" — {policy_result['text']}"
                hop_policy = policy_result
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

        in_interface = _resolve_in_interface(next_device, next_hop, run_id) if next_device else None
        hops.append({
            "device": current_device,
            "vrf": current_vrf,
            "next_hop": next_hop,
            "next_device": next_device,
            "protocol": protocol,
            "boundary": boundary,
            "role": role,
            "out_interface": interface or None,
            "in_interface": in_interface,
            "policy": hop_policy,
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

    path_devices: list[str] = []
    for h in hops:
        if h["device"] not in path_devices:
            path_devices.append(h["device"])
    highlight = {"devices": path_devices} if path_devices else {"device": source_device}

    # ── Typed verdict (machine-readable reachability judgment) ───────────
    verdict = _build_trace_verdict(
        hops, path_devices, run_id, destination,
        src_ip=src_ip, protocol=flow_protocol, dst_port=flow_dst_port,
    )
    return ToolResult("ok", "\n".join(lines), highlight=highlight, verdict=verdict)


def _build_trace_verdict(
    hops: list[dict], path_devices: list[str], run_id: str, destination: str,
    *, src_ip: str | None, protocol: str | None, dst_port: int | None,
) -> dict:
    """Assemble the frozen-shape trace verdict from the walked hops.

    ``result`` ∈ reachable/blocked/partial/unknown. ``reasons`` explain
    partial/unknown outcomes and name any unevaluated or approximated checks —
    never a clean-by-omission verdict. ``blocked_by`` names the denying
    device+policy; ``risks`` carries open findings on the traversed path.
    Evidence: run_id + device + policy/finding id per entry (Article VI).
    """
    reasons: list[str] = []
    blocked_by = None
    result = "unknown"

    policies = [h["policy"] for h in hops if h.get("policy")]
    deny = next((p for p in policies if p.get("decision") == "deny"), None)
    unknown_pol = next((p for p in policies if p.get("decision") == "unknown"), None)
    reached_exit = any(h.get("type") == "ebgp_exit" for h in hops)
    last = hops[-1] if hops else None
    external_dest = destination.lower() == "internet" or destination.startswith("0.0.0.0")

    if deny:
        result = "blocked"
        blocked_by = {"device": deny.get("policy_device") or _hop_device_for_policy(hops, deny),
                      "policy": deny.get("policy"), "id": deny.get("id")}
        reasons.append(f"denied by policy '{deny.get('policy')}'")
    elif not hops:
        result = "unknown"
        reasons.append("no hops could be evaluated (no routing data for source)")
    elif reached_exit or (last and last.get("boundary") == "exits collection scope" and external_dest):
        result = "reachable"
    else:
        result = "partial"
        reasons.append("trace did not cleanly reach the destination (stalled mid-path)")

    if unknown_pol and result != "blocked":
        if result == "reachable":
            result = "partial"
        reasons.append(f"policy '{unknown_pol.get('policy')}' matched via an unresolved "
                       f"Internet-Service feed (manual review)")

    if src_ip is None and policies:
        reasons.append("source IP not supplied — policy source-address matching not verified")

    risks = _findings_on_path(path_devices, run_id)

    return {
        "result": result,
        "reasons": reasons,
        "hops": len(hops),
        "blocked_by": blocked_by,
        "risks": risks,
        "run_id": run_id,
    }


def _hop_device_for_policy(hops: list[dict], policy: dict) -> str | None:
    """Find the device whose hop carried ``policy`` (for blocked_by attribution)."""
    for h in hops:
        if h.get("policy") is policy:
            # The firewall device is this hop's device or its next_device.
            return h.get("device")
    return None
