"""Device endpoint — device detail from Neo4j.

 Queries Neo4j for device info, interfaces (with L1 enrichment),
neighbors (from typed link relationships), protocols (from adjacencies
and shared services), and findings (from filesystem, AD-2).
"""

import json
import logging
import os
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from netcopilot.findings import load_findings_enriched
from netcopilot.model.interface_taxonomy import is_virtual_interface
from netcopilot.graph.client import get_driver, is_available

logger = logging.getLogger(__name__)

router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


@router.get("/api/device/{hostname}")
def get_device(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return detail for a specific device from Neo4j.

    Includes device info, interfaces (with L1 and peer enrichment),
    neighbors, protocols, and device-specific findings.
    Returns HTTP 503 if Neo4j is unavailable.
    """
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"error": "Neo4j unavailable. Start with: docker compose up -d"},
        )

    try:
        driver = get_driver()

        # ---- Query device ----
        device = _query_device(driver, run_id, hostname)
        if device is None:
            return JSONResponse(
                status_code=404,
                content={"error": f"Device '{hostname}' not found in run '{run_id}'"},
            )

        # ---- Query interfaces ----
        interfaces = _query_interfaces(driver, run_id, hostname)

        # ---- Query neighbors from typed links ----
        neighbors = _query_neighbors(driver, run_id, hostname)

        # ---- Enrich interfaces with peer info from neighbors ----
        _enrich_interface_peers(interfaces, neighbors)

        # ---- Query protocols ----
        protocols = _query_protocols(driver, run_id, hostname)

        # ---- Load findings from filesystem (AD-2) ----
        findings = _load_device_findings(run_id, hostname)

        return {
            "device": device,
            "interfaces": interfaces,
            "neighbors": neighbors,
            "protocols": protocols,
            "findings": findings,
        }

    except Exception as e:
        logger.error("Device detail query failed: %s", e)
        return JSONResponse(
            status_code=503,
            content={"error": f"Neo4j query failed: {type(e).__name__}: {e}"},
        )


# -------------------------------------------------------------------------
# Neo4j query helpers
# -------------------------------------------------------------------------

def _query_device(driver, run_id: str, hostname: str) -> dict | None:
    """Query a single Device node.

    If duplicates exist (multiple loads), picks the record with the
    most properties (ORDER BY platform DESC gets non-null first).
    """
    cypher = (
        "MATCH (d:Device {name: $hostname, run_id: $run_id}) "
        "RETURN d.name AS hostname, d.name AS device_id, "
        "d.platform AS platform, d.os_type AS os_type, "
        "d.os_version AS os_version, d.role AS role, "
        "d.site AS site, d.mgmt_ip AS management_ip, "
        "d.serial AS serial, "
        "d.interfaces_up AS interfaces_up, "
        "d.interfaces_down AS interfaces_down, "
        "d.interfaces_total AS interfaces_total, "
        "d.cluster_size AS cluster_size, "
        "d.cluster_members AS cluster_members "
        "ORDER BY d.site DESC, d.platform DESC LIMIT 1"
    )
    with driver.session() as session:
        result = session.run(cypher, hostname=hostname, run_id=run_id)
        rec = result.single()
        if rec is None:
            return None

        d = dict(rec)
        collected = bool(d.get("platform") or d.get("os_version"))

        device = {
            "hostname": d["hostname"],
            "device_id": d["device_id"],
            "platform": d.get("platform"),
            "os_type": d.get("os_type"),
            "os_version": d.get("os_version"),
            "role": d.get("role"),
            "site": d.get("site"),
            "management_ip": d.get("management_ip"),
            "collected": collected,
        }

        # Optional extended properties
        if d.get("serial"):
            device["serial"] = d["serial"]
        if d.get("interfaces_up") is not None:
            device["interfaces_up"] = d["interfaces_up"]
        if d.get("interfaces_down") is not None:
            device["interfaces_down"] = d["interfaces_down"]
        if d.get("interfaces_total") is not None:
            device["interfaces_total"] = d["interfaces_total"]
        if d.get("cluster_size"):
            device["cluster_size"] = d["cluster_size"]
        if d.get("cluster_members"):
            try:
                device["cluster_members"] = json.loads(d["cluster_members"])
            except (json.JSONDecodeError, TypeError):
                pass

        # OSPF areas from SharedService membership
        ospf_cypher = (
            "MATCH (d:Device {name: $hostname, run_id: $run_id})"
            "-[:MEMBER_OF]->(s:SharedService {service_type: 'ospf_area'}) "
            "RETURN s.identifier AS area ORDER BY area"
        )
        ospf_res = session.run(ospf_cypher, hostname=hostname, run_id=run_id)
        ospf_areas = [r["area"] for r in ospf_res if r["area"]]
        if ospf_areas:
            device["ospf_areas"] = ospf_areas

        # BGP ASN from SharedService membership — surfaced so the frontend
        # shows the BGP detail tab (gated on device.bgp_as), mirroring the OSPF
        # pattern above. Without this the BGP tab stays hidden for BGP speakers.
        bgp_cypher = (
            "MATCH (d:Device {name: $hostname, run_id: $run_id})"
            "-[:MEMBER_OF]->(s:SharedService {service_type: 'bgp_asn'}) "
            "RETURN s.identifier AS asn LIMIT 1"
        )
        bgp_row = session.run(bgp_cypher, hostname=hostname, run_id=run_id).single()
        if bgp_row and bgp_row["asn"]:
            device["bgp_as"] = bgp_row["asn"]

        return device


def _query_interfaces(driver, run_id: str, hostname: str) -> list[dict]:
    """Query Interface nodes for a device, including L1 and QoS enrichment.

    Deduplicates by interface name (picks the record with more
    properties if duplicates exist from multiple loads).
    """
    cypher = (
        "MATCH (d:Device {name: $hostname, run_id: $run_id})"
        "-[:HAS_INTERFACE]->(i:Interface) "
        "RETURN i.name AS name, i.admin_status AS admin_status, "
        "i.oper_status AS oper_status, i.ip AS ip_address, "
        "i.type AS type, "
        "i.speed AS speed, i.duplex AS duplex, "
        "i.mtu AS mtu, i.media_type AS media_type, "
        "i.description AS description, "
        # QoS input direction (, )
        "i.qos_input_policy_name AS qos_input_policy_name, "
        "i.qos_input_type AS qos_input_type, "
        "i.qos_input_cir_bps AS qos_input_cir_bps, "
        "i.qos_input_bc_bytes AS qos_input_bc_bytes, "
        "i.qos_input_conform_packets AS qos_input_conform_packets, "
        "i.qos_input_conform_bytes AS qos_input_conform_bytes, "
        "i.qos_input_exceed_packets AS qos_input_exceed_packets, "
        "i.qos_input_exceed_bytes AS qos_input_exceed_bytes, "
        "i.qos_input_exceed_action AS qos_input_exceed_action, "
        # QoS output direction (, )
        "i.qos_output_policy_name AS qos_output_policy_name, "
        "i.qos_output_type AS qos_output_type, "
        "i.qos_output_cir_bps AS qos_output_cir_bps, "
        "i.qos_output_queue_drops AS qos_output_queue_drops, "
        "i.qos_output_queue_depth AS qos_output_queue_depth, "
        "i.qos_output_conform_packets AS qos_output_conform_packets, "
        "i.qos_output_conform_bytes AS qos_output_conform_bytes, "
        "i.port_channel_int AS port_channel_int, "
        "i.port_channel_members AS port_channel_members, "
        "i.sfp_pid AS sfp_pid, "
        # L2 switchport fields (already in Neo4j via loader.py)
        "i.switchport_mode AS switchport_mode, "
        "i.access_vlan AS access_vlan, "
        "i.trunk_vlans AS trunk_vlans, "
        "i.native_vlan AS native_vlan, "
        "i.prefix_length AS prefix_length, "
        "i.vrf AS vrf "
        "ORDER BY i.name"
    )
    with driver.session() as session:
        result = session.run(cypher, hostname=hostname, run_id=run_id)
        # Deduplicate by name — keep the record with more properties
        seen: dict[str, dict] = {}
        for rec in result:
            intf = {k: v for k, v in dict(rec).items() if v is not None}
            name = intf.get("name", "")
            if name not in seen or len(intf) > len(seen[name]):
                seen[name] = intf
        # Reconstruct nested QoS dicts from flat Neo4j properties
        return [_reconstruct_qos(intf) for intf in seen.values()]


def _reconstruct_qos(intf: dict) -> dict:
    """Rebuild nested ``qos`` dict from flat ``qos_<dir>_<field>`` keys.

    Collects all ``qos_input_*`` and ``qos_output_*`` keys into a nested
    ``{input: {...}, output: {...}}`` structure, then removes the flat keys.
    Returns the interface dict unchanged if no QoS keys are present.
    """
    qos: dict = {}
    keys_to_remove: list[str] = []

    for direction in ("input", "output"):
        prefix = f"qos_{direction}_"
        dir_data: dict = {}
        for key, val in intf.items():
            if key.startswith(prefix):
                field = key[len(prefix):]
                dir_data[field] = val
                keys_to_remove.append(key)
        if dir_data:
            qos[direction] = dir_data

    for key in keys_to_remove:
        del intf[key]

    if qos:
        intf["qos"] = qos

    return intf


def _query_neighbors(driver, run_id: str, hostname: str) -> list[dict]:
    """Query neighbors from typed link relationships.

    Looks at both outgoing and incoming relationships.
    Returns deduplicated neighbor list.
    """
    # Audit note: scope second Device node by run_id too.
    # Audit 2026-05-15 bug #1: "Connected to:" must mean physical/management
    # cable peer only — L3_REACHABILITY (ARP-derived, same-subnet) and
    # INFERRED_LINK (heuristic) are not cables and produced wrong labels
    # (e.g., REI BE13's L3_REACHABILITY to FortiGate winning the first-row
    # race over its actual PHYSICAL_CABLE/MGMT_LINK peer).
    # Outgoing links: hostname → peer
    cypher_out = (
        "MATCH (a:Device {name: $hostname, run_id: $run_id})-[r]->(b:Device {run_id: $run_id}) "
        "WHERE type(r) IN ['PHYSICAL_CABLE', 'MGMT_LINK'] "
        "RETURN b.name AS peer_device, "
        "r.local_interface AS local_interface, "
        "r.remote_interface AS peer_interface, "
        "r.discovery_method AS discovery_method, "
        "r.status AS status, r.link_id AS link_id"
    )
    # Incoming links: peer → hostname
    cypher_in = (
        "MATCH (b:Device {run_id: $run_id})-[r]->(a:Device {name: $hostname, run_id: $run_id}) "
        "WHERE type(r) IN ['PHYSICAL_CABLE', 'MGMT_LINK'] "
        "RETURN b.name AS peer_device, "
        "r.remote_interface AS local_interface, "
        "r.local_interface AS peer_interface, "
        "r.discovery_method AS discovery_method, "
        "r.status AS status, r.link_id AS link_id"
    )
    seen_links: set[str] = set()
    neighbors = []
    with driver.session() as session:
        for cypher in [cypher_out, cypher_in]:
            result = session.run(cypher, hostname=hostname, run_id=run_id)
            for rec in result:
                d = dict(rec)
                link_id = d.pop("link_id", None)
                # Deduplicate by link_id
                if link_id and link_id in seen_links:
                    continue
                if link_id:
                    seen_links.add(link_id)
                neighbor = {k: v for k, v in d.items() if v is not None}
                neighbors.append(neighbor)
    return neighbors


def _enrich_interface_peers(
    interfaces: list[dict], neighbors: list[dict],
) -> None:
    """Add peer_device and peer_interface to interfaces from neighbor data.

    Two passes:
      1. Direct edge match — interface name → peer from typed-link neighbor.
      2. Bundle aggregation — for port-channel/bundle interfaces with no direct
         edge, inherit peer_device from members when ALL members share the same
         peer. Joins member peer-interfaces into a single label string.
         Rationale: PHYSICAL_CABLE edges from LACP discovery live on member
         ports (Hu0/0/1/0, Hu0/0/1/1), not on the bundle (BE13) itself, so the
         bundle's "Connected to:" footer would otherwise be blank.
    """
    # When multiple edges share the same local_interface (e.g. SMI-01 has both
    # a mac_subnet MGMT_LINK landing on a physical port and an arp_subnet
    # MGMT_LINK landing on an SVI), prefer the edge whose peer_interface is a
    # real physical port over a virtual one (Vlan SVI, BVI/BDI, Loopback,
    # Tunnel, NVE, FortiGate numeric VLAN). The taxonomy is shared with
    # `model.link_builder` via `lib.interface_taxonomy` so both layers stay
    # in sync (case-insensitive + FortiGate numeric VLAN handling).
    def _sort_key(n: dict) -> tuple:
        # Primary: non-virtual peer_interface first (False < True).
        # Secondary: stable tiebreaker on (peer_device, peer_interface) so the
        # selection is deterministic across pipeline runs even when multiple
        # physical-port edges exist for the same local_interface.
        peer_intf = n.get("peer_interface") or ""
        return (
            is_virtual_interface(peer_intf),
            n.get("peer_device") or "",
            peer_intf,
        )

    neighbors_sorted = sorted(neighbors, key=_sort_key)

    # Build lookup: local_interface → peer info (first wins after the sort).
    peer_lookup: dict[str, dict] = {}
    for n in neighbors_sorted:
        local_intf = n.get("local_interface")
        if local_intf and local_intf not in peer_lookup:
            peer_lookup[local_intf] = {
                "peer_device": n.get("peer_device"),
                "peer_interface": n.get("peer_interface"),
            }

    # Pass 1: direct edge match
    for intf in interfaces:
        name = intf.get("name", "")
        peer = peer_lookup.get(name)
        if peer:
            intf["peer_device"] = peer["peer_device"]
            if peer.get("peer_interface"):
                intf["peer_interface"] = peer["peer_interface"]

    # Pass 2: bundle aggregation for port-channel interfaces with no direct peer
    intf_by_name = {intf.get("name", ""): intf for intf in interfaces}
    for intf in interfaces:
        if intf.get("peer_device"):
            continue
        members = intf.get("port_channel_members")
        if not members:
            continue
        member_peers: set[str] = set()
        member_peer_intfs: list[str] = []
        for member_name in members:
            m = intf_by_name.get(member_name)
            if not m:
                continue
            mp = m.get("peer_device")
            if mp:
                member_peers.add(mp)
                mpi = m.get("peer_interface")
                if mpi and mpi not in member_peer_intfs:
                    member_peer_intfs.append(mpi)
        # Aggregate only when all member peers agree on a single device
        if len(member_peers) == 1:
            intf["peer_device"] = next(iter(member_peers))
            if member_peer_intfs:
                intf["peer_interface"] = ", ".join(member_peer_intfs)


def _query_protocols(driver, run_id: str, hostname: str) -> dict:
    """Query protocol adjacencies and shared services for a device."""
    protocols: dict = {}

    with driver.session() as session:
        # ---- ROUTING_ADJACENCY ----
        cypher_adj = (
            "MATCH (a:Device {name: $hostname, run_id: $run_id})"
            "-[r:ROUTING_ADJACENCY]-(peer:Device) "
            "RETURN peer.name AS peer, r.protocol AS protocol, "
            "r.state AS state, r.area AS area, "
            "r.local_as AS local_as, r.remote_as AS remote_as, "
            "r.vrf AS vrf"
        )
        result = session.run(cypher_adj, hostname=hostname, run_id=run_id)
        seen_peers: dict[str, set] = {"ospf": set(), "bgp": set()}
        for rec in result:
            proto = rec["protocol"]
            peer = rec["peer"]

            if proto == "ospf":
                if "ospf" not in protocols:
                    protocols["ospf"] = {"areas": set(), "router_id": None}
                if rec.get("area"):
                    protocols["ospf"]["areas"].add(rec["area"])

            elif proto == "bgp":
                if "bgp" not in protocols:
                    protocols["bgp"] = {"local_as": None, "peers": []}
                if peer not in seen_peers["bgp"]:
                    seen_peers["bgp"].add(peer)
                    protocols["bgp"]["peers"].append(peer)

        # ---- SharedService: BGP AS, OSPF areas, VLANs ----
        cypher_svc = (
            "MATCH (d:Device {name: $hostname, run_id: $run_id})"
            "-[:MEMBER_OF]->(s:SharedService) "
            "RETURN s.service_type AS stype, s.identifier AS ident"
        )
        result = session.run(cypher_svc, hostname=hostname, run_id=run_id)
        for rec in result:
            stype = rec["stype"]
            ident = rec["ident"]
            if stype == "bgp_asn":
                if "bgp" not in protocols:
                    protocols["bgp"] = {"local_as": None, "peers": []}
                protocols["bgp"]["local_as"] = ident
            elif stype == "ospf_area":
                if "ospf" not in protocols:
                    protocols["ospf"] = {"areas": set(), "router_id": None}
                protocols["ospf"]["areas"].add(ident)

    # Convert sets to sorted lists for JSON serialization
    if "ospf" in protocols:
        protocols["ospf"]["areas"] = sorted(protocols["ospf"]["areas"])

    return protocols


# -------------------------------------------------------------------------
# Findings from filesystem (AD-2)
# -------------------------------------------------------------------------

def _load_device_findings(run_id: str, hostname: str) -> list[dict]:
    """Load findings for a specific device via the canonical Neo4j-first loader.

    Uses load_findings_enriched() (acknowledgement-enriched); the
    element_id-to-device matcher (_finding_matches_device) delegates to the
    shared _devices_from_element_id parser, so device attribution stays
    consistent with the loader.
    """
    all_findings = load_findings_enriched(run_id) or []

    device_findings = []
    for f in all_findings:
        element_id = f.get("evidence", {}).get("element_id", "")
        if _finding_matches_device(element_id, hostname):
            device_findings.append({
                "finding_id": f.get("finding_id"),
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "message": f.get("message"),
            })
    return device_findings


def _finding_matches_device(element_id: str, hostname: str) -> bool:
    """Return True if ``element_id`` references ``hostname``.

    Delegates to ``the shared findings helpers _devices_from_element_id`` so the set of
    supported formats (single-device, link, cross-device NTP, STP globals,
    FDB management) stays consistent between the filter used by this
    endpoint and the one used by the graph loader.  CC-3 contract test
    enforces agreement.
    """
    from netcopilot.findings import _devices_from_element_id

    return hostname in _devices_from_element_id(element_id)


# =========================================================================
# Device VLANs endpoint ()
# =========================================================================


def _build_fortigate_interfaces_response(
    hostname: str,
    run_id: str,
    records: list,
    peer_map: dict[str, dict] | None = None,
) -> dict:
    """Build hierarchical FortiGate interfaces response from Neo4j Interface nodes.

    Groups interfaces by aggregate parent, showing physical member ports
    and nested VLAN sub-interfaces with L1/L3 info.  Non-hierarchical
    interfaces (tunnels, loopbacks, vdom-links) go into an "Other" group.

    Returns dict with ``interface_groups`` (hierarchical).
    """
    from ipaddress import ip_interface

    if peer_map is None:
        peer_map = {}

    # Track which interface names are "claimed" (aggregate, member, vlan child)
    claimed: set[str] = set()
    groups: dict[str, dict] = {}  # parent_name → group dict
    vlan_entries: list[tuple] = []
    other_entries: list[dict] = []
    rec_by_name: dict[str, dict] = {}  # name → record for L1 lookup

    for rec in records:
        rec_by_name[rec["name"] or ""] = rec

    for rec in records:
        name = rec["name"] or ""
        itype = rec["type"] or ""
        vlanid = rec["vlanid"]
        parent = rec["parent_interface"]
        members = rec["aggregate_members"]
        ip_raw = rec["ip"] or ""
        pfx = rec["prefix_length"]
        descr = rec["description"] or ""
        status_raw = rec["status"] or ""
        admin = rec["admin_status"] or ""
        status = "up" if status_raw == "up" or admin == "up" else "down"

        # Compute subnet
        subnet = None
        if ip_raw:
            try:
                cidr = ip_raw if "/" in ip_raw else (f"{ip_raw}/{pfx}" if pfx else None)
                if cidr:
                    subnet = str(ip_interface(cidr).network)
            except (ValueError, TypeError):
                pass

        if itype == "aggregate":
            member_list = list(members) if members else []
            claimed.add(name)
            claimed.update(member_list)
            peer = peer_map.get(name, {})
            groups[name] = {
                "name": name,
                "alias": descr,
                "type": "aggregate",
                "members": member_list,
                "status": status,
                "speed": rec.get("speed"),
                "duplex": rec.get("duplex"),
                "mtu": rec.get("mtu"),
                "media_type": rec.get("media_type"),
                "sfp_pid": rec.get("sfp_pid"),
                "peer_device": peer.get("peer_device"),
                "peer_interface": peer.get("peer_interface"),
                "children": [],
            }
        elif itype == "vlan" and vlanid is not None:
            claimed.add(name)
            vlan_entries.append((parent, {
                "name": name,
                "vlanid": int(vlanid),
                "type": "vlan",
                "description": descr,
                "ip": ip_raw or None,
                "subnet": subnet,
                "status": status,
            }))

    # Create groups for standalone physical ports that are VLAN parents
    for parent, _ in vlan_entries:
        if parent and parent not in groups:
            claimed.add(parent)
            peer = peer_map.get(parent, {})
            prec = rec_by_name.get(parent, {})
            groups[parent] = {
                "name": parent,
                "alias": prec.get("description") or "",
                "type": "physical",
                "members": [],
                "status": "up",
                "speed": prec.get("speed"),
                "duplex": prec.get("duplex"),
                "mtu": prec.get("mtu"),
                "media_type": prec.get("media_type"),
                "sfp_pid": prec.get("sfp_pid"),
                "peer_device": peer.get("peer_device"),
                "peer_interface": peer.get("peer_interface"),
                "children": [],
            }

    # Attach VLANs to parent groups
    for parent, vlan_entry in vlan_entries:
        if parent and parent in groups:
            groups[parent]["children"].append(vlan_entry)

    # Sort children within each group by vlanid
    for group in groups.values():
        group["children"].sort(key=lambda v: v.get("vlanid", 0))

    # Inherit L1 from physical members onto aggregate parents
    # Aggregates don't have speed/duplex/media — their member ports do.
    member_l1: dict[str, dict] = {}
    for rec in records:
        name = rec["name"] or ""
        if (rec["type"] or "") == "physical" and rec.get("speed"):
            member_l1[name] = {
                "speed": rec.get("speed"),
                "duplex": rec.get("duplex"),
                "media_type": rec.get("media_type"),
                "sfp_pid": rec.get("sfp_pid"),
            }
    for group in groups.values():
        if group.get("speed"):
            continue  # already has L1
        for m in group.get("members", []):
            if m in member_l1:
                group.update(member_l1[m])
                break

    # Collect "other" interfaces (not claimed by any group)
    for rec in records:
        name = rec["name"] or ""
        if name in claimed:
            continue
        itype = rec["type"] or ""
        ip_raw = rec["ip"] or ""
        pfx = rec["prefix_length"]
        descr = rec["description"] or ""
        status_raw = rec["status"] or ""
        admin = rec["admin_status"] or ""
        status = "up" if status_raw == "up" or admin == "up" else "down"
        subnet = None
        if ip_raw:
            try:
                cidr = ip_raw if "/" in ip_raw else (f"{ip_raw}/{pfx}" if pfx else None)
                if cidr:
                    subnet = str(ip_interface(cidr).network)
            except (ValueError, TypeError):
                pass
        other_entries.append({
            "name": name,
            "type": itype,
            "description": descr,
            "ip": ip_raw or None,
            "subnet": subnet,
            "status": status,
        })

    # Sort groups: aggregates first, then physicals
    interface_groups = sorted(
        groups.values(),
        key=lambda g: (0 if g["type"] == "aggregate" else 1, g["name"]),
    )

    # Append "Other" group if any unclaimed interfaces exist
    if other_entries:
        other_entries.sort(key=lambda e: e["name"])
        interface_groups.append({
            "name": "Other",
            "alias": "",
            "type": "other",
            "members": [],
            "status": "up",
            "children": other_entries,
        })

    return {
        "hostname": hostname,
        "run_id": run_id,
        "interface_groups": interface_groups,
    }


@router.get("/api/device/{hostname}/vlans")
def get_device_vlans(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return VLAN database for a device (show vlan brief equivalent).

    Queries Vlan nodes and enriches with Interface switchport data to show
    which ports carry each VLAN (access, trunk, or native).
    Returns HTTP 503 if Neo4j is unavailable.
    """
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"error": "Neo4j unavailable"},
        )

    driver = get_driver()

    cypher_vlans = """
    MATCH (d:Device {name: $hostname, run_id: $run_id})-[:HAS_VLAN]->(v:Vlan)
    RETURN v.vlan_id AS vlan_id, v.name AS name, v.state AS state,
           v.shutdown AS shutdown, v.interfaces AS interfaces
    ORDER BY v.vlan_id
    """

    # Get all switchport interfaces for this device
    cypher_intfs = """
    MATCH (i:Interface {run_id: $run_id, device: $hostname})
    WHERE i.switchport_mode IS NOT NULL
    RETURN i.name AS name, i.switchport_mode AS mode,
           i.access_vlan AS access_vlan, i.trunk_vlans AS trunk_vlans
    """

    # FortiGate fallback: interfaces with access_vlan + description (no Vlan nodes)
    cypher_fw_vlans = """
    MATCH (i:Interface {run_id: $run_id, device: $hostname})
    WHERE i.access_vlan IS NOT NULL
    RETURN i.name AS name, i.access_vlan AS vlan_id,
           i.description AS description,
           i.status AS status, i.admin_status AS admin_status
    """

    with driver.session() as session:
        vlan_records = list(session.run(cypher_vlans, hostname=hostname, run_id=run_id))
        intf_records = list(session.run(cypher_intfs, hostname=hostname, run_id=run_id))

    # Build vlan_id → set of interface names from switchport data
    vlan_ports: dict[int, set[str]] = {}
    all_trunk_ports: list[str] = []  # trunks with empty allowed list = all VLANs

    for rec in intf_records:
        name = rec["name"]
        mode = rec["mode"]
        if mode == "access":
            av = rec["access_vlan"]
            if av is not None:
                try:
                    vlan_ports.setdefault(int(av), set()).add(name)
                except (ValueError, TypeError):
                    pass
        elif mode == "trunk":
            trunk_vlans = rec["trunk_vlans"] or []
            if trunk_vlans:
                for v in trunk_vlans:
                    try:
                        vlan_ports.setdefault(int(v), set()).add(name)
                    except (ValueError, TypeError):
                        pass
            else:
                # Empty trunk_vlans = "all allowed" — carries every VLAN
                all_trunk_ports.append(name)

    # If Vlan nodes exist (Cisco), enrich with switchport data
    if vlan_records:
        vlans = []
        for rec in vlan_records:
            vid = rec["vlan_id"]
            base_intfs = set(rec["interfaces"] or [])
            sw_intfs = vlan_ports.get(vid, set())
            all_intfs = base_intfs | sw_intfs | set(all_trunk_ports)
            sorted_intfs = sorted(all_intfs, key=lambda x: (0 if x.startswith("Po") else 1, x))

            vlans.append({
                "vlan_id": vid,
                "name": rec["name"],
                "state": rec["state"],
                "shutdown": rec["shutdown"] or False,
                "interfaces": sorted_intfs,
            })
    else:
        # No Vlan nodes — check for FortiGate hierarchy (vdom field)
        cypher_fw_hierarchy = """
        MATCH (i:Interface {run_id: $run_id, device: $hostname})
        WHERE i.vdom IS NOT NULL
        RETURN i.name AS name, i.type AS type, i.vdom AS vdom,
               i.vlanid AS vlanid, i.parent_interface AS parent_interface,
               i.aggregate_members AS aggregate_members,
               i.ip AS ip, i.prefix_length AS prefix_length,
               i.description AS description,
               i.status AS status, i.admin_status AS admin_status,
               i.speed AS speed, i.duplex AS duplex, i.mtu AS mtu,
               i.media_type AS media_type, i.sfp_pid AS sfp_pid
        ORDER BY i.name
        """
        with driver.session() as session:
            fw_records = list(session.run(
                cypher_fw_hierarchy, hostname=hostname, run_id=run_id,
            ))

        if fw_records:
            # Build peer map from neighbor data
            neighbors = _query_neighbors(driver, run_id, hostname)
            peer_map: dict[str, dict] = {}
            for n in neighbors:
                local_intf = n.get("local_interface", "")
                if local_intf:
                    peer_map[local_intf] = {
                        "peer_device": n.get("peer_device"),
                        "peer_interface": n.get("peer_interface"),
                    }
            return _build_fortigate_interfaces_response(
                hostname, run_id, fw_records, peer_map,
            )

        # Final fallback: no Vlan nodes and no vdom data
        vlans = []

    return {"hostname": hostname, "run_id": run_id, "vlans": vlans}
