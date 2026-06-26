"""Topology endpoint — Cytoscape.js graph from Neo4j.

 Queries Neo4j for typed link relationships instead of reading
JSON files. View filtering is now a Cypher pattern, not a Python filter.
topology_view_filter.py is no longer needed.

Views:
    physical (default): PHYSICAL_CABLE edges, mgmt_switch excluded (AD-8)
    mgmt: MGMT_LINK edges
    all: all 4 typed link types
"""

import json
import logging
import os
import re
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netcopilot.findings import device_from_finding, load_findings_enriched
from netcopilot.graph.client import get_driver, get_site_for_run, is_available

logger = logging.getLogger(__name__)

router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

# Relationship types by view
VIEW_REL_TYPES = {
    "physical": ["PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"],
    "l2vlan": ["PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"],
    "mgmt": ["MGMT_LINK", "INFRASTRUCTURE_LINK"],
    "ospf": ["PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"],
    "bgp": ["PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"],
    "all": ["PHYSICAL_CABLE", "MGMT_LINK", "L3_REACHABILITY", "INFERRED_LINK", "INFRASTRUCTURE_LINK"],
}


@router.get("/api/topology")
def get_topology(
    run_id: str = Query(..., description="Pipeline run ID"),
    view: str = Query("physical", description="Topology view: physical, mgmt, or all"),
):
    """Query Neo4j for topology graph in Cytoscape.js format.

    Returns {nodes, edges, adjacencies} matching the selected view.
    Returns HTTP 503 if Neo4j is unavailable.
    """
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"error": "Neo4j unavailable. Start with: docker compose up -d"},
        )

    rel_types = VIEW_REL_TYPES.get(view, VIEW_REL_TYPES["physical"])

    try:
        driver = get_driver()

        # ---- Query devices (deduplicated by name) ----
        devices = _query_devices(driver, run_id)
        if not devices:
            return JSONResponse(
                status_code=404,
                content={"error": f"No devices found for run_id '{run_id}'"},
            )

        # Deduplicate device list by name (Neo4j may have duplicates
        # from multiple loads; keep first with most data)
        seen_names: set[str] = set()
        unique_devices = []
        for d in devices:
            if d["name"] not in seen_names:
                seen_names.add(d["name"])
                unique_devices.append(d)
        devices = unique_devices

        # ---- Query edges for the selected view ----
        edges = _query_edges(driver, run_id, rel_types)

        # AD-8: Identify mgmt_switch devices
        mgmt_switch_names = {
            d["name"] for d in devices if d.get("role") == "mgmt_switch"
        }

        # ---- Physical/L2 confidence filter ----
        # Only show high/very_high confidence links (CDP/LLDP/FDB/LACP bilateral).
        # Low/medium confidence links (e.g. lacp_unilateral) are excluded.
        # mgmt_switch devices with PHYSICAL_CABLE edges (e.g. SMI↔FWL fdb_firewall)
        # appear naturally; their management-only links (dp≥7) are classified as
        # MGMT_LINK at build time and excluded by VIEW_REL_TYPES.
        _PHYSICAL_CONF = {"high", "very_high"}
        if view in ("physical", "l2vlan"):
            edges = [
                e for e in edges
                if e.get("confidence") in _PHYSICAL_CONF
            ]

        # ---- Mgmt view: only cable-based links (exclude ARP/MAC/subnet) ----
        # Management links include both real cables (CDP/LLDP/LACP/FDB) and
        # L3 reachability via management subnets (ARP/MAC). The mgmt view
        # should only show the physical cables.
        if view == "mgmt":
            _CABLE_MAX_DP = 6  # CDP=1..5, LACP/FDB=5..6; ARP=7+
            edges = [
                e for e in edges
                if (e.get("discovery_priority") or 99) <= _CABLE_MAX_DP
            ]

        # ---- Anti-orphan: devices with 0 edges get their best link ----
        edge_devices = set()
        for e in edges:
            edge_devices.add(e["source"])
            edge_devices.add(e["target"])

        orphan_names = [
            d["name"] for d in devices
            if d["name"] not in edge_devices
            and d.get("device_type") != "external"
            and (view == "mgmt" or d.get("role") != "mgmt_switch")
        ]
        if orphan_names:
            # In mgmt view, prefer MGMT_LINK edges over other types,
            # and specifically prefer edges connecting to the mgmt_switch.
            # Without this, anti-orphan picks PHYSICAL_CABLE (lower priority
            # number) over MGMT_LINK — e.g. REI routers get LACP links to
            # SCI instead of management cables to SMI.
            preferred_types = ["MGMT_LINK"] if view == "mgmt" else None
            preferred_peers = mgmt_switch_names if view == "mgmt" else None
            rescue_edges = _query_best_links(
                driver, run_id, orphan_names,
                preferred_types=preferred_types,
                preferred_peers=preferred_peers,
            )
            if view in ("physical", "l2vlan"):
                rescue_edges = [e for e in rescue_edges if e.get("confidence") in _PHYSICAL_CONF]
            elif view == "mgmt":
                # Rescue orphans with genuine management links only — never fall
                # back to data cables. A network with no out-of-band management
                # fabric (e.g. the containerlab demo) then honestly shows its
                # devices unconnected instead of a fabricated data backbone.
                rescue_edges = [
                    e for e in rescue_edges
                    if e.get("link_type") in ("management", "infrastructure")
                ]
            edges.extend(rescue_edges)
            for e in rescue_edges:
                edge_devices.add(e["source"])
                edge_devices.add(e["target"])

        # ---- Deduplicate edges by link_id ----
        edges = _deduplicate_edges(edges)

        # ---- L2/VLAN: merge parallel edges into one per device pair ----
        if view == "l2vlan":
            edges = _merge_l2vlan_edges(edges)
            # Re-enrich L1: merged edges have port-channel ports that need
            # fallback to member interfaces for speed/duplex/media data
            _enrich_edges_l1(driver, run_id, edges)

        # ---- Enrich edges with VLAN names + trunk subnets for link detail panel ----
        edges = _enrich_edge_vlan_names(driver, run_id, edges)

        # ---- Enrich edges with routes that traverse each link ----
        _enrich_edge_routes(run_id, edges)

        # ---- Query adjacencies (OSPF/BGP) ----
        adjacencies = _query_adjacencies(driver, run_id)

        # ---- Deduplicate adjacencies ----
        adjacencies = _deduplicate_adjacencies(adjacencies)

        # ---- Query shared services for protocol metadata ----
        svc_metadata = _query_shared_service_metadata(driver, run_id)

        # ---- Enrich findings from filesystem ----
        findings_per_device, critical_devices = _load_findings_counts(run_id)

        # ---- Build Cytoscape nodes ----
        device_map = {d["name"]: d for d in devices}

        # Determine which devices to include as nodes:
        # 1. All devices that participate in edges (including rescue)
        # 2. In "all" or "mgmt" view: show all inventory devices (including
        #    unreachable ones) so operators see the full inventory state
        # 3. Exclude external devices unless they have edges
        node_names = set(edge_devices)
        if view in ("all", "mgmt"):
            for d in devices:
                if d.get("device_type") != "external":
                    node_names.add(d["name"])
        # mgmt_switch devices appear in node_names only if they have edges
        # (already handled by edge_devices set above)

        # OSPF view: restrict to devices that have OSPF adjacencies
        if view == "ospf":
            ospf_devices = set()
            for adj in adjacencies:
                if adj.get("protocol") == "ospf":
                    ospf_devices.add(adj["source"])
                    ospf_devices.add(adj["target"])
            node_names = node_names & ospf_devices if ospf_devices else node_names

        # BGP view: restrict to devices that have BGP adjacencies
        if view == "bgp":
            bgp_devices = set()
            for adj in adjacencies:
                if adj.get("protocol") == "bgp":
                    bgp_devices.add(adj["source"])
                    bgp_devices.add(adj["target"])
            # Include external peers from device list (they may not be in
            # edge_devices since they have no physical cables)
            for d in devices:
                if d.get("device_type") == "external" and d["name"] in bgp_devices:
                    node_names.add(d["name"])
            node_names = node_names & bgp_devices if bgp_devices else node_names

        nodes = []
        for name in sorted(node_names):
            d = device_map.get(name)
            if d:
                node = _build_node(d, svc_metadata, findings_per_device, critical_devices)
            else:
                # Placeholder for uncollected peer
                node = {
                    "data": {
                        "id": name,
                        "role": "external",
                        "device_type": "external",
                        "collected": False,
                        "findings_count": 0,
                    }
                }
            nodes.append(node)

        # ----  Expand compound nodes into parent + children ----
        nodes = _expand_compound_nodes(
            nodes, devices, findings_per_device, critical_devices,
        )

        # ----  Identify compound node names for edge rerouting ----
        compound_names = {
            n["data"]["id"] for n in nodes
            if n.get("data", {}).get("isCompound")
        }

        # ----  Reroute edges to member children ----
        if compound_names:
            edges = _reroute_edges_to_members(edges, compound_names)

        # ----  Query stack interconnect edges (internal) ----
        stack_edges = _query_stack_links(driver, run_id)
        # Filter to only include stack links for devices present in this view
        stack_edges = [
            e for e in stack_edges
            if e.get("source", "").split(":")[0] in node_names
        ]

        # ---- OSPF view: filter edges to OSPF-participating nodes only ----
        if view == "ospf":
            # Build set including compound child IDs (hostname:memberId)
            ospf_node_ids = set()
            for n in nodes:
                ospf_node_ids.add(n["data"]["id"])
            edges = [
                e for e in edges
                if e["source"].split(":")[0] in node_names
                and e["target"].split(":")[0] in node_names
            ]
            stack_edges = [
                e for e in stack_edges
                if e.get("source", "").split(":")[0] in node_names
            ]

        # ---- Build Cytoscape edges ----
        cyto_edges = [{"data": e} for e in edges]
        cyto_edges.extend({"data": e} for e in stack_edges)

        # ---- Classify cable_type on each edge ----
        for ce in cyto_edges:
            d = ce["data"]
            if d.get("linkType") == "stack_interconnect":
                d["cable_type"] = "stack"
            else:
                # A cable's medium is a property of BOTH endpoints, decided
                # copper-dominant: a fixed copper RJ45 port (e.g. a Catalyst
                # GigabitEthernet base port) physically cannot carry a fiber link,
                # so ANY copper endpoint => rj45. Fiber only on positive fiber
                # evidence with no copper endpoint. This is deterministic and
                # transceiver-database-free: a FortiGate "serdes-sfp" SFP is
                # ambiguous (could be a 1000Base-T copper module), so we never
                # assert fiber from it over a known-copper peer — the authoritative
                # copper switch port wins. (Old logic took one arbitrary endpoint
                # via `local or remote`, so a fiber guess masked a copper truth.)
                local_m = d.get("l1_local_media_type") or ""
                remote_m = d.get("l1_remote_media_type") or ""
                copper = ("copper", "copper-sfp")
                if local_m in copper or remote_m in copper:
                    d["cable_type"] = "rj45"
                elif local_m.startswith("fiber") or remote_m.startswith("fiber"):
                    d["cable_type"] = "fiber"
                else:
                    d["cable_type"] = "unknown"

        # ---- Build Cytoscape adjacencies ----
        cyto_adjs = [{"data": a} for a in adjacencies]

        # Determine which routing protocols exist in this run
        available_protocols = sorted({
            a.get("protocol") for a in adjacencies if a.get("protocol")
        })

        # ---- Device inventory summary ----
        external_peers = []
        unreachable_devices = []
        with driver.session() as inv_session:
            ext_result = inv_session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE d.role IS NULL "
                "RETURN d.name AS name",
                run_id=run_id,
            )
            external_peers = [r["name"] for r in ext_result]

            unreach_result = inv_session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE d.role IS NOT NULL AND d.collected = false "
                "RETURN d.name AS name, d.role AS role",
                run_id=run_id,
            )
            unreachable_devices = [
                {"name": r["name"], "role": r["role"]} for r in unreach_result
            ]

        return {
            "nodes": nodes,
            "edges": cyto_edges,
            "adjacencies": cyto_adjs,
            "available_protocols": available_protocols,
            "external_peers": external_peers,
            "unreachable_devices": unreachable_devices,
        }

    except Exception as e:
        logger.error("Topology query failed: %s", e)
        return JSONResponse(
            status_code=503,
            content={"error": f"Neo4j query failed: {type(e).__name__}: {e}"},
        )


# -------------------------------------------------------------------------
# Layout position persistence
# -------------------------------------------------------------------------

class _PositionsSaveRequest(BaseModel):
    run_id: str
    view: str
    positions: dict[str, dict]  # {node_id: {x: float, y: float}}


@router.get("/api/topology/positions")
def get_positions(
    run_id: str = Query(..., description="Pipeline run ID"),
    view: str = Query("physical", description="Topology view"),
):
    """Return saved node positions for a site+view combination."""
    site = get_site_for_run(run_id)
    if not site:
        return {"positions": {}}
    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (lp:LayoutPosition {site: $site, view: $view}) "
            "RETURN lp.node_id AS node_id, lp.x AS x, lp.y AS y",
            site=site,
            view=view,
        )
        positions = {r["node_id"]: {"x": r["x"], "y": r["y"]} for r in result}
    return {"positions": positions}


@router.post("/api/topology/positions")
def save_positions(body: _PositionsSaveRequest):
    """Save node positions to Neo4j, keyed by site+view+node_id."""
    site = get_site_for_run(body.run_id)
    if not site:
        raise HTTPException(status_code=404, detail="Run not found")
    driver = get_driver()
    saved_ids = list(body.positions.keys())
    with driver.session() as session:
        # Remove stale positions for this site+view that are no longer in the save set
        session.run(
            "MATCH (lp:LayoutPosition {site: $site, view: $view}) "
            "WHERE NOT lp.node_id IN $ids "
            "DELETE lp",
            site=site,
            view=body.view,
            ids=saved_ids,
        )
        # Audit note: batch via UNWIND so all positions land
        # in one transaction. Previous N+1 loop allowed partial-state on
        # Neo4j blip mid-save (Pin Layout would silently half-save).
        batch = [
            {"node_id": node_id, "x": float(pos["x"]), "y": float(pos["y"])}
            for node_id, pos in body.positions.items()
        ]
        session.run(
            "UNWIND $batch AS row "
            "MERGE (lp:LayoutPosition {node_id: row.node_id, site: $site, view: $view}) "
            "SET lp.x = row.x, lp.y = row.y",
            batch=batch,
            site=site,
            view=body.view,
        )
    return {"saved": len(body.positions)}


# -------------------------------------------------------------------------
# Neo4j query helpers
# -------------------------------------------------------------------------

def _query_devices(driver, run_id: str) -> list[dict]:
    """Query all Device nodes for a run."""
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device) WHERE d.run_id = $run_id "
            "RETURN d.name AS name, d.role AS role, d.platform AS platform, "
            "d.os_type AS os_type, d.os_version AS os_version, "
            "d.device_type AS device_type, d.site AS site, "
            "d.mgmt_ip AS management_ip, d.serial AS serial, "
            "d.interfaces_up AS interfaces_up, "
            "d.interfaces_down AS interfaces_down, "
            "d.interfaces_total AS interfaces_total, "
            "d.cluster_size AS cluster_size, "
            "d.cluster_declared_size AS cluster_declared_size, "
            "d.cluster_members AS cluster_members, "
            "d.remote_as AS remote_as, "
            "d.peer_label AS peer_label, "
            "d.is_route_reflector AS is_route_reflector, "
            "d.rr_cluster_id AS rr_cluster_id",
            run_id=run_id,
        )
        return [dict(record) for record in result]


def _query_edges(driver, run_id: str, rel_types: list[str]) -> list[dict]:
    """Query typed link relationships for a run.

    Returns edges as flat dicts matching frontend expectations.
    """
    # Audit note: was N+1 per-rel-type loop (6 round-
    # trips for 6 link types). Single MATCH with `type(r) IN $rel_types` is
    # one round-trip — Neo4j picks the right relationship-type label internally.
    cypher = (
        "MATCH (a:Device {run_id: $run_id})-[r]->(b:Device {run_id: $run_id}) "
        "WHERE type(r) IN $rel_types "
        "RETURN a.name AS source, b.name AS target, type(r) AS rel_type, "
        "r.link_id AS link_id, r.status AS status, "
        "r.local_interface AS local_interface, "
        "r.remote_interface AS remote_interface, "
        "r.discovery_method AS discovery_method, "
        "r.discovery_priority AS discovery_priority, "
        "r.discovery_protocol AS discovery_protocol, "
        "r.confidence AS confidence, "
        "r.peer_collected AS peer_collected, "
        "r.direction AS direction, "
        "r.link_type AS link_type, "
        "r.mgmt_type AS mgmt_type, "
        "r.mgmt_vlan AS mgmt_vlan, r.mgmt_vrf AS mgmt_vrf, "
        "r.source_member_id AS source_member_id, "
        "r.target_member_id AS target_member_id, "
        "r.ha_member AS ha_member, "
        "r.l2_local_mode AS l2_local_mode, r.l2_remote_mode AS l2_remote_mode, "
        "r.l2_local_vlan_id AS l2_local_vlan_id, r.l2_remote_vlan_id AS l2_remote_vlan_id, "
        "r.l2_local_trunk_mode AS l2_local_trunk_mode, r.l2_remote_trunk_mode AS l2_remote_trunk_mode, "
        "r.l2_local_vlans_carried AS l2_local_vlans_carried, r.l2_remote_vlans_carried AS l2_remote_vlans_carried, "
        "r.l2_local_native_vlan AS l2_local_native_vlan, r.l2_remote_native_vlan AS l2_remote_native_vlan, "
        "r.l3_subnet AS l3_subnet, r.l3_local_ip AS l3_local_ip, "
        "r.l3_remote_ip AS l3_remote_ip, "
        "r.l3_local_vrf AS l3_local_vrf, r.l3_remote_vrf AS l3_remote_vrf, "
        "r.lag_group AS lag_group, r.lag_group_target AS lag_group_target "
        "ORDER BY a.name, b.name"
    )
    all_edges = []
    with driver.session() as session:
        result = session.run(cypher, run_id=run_id, rel_types=rel_types)
        for rec in result:
            edge = _build_edge(dict(rec))
            all_edges.append(edge)

    # Enrich edges with L1 data from Interface nodes
    _enrich_edges_l1(driver, run_id, all_edges)
    return all_edges


def _enrich_edges_l1(driver, run_id: str, edges: list[dict]) -> None:
    """Enrich edges with L1 data (speed, duplex, mtu, media_type) from Interface nodes.

    After , link relationship local_interface stores the same long-form
    name as Interface.name (e.g., HundredGigE1/0/49), so direct (device, name)
    lookup works without abbreviation workarounds.
    """
    if not edges or not driver:
        return

    # Collect unique devices referenced in edges
    devices = {e.get("source") for e in edges} | {e.get("target") for e in edges}
    devices.discard(None)
    if not devices:
        return

    # Query all interfaces with L1 data for these devices
    cypher = (
        "MATCH (i:Interface) "
        "WHERE i.run_id = $run_id AND i.device IN $devices "
        "AND (i.speed IS NOT NULL OR i.media_type IS NOT NULL "
        "     OR i.sfp_pid IS NOT NULL) "
        "RETURN i.device AS device, i.name AS name, "
        "i.speed AS speed, i.duplex AS duplex, "
        "i.mtu AS mtu, i.media_type AS media_type, "
        "i.sfp_pid AS sfp_pid"
    )
    l1_lookup: dict[tuple[str, str], dict] = {}
    # Port-channel → first member mapping for LAG fallback
    pc_member_lookup: dict[tuple[str, str], str] = {}
    try:
        with driver.session() as session:
            result = session.run(cypher, run_id=run_id, devices=list(devices))
            for rec in result:
                dev = rec["device"]
                name = rec["name"]
                l1 = {}
                for k in ("speed", "duplex", "mtu", "media_type", "sfp_pid"):
                    if rec[k] is not None:
                        l1[k] = rec[k]
                if l1:
                    l1_lookup[(dev, name)] = l1

            # Build port-channel → first member mapping
            pc_cypher = (
                "MATCH (i:Interface) "
                "WHERE i.run_id = $run_id AND i.device IN $devices "
                "AND i.port_channel_int IS NOT NULL "
                "RETURN i.device AS device, i.name AS name, "
                "i.port_channel_int AS pc"
            )
            result = session.run(pc_cypher, run_id=run_id, devices=list(devices))
            for rec in result:
                key = (rec["device"], rec["pc"])
                if key not in pc_member_lookup:
                    pc_member_lookup[key] = rec["name"]
    except Exception:
        logger.debug("L1 enrichment query failed, skipping", exc_info=True)
        return

    def _l1_for(device: str, base_device: str, intf: str) -> dict | None:
        """Look up L1 data, falling back to port-channel member if needed."""
        l1 = l1_lookup.get((base_device, intf)) or l1_lookup.get((device, intf))
        # If port-channel has partial L1 (speed/duplex but no media/sfp),
        # merge with member data which has transceiver info
        member = pc_member_lookup.get((base_device, intf)) or pc_member_lookup.get((device, intf))
        if member:
            member_l1 = l1_lookup.get((base_device, member)) or l1_lookup.get((device, member))
            if member_l1:
                if l1:
                    merged = dict(member_l1)
                    merged.update(l1)  # port-channel values take precedence
                    return merged
                return member_l1
        return l1

    # Enrich each edge with bilateral L1 from source and target interfaces
    for edge in edges:
        src = edge.get("source", "")
        base_src = src.split(":")[0] if ":" in src else src
        local_intf = edge.get("sourcePort")
        if local_intf:
            l1 = _l1_for(src, base_src, local_intf)
            if l1:
                for k, v in l1.items():
                    edge[f"l1_local_{k}"] = v

        tgt = edge.get("target", "")
        base_tgt = tgt.split(":")[0] if ":" in tgt else tgt
        remote_intf = edge.get("targetPort")
        if remote_intf:
            l1_r = _l1_for(tgt, base_tgt, remote_intf)
            if l1_r:
                for k, v in l1_r.items():
                    edge[f"l1_remote_{k}"] = v


def _query_best_links(
    driver, run_id: str, device_names: list[str],
    preferred_types: list[str] | None = None,
    preferred_peers: set[str] | None = None,
) -> list[dict]:
    """Find the best available link for orphan devices.

    Queries across ALL relationship types and returns the lowest
    discovery_priority link for each orphan device.

    Preference tiers (tried in order, first match wins):
    1. preferred_types + preferred_peers (e.g., MGMT_LINK to mgmt_switch)
    2. preferred_types (e.g., any MGMT_LINK)
    3. all relationship types
    """
    all_types = ['PHYSICAL_CABLE', 'MGMT_LINK', 'L3_REACHABILITY', 'INFERRED_LINK', 'INFRASTRUCTURE_LINK']

    # Build preference tiers
    tiers: list[tuple[list[str], set[str] | None]] = []
    if preferred_types and preferred_peers:
        tiers.append((preferred_types, preferred_peers))
    if preferred_types:
        tiers.append((preferred_types, None))
    tiers.append((all_types, None))

    rescue = []
    for name in device_names:
        found = False
        for types, peers in tiers:
            if found:
                break
            edge = _query_one_best_link(driver, run_id, name, types, peers)
            if edge:
                rescue.append(edge)
                found = True
    return rescue


def _query_one_best_link(
    driver, run_id: str, name: str,
    rel_types: list[str], peer_names: set[str] | None = None,
) -> dict | None:
    """Query the best link for a single device.

    Tries outgoing first, then incoming. If peer_names is set,
    only returns links where the other device is in that set.
    """
    type_filter = ", ".join(f"'{t}'" for t in rel_types)
    peer_clause = "AND b.name IN $peers " if peer_names else ""

    # Outgoing
    cypher_out = (
        f"MATCH (a:Device {{name: $name, run_id: $run_id}})-[r]->(b:Device) "
        f"WHERE type(r) IN [{type_filter}] {peer_clause}"
        f"RETURN a.name AS source, b.name AS target, "
        f"r.link_id AS link_id, r.status AS status, "
        f"r.local_interface AS local_interface, "
        f"r.remote_interface AS remote_interface, "
        f"r.discovery_method AS discovery_method, "
        f"r.discovery_priority AS discovery_priority, "
        f"r.discovery_protocol AS discovery_protocol, "
        f"r.confidence AS confidence, "
        f"r.peer_collected AS peer_collected, "
        f"r.direction AS direction, r.link_type AS link_type, "
        f"r.mgmt_type AS mgmt_type, "
        f"r.mgmt_vlan AS mgmt_vlan, r.mgmt_vrf AS mgmt_vrf, "
        f"r.l3_subnet AS l3_subnet, r.l3_local_ip AS l3_local_ip, "
        f"r.l3_remote_ip AS l3_remote_ip, r.l3_local_vrf AS l3_local_vrf, r.l3_remote_vrf AS l3_remote_vrf "
        f"ORDER BY r.discovery_priority ASC LIMIT 1"
    )
    # Incoming
    cypher_in = (
        f"MATCH (b:Device)-[r]->(a:Device {{name: $name, run_id: $run_id}}) "
        f"WHERE type(r) IN [{type_filter}] {peer_clause}"
        f"RETURN b.name AS source, a.name AS target, "
        f"r.link_id AS link_id, r.status AS status, "
        f"r.local_interface AS local_interface, "
        f"r.remote_interface AS remote_interface, "
        f"r.discovery_method AS discovery_method, "
        f"r.discovery_priority AS discovery_priority, "
        f"r.discovery_protocol AS discovery_protocol, "
        f"r.confidence AS confidence, "
        f"r.peer_collected AS peer_collected, "
        f"r.direction AS direction, r.link_type AS link_type, "
        f"r.mgmt_type AS mgmt_type, "
        f"r.mgmt_vlan AS mgmt_vlan, r.mgmt_vrf AS mgmt_vrf, "
        f"r.l3_subnet AS l3_subnet, r.l3_local_ip AS l3_local_ip, "
        f"r.l3_remote_ip AS l3_remote_ip, r.l3_local_vrf AS l3_local_vrf, r.l3_remote_vrf AS l3_remote_vrf "
        f"ORDER BY r.discovery_priority ASC LIMIT 1"
    )

    params = {"name": name, "run_id": run_id}
    if peer_names:
        params["peers"] = list(peer_names)

    with driver.session() as session:
        rec = session.run(cypher_out, **params).single()
        if rec:
            return _build_edge(dict(rec))
        rec = session.run(cypher_in, **params).single()
        if rec:
            return _build_edge(dict(rec))
    return None


def _query_adjacencies(driver, run_id: str) -> list[dict]:
    """Query ROUTING_ADJACENCY relationships."""
    # Audit note: scope both Device nodes by run_id
    # (was relying on r.run_id only; index hit + multi-run defence).
    cypher = (
        "MATCH (a:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]->(b:Device {run_id: $run_id}) "
        "RETURN a.name AS source, b.name AS target, "
        "r.protocol AS protocol, r.state AS state, "
        "r.area AS area, r.process_id AS process_id, "
        "r.local_as AS local_as, r.remote_as AS remote_as, "
        "r.vrf AS vrf, r.bilateral AS bilateral, "
        "r.peer_collected AS peer_collected, "
        "r.interface_a AS interface_a, r.interface_b AS interface_b, "
        "r.neighbor_address AS neighbor_address, "
        "r.cost_a AS cost_a, r.cost_b AS cost_b, "
        "r.hello_a AS hello_a, r.hello_b AS hello_b, "
        "r.dead_a AS dead_a, r.dead_b AS dead_b, "
        "r.network_type_a AS network_type_a, r.network_type_b AS network_type_b, "
        "r.ip_a AS ip_a, r.ip_b AS ip_b, "
        "r.router_id_a AS router_id_a, r.router_id_b AS router_id_b, "
        "r.area_type AS area_type, "
        "r.passive_default_a AS passive_default_a, "
        "r.passive_default_b AS passive_default_b, "
        "r.active_interfaces_a AS active_interfaces_a, "
        "r.active_interfaces_b AS active_interfaces_b, "
        "r.vrf_lite_a AS vrf_lite_a, r.vrf_lite_b AS vrf_lite_b, "
        "r.redistribute_a AS redistribute_a, "
        "r.redistribute_b AS redistribute_b, "
        "r.reference_bandwidth_a AS reference_bandwidth_a, "
        "r.reference_bandwidth_b AS reference_bandwidth_b, "
        # BGP-specific fields (S19C-5)
        "r.session_type AS session_type, "
        "r.peer_label AS peer_label, "
        "r.rr_client AS rr_client, "
        "r.rr_reflector AS rr_reflector, "
        "r.description_a AS description_a, "
        "r.description_b AS description_b, "
        "r.prefixes_received_a AS prefixes_received_a, "
        "r.prefixes_received_b AS prefixes_received_b, "
        "r.msg_sent_a AS msg_sent_a, "
        "r.msg_sent_b AS msg_sent_b, "
        "r.msg_rcvd_a AS msg_rcvd_a, "
        "r.msg_rcvd_b AS msg_rcvd_b, "
        "r.up_down_a AS up_down_a, "
        "r.up_down_b AS up_down_b, "
        "r.keepalive_a AS keepalive_a, "
        "r.keepalive_b AS keepalive_b, "
        "r.hold_time_a AS hold_time_a, "
        "r.hold_time_b AS hold_time_b, "
        "r.route_policy_in_a AS route_policy_in_a, "
        "r.route_policy_in_b AS route_policy_in_b, "
        "r.route_policy_out_a AS route_policy_out_a, "
        "r.route_policy_out_b AS route_policy_out_b, "
        "r.bfd_a AS bfd_a, "
        "r.bfd_b AS bfd_b, "
        "r.graceful_restart_a AS graceful_restart_a, "
        "r.graceful_restart_b AS graceful_restart_b, "
        "r.password_configured_a AS password_configured_a, "
        "r.password_configured_b AS password_configured_b, "
        "r.maximum_prefix_a AS maximum_prefix_a, "
        "r.maximum_prefix_b AS maximum_prefix_b, "
        "r.update_source_a AS update_source_a, "
        "r.update_source_b AS update_source_b, "
        "r.send_community_a AS send_community_a, "
        "r.send_community_b AS send_community_b, "
        "r.network_statements_a AS network_statements_a, "
        "r.network_statements_b AS network_statements_b "
        "ORDER BY r.protocol, a.name"
    )
    with driver.session() as session:
        result = session.run(cypher, run_id=run_id)
        adjs = []
        for i, rec in enumerate(result):
            d = {k: v for k, v in dict(rec).items() if v is not None}
            d["id"] = f"adj-{i}"
            adjs.append(d)
        return adjs


def _query_shared_service_metadata(driver, run_id: str) -> dict:
    """Query SharedService nodes for protocol metadata on devices.

    Returns {device_name: {ospf_areas: [...], bgp_as: "...", vlans: [...]}}.
    """
    # Audit note: also filter s.run_id (was relying on
    # d.run_id alone; SharedService nodes carry run_id and the (site, run_id,
    # service_type) index can be used for s when scoped).
    cypher = (
        "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->(s:SharedService {run_id: $run_id}) "
        "RETURN d.name AS device, s.service_type AS stype, "
        "s.identifier AS ident "
        "ORDER BY d.name"
    )
    metadata: dict[str, dict] = {}
    with driver.session() as session:
        result = session.run(cypher, run_id=run_id)
        for rec in result:
            dev = rec["device"]
            if dev not in metadata:
                metadata[dev] = {"ospf_areas": set(), "bgp_as": None, "vlans": set()}
            stype = rec["stype"]
            ident = rec["ident"]
            if stype == "ospf_area":
                metadata[dev]["ospf_areas"].add(ident)
            elif stype == "bgp_asn":
                metadata[dev]["bgp_as"] = ident
            elif stype == "vlan":
                metadata[dev]["vlans"].add(ident)

    # Convert sets to sorted lists
    for dev in metadata:
        metadata[dev]["ospf_areas"] = sorted(metadata[dev]["ospf_areas"])
        metadata[dev]["vlans"] = sorted(metadata[dev]["vlans"])
    return metadata


# -------------------------------------------------------------------------
# Deduplication helpers
# -------------------------------------------------------------------------

def _deduplicate_edges(edges: list[dict]) -> list[dict]:
    """Deduplicate edges by link_id (or source--target fallback)."""
    seen: set[str] = set()
    unique = []
    for e in edges:
        eid = e.get("id") or f"{e['source']}--{e['target']}"
        if eid not in seen:
            seen.add(eid)
            unique.append(e)
    return unique


def _merge_l2vlan_edges(edges: list[dict]) -> list[dict]:
    """Merge parallel edges into one logical edge per port-channel (L2/VLAN view).

    Groups edges by canonical (sorted) device pair AND LAG pair, so that
    distinct port-channels between the same device pair (e.g. HA active vs
    passive firewall members) remain as separate merged edges.
    """
    from collections import defaultdict

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in edges:
        src, tgt = e.get("source", ""), e.get("target", "")
        lag_s = e.get("lag_group") or ""
        lag_t = e.get("lag_group_target") or ""
        # Canonical key: alphabetical device order + LAG pair
        if src <= tgt:
            key = (src, tgt, lag_s, lag_t)
            groups[key].append(e)
        else:
            # Flip the edge so source < target, swap port fields
            flipped = dict(e)
            flipped["source"], flipped["target"] = tgt, src
            flipped["sourcePort"], flipped["targetPort"] = e.get("targetPort"), e.get("sourcePort")
            flipped["lag_group"], flipped["lag_group_target"] = lag_t, lag_s
            key = (tgt, src, lag_t, lag_s)
            groups[key].append(flipped)

    merged = []
    for group_key, member_edges in groups.items():
        dev_a, dev_b = group_key[0], group_key[1]
        lag_key_s, lag_key_t = group_key[2], group_key[3]
        # Pick best edge (lowest discovery_priority) for base fields
        best = min(member_edges, key=lambda e: e.get("discovery_priority") or 99)

        # Port labels: prefer LAG name, else single interface, else "N links"
        lag_src = next((e.get("lag_group") for e in member_edges if e.get("lag_group")), None)
        lag_tgt = next((e.get("lag_group_target") for e in member_edges if e.get("lag_group_target")), None)

        if lag_src:
            src_port = lag_src
        elif len(member_edges) == 1:
            src_port = member_edges[0].get("sourcePort")
        else:
            src_port = f"{len(member_edges)} links"

        if lag_tgt:
            tgt_port = lag_tgt
        elif len(member_edges) == 1:
            tgt_port = member_edges[0].get("targetPort")
        else:
            tgt_port = f"{len(member_edges)} links"

        # VLAN union from all member edges — bilateral
        # Includes both trunk VLANs (l2_*_vlans_carried) and access VLANs
        # (l2_*_vlan_id) so that access links are matched by VLAN overlay.
        all_local_vlans: set[int] = set()
        all_remote_vlans: set[int] = set()
        has_trunk = False
        for e in member_edges:
            for side_key, vlan_id_key, vlan_set in (
                ("l2_local_vlans_carried", "l2_local_vlan_id", all_local_vlans),
                ("l2_remote_vlans_carried", "l2_remote_vlan_id", all_remote_vlans),
            ):
                carried = e.get(side_key)
                if carried:
                    if isinstance(carried, str):
                        carried = [v.strip() for v in carried.split(",") if v.strip()]
                    for v in carried:
                        try:
                            vlan_set.add(int(v))
                        except (ValueError, TypeError):
                            pass
                # Include access VLAN from l2_*_vlan_id
                av = e.get(vlan_id_key)
                if av is not None:
                    try:
                        vlan_set.add(int(av))
                    except (ValueError, TypeError):
                        pass
            if e.get("l2_local_mode") == "trunk" or e.get("l2_local_trunk_mode") == "trunk":
                has_trunk = True

        # Union of both sides for display
        all_vlans = all_local_vlans | all_remote_vlans
        vlans_sorted = sorted(all_vlans)

        # Build merged edge
        local_mode = "trunk" if has_trunk else (best.get("l2_local_mode") or "access")
        edge = {
            "id": f"{dev_a}--{dev_b}--{lag_key_s or 'x'}--{lag_key_t or 'x'}--l2merged",
            "source": dev_a,
            "target": dev_b,
            "sourcePort": src_port,
            "targetPort": tgt_port,
            "discovery_method": best.get("discovery_method"),
            "discovery_priority": best.get("discovery_priority"),
            "confidence": best.get("confidence"),
            "status": best.get("status"),
            "l2_local_mode": local_mode,
            "l2_remote_mode": best.get("l2_remote_mode") or local_mode,
            "member_count": len(member_edges),
        }

        # Carry through LAG and HA fields
        if lag_key_s:
            edge["lag_group"] = lag_key_s
        if lag_key_t:
            edge["lag_group_target"] = lag_key_t
        ha = best.get("haMember")
        if ha:
            edge["haMember"] = ha

        if vlans_sorted:
            edge["vlan_count"] = len(vlans_sorted)
            edge["vlans_carried"] = vlans_sorted
            edge["l2_local_vlans_carried"] = sorted(all_local_vlans) if all_local_vlans else vlans_sorted
            edge["l2_remote_vlans_carried"] = sorted(all_remote_vlans) if all_remote_vlans else vlans_sorted

        # Member edges for link detail panel
        if len(member_edges) > 1:
            edge["member_edges"] = [
                {
                    "id": e.get("id"),
                    "sourcePort": e.get("sourcePort"),
                    "targetPort": e.get("targetPort"),
                }
                for e in member_edges
            ]

        # Carry through L3 fields from best edge
        for key in ("l3_subnet", "l3_local_ip", "l3_remote_ip", "l3_local_vrf", "l3_remote_vrf"):
            if best.get(key) is not None:
                edge[key] = best[key]

        merged.append(edge)

    return merged


def _ip_to_subnet(ip: str, prefix_len: int) -> str:
    """Compute network address from IP + prefix_length → CIDR string."""
    parts = ip.split(".")
    if len(parts) != 4:
        return f"{ip}/{prefix_len}"
    try:
        addr = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
    except (ValueError, TypeError):
        return f"{ip}/{prefix_len}"
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    net = addr & mask
    return f"{(net >> 24) & 0xFF}.{(net >> 16) & 0xFF}.{(net >> 8) & 0xFF}.{net & 0xFF}/{prefix_len}"


def _enrich_edge_vlan_names(driver, run_id: str, edges: list[dict]) -> list[dict]:
    """Add vlans_with_names and trunk_subnets to edges for link detail panel."""
    # Build VLAN ID → best name lookup from Vlan nodes
    cypher = (
        "MATCH (v:Vlan {run_id: $run_id}) "
        "RETURN v.vlan_id AS vlan_id, v.name AS name, v.device AS device"
    )
    vlan_names_by_id: dict[int, list[str]] = {}
    with driver.session() as session:
        for rec in session.run(cypher, run_id=run_id):
            vid = rec["vlan_id"]
            name = rec["name"]
            if vid is not None and name:
                vlan_names_by_id.setdefault(vid, []).append(name)

    # Resolve best name per VLAN ID
    best_names: dict[int, str] = {}
    for vid, names in vlan_names_by_id.items():
        best = _best_vlan_name(names)
        if best:
            best_names[vid] = best

    # Build SVI subnet lookup: vlan_id → {subnet, vrf, svi_hosts}
    # Pass 1: Cisco SVIs (Vl90, Vlan90) — authoritative
    # Pass 2: FortiGate numeric interfaces (90, 93) — gap-fill only
    svi_cypher = (
        "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
        "WHERE i.ip IS NOT NULL "
        "RETURN d.name AS device, i.name AS name, i.ip AS ip, "
        "i.prefix_length AS prefix_length, i.vrf AS vrf"
    )
    vlan_subnets: dict[int, dict] = {}
    ip_to_device: dict[str, str] = {}

    def _parse_ip_pfx(ip_raw, pfx_raw):
        """Parse IP and prefix, handling FortiGate embedded prefix."""
        ip = ip_raw or ""
        pfx = pfx_raw
        if "/" in ip:
            parts = ip.split("/")
            ip = parts[0]
            if pfx is None:
                try:
                    pfx = int(parts[1])
                except (ValueError, TypeError):
                    pass
        if not ip or pfx is None:
            return None, None
        try:
            return ip, int(pfx)
        except (ValueError, TypeError):
            return None, None

    cisco_svi_rows = []
    fortigate_rows = []
    with driver.session() as session:
        for rec in session.run(svi_cypher, run_id=run_id):
            name = rec["name"] or ""
            ip, pfx = _parse_ip_pfx(rec["ip"], rec["prefix_length"])
            if not ip or pfx is None:
                continue
            ip_to_device[ip] = rec["device"]
            if name.startswith("Vl") or name.startswith("Vlan"):
                cisco_svi_rows.append((name, ip, pfx, rec))
            else:
                # Pure numeric names = potential FortiGate VLAN interfaces
                try:
                    int(name)
                    fortigate_rows.append((name, ip, pfx, rec))
                except ValueError:
                    pass

    def _add_svi(vid, ip, pfx, rec):
        subnet = _ip_to_subnet(ip, pfx)
        if vid not in vlan_subnets:
            vlan_subnets[vid] = {
                "subnet": subnet,
                "vrf": rec["vrf"],
                "svi_hosts": [],
            }
        vlan_subnets[vid]["svi_hosts"].append({
            "device": rec["device"],
            "ip": ip,
        })

    # Pass 1: Cisco SVIs — authoritative mapping
    for name, ip, pfx, rec in cisco_svi_rows:
        vid_str = name.replace("Vlan", "").replace("Vl", "")
        try:
            _add_svi(int(vid_str), ip, pfx, rec)
        except (ValueError, TypeError):
            pass

    # Pass 2: FortiGate numeric interfaces — only for VLANs not yet resolved
    for name, ip, pfx, rec in fortigate_rows:
        vid = int(name)
        if vid not in vlan_subnets:
            _add_svi(vid, ip, pfx, rec)

    # Build next-hop index from routing tables: IPs that appear as
    # next-hop in any device's routing table are confirmed gateways.
    next_hop_ips: set[str] = set()
    facts_base = RUNS_DIR / run_id / "facts"
    if facts_base.is_dir():
        for device_dir in facts_base.iterdir():
            if not device_dir.is_dir():
                continue
            routing_path = device_dir / "genie_routing.json"
            if not routing_path.exists():
                continue
            try:
                rdata = json.loads(routing_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for _vrf, vrf_data in rdata.get("vrf", {}).items():
                for _af, af_data in vrf_data.get("address_family", {}).items():
                    for _pfx, route in af_data.get("routes", {}).items():
                        nh = route.get("next_hop", {})
                        for _idx, nh_entry in nh.get("next_hop_list", {}).items():
                            nhip = nh_entry.get("next_hop", "")
                            if nhip:
                                next_hop_ips.add(nhip)

    # Build full IP → device lookup from ALL interfaces (not just SVIs)
    # to resolve next-hop IPs to device names (e.g., FWL VDOM interfaces)
    all_ip_cypher = (
        "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
        "WHERE i.ip IS NOT NULL "
        "RETURN d.name AS device, i.ip AS ip"
    )
    all_ip_to_device: dict[str, str] = {}
    with driver.session() as session:
        for rec in session.run(all_ip_cypher, run_id=run_id):
            ip_raw = rec["ip"] or ""
            # Strip prefix if stored as "198.51.100.1/29"
            bare_ip = ip_raw.split("/")[0] if "/" in ip_raw else ip_raw
            if bare_ip:
                all_ip_to_device[bare_ip] = rec["device"]

    # Resolve gateway per VLAN subnet:
    # Find next-hop IPs that fall within each VLAN's subnet → those are
    # the confirmed gateways (from actual routing table configuration).
    def _ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
        """Check if an IP falls within a CIDR subnet."""
        try:
            parts = ip_str.split(".")
            ip_int = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
            net_str, pfx_str = subnet_str.split("/")
            net_parts = net_str.split(".")
            net_int = sum(int(p) << (24 - 8 * i) for i, p in enumerate(net_parts))
            mask = (0xFFFFFFFF << (32 - int(pfx_str))) & 0xFFFFFFFF
            return (ip_int & mask) == net_int
        except (ValueError, TypeError, IndexError):
            return False

    vlan_gateway: dict[int, dict] = {}
    for vid, info in vlan_subnets.items():
        gateway_ip = None
        gateway_device = None
        subnet = info["subnet"]
        hosts = info["svi_hosts"]

        # Priority 1: next-hop from routing tables — an IP within this
        # subnet that other devices point to as next-hop.
        for nhip in next_hop_ips:
            if _ip_in_subnet(nhip, subnet):
                gateway_ip = nhip
                gateway_device = all_ip_to_device.get(nhip)
                break

        # Priority 2: SVI IP that is itself a next-hop for any route.
        if not gateway_ip:
            for host in hosts:
                if host["ip"] in next_hop_ips:
                    gateway_ip = host["ip"]
                    gateway_device = host["device"]
                    break

        # Priority 3: single SVI holder — only one L3 device on this
        # subnet, so it is the gateway by definition.
        if not gateway_ip and len(hosts) == 1:
            gateway_ip = hosts[0]["ip"]
            gateway_device = hosts[0]["device"]

        vlan_gateway[vid] = {
            "subnet": info["subnet"],
            "vrf": info["vrf"],
            "gateway_ip": gateway_ip,
            "gateway_device": gateway_device,
        }

    # Enrich edges — bilateral
    for edge in edges:
        local_vlans = edge.get("vlans_carried") or edge.get("l2_local_vlans_carried")
        remote_vlans = edge.get("l2_remote_vlans_carried")
        # Also include access VLANs (single int stored in l2_*_vlan_id)
        local_av = edge.get("l2_local_vlan_id")
        remote_av = edge.get("l2_remote_vlan_id")
        if not local_vlans and not remote_vlans and local_av is None and remote_av is None:
            continue

        # Union of both sides for subnet table
        all_vlan_ids: set[int] = set()
        local_set: set[int] = set()
        remote_set: set[int] = set()
        for v in (local_vlans or []):
            try:
                vid = int(v)
                all_vlan_ids.add(vid)
                local_set.add(vid)
            except (ValueError, TypeError):
                pass
        for v in (remote_vlans or []):
            try:
                vid = int(v)
                all_vlan_ids.add(vid)
                remote_set.add(vid)
            except (ValueError, TypeError):
                pass
        # Access VLANs (l2_*_vlan_id — single int, not in vlans_carried)
        for av, vset in ((local_av, local_set), (remote_av, remote_set)):
            if av is not None:
                try:
                    vid = int(av)
                    all_vlan_ids.add(vid)
                    vset.add(vid)
                except (ValueError, TypeError):
                    pass

        vlan_list = []
        subnet_list = []
        for vid in sorted(all_vlan_ids):
            vlan_list.append({"id": vid, "name": best_names.get(vid)})
            gw_info = vlan_gateway.get(vid)
            subnet_list.append({
                "vlan_id": vid,
                "name": best_names.get(vid),
                "subnet": gw_info["subnet"] if gw_info else None,
                "vrf": gw_info["vrf"] if gw_info else None,
                "gateway": (
                    f"{gw_info['gateway_ip']} ({gw_info['gateway_device']})"
                    if gw_info and gw_info.get("gateway_ip") and gw_info.get("gateway_device")
                    else (gw_info["gateway_ip"] if gw_info and gw_info.get("gateway_ip") else None)
                ),
            })

        if vlan_list:
            edge["vlans_with_names"] = vlan_list
        if subnet_list:
            edge["trunk_subnets"] = subnet_list

        # Compute VLAN mismatch detail for frontend
        if local_set and remote_set and local_set != remote_set:
            only_local = sorted(local_set - remote_set)
            only_remote = sorted(remote_set - local_set)
            edge["l2_vlan_mismatch"] = {}
            if only_local:
                edge["l2_vlan_mismatch"]["only_source"] = only_local
            if only_remote:
                edge["l2_vlan_mismatch"]["only_target"] = only_remote

    return edges


# ---------------------------------------------------------------------------
# Static route enrichment per edge
# ---------------------------------------------------------------------------

def _resolve_facts_dir(run_id: str, hostname: str) -> Path:
    """Resolve facts directory for a device.

     Facts dirs are named by inventory_name (= canonical ID).
    Direct path lookup — no manifest remapping needed.
    """
    return RUNS_DIR / run_id / "facts" / hostname


def _enrich_edge_routes(run_id: str, edges: list[dict]) -> None:
    """Attach routes that traverse each edge (all protocols).

    Builds an IP→device lookup from interface data, then for each edge
    checks if any device's route next-hop matches an IP belonging to the
    peer device on the other end of the link.
    Result: ``edge["routes_via_link"]`` list of route dicts with protocol info.
    Also sets ``edge["static_routes"]`` (subset) for backward compatibility.
    """
    import ipaddress as _ip

    # Collect all device hostnames that appear as edge endpoints
    device_set: set[str] = set()
    for e in edges:
        src = e.get("source", "")
        tgt = e.get("target", "")
        if src:
            device_set.add(src)
        if tgt:
            device_set.add(tgt)

    if not device_set:
        return

    # Build IP→device map from interface data + load ALL routes per device
    device_ips: dict[str, set[str]] = {}  # hostname → set of IPs on this device
    device_routes: dict[str, list[dict]] = {}  # hostname → flat route list

    for hostname in device_set:
        device_dir = _resolve_facts_dir(run_id, hostname)
        if not device_dir.is_dir():
            continue

        # --- Collect device IPs from interfaces ---
        ips: set[str] = set()

        # Genie interfaces
        intf_path = device_dir / "genie_interface.json"
        if intf_path.exists():
            try:
                intfs = json.loads(intf_path.read_text())
                for intf_data in intfs.values():
                    if not isinstance(intf_data, dict):
                        continue
                    for addr_data in (intf_data.get("ipv4") or {}).values():
                        if isinstance(addr_data, dict) and addr_data.get("ip"):
                            ips.add(addr_data["ip"])
            except (json.JSONDecodeError, OSError):
                pass

        # FortiGate interfaces
        fg_intf_path = device_dir / "fortigate_system_interface.json"
        if fg_intf_path.exists():
            try:
                data = json.loads(fg_intf_path.read_text())
                entries = data.get("results", data) if isinstance(data, dict) else data
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        ip_str = entry.get("ip", "")
                        if isinstance(ip_str, str) and " " in ip_str:
                            ip_part = ip_str.split()[0]
                            if ip_part and ip_part != "0.0.0.0":
                                ips.add(ip_part)
            except (json.JSONDecodeError, OSError):
                pass

        if ips:
            device_ips[hostname] = ips

        # --- Load ALL routes (genie_routing.json has ospf/bgp/static/connected) ---
        routes: list[dict] = []
        seen_keys: set[tuple] = set()

        # Primary: genie_routing.json (full RIB — all protocols)
        routing_path = device_dir / "genie_routing.json"
        if routing_path.exists():
            try:
                data = json.loads(routing_path.read_text())
                for vrf_name, vrf in data.get("vrf", {}).items():
                    if not isinstance(vrf, dict):
                        continue
                    for af_name, af in vrf.get("address_family", {}).items():
                        if not isinstance(af, dict):
                            continue
                        for prefix, route in af.get("routes", {}).items():
                            if not isinstance(route, dict):
                                continue
                            proto = route.get("source_protocol", "unknown")
                            ad = route.get("route_preference")
                            metric = route.get("metric")
                            nh = route.get("next_hop", {})
                            for _idx, entry in nh.get("next_hop_list", {}).items():
                                if isinstance(entry, dict) and entry.get("next_hop"):
                                    key = (vrf_name, prefix, entry["next_hop"])
                                    if key not in seen_keys:
                                        seen_keys.add(key)
                                        routes.append({
                                            "prefix": prefix,
                                            "vrf": vrf_name,
                                            "next_hop": entry["next_hop"],
                                            "protocol": proto,
                                            "ad": ad,
                                            "metric": metric,
                                            "interface": entry.get("outgoing_interface", ""),
                                        })
            except (json.JSONDecodeError, OSError):
                pass

        # Fallback: genie_static_routing.json (for devices without full RIB)
        if not routes:
            genie_path = device_dir / "genie_static_routing.json"
            if genie_path.exists():
                try:
                    data = json.loads(genie_path.read_text())
                    for vrf_name, vrf in data.get("vrf", {}).items():
                        if not isinstance(vrf, dict):
                            continue
                        for af_name, af in vrf.get("address_family", {}).items():
                            if not isinstance(af, dict):
                                continue
                            for prefix, route in af.get("routes", {}).items():
                                if not isinstance(route, dict):
                                    continue
                                nh = route.get("next_hop", {})
                                for _idx, entry in nh.get("next_hop_list", {}).items():
                                    if isinstance(entry, dict) and entry.get("next_hop"):
                                        routes.append({
                                            "prefix": prefix,
                                            "vrf": vrf_name,
                                            "next_hop": entry["next_hop"],
                                            "protocol": "static",
                                            "ad": route.get("route_preference"),
                                            "metric": route.get("metric"),
                                            "interface": entry.get("outgoing_interface", ""),
                                        })
                except (json.JSONDecodeError, OSError):
                    pass

        # FortiGate static routes
        fg_path = device_dir / "fortigate_static_route.json"
        if fg_path.exists():
            try:
                data = json.loads(fg_path.read_text())
                # FortiGate VDOMs are not Cisco VRFs — map to "default"
                vdom = "default"
                entries = data.get("results", data) if isinstance(data, dict) else data
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        gw = entry.get("gateway", "")
                        dst = entry.get("dst", "")
                        if gw and gw != "0.0.0.0" and dst:
                            parts = dst.strip().split()
                            if len(parts) == 2:
                                try:
                                    net = _ip.IPv4Network(
                                        f"{parts[0]}/{parts[1]}", strict=False
                                    )
                                    prefix = str(net)
                                except (ValueError, TypeError):
                                    prefix = dst
                            else:
                                prefix = dst
                            routes.append({
                                "prefix": prefix,
                                "vrf": vdom or "root",
                                "next_hop": gw,
                                "protocol": "static",
                                "ad": entry.get("distance"),
                                "metric": None,
                                "interface": entry.get("device", ""),
                            })
            except (json.JSONDecodeError, OSError):
                pass

        if routes:
            device_routes[hostname] = routes

    if not device_routes:
        return

    # Enrich each edge: match route next-hops against peer device IPs
    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        tgt_ips = device_ips.get(tgt, set())
        src_ips = device_ips.get(src, set())

        all_routes: list[dict] = []

        # Source device routes with next-hop pointing to target device
        if src in device_routes and tgt_ips:
            for r in device_routes[src]:
                if r["next_hop"] in tgt_ips:
                    all_routes.append({
                        "device": src,
                        "prefix": r["prefix"],
                        "next_hop": r["next_hop"],
                        "vrf": r["vrf"],
                        "protocol": r["protocol"],
                        "ad": r.get("ad"),
                        "metric": r.get("metric"),
                        "interface": r.get("interface", ""),
                        "direction": f"{src} → {tgt}",
                    })

        # Target device routes with next-hop pointing to source device
        if tgt in device_routes and src_ips:
            for r in device_routes[tgt]:
                if r["next_hop"] in src_ips:
                    all_routes.append({
                        "device": tgt,
                        "prefix": r["prefix"],
                        "next_hop": r["next_hop"],
                        "vrf": r["vrf"],
                        "protocol": r["protocol"],
                        "ad": r.get("ad"),
                        "metric": r.get("metric"),
                        "interface": r.get("interface", ""),
                        "direction": f"{tgt} → {src}",
                    })

        if all_routes:
            edge["routes_via_link"] = all_routes
            # Backward compat: static_routes subset
            static_only = [r for r in all_routes if r["protocol"] == "static"]
            if static_only:
                edge["static_routes"] = static_only


def _deduplicate_adjacencies(adjs: list[dict]) -> list[dict]:
    """Deduplicate adjacencies by (source, target, protocol, vrf)."""
    seen: set[tuple] = set()
    unique = []
    for a in adjs:
        key = (a["source"], a["target"], a.get("protocol"), a.get("vrf"))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


# -------------------------------------------------------------------------
# Findings enrichment
# -------------------------------------------------------------------------

def _load_findings_counts(run_id: str) -> tuple[Counter, set]:
    """Count findings per device — canonical Neo4j-first loader.

     was disk-only + had a local `_extract_device_name`
    parser handling 3/7 element_id formats ( silent-drop class
    +  helper-drift class). Now uses `the shared findings helpers 
    load_findings_enriched()` (Neo4j-first with disk fallback +
    DEVICE_UNREACHABLE synthesis + ack enrichment) and `device_from_finding`
    (canonical 7-format parser).
    """
    findings_per_device: Counter = Counter()
    critical_devices: set = set()

    findings = load_findings_enriched(run_id) or []
    for f in findings:
        device = device_from_finding(f)
        if device:
            findings_per_device[device] += 1
            if f.get("severity") == "critical":
                critical_devices.add(device)

    return findings_per_device, critical_devices


# -------------------------------------------------------------------------
# Cytoscape.js builders
# -------------------------------------------------------------------------

def _build_node(
    device: dict,
    svc_metadata: dict,
    findings_per_device: Counter,
    critical_devices: set,
) -> dict:
    """Build a Cytoscape.js node from a Neo4j Device record."""
    name = device["name"]
    collected = bool(device.get("platform") or device.get("os_version"))

    node_data = {
        "id": name,
        "role": device.get("role") or "unknown",
        "platform": device.get("platform"),
        "os_type": device.get("os_type"),
        "os_version": device.get("os_version"),
        "device_type": device.get("device_type") or "unknown",
        "site": device.get("site"),
        "management_ip": device.get("management_ip"),
        "collected": collected,
        "findings_count": findings_per_device.get(name, 0),
    }

    # External peer enrichment (BGP S19C)
    if device.get("device_type") == "external":
        node_data["role"] = "external"
        node_data["collected"] = False
        if device.get("remote_as"):
            node_data["remote_as"] = device["remote_as"]
        if device.get("peer_label"):
            node_data["peer_label"] = device["peer_label"]

    # BGP route-reflector role (only stamped on the reflector itself).
    if device.get("is_route_reflector"):
        node_data["is_route_reflector"] = True
        if device.get("rr_cluster_id"):
            node_data["rr_cluster_id"] = device["rr_cluster_id"]

    # Protocol metadata from shared services
    meta = svc_metadata.get(name, {})
    if meta.get("ospf_areas"):
        node_data["ospf_areas"] = meta["ospf_areas"]
    if meta.get("bgp_as"):
        node_data["bgp_as"] = meta["bgp_as"]
    if meta.get("vlans"):
        node_data["vlans"] = meta["vlans"]

    #  compound node metadata for stacked/HA devices
    cluster_size = device.get("cluster_size")
    if cluster_size and cluster_size >= 2:
        node_data["isCompound"] = True
        node_data["memberCount"] = cluster_size

    # Remove None values for clean JSON
    node_data = {k: v for k, v in node_data.items() if v is not None}

    return {"data": node_data}


def _expand_compound_nodes(
    nodes: list[dict],
    devices: list[dict],
    findings_per_device: Counter,
    critical_devices: set,
) -> list[dict]:
    """Expand compound parent nodes into parent + child member nodes.

    For each node with isCompound=True, deserialize cluster_members from
    the Neo4j JSON string and generate child nodes with parent reference.

    Returns a new node list with child nodes inserted after their parents.
    """
    device_map = {d["name"]: d for d in devices}
    expanded = []

    for node in nodes:
        expanded.append(node)
        data = node.get("data", {})
        if not data.get("isCompound"):
            continue

        name = data["id"]
        device = device_map.get(name)
        if not device:
            continue

        # Deserialize cluster_members JSON string from Neo4j
        cluster_members = _parse_cluster_members(device.get("cluster_members"))
        if not cluster_members:
            continue

        os_type = (device.get("os_type") or "").lower()
        is_fortios = os_type == "fortios"

        for member in cluster_members:
            member_id = member.get("member_id")
            if member_id is None:
                continue

            child_id = f"{name}:{member_id}"

            # Determine member role label
            if is_fortios:
                # FortiGate HA: map raw role to Active/Passive
                raw_role = (member.get("role") or "").lower()
                _HA_ACTIVE_ROLES = {"master", "active", "primary"}
                if raw_role in _HA_ACTIVE_ROLES:
                    member_role = "Active"
                elif raw_role:
                    member_role = "Passive"
                else:
                    member_role = "Active" if member_id == 0 else "Passive"
                opacity = 0.4 if member_role == "Passive" else 1.0
                label = member_role
            else:
                # Cisco stack: use member number
                member_role = member.get("role", f"Member {member_id}")
                opacity = 1.0
                label = f"M{member_id}"

            child_data = {
                "id": child_id,
                "parent": name,
                "memberId": member_id,
                "memberRole": member_role,
                "label": label,
                "opacity": opacity,
                "platform": member.get("platform") or data.get("platform"),
                "serial": member.get("serial"),
                "state": member.get("state"),
                "mac_address": member.get("mac_address"),
            }
            # Remove None values
            child_data = {k: v for k, v in child_data.items() if v is not None}
            expanded.append({"data": child_data})

    return expanded


def _parse_cluster_members(raw: str | None) -> list[dict] | None:
    """Parse cluster_members JSON string from Neo4j."""
    if not raw:
        return None
    try:
        members = json.loads(raw)
        if isinstance(members, list) and members:
            return members
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def _query_stack_links(driver, run_id: str) -> list[dict]:
    """Query STACK_LINK self-referencing relationships for internal edges."""
    cypher = (
        "MATCH (a:Device)-[r:STACK_LINK]->(b:Device) "
        "WHERE a.run_id = $run_id "
        "RETURN a.name AS source, b.name AS target, "
        "r.link_id AS link_id, r.status AS status, "
        "r.local_interface AS local_interface, "
        "r.remote_interface AS remote_interface, "
        "r.discovery_method AS discovery_method, "
        "r.discovery_priority AS discovery_priority, "
        "r.link_type AS link_type, "
        "r.stack_subtype AS stack_subtype, "
        "r.member_from AS member_from, "
        "r.member_to AS member_to "
        "ORDER BY a.name"
    )
    edges = []
    with driver.session() as session:
        result = session.run(cypher, run_id=run_id)
        for rec in result:
            d = dict(rec)
            hostname = d["source"]
            member_from = d.get("member_from")
            member_to = d.get("member_to")

            edge = {
                "id": d.get("link_id") or f"stack-{hostname}-{member_from}-{member_to}",
                "source": f"{hostname}:{member_from}" if member_from is not None else hostname,
                "target": f"{hostname}:{member_to}" if member_to is not None else hostname,
                "linkType": "stack_interconnect",
                "stackSubtype": d.get("stack_subtype"),
                "status": d.get("status"),
                "sourcePort": d.get("local_interface"),
                "targetPort": d.get("remote_interface"),
                "discovery_method": d.get("discovery_method"),
                "isInternal": True,
            }
            edges.append({k: v for k, v in edge.items() if v is not None})
    return edges


def _reroute_edges_to_members(edges: list[dict], compound_names: set[str]) -> list[dict]:
    """Reroute edges from parent compound nodes to specific child members.

    When an edge has sourceMemberId/targetMemberId and the corresponding
    endpoint is a compound node, reroute the edge to the child node
    (e.g., source "sw-01" with sourceMemberId 1 → "sw-01:1").
    """
    for edge in edges:
        # Synthetic inband links connect to parent compound node, not members
        if edge.get("discovery_method") == "inband_vlan_path":
            continue

        src = edge.get("source", "")
        tgt = edge.get("target", "")

        src_mid = edge.get("sourceMemberId")
        if src_mid is not None and src in compound_names:
            edge["source"] = f"{src}:{src_mid}"

        tgt_mid = edge.get("targetMemberId")
        if tgt_mid is not None and tgt in compound_names:
            edge["target"] = f"{tgt}:{tgt_mid}"

    return edges


def _build_edge(rec: dict) -> dict:
    """Build a Cytoscape.js edge dict from a Neo4j relationship record."""
    edge = {
        "id": rec.get("link_id") or f"{rec['source']}--{rec['target']}",
        "source": rec["source"],
        "target": rec["target"],
        "discovery_method": rec.get("discovery_method"),
        "discovery_priority": rec.get("discovery_priority"),
        "status": rec.get("status"),
        "confidence": rec.get("confidence"),
        "sourcePort": rec.get("local_interface"),
        "targetPort": rec.get("remote_interface"),
        "discovery_protocol": rec.get("discovery_protocol"),
        "peer_collected": rec.get("peer_collected"),
        "direction": rec.get("direction"),
        "mgmt_type": rec.get("mgmt_type"),
    }

    # Inband MGMT properties
    for key in ["mgmt_vlan", "mgmt_vrf"]:
        if rec.get(key) is not None:
            edge[key] = rec[key]

    #  member ID fields for compound node edge routing
    for key in ["source_member_id", "target_member_id", "ha_member"]:
        if rec.get(key) is not None:
            # Use camelCase for frontend compatibility
            camel = _to_camel(key)
            edge[camel] = rec[key]

    # L2 properties — bilateral
    for key in [
        "l2_local_mode", "l2_remote_mode",
        "l2_local_vlan_id", "l2_remote_vlan_id",
        "l2_local_trunk_mode", "l2_remote_trunk_mode",
        "l2_local_vlans_carried", "l2_remote_vlans_carried",
        "l2_local_native_vlan", "l2_remote_native_vlan",
    ]:
        if rec.get(key) is not None:
            edge[key] = rec[key]

    # L3 properties — bilateral
    for key in ["l3_subnet", "l3_local_ip", "l3_remote_ip", "l3_local_vrf", "l3_remote_vrf"]:
        if rec.get(key) is not None:
            edge[key] = rec[key]

    # LAG group (stored in Neo4j at build time, post-S19A architecture fix)
    for key in ["lag_group", "lag_group_target"]:
        if rec.get(key) is not None:
            edge[key] = rec[key]

    # L1 properties — bilateral (from Interface nodes, )
    for key in [
        "l1_local_speed", "l1_local_duplex", "l1_local_mtu", "l1_local_media_type", "l1_local_sfp_pid",
        "l1_remote_speed", "l1_remote_duplex", "l1_remote_mtu", "l1_remote_media_type", "l1_remote_sfp_pid",
    ]:
        if rec.get(key) is not None:
            edge[key] = rec[key]

    # Remove None values
    return {k: v for k, v in edge.items() if v is not None}


def _to_camel(snake: str) -> str:
    """Convert snake_case to camelCase."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# =========================================================================
# VLAN Data Endpoint (, )
# =========================================================================

def _best_vlan_name(names: list[str]) -> str | None:
    """Pick the most specific VLAN name from candidates across devices.

    Priority (lower = better):
        1: Site/location prefix (e.g. SITE1_, CORE_, DMZ_)
        2: Meaningful name (not auto-generated or generic template)
        3: Generic template (Vlan_transit, Vlan_management, etc.)
        4: Auto-generated default (VLAN0090, VLAN2602)

    Tie-breaker: longest name, then alphabetical.
    """
    import re

    if not names:
        return None

    _AUTOGEN_RE = re.compile(r"^VLAN\d+$")
    _GENERIC_RE = re.compile(r"^Vlan_", re.IGNORECASE)
    _SITE_PREFIX_RE = re.compile(r"^[A-Z0-9][A-Z0-9]*[_-]", re.IGNORECASE)

    def _priority(name: str) -> tuple:
        if _AUTOGEN_RE.match(name):
            return (4, -len(name), name)
        if _GENERIC_RE.match(name):
            return (3, -len(name), name)
        if _SITE_PREFIX_RE.match(name):
            return (1, -len(name), name)
        return (2, -len(name), name)

    return min(names, key=_priority)


def _trunk_carries_vlan(trunk_vlans, vlan_id: int) -> bool:
    """Does a trunk carry ``vlan_id``?

    A trunk carries the VLAN if it explicitly lists it, OR if it is **unfiltered**
    — ``trunk_vlans is None`` means no ``switchport trunk allowed vlan`` filter, so
    the trunk carries ALL VLANs (the Cisco default). An explicit empty list ``[]``
    (e.g. ``allowed vlan none``) carries nothing. This is what makes a switch with
    no access ports but an all-VLANs trunk show up as a transit member of the VLAN.
    """
    if trunk_vlans is None:
        return True  # unfiltered trunk → all VLANs
    if isinstance(trunk_vlans, list):
        for v in trunk_vlans:
            try:
                if int(v) == vlan_id:
                    return True
            except (ValueError, TypeError):
                pass
    return False


@router.get("/api/runs/{run_id}/vlans")
def get_vlans(run_id: str):
    """Return VLAN list with membership data for dropdown, matrix, and overlay.

    Queries Vlan nodes (per-device) and aggregates across the run.
    Also enriches with Interface switchport data for per-device mode resolution.

    Response:
        {"vlans": [{"vlan_id": 100, "name": "DATA", "subnet": ...,
                     "members": [{"hostname": ..., "mode": "trunk",
                                  "interfaces": [...]}]}]}
    """
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"detail": "Neo4j unavailable"},
        )

    driver = get_driver()

    # Step 1: Get all Vlan nodes (per-device) and aggregate by vlan_id
    cypher_vlans = """
    MATCH (v:Vlan {run_id: $run_id})
    RETURN v.vlan_id AS vlan_id, v.name AS name, v.device AS device
    ORDER BY v.vlan_id
    """

    # Step 2: Get all interfaces with switchport data for this run
    cypher_intfs = """
    MATCH (i:Interface {run_id: $run_id})
    WHERE i.switchport_mode IS NOT NULL
    RETURN i.device AS device, i.name AS intf_name,
           i.switchport_mode AS mode, i.access_vlan AS access_vlan,
           i.trunk_vlans AS trunk_vlans, i.native_vlan AS native_vlan
    """

    # Step 3: Get subnet info from two sources:
    #   a) SVI interfaces (Vl99) — canonical names, extract VLAN ID from suffix
    #   b) Interfaces with access_vlan + IP (FortiGate numeric VLANs, routed access)
    cypher_svi_subnets = """
    MATCH (i:Interface {run_id: $run_id})
    WHERE i.name STARTS WITH 'Vl' AND i.ip IS NOT NULL
    RETURN i.name AS svi_name, i.ip AS ip_address,
           i.prefix_length AS prefix_length
    """
    cypher_av_subnets = """
    MATCH (i:Interface {run_id: $run_id})
    WHERE i.access_vlan IS NOT NULL AND i.ip IS NOT NULL
    RETURN i.access_vlan AS vlan_id, i.ip AS ip_address,
           i.prefix_length AS prefix_length
    """

    # Step 4: Get routed interfaces with IPs (L3 devices in VLAN subnets)
    cypher_routed_ips = """
    MATCH (i:Interface {run_id: $run_id})
    WHERE i.ip IS NOT NULL AND i.switchport_mode IS NULL
    RETURN i.device AS device, i.name AS intf_name,
           i.ip AS ip, i.prefix_length AS prefix_length
    """

    with driver.session() as session:
        vlan_records = list(session.run(cypher_vlans, run_id=run_id))
        intf_records = list(session.run(cypher_intfs, run_id=run_id))
        svi_subnet_records = list(session.run(cypher_svi_subnets, run_id=run_id))
        av_subnet_records = list(session.run(cypher_av_subnets, run_id=run_id))
        routed_ip_records = list(session.run(cypher_routed_ips, run_id=run_id))

    # Aggregate Vlan nodes by vlan_id → {names: [], member_hostnames: set}
    vlan_agg: dict[int, dict] = {}
    for rec in vlan_records:
        vid = rec["vlan_id"]
        if vid is None:
            continue
        if vid not in vlan_agg:
            vlan_agg[vid] = {"names": [], "member_hostnames": set()}
        name = rec["name"]
        if name:
            vlan_agg[vid]["names"].append(name)
        device = rec["device"]
        if device:
            vlan_agg[vid]["member_hostnames"].add(device)

    # Build vlan_id → subnet lookup from two sources:
    #   1) SVIs: extract VLAN ID from canonical name (Vl99 → 99)
    #   2) access_vlan interfaces with IP (FortiGate, routed access ports)
    from ipaddress import ip_interface
    vlan_subnets: dict[int, str] = {}

    def _record_subnet(vid: int, ip: str, pfx) -> None:
        if vid in vlan_subnets:
            return
        try:
            cidr = f"{ip}/{pfx}" if pfx else ip
            vlan_subnets[vid] = str(ip_interface(cidr).network)
        except ValueError:
            vlan_subnets[vid] = ip

    # Source 1: SVIs (Vl99, Vl300)
    for rec in svi_subnet_records:
        svi_name = rec["svi_name"] or ""
        ip = rec["ip_address"] or ""
        if svi_name and ip:
            m = re.search(r"(\d+)$", svi_name)
            if m:
                _record_subnet(int(m.group(1)), ip, rec["prefix_length"])

    # Source 2: Interfaces with access_vlan + IP (FortiGate numeric VLANs, etc.)
    for rec in av_subnet_records:
        vid = rec["vlan_id"]
        ip = rec["ip_address"] or ""
        if vid is not None and ip:
            try:
                _record_subnet(int(vid), ip, rec["prefix_length"])
            except (ValueError, TypeError):
                pass

    # Build L3/routed member index: devices with IPs in VLAN subnets
    # These are L3 devices (firewalls, routers) connected via access links
    from ipaddress import ip_address, ip_network
    l3_vlan_members: dict[int, set[str]] = {}  # vlan_id → set of hostnames
    if vlan_subnets and routed_ip_records:
        # Pre-parse subnet networks
        subnet_nets: dict[int, "IPv4Network"] = {}
        for vid, cidr in vlan_subnets.items():
            try:
                subnet_nets[vid] = ip_network(cidr, strict=False)
            except ValueError:
                pass
        # Check each routed IP against each VLAN subnet
        for rec in routed_ip_records:
            ip_str = rec["ip"] or ""
            device = rec["device"] or ""
            if not ip_str or not device:
                continue
            try:
                addr = ip_address(ip_str)
            except ValueError:
                continue
            for vid, net in subnet_nets.items():
                if addr in net:
                    l3_vlan_members.setdefault(vid, set()).add(device)

    # Build per-device switchport index
    device_intf_index: dict[str, list[dict]] = {}
    for rec in intf_records:
        device = rec["device"] or ""
        device_intf_index.setdefault(device, []).append({
            "name": rec["intf_name"],
            "mode": rec["mode"],
            "access_vlan": rec["access_vlan"],
            "trunk_vlans": rec["trunk_vlans"],
            "native_vlan": rec["native_vlan"],
        })

    # Build VLAN response
    vlans = []
    for vlan_id in sorted(vlan_agg.keys()):
        agg = vlan_agg[vlan_id]
        name = _best_vlan_name(agg["names"])
        member_hostnames = agg["member_hostnames"]

        # Resolve subnet from SVI
        subnet = vlan_subnets.get(vlan_id)

        # Also discover devices from interface switchport data
        # (e.g. FortiGate has no Vlan nodes but has VLAN interfaces)
        all_candidate_hosts = set(member_hostnames)
        for device_name, intfs in device_intf_index.items():
            for di in intfs:
                if di["mode"] == "access":
                    av = di.get("access_vlan")
                    if av is not None and int(av) == vlan_id:
                        all_candidate_hosts.add(device_name)
                elif di["mode"] == "trunk":
                    # A trunk member includes the UNFILTERED ("all VLANs") case —
                    # such a switch is a transit member of every VLAN even with no
                    # access ports.
                    if _trunk_carries_vlan(di.get("trunk_vlans"), vlan_id):
                        all_candidate_hosts.add(device_name)

        members = []
        for hostname in sorted(all_candidate_hosts):
            device_intfs = device_intf_index.get(hostname, [])
            member_mode = None
            member_interfaces = []

            for di in device_intfs:
                if di["mode"] == "trunk":
                    if _trunk_carries_vlan(di.get("trunk_vlans"), vlan_id):
                        member_mode = "trunk"
                        member_interfaces.append(di["name"])
                    nv = di.get("native_vlan")
                    if nv is not None and int(nv) == vlan_id:
                        member_mode = "native"
                        if di["name"] not in member_interfaces:
                            member_interfaces.append(di["name"])
                elif di["mode"] == "access":
                    av = di.get("access_vlan")
                    if av is not None and int(av) == vlan_id:
                        member_mode = "access"
                        member_interfaces.append(di["name"])

            if member_mode:
                members.append({
                    "hostname": hostname,
                    "mode": member_mode,
                    "interfaces": member_interfaces,
                })
            elif hostname in member_hostnames:
                # Vlan node exists but no switchport match — keep as unknown
                members.append({
                    "hostname": hostname,
                    "mode": "unknown",
                    "interfaces": [],
                })

        # Add L3/routed members — devices with IPs in this VLAN's subnet
        # that aren't already switchport members
        existing_hosts = {m["hostname"] for m in members}
        for l3_host in sorted(l3_vlan_members.get(vlan_id, set())):
            if l3_host not in existing_hosts:
                members.append({
                    "hostname": l3_host,
                    "mode": "routed",
                    "interfaces": [],
                })

        vlans.append({
            "vlan_id": vlan_id,
            "name": name,
            "subnet": subnet,
            "members": members,
        })

    return {"vlans": vlans}


@router.get("/api/topology/area/{area_id}/lsdb")
def get_area_lsdb(
    area_id: str,
    run_id: str = Query(..., description="Pipeline run ID"),
    vrf: str = Query("default", description="VRF name"),
):
    """Return OSPF LSDB for a specific area from Neo4j OspfLsa nodes."""
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"detail": "Neo4j unavailable"},
        )

    driver = get_driver()
    cypher = """
    MATCH (area:SharedService {
        service_type: "ospf_area",
        identifier: $area_id,
        run_id: $run_id
    })-[:HAS_LSA]->(lsa:OspfLsa)
    WHERE area.vrf = $vrf
    RETURN lsa.lsa_type AS lsa_type, lsa.lsa_id AS lsa_id,
           lsa.prefix AS prefix, lsa.adv_router AS adv_router,
           lsa.metric AS metric, lsa.num_links AS num_links,
           lsa.fwd_addr AS fwd_addr
    ORDER BY lsa.lsa_type, lsa.prefix
    """
    with driver.session() as session:
        result = session.run(cypher, area_id=area_id, run_id=run_id, vrf=vrf)
        lsas = []
        for rec in result:
            lsa = {k: v for k, v in dict(rec).items() if v is not None}
            lsas.append(lsa)

    return {"area_id": area_id, "vrf": vrf, "lsas": lsas}


