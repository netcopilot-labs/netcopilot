"""Graph loader — seed JSON (demo) and the real network_model.json (pipeline).

Two entry points share one Neo4j-facing module:

* :func:`load_seed` — load a small synthetic graph for the local demo / tests.
* :func:`load_model` — the pipeline path: read ``model/network_model.json`` from
  a run directory and materialise the full property graph (devices, interfaces,
  VLANs, typed links, routing adjacencies, shared services, OSPF LSDB).

Every node and relationship carries ``site`` + ``run_id`` for multi-site
isolation; a reload of the same ``(site, run_id)`` deletes first (idempotent).
Routes, firewall policies, ARP, route-policies and security-config loading land
in later slices; findings load with the rules layer.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netcopilot.model.interface_normalizer import canonicalize

from .client import get_driver
from .schema import (
    ARP_ENTRY,
    CONNECTS_TO,
    DEVICE,
    FINDING,
    FIREWALL_POLICY,
    HAS_ARP,
    HAS_FINDING,
    HAS_INTERFACE,
    HAS_LSA,
    HAS_POLICY,
    HAS_PREFIX_ENTRY,
    HAS_ROUTE,
    HAS_ROUTE_POLICY,
    HAS_SECURITY_CONFIG,
    HAS_VLAN,
    INTERFACE,
    LINK_RELATIONSHIP_MAP,
    MEMBER_OF,
    OSPF_LSA,
    PHYSICAL_CABLE,
    PREFIX_SET_ENTRY,
    ROUTE,
    ROUTE_POLICY,
    ROUTING_ADJACENCY,
    RUN,
    SECURITY_CONFIG,
    SHARED_SERVICE,
    VLAN,
)

logger = logging.getLogger(__name__)


def load_seed(path: str | Path, *, driver=None) -> dict:
    """Load a seed JSON into Neo4j (demo/tests). Returns a small summary dict.

    NOT the production ingestion path (that is :func:`load_model`) — it just
    materialises an invented graph so the MCP spine has something to query.
    Single-direction entries are MERGEd directionally, so re-running is idempotent.
    """
    data = json.loads(Path(path).read_text())
    site, run_id = data["site"], data["run_id"]
    driver = driver or get_driver()

    with driver.session() as session:
        session.run(
            f"MERGE (r:{RUN} {{site: $site, run_id: $run_id}}) SET r.loaded_at = timestamp()",
            site=site, run_id=run_id,
        )
        session.run(
            f"UNWIND $rows AS row "
            f"MERGE (d:{DEVICE} {{site: $site, run_id: $run_id, name: row.name}}) SET d += row",
            rows=data.get("devices", []), site=site, run_id=run_id,
        )
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id, name: row.device}}) "
            f"MERGE (d)-[:{HAS_INTERFACE}]->"
            f"(i:{INTERFACE} {{site: $site, run_id: $run_id, device: row.device, name: row.name}}) "
            f"SET i += row",
            rows=data.get("interfaces", []), site=site, run_id=run_id,
        )
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (a:{DEVICE} {{site: $site, run_id: $run_id, name: row.a}}), "
            f"(b:{DEVICE} {{site: $site, run_id: $run_id, name: row.b}}) "
            f"MERGE (a)-[:{PHYSICAL_CABLE}]->(b)",
            rows=[link for link in data.get("links", []) if link.get("type") == "physical"],
            site=site, run_id=run_id,
        )
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (a:{DEVICE} {{site: $site, run_id: $run_id, name: row.a}}), "
            f"(b:{DEVICE} {{site: $site, run_id: $run_id, name: row.b}}) "
            f"MERGE (a)-[adj:{ROUTING_ADJACENCY}]->(b) SET adj.protocol = row.protocol",
            rows=data.get("adjacencies", []), site=site, run_id=run_id,
        )
        session.run(
            f"UNWIND $rows AS row "
            f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id, name: row.device}}) "
            f"MERGE (d)-[:{HAS_FINDING}]->"
            f"(f:{FINDING} {{site: $site, run_id: $run_id, finding_id: row.finding_id}}) "
            f"SET f += row",
            rows=data.get("findings", []), site=site, run_id=run_id,
        )

    return {
        "site": site,
        "run_id": run_id,
        "devices": len(data.get("devices", [])),
        "findings": len(data.get("findings", [])),
    }


def load_model(
    driver,
    run_dir: str | Path,
    site: str,
    run_id: str,
) -> dict[str, int]:
    """
    Load a network model into Neo4j from a pipeline run directory.

    Reads network_model.json from the run directory and creates all
    Neo4j nodes and relationships. If data for the same (site, run_id)
    already exists, it is deleted first (idempotent reload).

    Args:
        driver: neo4j.Driver instance (from client.get_driver()).
        run_dir: Path to the pipeline run directory (e.g., runs/2026-01-15_12-00-00).
        site: Site identifier (e.g., "prod1", "mysite"). Used for multi-site isolation.
        run_id: Run identifier (e.g., "2026-01-15_12-00-00").

    Returns:
        Dict with counts of loaded entities:
        {
            "devices": 6,
            "interfaces": 423,
            "links": 34,
            "adjacencies": 5,
            "shared_services": 10
        }

    Raises:
        FileNotFoundError: If network_model.json doesn't exist in run_dir.
    """
    run_dir = Path(run_dir)
    model_path = run_dir / "model" / "network_model.json"

    if not model_path.exists():
        raise FileNotFoundError(
            f"Network model not found: {model_path}. Run the pipeline first (netcopilot run)."
        )

    # -------------------------------------------------------------------------
    # Load model JSON
    # -------------------------------------------------------------------------
    with open(model_path) as f:
        model = json.load(f)

    devices = model.get("devices", [])
    interfaces = model.get("interfaces", [])
    links = model.get("links", [])
    adjacencies = model.get("adjacencies", [])
    shared_services = model.get("shared_services", [])
    ospf_lsdb = model.get("ospf_lsdb", [])

    logger.info(
        "Neo4j: loading model — %d devices, %d interfaces, %d links, "
        "%d adjacencies, %d shared services, %d OSPF LSAs",
        len(devices), len(interfaces), len(links),
        len(adjacencies), len(shared_services), len(ospf_lsdb),
    )

    # -------------------------------------------------------------------------
    # Delete existing data for this (site, run_id) — idempotent reload
    # -------------------------------------------------------------------------
    _delete_run_data(driver, site, run_id)

    # -------------------------------------------------------------------------
    # Load all entities in order (devices first, then relationships)
    # -------------------------------------------------------------------------
    counts = {}
    counts["devices"] = _load_devices(driver, devices, interfaces, site, run_id)
    counts["interfaces"] = _load_interfaces(driver, interfaces, site, run_id)
    counts["vlans"] = _load_vlans(driver, devices, site, run_id)
    counts["links"] = _load_links(driver, links, interfaces, site, run_id)
    counts["adjacencies"] = _load_adjacencies(driver, adjacencies, site, run_id)
    counts["shared_services"] = _load_shared_services(
        driver, shared_services, site, run_id,
    )
    counts["ospf_lsdb"] = _load_ospf_lsdb(driver, ospf_lsdb, site, run_id)
    # Routes (genie/fortigate RIBs + per-peer BGP + full-table/connected synthesis),
    # then eBGP transit/peering classification and BGP decision-attribute enrichment.
    counts["routes"] = _load_routes(driver, run_dir, site, run_id, interfaces)
    _classify_bgp_sessions(driver, run_id, site)
    _enrich_bgp_decision_attributes(driver, run_dir, run_id, site)
    # Firewall policies (FortiGate policy resolution + Cisco ACLs) and ARP entries.
    counts["firewall_policies"] = _load_firewall_policies(driver, run_dir, site, run_id)
    counts["arp_entries"] = _load_arp_entries(driver, run_dir, site, run_id)
    # Route-policies + prefix-sets, security configs, and VRFs (as SharedServices).
    rp_count, pse_count = _load_route_policies_and_prefix_sets(driver, run_dir, site, run_id)
    counts["route_policies"] = rp_count
    counts["prefix_set_entries"] = pse_count
    counts["security_configs"] = _load_security_configs(driver, run_dir, site, run_id)
    counts["vrfs"] = _load_vrfs(driver, run_dir, site, run_id, interfaces)
    # Findings from the rules layer (findings/findings.json), if a rules pass ran.
    counts["findings"] = _load_findings(driver, run_dir, site, run_id)

    # -------------------------------------------------------------------------
    # Create Run metadata node with actual counts
    # -------------------------------------------------------------------------
    _create_run_node(driver, site, run_id, counts)

    logger.info(
        "Neo4j: loaded %d devices, %d interfaces, %d links for site %s (run %s)",
        counts["devices"], counts["interfaces"], counts["links"],
        site, run_id,
    )

    return counts


# -------------------------------------------------------------------------
# Private — Delete existing run data
# -------------------------------------------------------------------------

def _delete_run_data(driver, site: str, run_id: str) -> None:
    """
    Delete all nodes and relationships for a specific (site, run_id).

    Uses batched deletion to avoid memory issues with large graphs.
    DETACH DELETE removes nodes and all their relationships in one pass.
    """
    cypher = """
    MATCH (n)
    WHERE n.site = $site AND n.run_id = $run_id
    DETACH DELETE n
    """
    with driver.session() as session:
        result = session.run(cypher, site=site, run_id=run_id)
        summary = result.consume()
        deleted = summary.counters.nodes_deleted
        if deleted > 0:
            logger.info(
                "Neo4j: deleted %d existing nodes for site=%s, run_id=%s",
                deleted, site, run_id,
            )


def delete_run(driver, run_id: str, site: str | None = None) -> int:
    """Delete all graph nodes for a run (optionally scoped to a site).

    Returns the number of nodes removed (0 if the run was not found).
    """
    where = "n.run_id = $run_id" + (" AND n.site = $site" if site else "")
    params = {"run_id": run_id}
    if site:
        params["site"] = site
    with driver.session() as session:
        summary = session.run(f"MATCH (n) WHERE {where} DETACH DELETE n", **params).consume()
        return summary.counters.nodes_deleted


def list_runs(driver) -> list[dict]:
    """Return the runs loaded in Neo4j, newest first:
    ``[{site, run_id, loaded_at, devices, findings}]``."""
    cypher = f"""
    MATCH (r:{RUN})
    OPTIONAL MATCH (d:{DEVICE} {{site: r.site, run_id: r.run_id}})
    OPTIONAL MATCH (f:{FINDING} {{site: r.site, run_id: r.run_id}})
    RETURN r.site AS site, r.run_id AS run_id, r.loaded_at AS loaded_at,
           count(DISTINCT d) AS devices, count(DISTINCT f) AS findings
    ORDER BY loaded_at DESC
    """
    with driver.session() as session:
        return [dict(rec) for rec in session.run(cypher)]


# -------------------------------------------------------------------------
# Private — Device loading
# -------------------------------------------------------------------------

def _load_devices(
    driver,
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create Device nodes from the devices array.

    Computes interface summary counts (up/down/admin_down/total) by
    scanning the interfaces array grouped by device_id.

    Args:
        driver: Neo4j driver.
        devices: List of device dicts from network_model.json.
        interfaces: List of interface dicts (for computing counts).
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of Device nodes created.
    """
    if not devices:
        return 0

    # -------------------------------------------------------------------------
    # Compute per-device interface counts from the interfaces array
    # -------------------------------------------------------------------------
    iface_counts = _compute_interface_counts(interfaces)

    # -------------------------------------------------------------------------
    # Prepare device property dicts for UNWIND batch creation
    # -------------------------------------------------------------------------
    device_params = []
    for device in devices:
        props = _clean_properties({
            "name": device.get("hostname") or device.get("device_id"),
            "device_id": device.get("device_id"),
            "platform": device.get("platform"),
            "os_type": device.get("os_family"),
            "os_version": device.get("version"),
            "role": device.get("role"),
            "serial": device.get("serial"),
            "mgmt_ip": device.get("management_ip"),
            "site": site,
            "run_id": run_id,
            "building": device.get("site"),  # per-device building/site label
        })

        # Add interface summary counts
        device_name = props.get("name", "")
        device_key = device.get("device_id", device_name)
        counts = iface_counts.get(device_key, {})
        props["interfaces_up"] = counts.get("up", 0)
        props["interfaces_down"] = counts.get("down", 0)
        props["interfaces_admin_down"] = counts.get("admin_down", 0)
        props["interfaces_total"] = counts.get("total", 0)

        # Cluster info — flatten to simple properties since Neo4j
        # doesn't support nested objects. Also store full cluster_members
        # as JSON string for future stack visualization.
        cluster_members = device.get("cluster_members")
        if cluster_members:
            props["cluster_size"] = len(cluster_members)
            props["cluster_declared_size"] = device.get("cluster_declared_size")
            props["cluster_members"] = json.dumps(cluster_members)

        # Stack ports — store as JSON string for
        # compound node rendering in the dashboard.
        stack_ports = device.get("stack_ports")
        if stack_ports:
            props["stack_ports"] = json.dumps(stack_ports)

        device_type = _infer_device_type(device)
        if device_type:
            props["device_type"] = device_type

        # BGP route-reflector role (from running-config; genie's BGP omits it).
        props["is_route_reflector"] = bool(device.get("is_route_reflector"))
        if device.get("rr_cluster_id"):
            props["rr_cluster_id"] = device.get("rr_cluster_id")

        # Collected = has platform or version (device was reachable during collection)
        props["collected"] = bool(props.get("platform") or props.get("os_version"))

        device_params.append(props)

    # -------------------------------------------------------------------------
    # Batch create Device nodes via UNWIND
    # -------------------------------------------------------------------------
    cypher = f"""
    UNWIND $devices AS d
    CREATE (dev:{DEVICE})
    SET dev = d
    """
    with driver.session() as session:
        session.run(cypher, devices=device_params)

    logger.debug("Neo4j: created %d Device nodes", len(device_params))
    return len(device_params)


# -------------------------------------------------------------------------
# Private — Interface loading
# -------------------------------------------------------------------------

def _load_interfaces(
    driver,
    interfaces: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create Interface nodes and HAS_INTERFACE relationships.

    Each interface becomes an :Interface node linked to its parent
    :Device node via a [:HAS_INTERFACE] relationship.

    Args:
        driver: Neo4j driver.
        interfaces: List of interface dicts from network_model.json.
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of Interface nodes created.
    """
    if not interfaces:
        return 0

    # -------------------------------------------------------------------------
    # Prepare interface property dicts
    # -------------------------------------------------------------------------
    iface_params = []
    for iface in interfaces:
        # Compute unified status from admin_status + oper_status
        status = _compute_interface_status(
            iface.get("admin_status", "unknown"),
            iface.get("oper_status", "unknown"),
        )

        # Clean ip_address — "unassigned" → None
        ip = iface.get("ip_address")
        if ip and ip.lower() == "unassigned":
            ip = None

        # QoS enrichment — flatten nested
        # qos dict into prefixed properties per direction.
        qos_props = _flatten_qos(iface.get("qos"))

        props = _clean_properties({
            "interface_id": iface.get("interface_id"),
            "name": iface.get("name"),
            "device": iface.get("device_id"),
            "status": status,
            "admin_status": iface.get("admin_status"),
            "oper_status": iface.get("oper_status"),
            "ip": ip,
            "prefix_length": iface.get("prefix_length"),
            "type": iface.get("type"),
            # L1 enrichment
            "speed": iface.get("speed"),
            "duplex": iface.get("duplex"),
            "mtu": iface.get("mtu"),
            "description": iface.get("description"),
            "media_type": iface.get("media_type"),
            "sfp_pid": iface.get("sfp_pid"),
            # Port-channel membership — for LAG group enrichment on link rels
            "port_channel_int": iface.get("port_channel_int"),
            "port_channel_members": iface.get("port_channel_members"),
            # Switchport enrichment
            "switchport_mode": iface.get("switchport_mode"),
            "access_vlan": iface.get("access_vlan"),
            "trunk_vlans": iface.get("trunk_vlans"),
            "native_vlan": iface.get("native_vlan"),
            "vrf": iface.get("vrf"),
            # FortiGate interface hierarchy
            "vdom": iface.get("vdom"),
            "vlanid": iface.get("vlanid"),
            "parent_interface": iface.get("parent_interface"),
            "aggregate_members": iface.get("aggregate_members"),
            "site": site,
            "run_id": run_id,
            **qos_props,
        })
        iface_params.append(props)

    # -------------------------------------------------------------------------
    # Batch create Interface nodes + HAS_INTERFACE relationships
    # -------------------------------------------------------------------------
    # Uses MATCH to find the parent Device node, then CREATE the Interface
    # and the relationship in one Cypher statement for efficiency.
    cypher = f"""
    UNWIND $interfaces AS i
    MATCH (dev:{DEVICE} {{name: i.device, site: i.site, run_id: i.run_id}})
    CREATE (iface:{INTERFACE})
    SET iface = i
    CREATE (dev)-[:{HAS_INTERFACE} {{site: i.site, run_id: i.run_id}}]->(iface)
    """
    with driver.session() as session:
        session.run(cypher, interfaces=iface_params)

    logger.debug("Neo4j: created %d Interface nodes with HAS_INTERFACE", len(iface_params))
    return len(iface_params)


# -------------------------------------------------------------------------
# Private — VLAN loading
# -------------------------------------------------------------------------

def _load_vlans(
    driver,
    devices: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create Vlan nodes and HAS_VLAN relationships from device vlans[] arrays.

    Each device's ``vlans`` list (populated by ``_enrich_devices_vlans()`` in
    model_builder.py) becomes a set of :Vlan nodes connected to the :Device
    via [:HAS_VLAN] relationships.

    Args:
        driver: Neo4j driver.
        devices: List of device dicts from network_model.json.
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of Vlan nodes created.
    """
    vlan_params = []
    for device in devices:
        hostname = device.get("hostname") or device.get("device_id", "")
        for vlan in device.get("vlans", []):
            props = _clean_properties({
                "vlan_id": vlan.get("vlan_id"),
                "name": vlan.get("name"),
                "state": vlan.get("state"),
                "shutdown": vlan.get("shutdown", False),
                "interfaces": vlan.get("interfaces", []),
                "device": hostname,
                "site": site,
                "run_id": run_id,
            })
            vlan_params.append(props)

    if not vlan_params:
        return 0

    # Create Vlan nodes
    cypher_create = f"""
    UNWIND $vlans AS v
    CREATE (vlan:{VLAN})
    SET vlan = v
    """
    with driver.session() as session:
        session.run(cypher_create, vlans=vlan_params)

    # Create HAS_VLAN relationships
    cypher_rel = f"""
    UNWIND $vlans AS v
    MATCH (d:{DEVICE} {{name: v.device, site: v.site, run_id: v.run_id}})
    MATCH (vlan:{VLAN} {{device: v.device, vlan_id: v.vlan_id, site: v.site, run_id: v.run_id}})
    CREATE (d)-[:{HAS_VLAN} {{site: v.site, run_id: v.run_id}}]->(vlan)
    """
    with driver.session() as session:
        session.run(cypher_rel, vlans=vlan_params)

    logger.debug("Neo4j: created %d Vlan nodes with HAS_VLAN", len(vlan_params))
    return len(vlan_params)


# -------------------------------------------------------------------------
# Private — Link loading
# -------------------------------------------------------------------------

def _load_links(
    driver,
    links: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create typed link relationships and CONNECTS_TO from links array.

    Links are typed based on the link_type field:
        physical        → :PHYSICAL_CABLE
        management      → :MGMT_LINK
        l3_reachability → :L3_REACHABILITY
        subnet_association → :INFERRED_LINK

    Backward compatibility: If a link has no link_type (old model), it
    defaults to :PHYSICAL_CABLE with a warning.

    For each link:
    1. Creates the appropriate typed relationship between Device nodes
       with all link properties and flattened L2/L3 metadata.
    2. Creates [:CONNECTS_TO] between Interface nodes when both endpoints
       exist as Interface nodes in the graph.

    Args:
        driver: Neo4j driver.
        links: List of link dicts from network_model.json.
        interfaces: List of interface dicts (for building match index).
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of device-to-device link relationships created.
    """
    if not links:
        return 0

    # -------------------------------------------------------------------------
    # Build canonical interface lookup for CONNECTS_TO matching
    # -------------------------------------------------------------------------
    iface_lookup = _build_interface_lookup(interfaces)

    # -------------------------------------------------------------------------
    # Build (device, canonical_intf) → lag_group lookup for link enrichment
    # canonicalize() is already imported at the top of this module.
    # -------------------------------------------------------------------------
    lag_group_lookup: dict[tuple[str, str], str] = {}
    for iface in interfaces:
        pc_int = iface.get("port_channel_int")
        if pc_int:
            c = canonicalize(iface.get("name", ""))
            if c:
                lag_group_lookup[(iface.get("device_id", ""), c)] = pc_int

    # -------------------------------------------------------------------------
    # Group links by relationship type
    # -------------------------------------------------------------------------
    links_by_type: dict[str, list[dict[str, Any]]] = {}
    connects_to_params: list[dict[str, Any]] = []
    old_model_count = 0

    for link in links:
        local_device = link.get("local_device_id", "")
        remote_device = link.get("remote_device_id", "")

        # Determine Neo4j relationship type from link_type
        link_type = link.get("link_type")
        if link_type:
            rel_type = LINK_RELATIONSHIP_MAP.get(link_type, PHYSICAL_CABLE)
        else:
            # Backward compat: old model without link_type → PHYSICAL_CABLE
            rel_type = PHYSICAL_CABLE
            old_model_count += 1

        # Flatten L2/L3 metadata from nested dicts to prefixed properties
        flat_props = _flatten_link_metadata(link)

        # Build link relationship properties
        pl_props = _clean_properties({
            "link_id": link.get("link_id"),
            "link_type": link_type,
            "local_device": local_device,
            "remote_device": remote_device,
            "local_interface": _extract_interface_name(link.get("local_interface_id")),
            "remote_interface": _extract_interface_name(link.get("remote_interface_id")),
            "status": link.get("status"),
            "direction": link.get("direction"),
            "discovery_method": link.get("discovery_method"),
            "confidence": link.get("confidence"),
            "discovery_protocol": link.get("discovery_protocol"),
            "discovery_priority": link.get("discovery_priority"),
            "peer_collected": link.get("peer_collected"),
            "mgmt_type": link.get("mgmt_type"),
            "mgmt_vlan": link.get("mgmt_vlan"),
            "mgmt_vrf": link.get("mgmt_vrf"),
            # stack member attribution
            "source_member_id": link.get("source_member_id"),
            "target_member_id": link.get("target_member_id"),
            "ha_member": link.get("ha_member"),
            "site": site,
            "run_id": run_id,
            **flat_props,
        })

        # Store evidence as a Neo4j string list
        evidence = link.get("evidence", [])
        if evidence:
            pl_props["evidence"] = evidence

        # Stack interconnect extra properties
        if link_type == "stack_interconnect":
            for key in ("stack_subtype", "local_member_id", "remote_member_id"):
                val = link.get(key)
                if val is not None:
                    pl_props[key] = val
            # Rename to match Neo4j convention (member_from/member_to)
            if "local_member_id" in pl_props:
                pl_props["member_from"] = pl_props.pop("local_member_id")
            if "remote_member_id" in pl_props:
                pl_props["member_to"] = pl_props.pop("remote_member_id")

        # Port-channel LAG group enrichment on link relationships
        # Stored at build time so topology API doesn't need filesystem reads.
        local_intf = _extract_interface_name(link.get("local_interface_id"))
        remote_intf = _extract_interface_name(link.get("remote_interface_id"))
        if local_intf:
            c = canonicalize(local_intf)
            lag = lag_group_lookup.get((local_device, c)) if c else None
            if lag:
                pl_props["lag_group"] = lag
        if remote_intf:
            c = canonicalize(remote_intf)
            lag = lag_group_lookup.get((remote_device, c)) if c else None
            if lag:
                pl_props["lag_group_target"] = lag

        links_by_type.setdefault(rel_type, []).append(pl_props)

        # -------------------------------------------------------------------------
        # Try to build CONNECTS_TO between Interface nodes
        # -------------------------------------------------------------------------
        local_iface_name = _extract_interface_name(link.get("local_interface_id"))
        remote_iface_name = _extract_interface_name(link.get("remote_interface_id"))

        local_iface_id = _resolve_interface(
            local_device, local_iface_name, iface_lookup,
        )
        remote_iface_id = _resolve_interface(
            remote_device, remote_iface_name, iface_lookup,
        )

        if local_iface_id and remote_iface_id:
            ct_props = _clean_properties({
                "link_id": link.get("link_id"),
                "local_interface_id": local_iface_id,
                "remote_interface_id": remote_iface_id,
                "discovery_method": link.get("discovery_method"),
                "confidence": link.get("confidence"),
                "status": link.get("status"),
                "site": site,
                "run_id": run_id,
            })
            connects_to_params.append(ct_props)

    if old_model_count > 0:
        logger.warning(
            "Neo4j: %d links have no link_type (old model) — defaulting to PHYSICAL_CABLE",
            old_model_count,
        )

    # -------------------------------------------------------------------------
    # Batch create typed link relationships via UNWIND (one batch per type)
    # -------------------------------------------------------------------------
    total_created = 0
    for rel_type, link_params in links_by_type.items():
        cypher_pl = f"""
        UNWIND $links AS l
        MATCH (a:{DEVICE} {{name: l.local_device, site: l.site, run_id: l.run_id}})
        MATCH (b:{DEVICE} {{name: l.remote_device, site: l.site, run_id: l.run_id}})
        CREATE (a)-[r:{rel_type}]->(b)
        SET r = l
        REMOVE r.local_device, r.remote_device
        """
        with driver.session() as session:
            session.run(cypher_pl, links=link_params)

        total_created += len(link_params)
        logger.debug(
            "Neo4j: created %d %s relationships", len(link_params), rel_type,
        )

    # -------------------------------------------------------------------------
    # Batch create CONNECTS_TO relationships via UNWIND
    # -------------------------------------------------------------------------
    if connects_to_params:
        cypher_ct = f"""
        UNWIND $links AS l
        MATCH (a:{INTERFACE} {{interface_id: l.local_interface_id, site: l.site, run_id: l.run_id}})
        MATCH (b:{INTERFACE} {{interface_id: l.remote_interface_id, site: l.site, run_id: l.run_id}})
        CREATE (a)-[r:{CONNECTS_TO}]->(b)
        SET r = l
        REMOVE r.local_interface_id, r.remote_interface_id
        """
        with driver.session() as session:
            session.run(cypher_ct, links=connects_to_params)

        logger.debug(
            "Neo4j: created %d CONNECTS_TO relationships", len(connects_to_params),
        )

    return total_created


# -------------------------------------------------------------------------
# Private — Adjacency loading
# -------------------------------------------------------------------------

def _load_adjacencies(
    driver,
    adjacencies: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create ROUTING_ADJACENCY relationships and external peer Device nodes.

    For each adjacency:
    1. If either endpoint is an external peer (IP address, not a managed
       hostname), creates a Device node with device_type="external".
    2. Creates [:ROUTING_ADJACENCY] between the two Device nodes.

    External peer Device nodes are deduplicated — the same IP appearing
    in multiple adjacencies creates only one node.

    Args:
        driver: Neo4j driver.
        adjacencies: List of adjacency dicts from network_model.json.
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of ROUTING_ADJACENCY relationships created.
    """
    if not adjacencies:
        return 0

    # -------------------------------------------------------------------------
    # Collect external peers — IPs that aren't managed device hostnames
    # -------------------------------------------------------------------------
    # Build set of managed device names from existing Device nodes.
    # External peers are identified by peer_collected=False: their device_a
    # is an IP address rather than a hostname.
    external_peers: dict[str, dict[str, Any]] = {}

    for adj in adjacencies:
        device_a = adj.get("device_a", "")
        device_b = adj.get("device_b", "")

        # External peer: not collected, device_a is typically an IP
        if not adj.get("peer_collected", False):
            # device_a is the external peer IP
            if device_a and device_a not in external_peers:
                external_peers[device_a] = _clean_properties({
                    "name": device_a,
                    "device_type": "external",
                    "collected": False,
                    "site": site,
                    "run_id": run_id,
                    # BGP enrichment for external peers
                    "remote_as": adj.get("local_as"),  # external peer's AS
                    "peer_label": adj.get("peer_label"),
                })

    # -------------------------------------------------------------------------
    # Create external peer Device nodes (deduplicated)
    # -------------------------------------------------------------------------
    if external_peers:
        ext_params = list(external_peers.values())
        cypher_ext = f"""
        UNWIND $peers AS p
        CREATE (d:{DEVICE})
        SET d = p
        """
        with driver.session() as session:
            session.run(cypher_ext, peers=ext_params)
        logger.debug(
            "Neo4j: created %d external peer Device nodes", len(ext_params),
        )

    # -------------------------------------------------------------------------
    # Prepare adjacency relationship properties
    # -------------------------------------------------------------------------
    adj_params = []
    for adj in adjacencies:
        props = _clean_properties({
            "device_a": adj.get("device_a"),
            "device_b": adj.get("device_b"),
            "protocol": adj.get("protocol"),
            "state": adj.get("state"),
            "vrf": adj.get("vrf"),
            "local_as": adj.get("local_as"),
            "remote_as": adj.get("remote_as"),
            "peer_collected": adj.get("peer_collected"),
            "bilateral": adj.get("bilateral"),
            "site": site,
            "run_id": run_id,
        })

        # OSPF-specific fields (may not be present in all environments)
        props.update(_clean_properties({
            "area": adj.get("area"),
            "process_id": adj.get("process_id"),
            "interface_a": adj.get("interface_a"),
            "interface_b": adj.get("interface_b"),
            "neighbor_address": adj.get("neighbor_address"),
            "cost_a": adj.get("cost_a"),
            "cost_b": adj.get("cost_b"),
            "hello_a": adj.get("hello_a"),
            "hello_b": adj.get("hello_b"),
            "dead_a": adj.get("dead_a"),
            "dead_b": adj.get("dead_b"),
            "network_type_a": adj.get("network_type_a"),
            "network_type_b": adj.get("network_type_b"),
            "ip_a": adj.get("ip_a"),
            "ip_b": adj.get("ip_b"),
            "router_id_a": adj.get("router_id_a"),
            "router_id_b": adj.get("router_id_b"),
            # Process-level config
            "area_type": adj.get("area_type"),
            "passive_default_a": adj.get("passive_default_a"),
            "passive_default_b": adj.get("passive_default_b"),
            "active_interfaces_a": adj.get("active_interfaces_a"),
            "active_interfaces_b": adj.get("active_interfaces_b"),
            "vrf_lite_a": adj.get("vrf_lite_a"),
            "vrf_lite_b": adj.get("vrf_lite_b"),
            "redistribute_a": adj.get("redistribute_a"),
            "redistribute_b": adj.get("redistribute_b"),
            "reference_bandwidth_a": adj.get("reference_bandwidth_a"),
            "reference_bandwidth_b": adj.get("reference_bandwidth_b"),
        }))

        # BGP-specific fields
        props.update(_clean_properties({
            "session_type": adj.get("session_type"),
            "peer_label": adj.get("peer_label"),
            "rr_client": adj.get("rr_client"),
            "rr_reflector": adj.get("rr_reflector"),
            "description_a": adj.get("description_a"),
            "description_b": adj.get("description_b"),
            "prefixes_received_a": adj.get("prefixes_received_a"),
            "prefixes_received_b": adj.get("prefixes_received_b"),
            "msg_sent_a": adj.get("msg_sent_a"),
            "msg_sent_b": adj.get("msg_sent_b"),
            "msg_rcvd_a": adj.get("msg_rcvd_a"),
            "msg_rcvd_b": adj.get("msg_rcvd_b"),
            "up_down_a": adj.get("up_down_a"),
            "up_down_b": adj.get("up_down_b"),
            "keepalive_a": adj.get("keepalive_a"),
            "keepalive_b": adj.get("keepalive_b"),
            "hold_time_a": adj.get("hold_time_a"),
            "hold_time_b": adj.get("hold_time_b"),
            "route_policy_in_a": adj.get("route_policy_in_a"),
            "route_policy_in_b": adj.get("route_policy_in_b"),
            "route_policy_out_a": adj.get("route_policy_out_a"),
            "route_policy_out_b": adj.get("route_policy_out_b"),
            "bfd_a": adj.get("bfd_a"),
            "bfd_b": adj.get("bfd_b"),
            "graceful_restart_a": adj.get("graceful_restart_a"),
            "graceful_restart_b": adj.get("graceful_restart_b"),
            "password_configured_a": adj.get("password_configured_a"),
            "password_configured_b": adj.get("password_configured_b"),
            "maximum_prefix_a": adj.get("maximum_prefix_a"),
            "maximum_prefix_b": adj.get("maximum_prefix_b"),
            "update_source_a": adj.get("update_source_a"),
            "update_source_b": adj.get("update_source_b"),
            "send_community_a": adj.get("send_community_a"),
            "send_community_b": adj.get("send_community_b"),
            "next_hop_self_a": adj.get("next_hop_self_a"),
            "next_hop_self_b": adj.get("next_hop_self_b"),
            "soft_reconfiguration_a": adj.get("soft_reconfiguration_a"),
            "soft_reconfiguration_b": adj.get("soft_reconfiguration_b"),
            "allowas_in_a": adj.get("allowas_in_a"),  # R1-BGP-2
            "allowas_in_b": adj.get("allowas_in_b"),
        }))

        # Network statements — store as Neo4j string lists
        for side in ("a", "b"):
            ns = adj.get(f"network_statements_{side}")
            if ns:
                props[f"network_statements_{side}"] = ns

        # Address families — store as Neo4j string list
        address_families = adj.get("address_families", [])
        if address_families:
            props["address_families"] = address_families

        adj_params.append(props)

    # -------------------------------------------------------------------------
    # Batch create ROUTING_ADJACENCY relationships
    # -------------------------------------------------------------------------
    cypher_adj = f"""
    UNWIND $adjs AS a
    MATCH (d1:{DEVICE} {{name: a.device_a, site: a.site, run_id: a.run_id}})
    MATCH (d2:{DEVICE} {{name: a.device_b, site: a.site, run_id: a.run_id}})
    CREATE (d1)-[r:{ROUTING_ADJACENCY}]->(d2)
    SET r = a
    REMOVE r.device_a, r.device_b
    """
    with driver.session() as session:
        session.run(cypher_adj, adjs=adj_params)

    logger.debug(
        "Neo4j: created %d ROUTING_ADJACENCY relationships", len(adj_params),
    )
    return len(adj_params)


# -------------------------------------------------------------------------
# Private — Shared service loading
# -------------------------------------------------------------------------

def _load_shared_services(
    driver,
    shared_services: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> int:
    """
    Create SharedService nodes and MEMBER_OF relationships.

    Each shared service (VLAN, subnet, OSPF area, BGP ASN) becomes a
    :SharedService node. Each device that participates in the service
    gets a [:MEMBER_OF] relationship to the SharedService node.

    Member format varies by service type:
        - VLANs/BGP ASNs: members is a list of hostname strings
        - Subnets: members is a list of dicts with {hostname, interface, ip}

    Args:
        driver: Neo4j driver.
        shared_services: List of shared service dicts from network_model.json.
        site: Site identifier.
        run_id: Run identifier.

    Returns:
        Number of SharedService nodes created.
    """
    if not shared_services:
        return 0

    # -------------------------------------------------------------------------
    # Create SharedService nodes
    # -------------------------------------------------------------------------
    svc_params = []
    for svc in shared_services:
        props = _clean_properties({
            "service_type": svc.get("service_type"),
            "identifier": str(svc.get("identifier", "")),
            "name": svc.get("name"),
            "vlan_id": svc.get("vlan_id"),
            "vrf": svc.get("vrf"),
            "site": site,
            "run_id": run_id,
            # OSPF area metadata
            "process_id": svc.get("process_id"),
            "area_type": svc.get("area_type"),
            "spf_runs": svc.get("spf_runs"),
            "lsa_count": svc.get("lsa_count"),
        })
        svc_params.append(props)

    cypher_svc = f"""
    UNWIND $services AS s
    CREATE (svc:{SHARED_SERVICE})
    SET svc = s
    """
    with driver.session() as session:
        session.run(cypher_svc, services=svc_params)

    logger.debug("Neo4j: created %d SharedService nodes", len(svc_params))

    # -------------------------------------------------------------------------
    # Create MEMBER_OF relationships
    # -------------------------------------------------------------------------
    member_params = []
    for svc in shared_services:
        svc_type = svc.get("service_type", "")
        identifier = str(svc.get("identifier", ""))
        members = svc.get("members", [])
        # vrf + process_id disambiguate SharedService nodes that share a
        # (service_type, identifier) — e.g. OSPF area 0.0.0.0 exists once per
        # VRF/process. Without them the MATCH below hit every same-area node and
        # cross-linked members across VRFs (inflated, wrong membership). Non-OSPF
        # services leave both null; the coalesce WHERE then matches the single
        # node with no vrf/process_id, unchanged.
        vrf = svc.get("vrf")
        process_id = svc.get("process_id")

        for member in members:
            # Extract hostname — members can be strings or dicts
            hostname = _extract_member_hostname(member)
            if not hostname:
                continue

            member_params.append({
                "device_name": hostname,
                "service_type": svc_type,
                "identifier": identifier,
                "vrf": vrf,
                "process_id": process_id,
                "site": site,
                "run_id": run_id,
            })

    if member_params:
        cypher_member = f"""
        UNWIND $members AS m
        MATCH (d:{DEVICE} {{name: m.device_name, site: m.site, run_id: m.run_id}})
        MATCH (s:{SHARED_SERVICE} {{
            service_type: m.service_type,
            identifier: m.identifier,
            site: m.site,
            run_id: m.run_id
        }})
        WHERE coalesce(s.vrf, '') = coalesce(m.vrf, '')
          AND coalesce(toString(s.process_id), '') = coalesce(toString(m.process_id), '')
        CREATE (d)-[:{MEMBER_OF} {{site: m.site, run_id: m.run_id}}]->(s)
        """
        with driver.session() as session:
            session.run(cypher_member, members=member_params)

        logger.debug(
            "Neo4j: created %d MEMBER_OF relationships", len(member_params),
        )

    return len(svc_params)


# -------------------------------------------------------------------------
# Private — OSPF LSDB nodes
# -------------------------------------------------------------------------


def _load_ospf_lsdb(
    driver,
    lsdb_entries: list[dict],
    site: str,
    run_id: str,
) -> int:
    """Create OspfLsa nodes linked to SharedService ospf_area nodes.

    Each LSA entry is linked to the SharedService node for its OSPF area
    via a :HAS_LSA relationship.

    Args:
        driver: neo4j.Driver instance.
        lsdb_entries: List of LSA dicts from ``extract_ospf_lsdb()``.
        site: Site identifier.
        run_id: Pipeline run ID.

    Returns:
        Number of OspfLsa nodes created.
    """
    if not lsdb_entries:
        return 0

    lsa_params = []
    for entry in lsdb_entries:
        props = _clean_properties({
            "lsa_type": entry.get("lsa_type"),
            "lsa_id": entry.get("lsa_id"),
            "adv_router": entry.get("adv_router"),
            "prefix": entry.get("prefix"),
            "metric": entry.get("metric"),
            "num_links": entry.get("num_links"),
            "fwd_addr": entry.get("fwd_addr"),
            "site": site,
            "run_id": run_id,
            # Keys for MATCH to SharedService
            "_area_id": entry.get("area_id"),
            "_vrf": entry.get("vrf"),
        })
        lsa_params.append(props)

    cypher = f"""
    UNWIND $lsas AS l
    MATCH (area:{SHARED_SERVICE} {{
        service_type: "ospf_area",
        identifier: l._area_id,
        site: l.site,
        run_id: l.run_id
    }})
    WHERE area.vrf = l._vrf
    CREATE (area)-[:{HAS_LSA}]->(lsa:{OSPF_LSA})
    SET lsa = l
    REMOVE lsa._area_id, lsa._vrf
    """
    with driver.session() as session:
        session.run(cypher, lsas=lsa_params)

    logger.debug("Neo4j: created %d OspfLsa nodes", len(lsa_params))
    return len(lsa_params)




def _create_run_node(
    driver,
    site: str,
    run_id: str,
    counts: dict[str, int],
) -> None:
    """
    Create a Run metadata node with counts and lifecycle properties.

    The Run node serves as the entry point for retention management:
    listing runs, pinning, cleanup. Counts are computed from the actual
    loaded data (not from model JSON metadata) to ensure accuracy.

    Args:
        driver: Neo4j driver.
        site: Site identifier.
        run_id: Run identifier.
        counts: Dict of entity counts from the loading phase:
                {"devices": 6, "interfaces": 423, "links": 34, ...}
    """
    now = datetime.now(timezone.utc).isoformat()

    props = {
        "run_id": run_id,
        "site": site,
        "loaded_at": now,
        "pinned": False,
        "devices_count": counts.get("devices", 0),
        "interfaces_count": counts.get("interfaces", 0),
        "links_count": counts.get("links", 0),
        "adjacencies_count": counts.get("adjacencies", 0),
        "shared_services_count": counts.get("shared_services", 0),
    }

    cypher = f"""
    CREATE (r:{RUN})
    SET r = $props
    """
    with driver.session() as session:
        session.run(cypher, props=props)

    logger.debug(
        "Neo4j: created Run node — site=%s, run_id=%s, %d devices",
        site, run_id, counts.get("devices", 0),
    )


# -------------------------------------------------------------------------
# Private — Utility functions
# -------------------------------------------------------------------------

def _clean_properties(props: dict[str, Any]) -> dict[str, Any]:
    """
    Remove None values from a property dict.

    Neo4j doesn't store null properties — they simply don't exist on the
    node. Removing them before UNWIND keeps the graph clean and avoids
    the need for COALESCE() in queries.

    Args:
        props: Dict of property name → value.

    Returns:
        New dict with None values removed.
    """
    return {k: v for k, v in props.items() if v is not None}


# QoS fields to flatten from the per-direction sub-dicts onto Interface nodes.
_QOS_FIELDS = (
    "policy_name", "type", "cir_bps", "bc_bytes",
    "conform_packets", "conform_bytes",
    "exceed_packets", "exceed_bytes", "exceed_action",
    "queue_drops", "queue_depth",
)


def _flatten_qos(qos: dict[str, Any] | None) -> dict[str, Any]:
    """
    Flatten nested QoS dict into prefixed Neo4j-safe properties.

    The model stores QoS as ``{input: {...}, output: {...}}`` but Neo4j
    nodes can't hold nested objects.  This flattens to prefixed keys::

        qos_input_type, qos_input_cir_bps, qos_output_queue_drops, ...

    Args:
        qos: Per-interface QoS dict from the model, or None.

    Returns:
        Flat dict of ``qos_<direction>_<field>`` properties (may be empty).
    """
    if not qos:
        return {}
    flat: dict[str, Any] = {}
    for direction in ("input", "output"):
        dir_data = qos.get(direction)
        if not dir_data:
            continue
        for field in _QOS_FIELDS:
            val = dir_data.get(field)
            if val is not None:
                flat[f"qos_{direction}_{field}"] = val
    return flat


def _compute_interface_counts(
    interfaces: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    """
    Compute per-device interface status counts.

    Groups interfaces by device_id and counts up/down/admin_down
    using the unified status logic.

    Args:
        interfaces: List of interface dicts from network_model.json.

    Returns:
        Dict keyed by device_id:
        {
            "sw-01": {"up": 38, "down": 2, "admin_down": 10, "total": 50}
        }
    """
    counts: dict[str, dict[str, int]] = {}

    for iface in interfaces:
        device_id = iface.get("device_id", "unknown")
        if device_id not in counts:
            counts[device_id] = {"up": 0, "down": 0, "admin_down": 0, "total": 0}

        status = _compute_interface_status(
            iface.get("admin_status", "unknown"),
            iface.get("oper_status", "unknown"),
        )

        counts[device_id]["total"] += 1
        if status == "up":
            counts[device_id]["up"] += 1
        elif status == "admin_down":
            counts[device_id]["admin_down"] += 1
        else:
            counts[device_id]["down"] += 1

    return counts


def _compute_interface_status(admin_status: str, oper_status: str) -> str:
    """
    Derive a unified interface status from admin + operational status.

    Mapping:
        admin=down (any oper)    → "admin_down"
        admin=up + oper=up       → "up"
        admin=up + oper=unknown  → "up"  (FortiGate VLAN interfaces report unknown oper)
        admin=up + oper=down     → "down"
        anything else            → "down"

    Args:
        admin_status: Administrative status ("up", "down", etc.).
        oper_status: Operational status ("up", "down", "unknown", etc.).

    Returns:
        Unified status: "up", "down", or "admin_down".
    """
    admin = admin_status.lower() if admin_status else "unknown"
    oper = oper_status.lower() if oper_status else "unknown"

    if admin == "down":
        return "admin_down"
    if admin == "up" and oper in ("up", "unknown"):
        return "up"
    return "down"


def _infer_device_type(device: dict[str, Any]) -> str | None:
    """
    Infer device_type from os_family and role.

    This provides a coarse classification for graph queries that want
    to filter by device category (switch, router, firewall).

    Args:
        device: Device dict from network_model.json.

    Returns:
        "switch", "router", "firewall", or None if unknown.
    """
    os_family = (device.get("os_family") or "").lower()
    role = (device.get("role") or "").lower()

    if os_family == "fortios" or "firewall" in role:
        return "firewall"
    if "router" in role or "border" in role:
        return "router"
    if "switch" in role:
        return "switch"
    return None


def _build_interface_lookup(
    interfaces: list[dict[str, Any]],
) -> dict[tuple[str, str], str]:
    """
    Build a lookup index for matching link endpoints to Interface nodes.

    Links use abbreviated interface names (e.g., "Hu0/0/1/0") while interface
    nodes use full Genie names (e.g., "HundredGigE0/0/1/0"). This function
    builds an index keyed by (device_id, canonical_name) → interface_id
    so that _resolve_interface() can find the matching Interface node.

    Args:
        interfaces: List of interface dicts from network_model.json.

    Returns:
        Dict mapping (device_id, canonical_name) → interface_id.
    """
    lookup: dict[tuple[str, str], str] = {}

    for iface in interfaces:
        device_id = iface.get("device_id", "")
        name = iface.get("name", "")
        iface_id = iface.get("interface_id", "")

        canonical = canonicalize(name)
        if canonical and device_id:
            lookup[(device_id, canonical)] = iface_id

    return lookup


def _resolve_interface(
    device_id: str,
    interface_name: str | None,
    lookup: dict[tuple[str, str], str],
) -> str | None:
    """
    Resolve a link endpoint's interface to an Interface node's interface_id.

    Uses canonicalize() to normalize both the link's abbreviated name and
    the interface node's full name to the same canonical form for matching.

    Args:
        device_id: Device hostname (e.g., "core-rtr-01").
        interface_name: Interface name from the link (may be abbreviated).
        lookup: Index from _build_interface_lookup().

    Returns:
        The interface_id of the matching Interface node, or None if no match.
    """
    if not device_id or not interface_name:
        return None

    canonical = canonicalize(interface_name)
    if not canonical:
        return None

    return lookup.get((device_id, canonical))


def _extract_interface_name(interface_id: str | None) -> str | None:
    """
    Extract the interface name from a compound interface_id.

    Interface IDs in the model use the format "DEVICE:INTERFACE"
    (e.g., "core-rtr-01:Hu0/0/1/0"). This extracts the part
    after the colon.

    Args:
        interface_id: Compound interface ID or None.

    Returns:
        Interface name portion, or None if input is None/empty.
    """
    if not interface_id:
        return None

    # Split on first colon — device:interface
    parts = interface_id.split(":", 1)
    if len(parts) == 2:
        return parts[1]
    return interface_id


def _flatten_link_metadata(link: dict[str, Any]) -> dict[str, Any]:
    """
    Flatten nested L2 and L3 metadata dicts to prefixed properties.

    Neo4j relationships can't have nested objects, so we flatten
    bilaterally:
        l2.local.mode          → l2_local_mode
        l2.remote.mode         → l2_remote_mode
        l2.local.vlan.id       → l2_local_vlan_id
        l2.remote.vlan.id      → l2_remote_vlan_id
        l3.subnet              → l3_subnet
        l3.local.ip            → l3_local_ip
        l3.remote.ip           → l3_remote_ip
        l3.local.vrf           → l3_local_vrf
        l3.remote.vrf          → l3_remote_vrf

    Args:
        link: Link dict from network_model.json.

    Returns:
        Dict of flattened properties (only non-None values).
    """
    flat: dict[str, Any] = {}

    # -------------------------------------------------------------------------
    # L2 metadata — bilateral
    # -------------------------------------------------------------------------
    l2 = link.get("l2")
    if l2:
        for side, prefix in (("local", "l2_local"), ("remote", "l2_remote")):
            side_l2 = l2.get(side) or {}

            flat[f"{prefix}_mode"] = side_l2.get("mode")

            vlan = side_l2.get("vlan") or {}
            flat[f"{prefix}_vlan_id"] = vlan.get("id")
            flat[f"{prefix}_vlan_name"] = vlan.get("name") or None

            trunk = side_l2.get("trunk") or {}
            if trunk:
                flat[f"{prefix}_trunk_mode"] = trunk.get("mode")
                vlans = trunk.get("vlans_carried")
                if vlans:
                    flat[f"{prefix}_vlans_carried"] = vlans
                flat[f"{prefix}_native_vlan"] = trunk.get("native_vlan")

            flat[f"{prefix}_stp_state"] = side_l2.get("stp_state")

    # -------------------------------------------------------------------------
    # L3 metadata — bilateral
    # -------------------------------------------------------------------------
    l3 = link.get("l3")
    if l3:
        flat["l3_subnet"] = l3.get("subnet")

        local_l3 = l3.get("local") or {}
        remote_l3 = l3.get("remote") or {}

        flat["l3_local_ip"] = local_l3.get("ip")
        flat["l3_remote_ip"] = remote_l3.get("ip")
        flat["l3_local_vrf"] = local_l3.get("vrf")
        flat["l3_remote_vrf"] = remote_l3.get("vrf")
        flat["l3_local_prefix_length"] = local_l3.get("prefix_length")
        flat["l3_remote_prefix_length"] = remote_l3.get("prefix_length")

        # MTU — may be on local/remote or at top level
        flat["l3_local_mtu"] = local_l3.get("mtu")
        flat["l3_remote_mtu"] = remote_l3.get("mtu")

    # Remove None values
    return {k: v for k, v in flat.items() if v is not None}


def _extract_member_hostname(member) -> str | None:
    """
    Extract a hostname from a shared service member entry.

    Members can be either plain strings (VLANs, BGP ASNs) or dicts
    with a 'hostname' key (subnets). This function handles both formats.

    Args:
        member: Either a hostname string or a dict like
                {"hostname": "sw-01", "interface": "Vlan10", "ip": "192.0.2.1"}

    Returns:
        Hostname string, or None if not extractable.
    """
    if isinstance(member, str):
        return member
    if isinstance(member, dict):
        return member.get("hostname")
    return None



# =========================================================================
# F2-6-b — Route loading (all protocols + BGP full-table synthesis) +
# eBGP transit/peering classification + BGP decision-attribute enrichment.
# Reads facts_dirs (genie_routing/bgp, fortigate routing, running_config).
# =========================================================================

# Threshold: peers sending fewer routes than this are peering, not transit
_PEERING_PREFIX_THRESHOLD = 100
_PER_PEER_ROUTE_LIMIT = 1_000  # Skip per-peer files exceeding this (OOM guard)


def _classify_bgp_sessions(
    driver,
    run_id: str,
    site: str,
) -> None:
    """Classify eBGP ROUTING_ADJACENCY edges as transit or peering.

    Transit: peer sends a default route or contributes to a full BGP table
    (100K+ routes). Used for general internet access.

    Peering: peer sends only a few specific prefixes (< threshold).
    Direct interconnect with a CDN, content provider, or IX peer.
    Cannot route arbitrary internet traffic through it.

    Classification method:
    1. Count eBGP per-peer Route nodes in Neo4j by peer IP
    2. If no per-peer routes but device has a synthesized default route
       via this peer → transit
    3. Sets bgp_type property on ROUTING_ADJACENCY edge
    """
    # Find all eBGP adjacencies. Device matches carry `site` so the composite
    # (site, run_id, name) index is used — site is its leading column.
    with driver.session() as session:
        result = session.run(
            f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}})-[r:{ROUTING_ADJACENCY}]->"
            f"(p:{DEVICE} {{site: $site, run_id: $run_id}}) "
            "WHERE r.protocol = 'bgp' AND r.local_as <> r.remote_as "
            "RETURN d.name AS device, p.name AS peer, r.peer_address AS peer_addr",
            site=site, run_id=run_id,
        )
        ebgp_edges = [dict(r) for r in result]

    if not ebgp_edges:
        return

    # Build peer IP → prefix count from eBGP per-peer Route nodes in Neo4j
    # Only eBGP routes count — iBGP prefix counts must not influence
    # transit/peering classification (iBGP is internal redistribution).
    peer_prefix_counts: dict[str, int] = {}
    with driver.session() as session:
        result = session.run(
            f"MATCH (:{DEVICE} {{site: $site, run_id: $run_id}})-[:{HAS_ROUTE}]->"
            f"(r:{ROUTE} {{site: $site, run_id: $run_id, source: 'per-peer', ebgp: true}}) "
            "WHERE r.peer IS NOT NULL "
            "RETURN r.peer AS peer, count(r) AS cnt",
            site=site, run_id=run_id,
        )
        for rec in result:
            peer_prefix_counts[rec["peer"]] = rec["cnt"]

    # Build set of transit peer IPs from synthesized routes (next_hop → transit)
    transit_peers: set[str] = set()
    with driver.session() as session:
        result = session.run(
            f"MATCH (r:{ROUTE} {{site: $site, run_id: $run_id, source: 'synthesized'}}) "
            "RETURN r.next_hop AS nh",
            site=site, run_id=run_id,
        )
        for rec in result:
            if rec["nh"]:
                transit_peers.add(rec["nh"])

    # Classify each eBGP edge
    updates = []
    for edge in ebgp_edges:
        # The external peer is whichever side is NOT a managed device.
        # Edge direction: external_peer → managed_device (stored by loader).
        # So edge["device"] is the external peer IP, edge["peer"] is the managed device.
        external_ip = edge["device"]
        managed_device = edge["peer"]

        # Check per-peer prefix count using the external IP
        prefix_count = peer_prefix_counts.get(external_ip)

        if prefix_count is not None and prefix_count < _PEERING_PREFIX_THRESHOLD:
            bgp_type = "peering"
        elif external_ip in transit_peers:
            bgp_type = "transit"
        elif prefix_count is not None and prefix_count >= _PEERING_PREFIX_THRESHOLD:
            bgp_type = "transit"
        else:
            # No per-peer data and not a synthesized route peer
            # Default: if device has a full table, unknown peers are likely transit
            bgp_type = "transit"

        updates.append({
            "device": external_ip,
            "peer": managed_device,
            "bgp_type": bgp_type,
            "prefix_count": prefix_count or 0,
        })
        logger.debug(
            "%s → %s: bgp_type=%s (prefixes=%s)",
            external_ip, managed_device, bgp_type,
            prefix_count if prefix_count is not None else "unknown",
        )

    # Batch update edges by matching device→peer (both Device patterns scoped by site).
    if updates:
        with driver.session() as session:
            session.run(
                f"UNWIND $updates AS u "
                f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id, name: u.device}})"
                f"-[r:{ROUTING_ADJACENCY}]->"
                f"(p:{DEVICE} {{site: $site, run_id: $run_id, name: u.peer}}) "
                "WHERE r.protocol = 'bgp' "
                "SET r.bgp_type = u.bgp_type, r.prefix_count = u.prefix_count",
                updates=updates, site=site, run_id=run_id,
            )
        logger.info(
            "Neo4j: classified %d eBGP sessions (%d transit, %d peering)",
            len(updates),
            sum(1 for u in updates if u["bgp_type"] == "transit"),
            sum(1 for u in updates if u["bgp_type"] == "peering"),
        )


# -------------------------------------------------------------------------
# Private — Route loading (all protocols + BGP full-table synthesis)
# -------------------------------------------------------------------------

# A BGP table above this threshold is considered a full internet table.
_FULL_TABLE_THRESHOLD = 100_000


def _dedupe_cross_source_static_routes(
    route_params: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Drop config-sourced static-route copies already present as RIB-installed.

    A configured-and-installed static route appears twice in the build: once from
    the RIB file (``source="dynamic"`` — real AD, ``active`` state) and once from
    the static-config file (``source="static"`` — ad=0). Both materialise a
    ``:Route`` node, so the dashboard Routing tab shows the same static twice
    (R2-RT-1 Cisco, R2-RT-2 FortiGate).

    Keep the RIB-installed copy (authoritative) and drop the config copy when the
    full identity ``(device, prefix, vrf, protocol, next_hop, interface)`` matches.
    Config-only statics — configured but NOT installed (next-hop down, floating
    blackhole defaults) — have no RIB counterpart and are PRESERVED; the
    ``static_route_inactive`` rule reads the raw genie file independently, so its
    behaviour is unaffected. ``interface`` is part of the identity so genuinely
    distinct interface / SD-WAN routes that share a prefix are never merged.
    """
    def _identity(r: dict[str, Any]) -> tuple:
        return (r.get("device"), r.get("prefix"), r.get("vrf"),
                r.get("protocol"), r.get("next_hop"), r.get("interface"))

    rib_identities = {
        _identity(r) for r in route_params if r.get("source") == "dynamic"
    }
    deduped: list[dict[str, Any]] = []
    for r in route_params:
        if r.get("source") == "static" and _identity(r) in rib_identities:
            continue  # RIB-installed copy wins
        deduped.append(r)
    return deduped


def _build_route_params(
    run_dir: Path,
    site: str,
    run_id: str,
    interfaces: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build Route node param dicts from a run's facts — **pure, no Neo4j**.

    Extracted from ``_load_routes`` (R2 Phase 0) so the golden-master harness can
    snapshot the route layer without a database. Every source it calls
    (``_parse_routes_genie`` / ``_parse_routes_fortigate`` / ``_parse_per_peer_bgp``
    / ``_check_bgp_full_table`` / ``_synthesize_connected_routes_from_interfaces``)
    is already a pure function of the facts; this only relocates the build loop —
    no logic change. ``_load_routes`` keeps the (impure) Neo4j write.

    Returns:
        ``(route_params, bgp_full_table_devices)`` — uncleaned route dicts and the
        list of devices whose RIB was synthesized as a full-table default.
    """
    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return [], []

    route_params: list[dict[str, Any]] = []
    bgp_full_table_devices: list[dict[str, Any]] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name
        has_dynamic_rib = False  # True if genie_routing.json has actual route entries

        # ── Genie routing (dynamic + static) ────────────────────────
        for fname, source in [
            ("genie_routing.json", "dynamic"),
            ("genie_static_routing.json", "static"),
        ]:
            fpath = device_dir / fname
            if not fpath.exists():
                continue
            try:
                data = json.loads(fpath.read_text())
                parsed = _parse_routes_genie(data, device, source, site, run_id)
                if parsed:
                    route_params.extend(parsed)
                    if source == "dynamic":
                        has_dynamic_rib = True
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse %s for %s: %s", fname, device, exc)

        # ── FortiGate routing ───────────────────────────────────────
        fg_path = device_dir / "fortigate_routing.json"
        if fg_path.exists():
            try:
                data = json.loads(fg_path.read_text())
                parsed = _parse_routes_fortigate(data, device, site, run_id)
                if parsed:
                    route_params.extend(parsed)
                    has_dynamic_rib = True
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse fortigate_routing.json for %s: %s", device, exc)

        # ── FortiGate static routes ──────────────────────────
        fg_static_path = device_dir / "fortigate_static_route.json"
        if fg_static_path.exists():
            try:
                data = json.loads(fg_static_path.read_text())
                parsed = _parse_routes_fortigate_static(data, device, site, run_id)
                if parsed:
                    route_params.extend(parsed)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse fortigate_static_route.json for %s: %s", device, exc)

        # ── Per-peer BGP routes ─────────────────────────────────────
        per_peer = _parse_per_peer_bgp(device_dir, device, site, run_id)
        if per_peer:
            route_params.extend(per_peer)

        # ── BGP full-table synthesis ────────────────────────────────
        # Only synthesize when no dynamic RIB was collected (summary-only).
        # Static routes may exist alongside a full BGP table — that's fine.
        # Per-peer routes do NOT set has_dynamic_rib — both coexist.
        if not has_dynamic_rib:
            synth = _check_bgp_full_table(device_dir, device, site, run_id)
            if synth:
                route_params.append(synth)
                bgp_full_table_devices.append({
                    "device": device,
                    "count": synth["bgp_route_count"],
                })

    # ── Connected route synthesis from interface IPs ──
    # IOS-XR full-table devices ship genie_routing.json as summary-only
    # (`route_source` stats, no per-prefix entries), so _parse_routes_genie
    # returns [] above for them. Without this step, those devices have ZERO
    # connected Route nodes in Neo4j and the dashboard Routing tab's
    # "Connected" filter is empty.
    if interfaces:
        synthesized = _synthesize_connected_routes_from_interfaces(
            interfaces, route_params, site, run_id,
        )
        route_params.extend(synthesized)

    route_params = _dedupe_cross_source_static_routes(route_params)
    return route_params, bgp_full_table_devices


def _load_routes(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
    interfaces: list[dict[str, Any]] | None = None,
) -> int:
    """Load routing table entries as Route nodes in Neo4j.

    Builds the route params via the pure ``_build_route_params`` then writes them.
    For devices with BGP full tables (>100K routes, no collected RIB), a single
    0.0.0.0/0 is synthesized.

    Sources (see ``_build_route_params``):
      - genie_routing.json / genie_static_routing.json / fortigate_routing.json
      - genie_bgp_routes_*.json (per-peer BGP), BGP-summary full-table synthesis,
        interface-IP connected-route synthesis.

    Returns:
        Number of Route nodes created.
    """
    route_params, bgp_full_table_devices = _build_route_params(
        run_dir, site, run_id, interfaces,
    )

    if not route_params:
        return 0

    # Clean properties (remove None values)
    cleaned = [_clean_properties(r) for r in route_params]

    # Batch create Route nodes + HAS_ROUTE relationships
    with driver.session() as session:
        session.run(
            f"""
            UNWIND $routes AS r
            MATCH (d:{DEVICE} {{run_id: r.run_id, name: r.device}})
            CREATE (d)-[:{HAS_ROUTE}]->(route:{ROUTE})
            SET route = r
            """,
            routes=cleaned,
        )

    # Set bgp_full_table on devices with synthesized routes — one UNWIND batch
    # so all marks land in a single transaction (not an N+1 per-device loop).
    if bgp_full_table_devices:
        with driver.session() as session:
            session.run(
                f"UNWIND $devs AS dev "
                f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id, name: dev.name}}) "
                "SET d.bgp_full_table = true, d.bgp_route_count = dev.count",
                site=site,
                run_id=run_id,
                devs=[{"name": d["device"], "count": d["count"]} for d in bgp_full_table_devices],
            )

    per_peer_count = sum(1 for r in cleaned if r.get("source") == "per-peer")
    logger.info(
        "Neo4j: created %d Route nodes (%d synthesized, %d per-peer BGP)",
        len(cleaned), len(bgp_full_table_devices), per_peer_count,
    )
    return len(cleaned)


def _synthesize_connected_routes_from_interfaces(
    interfaces: list[dict[str, Any]],
    existing_routes: list[dict[str, Any]],
    site: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Derive `protocol="connected"` Route records from interface IPs.

    Every interface with an IPv4 address has an implicit connected route
    for its subnet. The genie parser (`_parse_routes_genie`) only emits
    them when the routing facts contain per-prefix detail; IOS-XR
    full-table devices ship summary-only data and yield zero connected
    routes — leaving the dashboard Routing tab's "Connected" filter empty.

    Filters:
      - `oper_status == "up"` only (a shut loopback has no live connected
        route on a real Cisco device).
      - Requires `ip` and `prefix_length`.
      - Per (device, prefix) dedup against any connected Route records
        already parsed from genie_routing.json (IOS-XE devices with full
        RIB). Order-stable: interfaces are sorted by name to keep
        synthesis output deterministic across runs.

    Args:
        interfaces: model interface list (same shape as `_load_interfaces`).
        existing_routes: route records already collected this run, used
            only for per-(device, prefix) dedup.
        site, run_id: pipeline context.

    Returns:
        List of Route property dicts ready for batch insert.
    """
    import ipaddress

    existing: set[tuple[str, str]] = {
        (r.get("device", ""), r.get("prefix", ""))
        for r in existing_routes
        if (r.get("protocol") or "").lower() == "connected"
    }

    synthesized: list[dict[str, Any]] = []
    for iface in sorted(interfaces, key=lambda i: (i.get("device_id") or "", i.get("name") or "")):
        if (iface.get("oper_status") or "").lower() != "up":
            continue
        ip = iface.get("ip_address")
        if not ip or (isinstance(ip, str) and ip.lower() == "unassigned"):
            continue
        pfx = iface.get("prefix_length")
        if pfx is None:
            continue
        try:
            subnet = ipaddress.ip_network(f"{ip}/{pfx}", strict=False).with_prefixlen
        except (ValueError, TypeError):
            continue
        device_id = iface.get("device_id") or ""
        key = (device_id, subnet)
        if key in existing:
            continue
        existing.add(key)  # in-pass dedup (interface listed twice → only one route)
        synthesized.append({
            "prefix": subnet,
            "vrf": iface.get("vrf") or "default",
            "protocol": "connected",
            "next_hop": "",
            "interface": iface.get("name"),
            "ad": 0,
            "metric": 0,
            "active": True,
            "source": "interface-derived",
            "device": device_id,
            "site": site,
            "run_id": run_id,
        })
    return synthesized


def _parse_routes_genie(
    data: dict,
    device: str,
    source: str,
    site: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Parse Genie routing JSON into Route node property dicts.

    Handles both genie_routing.json and genie_static_routing.json.
    Skips route-summary-only files (no vrf.*.routes entries).

    `genie_static_routing.json` does NOT include a `source_protocol` field on
    each entry — only the dynamic file does. Falling back to `"?"` when missing
    mislabels static routes; when the file is the static file
    (source == "static"), `"static"` is the correct fallback.
    """
    proto_fallback = "static" if source == "static" else "?"

    routes: list[dict[str, Any]] = []
    vrf_data = data.get("vrf", data)

    # Skip summary-only files (route_source stats, no actual routes)
    if "route_source" in data and "vrf" not in data:
        return routes

    for vrf_name, vrf_info in vrf_data.items():
        # Skip non-VRF keys like "route_source", "total_route_source"
        if not isinstance(vrf_info, dict) or "address_family" not in vrf_info:
            continue
        for af_name, af_info in vrf_info.get("address_family", {}).items():
            for prefix, route_info in af_info.get("routes", {}).items():
                next_hops = route_info.get("next_hop", {}).get("next_hop_list", {})
                if next_hops:
                    for _, nh_info in next_hops.items():
                        routes.append(_clean_properties({
                            "prefix": prefix,
                            "vrf": vrf_name,
                            "protocol": route_info.get("source_protocol") or proto_fallback,
                            "next_hop": nh_info.get("next_hop", ""),
                            "interface": nh_info.get("outgoing_interface", ""),
                            "ad": route_info.get("route_preference", 0),
                            "metric": route_info.get("metric", 0),
                            "active": nh_info.get("active", True),
                            "source": source,
                            "device": device,
                            "site": site,
                            "run_id": run_id,
                        }))
                else:
                    # Connected/local routes with only outgoing_interface
                    out_intf = route_info.get("next_hop", {}).get("outgoing_interface", {})
                    intf_name = ""
                    if out_intf:
                        intf_name = next(iter(out_intf.keys()), "")
                    routes.append(_clean_properties({
                        "prefix": prefix,
                        "vrf": vrf_name,
                        "protocol": route_info.get("source_protocol") or proto_fallback,
                        "next_hop": "",
                        "interface": intf_name,
                        "ad": route_info.get("route_preference", 0),
                        "metric": route_info.get("metric", 0),
                        "active": True,
                        "source": source,
                        "device": device,
                        "site": site,
                        "run_id": run_id,
                    }))
    return routes


def _parse_routes_fortigate(
    data: dict,
    device: str,
    site: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Parse FortiGate routing JSON into Route node property dicts.

    FortiGate's `fortigate_routing.json` emits entries with `type` values
    `"connect"`, `"static"`, `"bgp"`, etc. Connected entries have
    `gateway = "0.0.0.0"` (no next-hop — the destination is on a directly
    attached interface). connected entries must
    appear in the dashboard Routing tab; they are NOT skipped. The type
    literal is normalised: `"connect"` → `"connected"` so it matches the
    cross-vendor canonical name used by the frontend PROTO_MAP and by
    Cisco-side parsers.
    """
    # FortiGate `type` values that are not next-hop-bearing.
    _NO_GATEWAY_TYPES = {"connect", "connected"}

    routes: list[dict[str, Any]] = []

    if isinstance(data, dict):
        entries = data.get("results", [])
        vdom = data.get("vdom", "root")
    elif isinstance(data, list):
        entries = data
        vdom = "root"
    else:
        return routes

    for entry in entries:
        raw_type = (entry.get("type") or "").lower()
        # Normalise FortiGate's "connect" to canonical "connected".
        protocol = "connected" if raw_type == "connect" else raw_type or "unknown"

        gw = entry.get("gateway", "")
        # Connected routes legitimately have no next-hop (gateway = "0.0.0.0"
        # or empty); only skip routes whose gateway is missing AND aren't
        # one of the no-gateway types (this would be malformed data).
        if (not gw or gw == "0.0.0.0") and raw_type not in _NO_GATEWAY_TYPES:
            continue

        ip_mask = entry.get("ip_mask", "")
        if "/" in ip_mask:
            prefix = ip_mask
        else:
            pfx_len = entry.get("ip_mask_prefix", entry.get("mask", "0"))
            prefix = f"{ip_mask}/{pfx_len}"

        next_hop = "" if raw_type in _NO_GATEWAY_TYPES else gw

        routes.append(_clean_properties({
            "prefix": prefix,
            "vrf": vdom,
            "protocol": protocol,
            "next_hop": next_hop,
            "interface": entry.get("interface", ""),
            "ad": entry.get("distance", 0),
            "metric": entry.get("metric", 0),
            "active": True,
            "source": "dynamic",
            "device": device,
            "site": site,
            "run_id": run_id,
        }))
    return routes


def _parse_per_peer_bgp(
    device_dir: Path,
    device: str,
    site: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Parse per-peer BGP route files into Route node property dicts.

    Collected via 'show bgp neighbors <ip> routes' for peers with small
    prefix counts (summary-only devices). Determines iBGP vs eBGP from
    genie_bgp.json to set correct AD (20 eBGP, 200 iBGP) and ``ebgp``
    flag used by _classify_bgp_sessions for transit/peering classification.

    Guard: files exceeding _PER_PEER_ROUTE_LIMIT are skipped entirely.
    """
    bgp_route_files = sorted(device_dir.glob("genie_bgp_routes_*.json"))
    if not bgp_route_files:
        return []

    # Determine eBGP vs iBGP per peer from genie_bgp.json
    peer_is_ebgp: dict[str, bool] = {}
    bgp_path = device_dir / "genie_bgp.json"
    if bgp_path.exists():
        try:
            bgp_data = json.loads(bgp_path.read_text())
            for inst_block in bgp_data.get("instance", {}).values():
                # R1-BGP-1: local AS is the instance-level bgp_id. genie does NOT
                # put local_as in the AF block (af.get("local_as") was always None
                # on real data → every peer defaulted to eBGP / AD 20). Mirror
                # _check_bgp_full_table, which already reads bgp_id.
                local_as = inst_block.get("bgp_id")
                for vrf_block in inst_block.get("vrf", {}).values():
                    if local_as is None:
                        for af in vrf_block.get("address_family", {}).values():
                            local_as = af.get("local_as")
                            if local_as is not None:
                                break
                    for peer_ip, peer_block in vrf_block.get("neighbor", {}).items():
                        remote_as = peer_block.get("remote_as")
                        peer_local = (
                            local_as if local_as is not None
                            else peer_block.get("local_as_as_no")
                        )
                        if remote_as is not None and peer_local is not None:
                            peer_is_ebgp[peer_ip] = int(remote_as) != int(peer_local)
        except (json.JSONDecodeError, OSError):
            pass

    routes: list[dict[str, Any]] = []
    for bgp_route_file in bgp_route_files:
        try:
            peer_ip = bgp_route_file.stem.replace(
                "genie_bgp_routes_", ""
            ).replace("_", ".")
            data = json.loads(bgp_route_file.read_text())
            peer_routes = data.get("routes", [])

            # Guard: skip oversized files
            if len(peer_routes) > _PER_PEER_ROUTE_LIMIT:
                logger.warning(
                    "%s: skipping per-peer BGP file %s (%d routes > %d limit)",
                    device, bgp_route_file.name, len(peer_routes),
                    _PER_PEER_ROUTE_LIMIT,
                )
                continue

            is_ebgp = peer_is_ebgp.get(peer_ip, True)  # default eBGP
            ad = 20 if is_ebgp else 200

            for r in peer_routes:
                routes.append(_clean_properties({
                    "prefix": r.get("prefix", ""),
                    "vrf": "default",
                    "protocol": "bgp",
                    "next_hop": r.get("next_hop", peer_ip),
                    "interface": "",
                    "ad": ad,
                    "metric": 0,
                    "active": r.get("status", "").startswith("*>"),
                    "source": "per-peer",
                    "peer": peer_ip,
                    "ebgp": is_ebgp,
                    "as_path": r.get("path", ""),
                    "origin": r.get("origin", ""),
                    "device": device,
                    "site": site,
                    "run_id": run_id,
                }))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse %s: %s", bgp_route_file, exc)

    if routes:
        logger.debug(
            "%s: loaded %d per-peer BGP routes from %d peers",
            device, len(routes), len(bgp_route_files),
        )
    return routes


def _check_bgp_full_table(
    device_dir: Path,
    device: str,
    site: str,
    run_id: str,
) -> dict[str, Any] | None:
    """Check if device has a BGP full table and return a synthesized route.

    Returns a Route property dict for 0.0.0.0/0 if BGP route count
    exceeds threshold and no real RIB was collected.
    """
    routing_summary = device_dir / "genie_routing.json"
    if not routing_summary.exists():
        return None

    try:
        data = json.loads(routing_summary.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    bgp_info = data.get("route_source", {}).get("bgp", {})
    total_bgp = sum(info.get("routes", 0) for info in bgp_info.values())

    if total_bgp < _FULL_TABLE_THRESHOLD:
        return None

    # Find eBGP peer IP from genie_bgp.json
    peer_ip = ""
    bgp_path = device_dir / "genie_bgp.json"
    if bgp_path.exists():
        try:
            bgp_data = json.loads(bgp_path.read_text())
            for inst in bgp_data.get("instance", {}).values():
                local_as = inst.get("bgp_id", 0)
                for vrf_data in inst.get("vrf", {}).values():
                    for pip, pdata in vrf_data.get("neighbor", {}).items():
                        if pdata.get("remote_as", 0) != local_as and pdata.get("remote_as", 0):
                            peer_ip = pip
                            break
                    if peer_ip:
                        break
                if peer_ip:
                    break
        except (json.JSONDecodeError, OSError):
            pass

    logger.info(
        "%s: synthesized 0.0.0.0/0 from BGP full table (%d routes, peer %s)",
        device, total_bgp, peer_ip,
    )

    return _clean_properties({
        "prefix": "0.0.0.0/0",
        "vrf": "default",
        "protocol": "bgp (synthesized)",
        "next_hop": peer_ip,
        "interface": "",
        "ad": 20,
        "metric": 0,
        "active": True,
        "source": "synthesized",
        "bgp_route_count": total_bgp,
        "note": (
            f"Synthesized from BGP full table ({total_bgp:,} routes). "
            "Full RIB not collected to avoid OOM."
        ),
        "device": device,
        "site": site,
        "run_id": run_id,
    })


# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# Private — BGP decision attribute enrichment
# -------------------------------------------------------------------------

import re as _re

_LOCAL_PREF_RE = _re.compile(r"set\s+local.preference\s+(\d+)")
_ROUTE_POLICY_BLOCK_RE = _re.compile(
    r"^route-policy\s+(\S+)\s*$(.*?)^end-policy",
    _re.MULTILINE | _re.DOTALL,
)
# IOS XR: default-originate route-policy <name> under neighbor AF
_DEFAULT_ORIGINATE_RE = _re.compile(r"default-originate(?:\s+route-policy\s+(\S+))?")
# IOS XE: neighbor <ip> default-originate route-map <name>
_DEFAULT_ORIGINATE_XE_RE = _re.compile(r"neighbor\s+(\S+)\s+default-originate(?:\s+route-map\s+(\S+))?")


def _parse_local_pref_from_config(config_text: str) -> dict[str, int]:
    """Extract route-policy name → local-preference value from running config.

    Returns: {"LOCAL-PREF": 300, "PREF-HIGH": 500, ...}
    """
    policy_local_prefs: dict[str, int] = {}
    for match in _ROUTE_POLICY_BLOCK_RE.finditer(config_text):
        policy_name = match.group(1)
        body = match.group(2)
        lp_match = _LOCAL_PREF_RE.search(body)
        if lp_match:
            policy_local_prefs[policy_name] = int(lp_match.group(1))
    # Also handle IOS XE route-map: "route-map <name> permit 10 / set local-preference <N>"
    for line in config_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("set local-preference"):
            lp_match = _LOCAL_PREF_RE.search(stripped)
            if lp_match:
                # Find the route-map name — look backwards for "route-map <name>"
                pass  # IOS XE handled below via neighbor default-originate route-map
    return policy_local_prefs


def _parse_bgp_neighbor_policies(config_text: str, policy_prefs: dict[str, int]) -> dict[str, dict]:
    """Extract per-neighbor BGP policy config with local-preference.

    Detects two patterns:
    1. default-originate route-policy <NAME>
    2. route-policy <NAME> out (outbound policy with local-pref)

    Returns: {peer_ip: {"default_originate": bool, "local_pref": N, "policy": "..."}, ...}
    """
    result: dict[str, dict] = {}

    # IOS XR: parse neighbor blocks
    current_neighbor = None
    in_af = False
    for line in config_text.split("\n"):
        stripped = line.strip()
        # Detect neighbor block start (IOS XR — 1-space indent)
        if line.startswith(" neighbor ") and not line.startswith("  "):
            parts = stripped.split()
            if len(parts) >= 2:
                current_neighbor = parts[1]
        elif line.startswith("  address-family"):
            in_af = True
        elif stripped == "!" and in_af:
            in_af = False
            current_neighbor = None
        elif in_af and current_neighbor:
            # Check default-originate
            do_match = _DEFAULT_ORIGINATE_RE.search(stripped)
            if do_match:
                policy_name = do_match.group(1) or ""
                local_pref = policy_prefs.get(policy_name)
                if current_neighbor not in result:
                    result[current_neighbor] = {}
                result[current_neighbor]["default_originate"] = True
                if local_pref is not None:
                    result[current_neighbor]["local_pref"] = local_pref
                    result[current_neighbor]["policy"] = policy_name
            # Check outbound route-policy (may set local-pref on advertised routes)
            if "route-policy" in stripped and "out" in stripped:
                parts = stripped.split()
                for i, p in enumerate(parts):
                    if p == "route-policy" and i + 1 < len(parts):
                        out_policy = parts[i + 1]
                        lp = policy_prefs.get(out_policy)
                        if lp is not None and current_neighbor not in result:
                            result[current_neighbor] = {}
                        if lp is not None:
                            result[current_neighbor]["outbound_local_pref"] = lp
                            result[current_neighbor]["outbound_policy"] = out_policy

    # IOS XE: neighbor <IP> default-originate [route-map <NAME>]
    for match in _DEFAULT_ORIGINATE_XE_RE.finditer(config_text):
        peer_ip = match.group(1)
        route_map = match.group(2) or ""
        local_pref = policy_prefs.get(route_map)
        if peer_ip not in result:
            result[peer_ip] = {}
        result[peer_ip]["default_originate"] = True
        if local_pref is not None:
            result[peer_ip]["local_pref"] = local_pref
            result[peer_ip]["policy"] = route_map

    return result


def _enrich_bgp_decision_attributes(driver, run_dir: Path, run_id: str, site: str) -> None:
    """Enrich BGP ROUTING_ADJACENCY edges with local-preference from running configs.

    For each device with a running_config.txt:
    1. Parse route-policy/route-map blocks for set local-preference
    2. Find neighbors with default-originate referencing those policies
    3. Set default_originate_local_pref on the ROUTING_ADJACENCY edge

    This enables trace_path to explain why one path wins on local-preference
    (e.g. "the peer advertising local-pref 200 wins over the 100 path").
    """
    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return

    updates = []
    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name
        rc_path = device_dir / "running_config.txt"
        if not rc_path.exists():
            continue

        try:
            config = rc_path.read_text()
        except OSError:
            continue

        # Parse local-preference values from route policies
        policy_prefs = _parse_local_pref_from_config(config)
        if not policy_prefs:
            continue

        # Find which neighbors get default-originate or outbound local-pref
        nbr_policies = _parse_bgp_neighbor_policies(config, policy_prefs)
        if not nbr_policies:
            continue

        for peer_ip, info in nbr_policies.items():
            lp = info.get("local_pref") or info.get("outbound_local_pref")
            policy = info.get("policy") or info.get("outbound_policy", "")
            if lp is not None:
                updates.append({
                    "device": device,
                    "peer_ip": peer_ip,
                    "default_originate": info.get("default_originate", False),
                    "default_originate_local_pref": lp,
                    "default_originate_policy": policy,
                })

    if not updates:
        return

    # Resolve peer IPs to device names via Interface nodes (Device scoped by site).
    ip_to_device: dict[str, str] = {}
    with driver.session() as session:
        result = session.run(
            f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}})-[:{HAS_INTERFACE}]->(i:{INTERFACE}) "
            "WHERE i.ip IS NOT NULL "
            "RETURN d.name AS name, i.ip AS ip",
            site=site, run_id=run_id,
        )
        for rec in result:
            raw_ip = rec["ip"].split("/")[0] if "/" in rec["ip"] else rec["ip"]
            ip_to_device[raw_ip] = rec["name"]

    # One UNWIND batch (not an N+1 per-update loop): pre-resolve peer names in
    # Python, then batch-update all edges in one round-trip / transaction.
    batch = [
        {
            "device": u["device"],
            "peer_name": ip_to_device.get(u["peer_ip"], u["peer_ip"]),
            "do": u["default_originate"],
            "lp": u["default_originate_local_pref"],
            "policy": u["default_originate_policy"],
        }
        for u in updates
    ]
    with driver.session() as session:
        session.run(
            f"UNWIND $batch AS u "
            f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id, name: u.device}})"
            f"-[r:{ROUTING_ADJACENCY}]-"
            f"(p:{DEVICE} {{site: $site, run_id: $run_id, name: u.peer_name}}) "
            "WHERE r.protocol = 'bgp' "
            "SET r.default_originate = u.do, "
            "r.default_originate_local_pref = u.lp, "
            "r.default_originate_policy = u.policy",
            site=site,
            run_id=run_id,
            batch=batch,
        )

    logger.info(
        "Neo4j: enriched %d BGP edges with default-originate local-preference",
        len(updates),
    )




def _netmask_to_cidr(dst: str) -> str | None:
    """Convert FortiGate 'dst' format ('192.0.2.0 255.255.255.0') to CIDR ('192.0.2.0/24')."""
    parts = dst.strip().split()
    if len(parts) != 2:
        return None
    ip_addr, netmask = parts
    try:
        # Count bits in netmask
        octets = netmask.split(".")
        if len(octets) != 4:
            return None
        bits = sum(bin(int(o)).count("1") for o in octets)
        return f"{ip_addr}/{bits}"
    except (ValueError, TypeError):
        return None


def _parse_routes_fortigate_static(
    data: dict,
    device: str,
    site: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Parse FortiGate static route JSON into Route node property dicts."""
    routes: list[dict[str, Any]] = []

    if isinstance(data, dict):
        entries = data.get("results", [])
        vdom = data.get("vdom", "root")
    elif isinstance(data, list):
        entries = data
        vdom = "root"
    else:
        return routes

    for entry in entries:
        if entry.get("status") != "enable":
            continue

        dst = entry.get("dst", "")
        prefix = _netmask_to_cidr(dst)
        if not prefix:
            continue

        gw = entry.get("gateway", "0.0.0.0")
        comment = entry.get("comment", "")

        routes.append(_clean_properties({
            "prefix": prefix,
            "vrf": vdom,
            "protocol": "static",
            "next_hop": gw if gw != "0.0.0.0" else None,
            "interface": entry.get("device", ""),
            "ad": entry.get("distance", 10),
            "metric": entry.get("priority", 0),
            "active": True,
            "source": "static",
            "description": comment or None,
            "device": device,
            "site": site,
            "run_id": run_id,
        }))

    return routes



# =========================================================================
# F2-6-c — ARP entries (Cisco/FortiGate) + firewall policies (FortiGate
# policy resolution + Cisco ACLs). Read facts_dirs (fortigate_*/genie_*).
# =========================================================================

def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to lowercase colon-separated format.

    Handles: aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, AA-BB-CC-DD-EE-FF
    """
    raw = mac.lower().replace(":", "").replace(".", "").replace("-", "")
    if len(raw) == 12:
        return ":".join(raw[i:i+2] for i in range(0, 12, 2))
    return mac.lower()


def _load_arp_entries(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
) -> int:
    """Load ARP table entries as ArpEntry nodes in Neo4j.

    Parses both FortiGate (flat array) and Cisco Genie (nested) ARP formats.

    Returns:
        Number of ArpEntry nodes created.
    """
    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return 0

    arp_params: list[dict[str, Any]] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        # ── FortiGate ARP ──────────────────────────────────────────
        fg_arp = device_dir / "fortigate_arp.json"
        if fg_arp.exists():
            try:
                data = json.loads(fg_arp.read_text())
                for entry in data.get("results", []):
                    ip = entry.get("ip", "")
                    mac = entry.get("mac", "")
                    if ip and mac:
                        arp_params.append({
                            "ip": ip,
                            "mac": _normalize_mac(mac),
                            "interface": entry.get("interface", ""),
                            "origin": "dynamic",
                            "device": device,
                            "site": site,
                            "run_id": run_id,
                        })
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse FortiGate ARP for %s: %s", device, exc)

        # ── Cisco Genie ARP ────────────────────────────────────────
        genie_arp = device_dir / "genie_arp.json"
        if genie_arp.exists():
            try:
                data = json.loads(genie_arp.read_text())
                for intf_name, intf_data in data.get("interfaces", {}).items():
                    for ip, neighbor in intf_data.get("ipv4", {}).get("neighbors", {}).items():
                        mac = neighbor.get("link_layer_address", "")
                        if ip and mac:
                            arp_params.append({
                                "ip": ip,
                                "mac": _normalize_mac(mac),
                                "interface": intf_name,
                                "origin": neighbor.get("origin", "dynamic"),
                                "device": device,
                                "site": site,
                                "run_id": run_id,
                            })
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse Genie ARP for %s: %s", device, exc)

    if not arp_params:
        return 0

    # Batch create ArpEntry nodes + HAS_ARP relationships
    with driver.session() as session:
        session.run(
            f"""
            UNWIND $entries AS e
            MATCH (d:{DEVICE} {{run_id: e.run_id, name: e.device}})
            CREATE (d)-[:{HAS_ARP}]->(a:{ARP_ENTRY})
            SET a = e
            """,
            entries=arp_params,
        )

    logger.info("Neo4j: created %d ArpEntry nodes", len(arp_params))
    return len(arp_params)



def _load_firewall_policies(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
) -> int:
    """Load firewall policies as FirewallPolicy nodes in Neo4j.

    Reads FortiGate policy files (with address/service/zone resolution)
    and Cisco ACL files for every device in the run.

    Sources:
      - fortigate_firewall_policy.json + address/service/zone files (FortiGate)
      - genie_acl.json (Cisco IOS-XE/XR ACLs)

    Returns:
        Number of FirewallPolicy nodes created.
    """
    from netcopilot.parse.policy_resolver import (
        build_zone_map, build_address_resolver,
        build_service_resolver, parse_genie_acl,
    )

    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return 0

    policy_params: list[dict[str, Any]] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        # ── FortiGate policies ─────────────────────────────────────
        fg_policy_path = device_dir / "fortigate_firewall_policy.json"
        if fg_policy_path.exists():
            try:
                zone_map = build_zone_map(device_dir)
                addr_resolver = build_address_resolver(device_dir)
                svc_resolver = build_service_resolver(device_dir)

                data = json.loads(fg_policy_path.read_text())
                for idx, policy in enumerate(data.get("results", []), 1):
                    # Resolve source/dest interfaces with zones
                    srcintf = [
                        {"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""), "")}
                        for i in policy.get("srcintf", [])
                    ]
                    dstintf = [
                        {"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""), "")}
                        for i in policy.get("dstintf", [])
                    ]
                    # Resolve addresses
                    srcaddr = ", ".join(
                        addr_resolver.get(a.get("name", ""), a.get("name", ""))
                        for a in policy.get("srcaddr", [])
                    )
                    dstaddr = ", ".join(
                        addr_resolver.get(a.get("name", ""), a.get("name", ""))
                        for a in policy.get("dstaddr", [])
                    )
                    # Resolve services
                    services = []
                    for s in policy.get("service", []):
                        sname = s.get("name", "")
                        resolved = svc_resolver.get(sname, sname)
                        services.append(str(resolved) if resolved else sname)
                    service_str = ", ".join(services)

                    # Extract zone names for easy Cypher filtering
                    src_zones = [i["zone"] for i in srcintf if i["zone"]]
                    dst_zones = [i["zone"] for i in dstintf if i["zone"]]

                    policy_params.append(_clean_properties({
                        "policyid": policy.get("policyid", 0),
                        "seq": idx,
                        "name": policy.get("name", ""),
                        "status": policy.get("status", ""),
                        "action": policy.get("action", ""),
                        "srcintf": json.dumps(srcintf),
                        "dstintf": json.dumps(dstintf),
                        "src_zones": src_zones,
                        "dst_zones": dst_zones,
                        "srcaddr": srcaddr,
                        "dstaddr": dstaddr,
                        "service": service_str,
                        # SF-NEGATE-1: an enabled *-negate inverts the policy
                        # (match everything EXCEPT the listed addr/service).
                        # Captured so it can't silently invert meaning downstream.
                        "src_negate": policy.get("srcaddr-negate", "") == "enable",
                        "dst_negate": policy.get("dstaddr-negate", "") == "enable",
                        "service_negate": policy.get("service-negate", "") == "enable",
                        "nat": policy.get("nat", ""),
                        "schedule": policy.get("schedule", ""),
                        "logtraffic": policy.get("logtraffic", ""),
                        "comments": policy.get("comments", ""),
                        "policy_type": "fortigate",
                        "device": device,
                        "site": site,
                        "run_id": run_id,
                    }))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse FortiGate policies for %s: %s", device, exc)

        # ── Cisco ACLs ─────────────────────────────────────────────
        acl_path = device_dir / "genie_acl.json"
        if acl_path.exists():
            # Compute interface bindings once per device and persist applied_to,
            # so query tools can't infer "not applied" from an empty/absent field.
            from netcopilot.parse.policy_resolver import parse_acl_interface_bindings
            acl_bindings = parse_acl_interface_bindings(device_dir)
            try:
                data = json.loads(acl_path.read_text())
                acls = parse_genie_acl(data)
                for acl in acls:
                    applied_to = [
                        f"{b.get('interface','?')} {b.get('direction','?')}"
                        + (f" (vrf {b['vrf']})" if b.get("vrf") else "")
                        for b in acl_bindings.get(acl["name"], [])
                    ]
                    for ace in acl.get("aces", []):
                        policy_params.append(_clean_properties({
                            "policyid": ace.get("seq", 0),
                            # seq = ACE evaluation order; mirrors the FortiGate
                            # block's seq so get_firewall_policies' ORDER BY
                            # p.device, p.seq is deterministic for ACL nodes too
                            # (without it ACL nodes have seq=NULL → scan order).
                            "seq": ace.get("seq", 0),
                            "name": acl["name"],
                            "status": "enable",
                            "action": ace.get("action", ""),
                            "srcaddr": ace.get("source", "any"),
                            "dstaddr": ace.get("destination", "any"),
                            "service": f"{ace.get('protocol', '')} {ace.get('l4_ports', '')}".strip() or "any",
                            "policy_type": "acl",
                            "acl_type": acl.get("type", ""),
                            "applied_to": applied_to,
                            "device": device,
                            "site": site,
                            "run_id": run_id,
                        }))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse Cisco ACLs for %s: %s", device, exc)

    if not policy_params:
        return 0

    # Batch create FirewallPolicy nodes + HAS_POLICY relationships
    with driver.session() as session:
        session.run(
            f"""
            UNWIND $policies AS p
            MATCH (d:{DEVICE} {{run_id: p.run_id, name: p.device}})
            CREATE (d)-[:{HAS_POLICY}]->(pol:{FIREWALL_POLICY})
            SET pol = p
            """,
            policies=policy_params,
        )

    logger.info(
        "Neo4j: created %d FirewallPolicy nodes", len(policy_params),
    )
    return len(policy_params)




# =========================================================================
# F2-6-d — Route-policies + prefix-sets (Cisco route-maps/route-policies),
# security configs (Cisco/FortiGate), and VRFs (as SharedService nodes).
# Read facts_dirs (parsed_route_policy/prefix_list, security_config, genie_vrf).
# =========================================================================

def _load_route_policies_and_prefix_sets(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
) -> tuple[int, int]:
    """Load Cisco route-policies and prefix-sets/prefix-lists into Neo4j.

    Reuses `policy_resolver.parse_xr_route_policies` for IOS XR (regex parse of
    running_config.txt) and reads `parsed_route_policy.json` +
    `parsed_prefix_list.json` for IOS XE (one parser shared with the query layer).

    Schema:
      :RoutePolicy {name, device, run_id, site, body: list[str]}
        via [:HAS_ROUTE_POLICY] from Device
      :PrefixSetEntry {name, seq, action, prefix, device, run_id, site}
        via [:HAS_PREFIX_ENTRY] from Device — one node per entry
        (mirrors :FirewallPolicy ACE granularity)

    Returns: (route_policy_node_count, prefix_set_entry_node_count).
    """
    from netcopilot.parse.policy_resolver import (
        parse_bgp_neighbor_context,
        parse_route_policy_bindings,
        parse_xr_route_policies,
    )

    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return 0, 0

    rp_params: list[dict[str, Any]] = []
    pse_params: list[dict[str, Any]] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        # Compute bindings once per device for use across route-policies +
        # prefix-sets (parser is fast, cost negligible).
        bgp_bindings = parse_bgp_neighbor_context(device_dir)
        _, pl_refs = parse_route_policy_bindings(device_dir)

        def _fmt_bgp_binding(b: dict) -> str:
            ctx = b.get("context", "?")
            direction = b.get("direction", "?")
            vrf = b.get("vrf")
            tail = f" {direction}"
            if vrf and vrf != "default":
                tail += f" (vrf {vrf})"
            return f"{ctx}{tail}"

        # IOS XE route-maps from parsed JSON
        rm_path = device_dir / "parsed_route_policy.json"
        used_iosxe = False
        if rm_path.exists():
            try:
                data = json.loads(rm_path.read_text())
                for rm_name, rm_data in sorted(data.items()):
                    if not isinstance(rm_data, dict):
                        continue
                    body_lines: list[str] = []
                    for seq in rm_data.get("sequences", []):
                        s = seq.get("seq", "?")
                        action = seq.get("action", "?")
                        match = seq.get("match", {}) or {}
                        set_clause = seq.get("set", {}) or {}
                        body_lines.append(
                            f"seq {s} {action} match={match} set={set_clause}"
                        )
                    rp_params.append({
                        "name": rm_name,
                        "device": device,
                        "site": site,
                        "run_id": run_id,
                        "body": body_lines,
                        "applied_to": [_fmt_bgp_binding(b) for b in bgp_bindings.get(rm_name, [])],
                    })
                    used_iosxe = True
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse %s: %s", rm_path, exc)

        # IOS XR route-policies + prefix-sets (running-config regex) —
        # used as fallback when no IOS XE parsed JSON was found.
        if not used_iosxe:
            xr_policies, xr_prefix_sets = parse_xr_route_policies(device_dir)
            # Build XR prefix-set → route-policy reference map from body text
            # (parse_route_policy_bindings handles IOS XE prefix-list refs;
            # for IOS XR we have to grep the bodies because IOS XR uses
            # "if destination in PS-NAME" syntax inside route-policy blocks).
            xr_ps_refs: dict[str, list[str]] = {}
            for rp in xr_policies:
                for line in rp.get("body", []):
                    for ps in xr_prefix_sets:
                        if ps["name"] in line:
                            xr_ps_refs.setdefault(ps["name"], [])
                            if rp["name"] not in xr_ps_refs[ps["name"]]:
                                xr_ps_refs[ps["name"]].append(rp["name"])
            for rp in xr_policies:
                rp_params.append({
                    "name": rp["name"],
                    "device": device,
                    "site": site,
                    "run_id": run_id,
                    "body": rp.get("body", []),
                    "applied_to": [_fmt_bgp_binding(b) for b in bgp_bindings.get(rp["name"], [])],
                })
            for ps in xr_prefix_sets:
                refs = xr_ps_refs.get(ps["name"], []) or pl_refs.get(ps["name"], [])
                for entry in ps.get("entries", []):
                    pse_params.append({
                        "name": ps["name"],
                        "device": device,
                        "site": site,
                        "run_id": run_id,
                        "seq": entry.get("seq", 0),
                        "action": entry.get("action", "permit"),
                        "prefix": entry.get("prefix", ""),
                        "referenced_by": refs,
                    })

        # IOS XE prefix-lists from parsed JSON (parallel to route-maps above)
        pl_path = device_dir / "parsed_prefix_list.json"
        if pl_path.exists():
            try:
                data = json.loads(pl_path.read_text())
                for pl_name, pl_data in sorted(data.items()):
                    if not isinstance(pl_data, dict):
                        continue
                    refs = pl_refs.get(pl_name, [])
                    for entry in pl_data.get("entries", []):
                        pse_params.append({
                            "name": pl_name,
                            "device": device,
                            "site": site,
                            "run_id": run_id,
                            "seq": entry.get("seq", 0),
                            "action": entry.get("action", "permit"),
                            "prefix": entry.get("prefix", ""),
                            "referenced_by": refs,
                        })
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse %s: %s", pl_path, exc)

    if not rp_params and not pse_params:
        return 0, 0

    rp_count = 0
    pse_count = 0
    with driver.session() as session:
        if rp_params:
            session.run(
                f"""
                UNWIND $rps AS r
                MATCH (d:{DEVICE} {{run_id: r.run_id, name: r.device}})
                CREATE (d)-[:{HAS_ROUTE_POLICY}]->(rp:{ROUTE_POLICY})
                SET rp = r
                """,
                rps=rp_params,
            )
            rp_count = len(rp_params)
        if pse_params:
            session.run(
                f"""
                UNWIND $ents AS e
                MATCH (d:{DEVICE} {{run_id: e.run_id, name: e.device}})
                CREATE (d)-[:{HAS_PREFIX_ENTRY}]->(ent:{PREFIX_SET_ENTRY})
                SET ent = e
                """,
                ents=pse_params,
            )
            pse_count = len(pse_params)

    logger.info(
        "Neo4j: created %d RoutePolicy nodes + %d PrefixSetEntry nodes",
        rp_count, pse_count,
    )
    return rp_count, pse_count


def _flatten_security_section(section_name: str, data: dict | None) -> dict[str, Any]:
    """Flatten a security_config section to prefixed properties."""
    if not data:
        return {}
    flat: dict[str, Any] = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue  # Skip internal fields like _parser_coverage
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            flat[f"{section_name}_{k}"] = v
        elif isinstance(v, list):
            flat[f"{section_name}_{k}"] = json.dumps(v)
        # Skip nested dicts (too deep for Neo4j)
    return flat


def _load_security_configs(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
) -> int:
    """Load security_config.json into Neo4j as SecurityConfig nodes."""
    facts_dir = run_dir / "facts"
    if not facts_dir.is_dir():
        return 0

    config_params: list[dict[str, Any]] = []

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        props: dict[str, Any] = {
            "device": device,
            "site": site,
            "run_id": run_id,
        }

        # Cisco security_config.json
        sec_path = device_dir / "security_config.json"
        if sec_path.exists():
            try:
                sec = json.loads(sec_path.read_text(encoding="utf-8"))
                for section_name in (
                    "aaa", "ssh", "ntp", "logging", "services",
                    "vty_lines", "console", "snmp", "banner",
                    "http_server", "cdp_lldp", "domain_lookup",
                    "password_policy", "tacacs_radius", "ip_source_routing",
                ):
                    props.update(_flatten_security_section(section_name, sec.get(section_name)))
                props["config_source"] = "cisco"
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read security_config.json for %s: %s", device, exc)
                continue

        # FortiGate security files
        elif (device_dir / "fortigate_system_admin.json").exists():
            props["config_source"] = "fortigate"
            for fname, section in [
                ("fortigate_system_admin.json", "admin"),
                ("fortigate_password_policy.json", "password_policy"),
                ("fortigate_system_ntp.json", "ntp"),
                ("fortigate_snmp_community.json", "snmp"),
                ("fortigate_system_ha.json", "ha"),
            ]:
                fpath = device_dir / fname
                if fpath.exists():
                    try:
                        data = json.loads(fpath.read_text(encoding="utf-8"))
                        results = data.get("results", data)
                        if isinstance(results, list):
                            props[f"fg_{section}"] = json.dumps(results)
                        elif isinstance(results, dict):
                            props.update(_flatten_security_section(f"fg_{section}", results))
                    except (json.JSONDecodeError, OSError):
                        pass
        else:
            continue  # No security data for this device

        config_params.append(_clean_properties(props))

    if not config_params:
        return 0

    with driver.session() as session:
        session.run(
            f"""
            UNWIND $configs AS c
            MATCH (d:{DEVICE} {{run_id: c.run_id, name: c.device}})
            CREATE (d)-[:{HAS_SECURITY_CONFIG}]->(sc:{SECURITY_CONFIG})
            SET sc = c
            """,
            configs=config_params,
        )

    logger.info("SecurityConfig: loaded %d for run %s", len(config_params), run_id)
    return len(config_params)


def _build_vrf_members(
    run_dir: Path,
    interfaces: list[dict[str, Any]] | None = None,
) -> dict[str, set[str]]:
    """VRF membership (``vrf_name -> set of device names``) — pure, no Neo4j.

    Unions two sources so the VRF SharedService graph stops contradicting
    ``interface.vrf`` (R2-VRF-1):

      * ``genie_vrf.json`` per device — VRFs declared in config (incl. any with
        no interface yet assigned). Skips Catalyst SVL internal ``__`` VRFs.
      * ``interface.vrf`` from the model interfaces — the running-config-parsed,
        **authoritative** per-interface VRF. ``genie_vrf.json`` returns *empty*
        for IOS-XR, so without this source XR VRFs (e.g. an OOB mgmt VRF) are
        dropped from the graph while ``interface.vrf`` carries them — the
        double-source drift. The interface field is the right one to trust.
      * ``default`` VRF — every device with a collected RIB (``genie_routing.json``).

    Extracted from ``_load_vrfs`` (R2-COV-1) so the golden master can snapshot the
    VRF membership Neo4j-free; ``_load_vrfs`` keeps the (impure) write.
    """
    facts_dir = run_dir / "facts"
    vrf_members: dict[str, set[str]] = {}
    if not facts_dir.is_dir():
        return vrf_members

    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        device = device_dir.name

        vrf_path = device_dir / "genie_vrf.json"
        if vrf_path.exists():
            try:
                data = json.loads(vrf_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read genie_vrf.json for %s: %s", device, exc)
                data = {}
            for vrf_name in data.get("vrfs", {}):
                # Skip internal platform VRFs (Catalyst 9500 SVL control plane)
                if vrf_name.startswith("__"):
                    continue
                vrf_members.setdefault(vrf_name, set()).add(device)

        # 'default' VRF — the implicit global table (not declared in genie_vrf).
        # Cisco devices have genie_routing.json, FortiGate does not.
        if (device_dir / "genie_routing.json").exists():
            vrf_members.setdefault("default", set()).add(device)

    # Authoritative per-interface VRF (running-config) — captures the IOS-XR VRFs
    # that genie_vrf.json silently drops.
    for intf in interfaces or []:
        vrf_name = intf.get("vrf")
        device = intf.get("device_id")
        if not vrf_name or not device or vrf_name.startswith("__") or vrf_name == "default":
            continue
        vrf_members.setdefault(vrf_name, set()).add(device)

    return vrf_members


def _load_vrfs(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
    interfaces: list[dict[str, Any]] | None = None,
) -> int:
    """Load VRFs as SharedService nodes from the unioned VRF membership.

    Same pattern as VLANs and OSPF areas: one SharedService node per unique VRF
    name (service_type="vrf"), with MEMBER_OF relationships from each participating
    Device. Membership comes from ``_build_vrf_members`` (genie_vrf.json ∪
    interface.vrf ∪ default), so IOS-XR VRFs are no longer dropped. Queryable via
    get_shared_services with no tool changes.
    """
    vrf_members = _build_vrf_members(run_dir, interfaces)

    if not vrf_members:
        return 0

    # Create SharedService nodes + MEMBER_OF relationships
    svc_params = []
    member_params = []

    for vrf_name, devices in vrf_members.items():
        svc_params.append(_clean_properties({
            "service_type": "vrf",
            "identifier": vrf_name,
            "name": vrf_name,
            "site": site,
            "run_id": run_id,
        }))
        for dev in devices:
            member_params.append({
                "device_name": dev,
                "service_type": "vrf",
                "identifier": vrf_name,
                "site": site,
                "run_id": run_id,
            })

    with driver.session() as session:
        session.run(
            f"""
            UNWIND $services AS s
            CREATE (svc:{SHARED_SERVICE})
            SET svc = s
            """,
            services=svc_params,
        )
        if member_params:
            session.run(
                f"""
                UNWIND $members AS m
                MATCH (d:{DEVICE} {{name: m.device_name, site: m.site, run_id: m.run_id}})
                MATCH (s:{SHARED_SERVICE} {{
                    service_type: m.service_type,
                    identifier: m.identifier,
                    site: m.site,
                    run_id: m.run_id
                }})
                CREATE (d)-[:{MEMBER_OF} {{site: m.site, run_id: m.run_id}}]->(s)
                """,
                members=member_params,
            )

    logger.info("VRFs: loaded %d as SharedService nodes for run %s", len(vrf_members), run_id)
    return len(vrf_members)



# =========================================================================
# F3h — Findings loader: findings/findings.json (rules layer) → Finding
# nodes via HAS_FINDING. Closes the F2-6 deferral.
# =========================================================================

# Category mapping: rule_id prefix → category (same as findings.py)
_CATEGORY_PREFIXES = {
    "bgp": ["BGP_"],
    "ospf": ["OSPF_"],
    "security": ["CIS_", "WEAK_", "NETCONF_", "SNMP_", "AUTH_"],
    "interface": ["INTF_"],
    "topology": ["TOPO_", "LINK_"],
    "routing": ["ROUTE_", "VRF_", "STATIC_"],
    "cluster": ["CLUSTER_", "HA_", "STACK_"],
    "qos": ["QOS_"],
}

# Legacy severity normalization
_SEVERITY_MAP = {"medium": "low"}


def _derive_category(rule_id: str) -> str:
    """Derive finding category from rule_id prefix."""
    for category, prefixes in _CATEGORY_PREFIXES.items():
        for pfx in prefixes:
            if rule_id.startswith(pfx):
                return category
    return "other"


def _devices_from_element_id(element_id: str) -> list[str]:
    """Extract ALL device names from evidence.element_id.

    Returns a list of device names involved in the finding.
    First device is the "primary" (stored as f.device property).

    Handles multiple formats:
      - "DEVICE/bgp/vrf/peer/aspect" → ["DEVICE"]
      - "DEVICE:Interface" → ["DEVICE"]
      - "DEVICE:Intf/path" → ["DEVICE"]
      - "DEVICE:Intf--DEVICE2:Intf" → ["DEVICE", "DEVICE2"] (link findings)
      - "ntp::source_inconsistent::DEV1,DEV2,DEV3" → ["DEV1", "DEV2", "DEV3"]
      - "stp_vlan_1::root_conflict" → [] (global, no single device)
      - "fdb_mgmt_DEVICE_m2" → ["DEVICE"] (extract from pattern)
    """
    if not element_id:
        return []

    # STP global findings — extract devices from key_facts if available
    if element_id.startswith("stp_"):
        return []  # Handled separately in _load_findings via key_facts

    # VLAN-fragmented global findings — "vlan_fragmented::<vlan_id>".
    # Multi-island, no single device; attach via key_facts.devices.
    if element_id.startswith("vlan_fragmented::"):
        return []

    # Duplicate-IP global findings — "duplicate_ip::<ip>". The IP spans several
    # devices; attach to all of them via key_facts.devices.
    if element_id.startswith("duplicate_ip::"):
        return []

    # NTP cross-device — "ntp::source_inconsistent::DEV1,DEV2,DEV3"
    if element_id.startswith("ntp::"):
        parts = element_id.split("::")
        if len(parts) >= 3:
            return [d.strip() for d in parts[2].split(",") if d.strip()]
        return []

    # FDB management link — "fdb_mgmt_DEVICE_m2"
    if element_id.startswith("fdb_mgmt_"):
        # Extract device name: fdb_mgmt_dist-sw-01_m2 → dist-sw-01
        core = element_id[len("fdb_mgmt_"):]
        # Remove trailing _m1 or _m2
        if core.endswith(("_m1", "_m2")):
            core = core[:-3]
        return [core] if core else []

    # Link findings — "DEVICE:Intf--DEVICE2:Intf"
    if "--" in element_id:
        devices = []
        for part in element_id.split("--"):
            if ":" in part:
                dev = part.split(":")[0]
                if dev and dev not in devices:
                    devices.append(dev)
        return devices

    # Two formats with both ":" and "/":
    #   "DEVICE:Interface/path"     → "DEVICE" (: separates device from interface)
    #   "DEVICE/vrf/VRF:NAME/path"  → "DEVICE" (: is part of VRF name)
    # Heuristic: if part before first ":" contains no "/", it's a device name.
    if ":" in element_id and "/" in element_id:
        before_colon = element_id.split(":")[0]
        if "/" not in before_colon:
            # "DEVICE:Interface/path" — device is before ":"
            return [before_colon]
        else:
            # "DEVICE/vrf/VRF:NAME/..." — device is before first "/"
            return [element_id.split("/")[0]]

    # "DEVICE/path" format (no colon)
    if "/" in element_id:
        return [element_id.split("/")[0]]

    # "DEVICE:Interface" format (no slash)
    if ":" in element_id:
        device_part = element_id.split(":")[0]
        if device_part:
            return [device_part]

    return [element_id] if element_id else []


def _flatten_key_facts(key_facts: dict | None) -> dict[str, Any]:
    """Flatten key_facts dict to kf_* prefixed properties."""
    if not key_facts:
        return {}
    flat: dict[str, Any] = {}
    for k, v in key_facts.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            flat[f"kf_{k}"] = v
        elif isinstance(v, list):
            flat[f"kf_{k}"] = json.dumps(v)
        # Skip dicts and other non-scalar types
    return flat


def _load_findings(
    driver,
    run_dir: Path,
    site: str,
    run_id: str,
) -> int:
    """Load findings.json into Neo4j as Finding nodes linked to Device nodes."""
    findings_path = run_dir / "findings" / "findings.json"
    if not findings_path.exists():
        logger.info("No findings.json found for %s", run_id)
        return 0

    try:
        raw = json.loads(findings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read findings.json for %s: %s", run_id, exc)
        return 0

    # Handle both formats: {metadata, findings} or flat array
    findings = raw.get("findings", []) if isinstance(raw, dict) else raw

    finding_params: list[dict[str, Any]] = []
    # Extra HAS_FINDING relationships for cross-device findings
    extra_relations: list[dict[str, str]] = []
    skipped = 0

    for f in findings:
        element_id = f.get("evidence", {}).get("element_id", "")
        key_facts = f.get("evidence", {}).get("key_facts", {})
        devices = _devices_from_element_id(element_id)
        # STP/global findings: extract devices from key_facts.devices array
        if not devices and isinstance(key_facts.get("devices"), list):
            devices = [d for d in key_facts["devices"] if isinstance(d, str)]
        if not devices:
            # No attachable Device node — surface it instead of silently
            # dropping. A finding whose element_id maps to no device and that
            # carries no key_facts.devices would vanish from Neo4j (and from the
            # agent/dashboard) unnoticed; warn so the gap is visible.
            logger.warning(
                "Finding %s (%s, element_id=%r) attaches to no device — "
                "not loaded. Add key_facts.devices or a parseable element_id.",
                f.get("finding_id", "?"), f.get("rule_id", "?"), element_id,
            )
            skipped += 1
            continue

        primary_device = devices[0]
        rule_id = f.get("rule_id", "")
        severity = f.get("severity", "info")
        severity = _SEVERITY_MAP.get(severity, severity)

        finding_id = f.get("finding_id", "")

        props = {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": severity,
            "title": f.get("title", ""),
            "message": f.get("message", ""),
            "element_id": element_id,
            "element_type": f.get("evidence", {}).get("element_type", "device"),
            "recommendation": f.get("recommendation", ""),
            "detected_at": f.get("detected_at", ""),
            "category": _derive_category(rule_id),
            "device": primary_device,
            "site": site,
            "run_id": run_id,
        }
        if len(devices) > 1:
            props["cross_device"] = True
            props["involved_devices"] = json.dumps(devices)
        props.update(_flatten_key_facts(f.get("evidence", {}).get("key_facts")))
        finding_params.append(_clean_properties(props))

        # Queue extra HAS_FINDING relationships for secondary devices
        for secondary in devices[1:]:
            extra_relations.append({
                "finding_id": finding_id,
                "device": secondary,
                "run_id": run_id,
            })

    if not finding_params:
        return 0

    with driver.session() as session:
        # Create Finding nodes linked to primary device
        session.run(
            f"""
            UNWIND $findings AS f
            MATCH (d:{DEVICE} {{run_id: f.run_id, name: f.device}})
            CREATE (d)-[:{HAS_FINDING}]->(fin:{FINDING})
            SET fin = f
            """,
            findings=finding_params,
        )

        # Create additional HAS_FINDING from secondary devices to existing Finding nodes
        if extra_relations:
            session.run(
                f"""
                UNWIND $rels AS r
                MATCH (d:{DEVICE} {{run_id: r.run_id, name: r.device}})
                MATCH (f:{FINDING} {{run_id: r.run_id, finding_id: r.finding_id}})
                MERGE (d)-[:{HAS_FINDING}]->(f)
                """,
                rels=extra_relations,
            )
            logger.info("Findings: created %d cross-device relationships", len(extra_relations))

    if skipped:
        logger.warning("Findings: skipped %d with unresolvable element_id", skipped)
    logger.info("Findings: loaded %d for run %s", len(finding_params), run_id)
    return len(finding_params)




def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/seed.json"
    summary = load_seed(path)
    print(f"Loaded seed: {summary}")


if __name__ == "__main__":
    main()
