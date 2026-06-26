"""Routing table endpoint — device routing from Neo4j Route nodes.

All routing data is served from Neo4j. Route nodes are created by the
graph loader from genie_routing.json, genie_static_routing.json,
fortigate_routing.json, per-peer BGP routes (genie_bgp_routes_*.json
with source='per-peer', peer, ebgp, as_path properties), and BGP
full-table synthesis.
"""

import ipaddress
import json
import logging
import os
import re
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from netcopilot.graph.client import get_driver, is_available

logger = logging.getLogger(__name__)

router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


def _resolve_facts_dir(run_id: str, hostname: str) -> Path:
    """Resolve facts directory for a device."""
    return RUNS_DIR / run_id / "facts" / hostname


@router.get("/api/device/{hostname}/routing")
def get_device_routing(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return flattened routing table for a device from Neo4j Route nodes."""
    if not is_available():
        return {"hostname": hostname, "run_id": run_id, "routes": [],
                "routing_summary_only": True}

    driver = get_driver()
    routes = []

    # Query all Route nodes for this device (including per-peer BGP)
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id})-[:HAS_ROUTE]->(r:Route) "
            "WHERE d.name = $hostname "
            "RETURN r.prefix AS prefix, r.vrf AS vrf, r.protocol AS protocol, "
            "r.next_hop AS next_hop, r.interface AS interface, "
            "r.ad AS ad, r.metric AS metric, r.active AS active, "
            "r.source AS source, r.note AS note, "
            "r.peer AS peer, r.as_path AS as_path",
            run_id=run_id, hostname=hostname,
        )
        for rec in result:
            protocol = rec["protocol"] or "?"
            # Map protocol to display codes
            code = _PROTO_CODE_MAP.get(protocol.split()[0], "")
            route = {
                "prefix": rec["prefix"] or "",
                "vrf": rec["vrf"] or "default",
                "address_family": "ipv4",
                "protocol": protocol,
                "protocol_codes": code,
                "active": rec["active"] if rec["active"] is not None else True,
                "ad": rec["ad"],
                "metric": rec["metric"],
                "next_hop": rec["next_hop"] or "",
                "interface": rec["interface"] or "",
                "note": rec["note"] or "",
            }
            if rec.get("as_path"):
                route["as_path"] = rec["as_path"]
            if rec.get("peer"):
                route["peer"] = rec["peer"]
            routes.append(route)

    # Detect summary-only mode: device has synthesized BGP routes (full table skipped)
    routing_summary_only = any(
        "synthesized" in r.get("protocol", "") for r in routes
    )

    return {
        "hostname": hostname,
        "run_id": run_id,
        "routes": routes,
        "routing_summary_only": routing_summary_only,
    }


_PROTO_CODE_MAP = {
    "connected": "C",
    "local": "L",
    "static": "S",
    "ospf": "O",
    "bgp": "B",
    "rip": "R",
    "isis": "i",
    "connect": "C",
}



# -------------------------------------------------------------------------
# OSPF device detail endpoint (ADR-217)
# -------------------------------------------------------------------------

@router.get("/api/device/{hostname}/ospf")
def get_device_ospf(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return structured OSPF data for a device.

    Parses genie_ospf.json: processes → areas → interfaces → neighbors.
    Returns empty result if no OSPF data exists.
    """
    facts_dir = _resolve_facts_dir(run_id, hostname)
    ospf_path = facts_dir / "genie_ospf.json"

    if not ospf_path.exists():
        return {"processes": [], "hostname": hostname}

    try:
        data = json.loads(ospf_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse %s: %s", ospf_path, e)
        return {"processes": [], "hostname": hostname}

    processes = _parse_ospf_json(data)

    # Enrich with running_config process-level config (ADR-220)
    rc_path = facts_dir / "running_config.txt"
    if rc_path.exists():
        try:
            rc_configs = _parse_running_config_ospf(rc_path.read_text())
            for proc in processes:
                pid = proc["process_id"]
                vrf = proc.get("vrf", "default")
                rc_cfg = rc_configs.get((pid, vrf), {})
                if rc_cfg:
                    proc["passive_default"] = rc_cfg.get("passive_default", False)
                    proc["active_interfaces"] = rc_cfg.get("active_interfaces", [])
                    proc["capability_vrf_lite"] = rc_cfg.get("capability_vrf_lite", False)
                    proc["redistribute"] = rc_cfg.get("redistribute", [])
                    # Enrich area_type from running_config (more accurate: detects totally-*)
                    for area in proc.get("areas", []):
                        area_int = _area_id_to_int(area["area_id"])
                        rc_area_type = rc_cfg.get("area_types", {}).get(area_int)
                        if rc_area_type:
                            area["area_type"] = rc_area_type
        except Exception as e:
            logger.warning("Failed to parse running_config for OSPF: %s", e)

    # Enrich areas with LSDB from genie_ospf.json default VRF (ADR-220)
    _enrich_lsdb_from_genie(processes, data)

    return {"processes": processes, "hostname": hostname}


def _area_id_to_int(area_id: str) -> int:
    """Convert dotted-quad OSPF area ID to integer. '0.0.0.2' → 2."""
    parts = area_id.split(".")
    if len(parts) == 4:
        try:
            return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        except ValueError:
            pass
    try:
        return int(area_id)
    except ValueError:
        return 0


def _mask_to_prefix_len(mask: str) -> int:
    """Convert subnet mask '255.255.255.0' → 24."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except (ValueError, AttributeError):
        return 0


def _enrich_lsdb_from_genie(processes: list[dict], data: dict) -> None:
    """Enrich area blocks with LSDB entries from genie_ospf.json.

    Genie stores LSDB under 'default' VRF regardless of actual VRF.
    Cross-reference by process_id to find the right LSDB.
    """
    # Build process_id → vrf map from the parsed processes
    pid_to_vrf = {}
    for proc in processes:
        pid_to_vrf[proc["process_id"]] = proc.get("vrf", "default")

    # Read LSDB from default VRF in genie data
    default_vrf = data.get("vrf", data).get("default", {})
    instances = default_vrf.get("address_family", {}).get("ipv4", {}).get("instance", {})

    for pid, pblk in instances.items():
        for area_id, ablk in pblk.get("areas", {}).items():
            lsa_types_block = ablk.get("database", {}).get("lsa_types", {})
            if not lsa_types_block:
                continue

            lsas = []
            for lsa_type_str, type_block in lsa_types_block.items():
                try:
                    lsa_type = int(lsa_type_str)
                except ValueError:
                    continue
                for _key, lsa in type_block.get("lsas", {}).items():
                    # Genie structure: lsa.ospfv2.header + lsa.ospfv2.body
                    ospfv2 = lsa.get("ospfv2", {})
                    header = ospfv2.get("header", {})
                    body = ospfv2.get("body", {})
                    lsa_id = header.get("lsa_id", lsa.get("lsa_id", ""))
                    adv_router = header.get("adv_router", lsa.get("adv_router", ""))
                    if not lsa_id:
                        continue
                    entry = {
                        "lsa_type": lsa_type,
                        "lsa_id": lsa_id,
                        "adv_router": adv_router,
                    }
                    if lsa_type == 1:
                        router_body = body.get("router", {})
                        entry["num_links"] = router_body.get("num_of_links", 0)
                    elif lsa_type == 3:
                        summary = body.get("summary", {})
                        mask = summary.get("network_mask", "")
                        if mask:
                            entry["prefix"] = f"{lsa_id}/{_mask_to_prefix_len(mask)}"
                        topo = summary.get("topologies", {}).get("0", {})
                        entry["metric"] = topo.get("metric", 0)
                    elif lsa_type in (5, 7):
                        ext = body.get("external", {})
                        mask = ext.get("network_mask", "")
                        if mask:
                            entry["prefix"] = f"{lsa_id}/{_mask_to_prefix_len(mask)}"
                        topo = ext.get("topologies", {}).get("0", {})
                        entry["metric"] = topo.get("metric", 0)
                        fwd = topo.get("forwarding_address", "")
                        if fwd and fwd != "0.0.0.0":
                            entry["fwd_addr"] = fwd
                    lsas.append(entry)

            # Find matching area in processes
            actual_vrf = pid_to_vrf.get(pid, "default")
            for proc in processes:
                if proc["process_id"] != pid or proc.get("vrf", "default") != actual_vrf:
                    continue
                for area in proc.get("areas", []):
                    if area["area_id"] == area_id:
                        area["lsdb"] = lsas
                        break


# -------------------------------------------------------------------------
# Inline OSPF running_config parser (mirrors parse.cisco_native.ospf_config)
# Inlined because dashboard container doesn't include parse/ package.
# -------------------------------------------------------------------------
_ROUTER_OSPF_RE = re.compile(r"^router\s+ospf\s+(\d+)(?:\s+vrf\s+(\S+))?$")
_AREA_TYPE_RE = re.compile(r"^\s*area\s+(\d+)\s+(stub|nssa)(.*)$")
_PASSIVE_DEFAULT_RE = re.compile(r"^\s*passive-interface\s+default\s*$")
_NO_PASSIVE_RE = re.compile(r"^\s*no\s+passive-interface\s+(\S+)")
_CAPABILITY_VRF_LITE_RE = re.compile(r"^\s*capability\s+vrf-lite\s*$")
_REDISTRIBUTE_RE = re.compile(r"^\s*redistribute\s+(\S+)")


def _parse_running_config_ospf(config_text: str) -> dict:
    """Parse OSPF process blocks from IOS XE running config.

    Returns dict keyed by (process_id_str, vrf_name).
    """
    results = {}
    current_key = None
    current_cfg = None

    for line in config_text.splitlines():
        m = _ROUTER_OSPF_RE.match(line)
        if m:
            if current_key is not None and current_cfg is not None:
                results[current_key] = current_cfg
            pid = m.group(1)
            vrf = m.group(2) or "default"
            current_key = (pid, vrf)
            current_cfg = {
                "area_types": {}, "passive_default": False,
                "active_interfaces": [], "capability_vrf_lite": False,
                "redistribute": [],
            }
            continue
        if current_cfg is not None and line and not line[0].isspace():
            if not _ROUTER_OSPF_RE.match(line):
                results[current_key] = current_cfg
                current_key = None
                current_cfg = None
            continue
        if current_cfg is None:
            continue
        am = _AREA_TYPE_RE.match(line)
        if am:
            area_int = int(am.group(1))
            base = am.group(2)
            current_cfg["area_types"][area_int] = f"totally-{base}" if "no-summary" in am.group(3) else base
            continue
        if _PASSIVE_DEFAULT_RE.match(line):
            current_cfg["passive_default"] = True
            continue
        npm = _NO_PASSIVE_RE.match(line)
        if npm:
            current_cfg["active_interfaces"].append(npm.group(1))
            continue
        if _CAPABILITY_VRF_LITE_RE.match(line):
            current_cfg["capability_vrf_lite"] = True
            continue
        rm = _REDISTRIBUTE_RE.match(line)
        if rm:
            current_cfg["redistribute"].append(rm.group(1))
            continue
    if current_key is not None and current_cfg is not None:
        results[current_key] = current_cfg
    return results


def _parse_ospf_json(data: dict) -> list[dict]:
    """Parse genie_ospf.json into structured process list.

    Structure: vrf → address_family → ipv4 → instance → areas → interfaces → neighbors
    """
    processes = []
    vrf_dict = data.get("vrf", data)

    # Pre-pass: extract process-level metadata and area stats from "default" VRF.
    # Genie stores config (SPF throttle, max_lsa, GR, area_type, SPF stats) only
    # under "default" — VRF-specific processes inherit these but Genie omits them.
    default_proc_meta: dict[str, dict] = {}  # process_id → {spf_throttle, max_lsa, ...}
    default_area_stats: dict[str, dict] = {}  # "process_id:area_id" → {area_type, spf_runs, ...}
    default_block = vrf_dict.get("default", {})
    for pid, pblk in default_block.get("address_family", {}).get(
        "ipv4", {}
    ).get("instance", {}).items():
        # Process-level
        db_ctrl = pblk.get("database_control", {})
        spf_ctrl = pblk.get("spf_control", {}).get("throttle", {}).get("spf", {})
        gr_cisco = pblk.get("graceful_restart", {}).get("cisco", {}).get("enable", False)
        gr_ietf = pblk.get("graceful_restart", {}).get("ietf", {}).get("enable", False)
        meta = {
            "router_id": pblk.get("router_id", ""),
            "graceful_restart": gr_cisco or gr_ietf,
            "bfd": pblk.get("bfd", {}).get("enable", False),
            "stub_router": pblk.get("stub_router", {}).get("always", {}).get("always", False),
        }
        if db_ctrl.get("max_lsa"):
            meta["max_lsa"] = db_ctrl["max_lsa"]
        if spf_ctrl:
            meta["spf_throttle"] = {
                "start": spf_ctrl.get("start"),
                "hold": spf_ctrl.get("hold"),
                "maximum": spf_ctrl.get("maximum"),
            }
        default_proc_meta[pid] = meta
        # Area-level stats
        for aid, ablk in pblk.get("areas", {}).items():
            astats = ablk.get("statistics", {})
            default_area_stats[f"{pid}:{aid}"] = {
                "area_type": ablk.get("area_type", "normal"),
                "spf_runs": astats.get("spf_runs_count"),
                "lsa_count": astats.get("area_scope_lsa_count"),
            }

    for vrf_name, vrf_block in vrf_dict.items():
        af_block = vrf_block.get("address_family", {})
        ipv4_block = af_block.get("ipv4", {})
        instances = ipv4_block.get("instance", {})

        for process_id, proc_block in instances.items():
            # Fallback to default VRF metadata for VRF-specific processes
            dmeta = default_proc_meta.get(process_id, {})
            router_id = proc_block.get("router_id") or dmeta.get("router_id", "")

            # Process-level health indicators (with default VRF fallback)
            db_ctrl = proc_block.get("database_control", {})
            spf_ctrl = proc_block.get("spf_control", {}).get("throttle", {}).get("spf", {})
            gr_cisco = proc_block.get("graceful_restart", {}).get("cisco", {}).get("enable", False)
            gr_ietf = proc_block.get("graceful_restart", {}).get("ietf", {}).get("enable", False)
            proc_bfd = proc_block.get("bfd", {}).get("enable", False)
            stub_rtr = proc_block.get("stub_router", {}).get("always", {}).get("always", False)

            areas_out = []
            for area_id, area_block in proc_block.get("areas", {}).items():
                interfaces_out = []
                for intf_name, intf_block in area_block.get("interfaces", {}).items():
                    neighbors_out = []
                    for nbr_rid, nbr_block in intf_block.get("neighbors", {}).items():
                        neighbors_out.append({
                            "router_id": nbr_rid,
                            "address": nbr_block.get("address", ""),
                            "state": nbr_block.get("state", "unknown"),
                            "dead_timer": nbr_block.get("dead_timer", ""),
                        })

                    interfaces_out.append({
                        "name": intf_name,
                        "cost": intf_block.get("cost"),
                        "network_type": intf_block.get("interface_type", ""),
                        "state": intf_block.get("state", ""),
                        "passive": intf_block.get("passive", False),
                        "hello_interval": intf_block.get("hello_interval"),
                        "dead_interval": intf_block.get("dead_interval"),
                        "bfd": intf_block.get("bfd", {}).get("enable", False),
                        "neighbors": neighbors_out,
                    })

                area_stats = area_block.get("statistics", {})
                # Fallback to default VRF area stats for VRF-specific areas
                darea = default_area_stats.get(f"{process_id}:{area_id}", {})
                areas_out.append({
                    "area_id": area_id,
                    "area_type": area_block.get("area_type") or darea.get("area_type", "normal"),
                    "spf_runs": area_stats.get("spf_runs_count") or darea.get("spf_runs"),
                    "lsa_count": area_stats.get("area_scope_lsa_count") or darea.get("lsa_count"),
                    "interfaces": interfaces_out,
                })

            proc_out = {
                "process_id": process_id,
                "router_id": router_id,
                "vrf": vrf_name,
                "areas": areas_out,
                "graceful_restart": (gr_cisco or gr_ietf) or dmeta.get("graceful_restart", False),
                "bfd": proc_bfd or dmeta.get("bfd", False),
                "stub_router": stub_rtr or dmeta.get("stub_router", False),
            }
            max_lsa = db_ctrl.get("max_lsa") or dmeta.get("max_lsa")
            if max_lsa:
                proc_out["max_lsa"] = max_lsa
            spf_throttle = spf_ctrl or dmeta.get("spf_throttle")
            if spf_throttle:
                proc_out["spf_throttle"] = {
                    "start": spf_throttle.get("start"),
                    "hold": spf_throttle.get("hold"),
                    "maximum": spf_throttle.get("maximum"),
                }
            processes.append(proc_out)

    return processes


# -------------------------------------------------------------------------
# BGP device detail endpoint (S19C-6)
# -------------------------------------------------------------------------

@router.get("/api/device/{hostname}/bgp")
def get_device_bgp(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return structured BGP data for a device.

    Served from Neo4j ROUTING_ADJACENCY edges (bilateral properties) only — the
    divergent facts-fallback was removed in R1 Phase 1.3. Returns 404 when the
    device has no BGP adjacencies, 503 when the graph database is unavailable.
    """
    # ── Primary: Neo4j query ────────────────────────────────────────
    if is_available():
        try:
            driver = get_driver()
            with driver.session() as session:
                result = session.run(
                    "MATCH (d:Device {run_id: $run_id, name: $hostname})"
                    "-[r:ROUTING_ADJACENCY]-(peer:Device) "
                    "WHERE r.protocol = 'bgp' "
                    "RETURN DISTINCT peer.name AS peer_name, "
                    "r.local_as AS local_as, r.remote_as AS remote_as, "
                    "r.state AS state, r.session_type AS session_type, "
                    "r.vrf AS vrf, r.bgp_type AS bgp_type, "
                    "r.address_families AS address_families, "
                    "r.bilateral AS bilateral, "
                    "r.router_id_a AS rid_a, r.router_id_b AS rid_b, "
                    "r.keepalive_a AS ka_a, r.keepalive_b AS ka_b, "
                    "r.hold_time_a AS ht_a, r.hold_time_b AS ht_b, "
                    "r.up_down_a AS ud_a, r.up_down_b AS ud_b, "
                    "r.msg_sent_a AS ms_a, r.msg_sent_b AS ms_b, "
                    "r.msg_rcvd_a AS mr_a, r.msg_rcvd_b AS mr_b, "
                    "r.prefixes_received_a AS pr_a, r.prefixes_received_b AS pr_b, "
                    "r.description_a AS desc_a, r.description_b AS desc_b, "
                    "r.route_policy_in_a AS rpi_a, r.route_policy_in_b AS rpi_b, "
                    "r.route_policy_out_a AS rpo_a, r.route_policy_out_b AS rpo_b, "
                    "r.bfd_a AS bfd_a, r.bfd_b AS bfd_b, "
                    "r.graceful_restart_a AS gr_a, r.graceful_restart_b AS gr_b, "
                    "r.password_configured_a AS pw_a, r.password_configured_b AS pw_b, "
                    "r.send_community_a AS sc_a, r.send_community_b AS sc_b, "
                    "r.next_hop_self_a AS nhs_a, r.next_hop_self_b AS nhs_b, "
                    "r.soft_reconfiguration_a AS sr_a, r.soft_reconfiguration_b AS sr_b, "
                    "r.network_statements_a AS ns_a, r.network_statements_b AS ns_b, "
                    "r.prefix_count AS prefix_count, "
                    "r.rr_client AS rr_client, r.rr_reflector AS rr_reflector, "
                    "d.is_route_reflector AS d_is_rr, "
                    "d.rr_cluster_id AS d_cluster_id, "
                    "startNode(r) = d AS d_is_start",
                    run_id=run_id, hostname=hostname,
                )
                edges = [dict(r) for r in result]

            if edges:
                # Determine which side (_a or _b) is this device
                # Edge direction is stored as created — for external peers:
                #   external_peer → managed_device (d_is_start = False, device is side B)
                # For bilateral (iBGP between managed devices):
                #   need to check d_is_start to pick correct side
                neighbors = []
                as_number = None
                router_id = None
                vrf = "default"

                for e in edges:
                    # Determine perspective: is this device side A or B?
                    if e["bilateral"]:
                        # Bilateral: device could be either side
                        if e["d_is_start"]:
                            suffix = "_a"  # device is startNode = side A
                            peer_as = e["remote_as"]
                            own_as = e["local_as"]
                        else:
                            suffix = "_b"
                            peer_as = e["local_as"]
                            own_as = e["remote_as"]
                    else:
                        # Unilateral: external→managed, device is always side B
                        suffix = "_b"
                        peer_as = e["local_as"]  # external peer's AS
                        own_as = e["remote_as"]  # managed device's AS

                    if as_number is None:
                        as_number = own_as
                    rid = e.get(f"rid{suffix}")
                    if rid and router_id is None:
                        router_id = rid
                    if e.get("vrf"):
                        vrf = e["vrf"]

                    s = suffix.replace("_", "")  # "a" or "b"
                    # RR role of the peer on this session: if this device is the
                    # reflector, the peer is its client; if the peer is the
                    # reflector, the peer is our RR. (rr_reflector names the
                    # reflecting end of the session.)
                    rr_reflector = e.get("rr_reflector")
                    peer_is_rr_client = bool(e.get("rr_client")) and rr_reflector == hostname
                    peer_is_rr = bool(e.get("rr_client")) and rr_reflector == e["peer_name"]
                    neighbors.append({
                        "peer_ip": e["peer_name"],
                        "remote_as": peer_as,
                        "session_type": e.get("session_type", ""),
                        "state": (e.get("state") or "unknown").capitalize(),
                        "prefixes_received": e.get(f"pr_{s}") or e.get("prefix_count") or 0,
                        "msg_sent": e.get(f"ms_{s}") or 0,
                        "msg_rcvd": e.get(f"mr_{s}") or 0,
                        "up_down": e.get(f"ud_{s}") or "",
                        "keepalive": e.get(f"ka_{s}"),
                        "hold_time": e.get(f"ht_{s}"),
                        "description": e.get(f"desc_{s}") or "",
                        "address_families": e.get("address_families") or [],
                        "bfd": e.get(f"bfd_{s}") or False,
                        "password_configured": e.get(f"pw_{s}") or False,
                        "graceful_restart": e.get(f"gr_{s}") or False,
                        "send_community": e.get(f"sc_{s}") or False,
                        "route_policy_in": e.get(f"rpi_{s}") or "",
                        "route_policy_out": e.get(f"rpo_{s}") or "",
                        "next_hop_self": e.get(f"nhs_{s}") or False,
                        "soft_reconfiguration": e.get(f"sr_{s}") or False,
                        "route_reflector_client": peer_is_rr_client,
                        "route_reflector": peer_is_rr,
                    })

                is_rr = bool(edges[0].get("d_is_rr"))
                processes = [{
                    "as_number": as_number,
                    "router_id": router_id or "",
                    "vrf": vrf,
                    "graceful_restart": any(n.get("graceful_restart") for n in neighbors),
                    "log_neighbor_changes": True,
                    "network_statements": edges[0].get(f"ns_{suffix.replace('_','')}", []) or [],
                    "redistribute": [],
                    "is_route_reflector": is_rr,
                    "cluster_id": edges[0].get("d_cluster_id") if is_rr else None,
                    "neighbors": neighbors,
                }]

                return {"hostname": hostname, "run_id": run_id, "processes": processes}
            # Query ran but the device has no BGP adjacencies in the graph.
            return JSONResponse(
                status_code=404, content={"error": f"No BGP data for {hostname}"}
            )
        except Exception as exc:
            logger.error("Neo4j BGP query failed for %s: %s", hostname, exc)
            return JSONResponse(
                status_code=500, content={"error": f"BGP query failed: {exc}"}
            )

    # BGP is served from Neo4j only — the divergent facts-fallback (a second code
    # path whose values drifted from the Neo4j path) was removed (R1 Phase 1.3).
    # The dashboard requires the graph database.
    return JSONResponse(
        status_code=503,
        content={"error": "BGP data requires Neo4j (graph database unavailable)"},
    )


@router.get("/api/bgp-peer-routes/{hostname}/{peer_ip}")
def get_bgp_peer_routes(
    hostname: str,
    peer_ip: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return BGP routes received from a specific peer from Neo4j."""
    if not is_available():
        return JSONResponse(status_code=404, content={"routes": []})

    driver = get_driver()
    routes = []
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $hostname})"
            "-[:HAS_ROUTE]->(r:Route {source: 'per-peer', peer: $peer}) "
            "RETURN r.prefix AS prefix, r.next_hop AS next_hop, "
            "r.metric AS metric, r.as_path AS path, "
            "r.origin AS origin, r.active AS active",
            run_id=run_id, hostname=hostname, peer=peer_ip,
        )
        for rec in result:
            routes.append({
                "prefix": rec["prefix"] or "",
                "next_hop": rec["next_hop"] or "",
                "metric": rec["metric"],
                "local_pref": None,
                "weight": None,
                "path": rec["path"] or "",
                "origin": rec["origin"] or "",
                "status": "*>" if rec["active"] else "*",
            })

    if not routes:
        return JSONResponse(status_code=404, content={"routes": []})

    return {"hostname": hostname, "peer_ip": peer_ip, "routes": routes}



# ---------------------------------------------------------------------------
# Sprint 19D: Firewall Policies & Security Policies
# ---------------------------------------------------------------------------


def _build_zone_map(facts_dir: Path) -> dict[str, str]:
    """Build interface-name → zone-name reverse map. Delegates to shared utility."""
    from netcopilot.parse.policy_resolver import build_zone_map
    return build_zone_map(facts_dir)


def _build_address_resolver(facts_dir: Path) -> dict[str, str]:
    """Build address-name → resolved-value map. Delegates to shared utility."""
    from netcopilot.parse.policy_resolver import build_address_resolver
    return build_address_resolver(facts_dir)


def _build_service_resolver(facts_dir: Path) -> dict[str, str | None]:
    """Build service-name → resolved-value map. Delegates to shared utility."""
    from netcopilot.parse.policy_resolver import build_service_resolver
    return build_service_resolver(facts_dir)


@router.get("/api/device/{hostname}/firewall-policies")
def get_firewall_policies(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return firewall policies with resolved addresses/services.

    Primary: queries Neo4j FirewallPolicy nodes (pre-resolved at load time).
    Fallback: parses fortigate_firewall_policy.json + resolver files.
    Returns 404 if no policy data exists.
    """
    # ── Primary: Neo4j query ────────────────────────────────────────
    if is_available():
        try:
            driver = get_driver()
            with driver.session() as session:
                result = session.run(
                    "MATCH (d:Device {run_id: $run_id, name: $hostname})"
                    "-[:HAS_POLICY]->(p:FirewallPolicy) "
                    "RETURN p.seq AS seq, p.policyid AS policyid, "
                    "p.name AS name, p.status AS status, p.action AS action, "
                    "p.srcintf AS srcintf, p.dstintf AS dstintf, "
                    "p.srcaddr AS srcaddr, p.dstaddr AS dstaddr, "
                    "p.service AS service, p.nat AS nat, "
                    "p.schedule AS schedule, p.logtraffic AS logtraffic, "
                    "p.comments AS comments, p.policy_type AS policy_type, "
                    "p.src_zones AS src_zones, p.dst_zones AS dst_zones "
                    "ORDER BY p.seq",
                    run_id=run_id, hostname=hostname,
                )
                rows = [dict(r) for r in result]

            if rows:
                # Reconstruct response format matching the frontend
                zones_set = set()
                policies = []
                for row in rows:
                    if row.get("policy_type") != "fortigate":
                        continue  # ACLs handled by security-policies endpoint

                    # Parse srcintf/dstintf from JSON strings
                    try:
                        srcintf_list = json.loads(row.get("srcintf") or "[]")
                    except (json.JSONDecodeError, TypeError):
                        srcintf_list = []
                    try:
                        dstintf_list = json.loads(row.get("dstintf") or "[]")
                    except (json.JSONDecodeError, TypeError):
                        dstintf_list = []

                    # Collect zones
                    for z in (row.get("src_zones") or []):
                        if z:
                            zones_set.add(z)
                    for z in (row.get("dst_zones") or []):
                        if z:
                            zones_set.add(z)

                    # Reconstruct address lists from resolved strings
                    srcaddr_str = row.get("srcaddr") or ""
                    dstaddr_str = row.get("dstaddr") or ""
                    srcaddr_list = [{"name": s.strip(), "resolved": s.strip()}
                                    for s in srcaddr_str.split(", ") if s.strip()] or [{"name": "any", "resolved": "0.0.0.0/0"}]
                    dstaddr_list = [{"name": s.strip(), "resolved": s.strip()}
                                    for s in dstaddr_str.split(", ") if s.strip()] or [{"name": "any", "resolved": "0.0.0.0/0"}]

                    # Reconstruct service list
                    svc_str = row.get("service") or ""
                    service_list = [{"name": s.strip(), "resolved": s.strip()}
                                    for s in svc_str.split(", ") if s.strip()] or [{"name": "ALL", "resolved": None}]

                    policies.append({
                        "seq": row.get("seq", 0),
                        "policyid": row.get("policyid"),
                        "name": row.get("name", ""),
                        "status": row.get("status", "enable"),
                        "action": row.get("action", "deny"),
                        "srcintf": srcintf_list,
                        "dstintf": dstintf_list,
                        "srcaddr": srcaddr_list,
                        "dstaddr": dstaddr_list,
                        "service": service_list,
                        "nat": row.get("nat", "disable"),
                        "schedule": row.get("schedule", ""),
                        "logtraffic": row.get("logtraffic", "disable"),
                        "comments": row.get("comments", ""),
                        "utm": {},
                    })

                if policies:
                    return {
                        "hostname": hostname,
                        "run_id": run_id,
                        "zones": sorted(zones_set),
                        "policies": policies,
                    }
        except Exception as exc:
            logger.warning("Neo4j firewall query failed for %s, falling back: %s", hostname, exc)

    # ── Fallback: facts file parsing ────────────────────────────────
    facts_dir = _resolve_facts_dir(run_id, hostname)
    policy_path = facts_dir / "fortigate_firewall_policy.json"

    if not policy_path.exists():
        return JSONResponse(
            status_code=404,
            content={"error": f"No firewall policy data for {hostname}"},
        )

    try:
        policy_data = json.loads(policy_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse %s: %s", policy_path, e)
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to parse policy data: {e}"},
        )

    zone_map = _build_zone_map(facts_dir)
    addr_resolver = _build_address_resolver(facts_dir)
    svc_resolver = _build_service_resolver(facts_dir)
    zones = sorted(set(zone_map.values()))

    policies = []
    for seq, pol in enumerate(policy_data.get("results", []), start=1):
        if not isinstance(pol, dict):
            continue

        srcintf_list = [{"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""))}
                        for i in pol.get("srcintf", [])]
        dstintf_list = [{"name": i.get("name", ""), "zone": zone_map.get(i.get("name", ""))}
                        for i in pol.get("dstintf", [])]
        srcaddr_list = [{"name": a.get("name", ""), "resolved": addr_resolver.get(a.get("name", ""), a.get("name", ""))}
                        for a in pol.get("srcaddr", [])]
        dstaddr_list = [{"name": a.get("name", ""), "resolved": addr_resolver.get(a.get("name", ""), a.get("name", ""))}
                        for a in pol.get("dstaddr", [])]
        service_list = [{"name": s.get("name", ""), "resolved": svc_resolver.get(s.get("name", ""), s.get("name", ""))}
                        for s in pol.get("service", [])]

        utm = {}
        if pol.get("utm-status") == "enable":
            for key in ("ips-sensor", "av-profile", "webfilter-profile",
                        "application-list", "ssl-ssh-profile", "dnsfilter-profile"):
                val = pol.get(key, "")
                if val:
                    utm[key] = val

        policies.append({
            "seq": seq, "policyid": pol.get("policyid"),
            "name": pol.get("name", ""), "status": pol.get("status", "enable"),
            "action": pol.get("action", "deny"),
            "srcintf": srcintf_list, "dstintf": dstintf_list,
            "srcaddr": srcaddr_list, "dstaddr": dstaddr_list,
            "service": service_list,
            "nat": pol.get("nat", "disable"), "schedule": pol.get("schedule", ""),
            "logtraffic": pol.get("logtraffic", "disable"),
            "comments": pol.get("comments", ""), "utm": utm,
        })

    return {"hostname": hostname, "run_id": run_id, "zones": zones, "policies": policies}


# ---------------------------------------------------------------------------
# Cisco Security Policies (S19D-3)
# ---------------------------------------------------------------------------


def _parse_genie_acl(data: dict) -> list[dict]:
    """Parse genie_acl.json into structured ACL list. Delegates to shared utility."""
    from netcopilot.parse.policy_resolver import parse_genie_acl
    return parse_genie_acl(data)


def _parse_acl_interface_bindings(facts_dir: Path) -> dict[str, list[dict]]:
    """Parse running_config.txt for ACL-to-interface bindings.

    Returns a dict mapping ACL name → list of {interface, direction} dicts.
    Handles both IOS XE ('ip access-group X in/out') and
    IOS XR ('ipv4/ipv6 access-group X ingress/egress').
    Also captures VTY line bindings ('access-class X in').
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}

    bindings: dict[str, list[dict]] = {}
    current_interface = None
    current_line = None  # for VTY lines
    current_vrf = None   # VRF of current interface

    _INTF_RE = re.compile(r"^interface\s+(.+)")
    _LINE_RE = re.compile(r"^line\s+(vty|con|aux|default)\s*(.*)")
    # IOS XE: vrf forwarding X  or  ip vrf forwarding X
    _VRF_FWD_RE = re.compile(r"^\s+(?:ip\s+)?vrf\s+forwarding\s+(\S+)")
    # IOS XE: ip access-group NAME in|out
    _XE_ACL_RE = re.compile(r"^\s+ip\s+access-group\s+(\S+)\s+(in|out)")
    # IOS XR: ipv4/ipv6 access-group NAME ingress|egress
    _XR_ACL_RE = re.compile(r"^\s+ipv[46]\s+access-group\s+(\S+)\s+(ingress|egress)")
    # VTY: access-class NAME in|out  (IOS XE)
    _VTY_XE_RE = re.compile(r"^\s+access-class\s+(\S+)\s+(in|out)")
    # VTY: access-class ingress|egress NAME  (IOS XR)
    _VTY_XR_RE = re.compile(r"^\s+access-class\s+(ingress|egress)\s+(\S+)")
    # SSH server ACL: ssh server ... access-list NAME
    _SSH_ACL_RE = re.compile(r"^ssh\s+server\s+.*access-list\s+(\S+)")
    # HTTP access-class: ip http access-class ipv4 NAME
    _HTTP_ACL_RE = re.compile(r"^ip\s+http\s+access-class\s+\S+\s+(\S+)")

    dir_map = {"in": "inbound", "out": "outbound",
               "ingress": "inbound", "egress": "outbound"}

    for line in lines:
        m = _INTF_RE.match(line)
        if m:
            current_interface = m.group(1).strip()
            current_line = None
            current_vrf = None
            continue

        m = _LINE_RE.match(line)
        if m:
            suffix = m.group(2).strip()
            current_line = f"line {m.group(1)} {suffix}" if suffix else f"line {m.group(1)}"
            current_interface = None
            continue

        if line and not line[0].isspace():
            current_interface = None
            current_line = None

        # Interface ACL bindings
        if current_interface:
            m = _VRF_FWD_RE.match(line)
            if m:
                current_vrf = m.group(1)
                continue
            m = _XE_ACL_RE.match(line) or _XR_ACL_RE.match(line)
            if m:
                acl_name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
                entry = {"interface": current_interface, "direction": direction}
                if current_vrf:
                    entry["vrf"] = current_vrf
                bindings.setdefault(acl_name, []).append(entry)
                continue

        # VTY line ACL bindings
        if current_line:
            m = _VTY_XE_RE.match(line)
            if m:
                acl_name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
                bindings.setdefault(acl_name, []).append(
                    {"interface": current_line, "direction": direction}
                )
                continue
            m = _VTY_XR_RE.match(line)
            if m:
                direction, acl_name = dir_map.get(m.group(1), m.group(1)), m.group(2)
                bindings.setdefault(acl_name, []).append(
                    {"interface": current_line, "direction": direction}
                )
                continue

        # Global SSH/HTTP ACL references
        m = _SSH_ACL_RE.match(line)
        if m:
            bindings.setdefault(m.group(1), []).append(
                {"interface": "SSH server", "direction": "inbound"}
            )
            continue
        m = _HTTP_ACL_RE.match(line)
        if m:
            bindings.setdefault(m.group(1), []).append(
                {"interface": "HTTP server", "direction": "inbound"}
            )
            continue

    return bindings


def _parse_route_policy_bindings(facts_dir: Path) -> tuple[dict[str, list[dict]], dict[str, list[str]]]:
    """Parse running_config.txt for route-map/route-policy and prefix-list usage.

    Returns:
        rm_bindings: route-map name → list of {context, direction} dicts
        pl_refs: prefix-list name → list of referencing route-map names
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}, {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}, {}

    rm_bindings: dict[str, list[dict]] = {}
    pl_refs: dict[str, list[str]] = {}

    # IOS XE: neighbor X.X.X.X route-map NAME in|out
    _BGP_RM_RE = re.compile(r"^\s+(?:neighbor\s+\S+\s+)?route-map\s+(\S+)\s+(in|out)")
    # IOS XR: route-policy NAME in|out
    _BGP_RP_RE = re.compile(r"^\s+route-policy\s+(\S+)\s+(in|out)")
    # redistribute ... route-map NAME
    _REDIST_RM_RE = re.compile(r"^\s+redistribute\s+(\S+).*\s+route-map\s+(\S+)")
    # IOS XE: match ip address prefix-list NAME (inside route-map)
    _MATCH_PL_RE = re.compile(r"^\s+match\s+ip\s+address\s+prefix-list\s+(\S+)")
    # IOS XR: if destination in PREFIX-SET (inside route-policy)
    _MATCH_PS_RE = re.compile(r"^\s+if\s+destination\s+in\s+(\S+)")

    dir_map = {"in": "inbound", "out": "outbound"}
    current_rm = None  # track current route-map context for prefix-list refs

    for line in lines:
        # Track route-map/route-policy definition context
        rm_def = re.match(r"^route-map\s+(\S+)", line) or re.match(r"^route-policy\s+(\S+)", line)
        if rm_def:
            current_rm = rm_def.group(1)
            continue

        if line and not line[0].isspace() and not line.startswith("!"):
            current_rm = None

        # BGP neighbor route-map / route-policy
        m = _BGP_RM_RE.match(line) or _BGP_RP_RE.match(line)
        if m:
            name, direction = m.group(1), dir_map.get(m.group(2), m.group(2))
            rm_bindings.setdefault(name, []).append(
                {"context": "BGP neighbor", "direction": direction}
            )
            continue

        # redistribute ... route-map
        m = _REDIST_RM_RE.match(line)
        if m:
            proto, name = m.group(1), m.group(2)
            rm_bindings.setdefault(name, []).append(
                {"context": f"redistribute {proto}", "direction": "outbound"}
            )
            continue

        # prefix-list referenced from route-map
        if current_rm:
            m = _MATCH_PL_RE.match(line) or _MATCH_PS_RE.match(line)
            if m:
                pl_name = m.group(1)
                pl_refs.setdefault(pl_name, [])
                if current_rm not in pl_refs[pl_name]:
                    pl_refs[pl_name].append(current_rm)
                continue

    return rm_bindings, pl_refs


def _parse_xr_route_policies(facts_dir: Path) -> tuple[list[dict], list[dict]]:
    """Compatibility shim — delegates to the canonical parser.

    Moved to `parse.policy_resolver.parse_xr_route_policies` (audit 2026-05-15 #5)
    so the graph loader and this REST endpoint share one source of truth.
    """
    from netcopilot.parse.policy_resolver import parse_xr_route_policies
    return parse_xr_route_policies(facts_dir)


def _parse_bgp_neighbor_context(facts_dir: Path) -> dict[str, list[dict]]:
    """Parse BGP neighbor route-map/route-policy bindings with neighbor details.

    Returns route-map/policy name → list of {context, direction} where context
    includes the neighbor IP and description.
    IOS XE: 'neighbor X.X.X.X route-map NAME in|out'
    IOS XR: 'route-policy NAME in|out' (under neighbor block)
    """
    import re

    config_path = facts_dir / "running_config.txt"
    if not config_path.exists():
        return {}

    try:
        lines = config_path.read_text().splitlines()
    except OSError:
        return {}

    bindings: dict[str, list[dict]] = {}
    in_bgp = False
    current_neighbor = None
    neighbor_desc = {}  # neighbor_ip → description
    current_vrf = "default"

    dir_map = {"in": "inbound", "out": "outbound"}

    for line in lines:
        # Detect router bgp section
        if re.match(r"^router\s+bgp\s+(\d+)", line):
            in_bgp = True
            current_vrf = "default"
            current_neighbor = None
            continue

        if in_bgp and line and not line[0].isspace() and not line.startswith("!"):
            in_bgp = False
            current_neighbor = None
            continue

        if not in_bgp:
            continue

        stripped = line.strip()

        # VRF context
        m = re.match(r"^\s+vrf\s+(\S+)", line)
        if m:
            current_vrf = m.group(1)
            current_neighbor = None
            continue

        # Neighbor block
        m = re.match(r"^\s+neighbor\s+(\S+)", line)
        if m:
            current_neighbor = m.group(1)
            continue

        # Description inside neighbor
        if current_neighbor and stripped.startswith("description"):
            desc = stripped[len("description"):].strip().strip("*").strip()
            neighbor_desc[current_neighbor] = desc

        # IOS XR: route-policy NAME in|out (inside neighbor)
        m = re.match(r"^\s+route-policy\s+(\S+)\s+(in|out)", line)
        if m and current_neighbor:
            name, direction = m.group(1), dir_map[m.group(2)]
            desc = neighbor_desc.get(current_neighbor, "")
            label = f"BGP {current_neighbor}"
            if desc:
                label += f" ({desc})"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": direction, "vrf": current_vrf}
            )
            continue

        # IOS XE: neighbor X.X.X.X route-map NAME in|out
        m = re.match(r"^\s+neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)", line)
        if m:
            neighbor_ip, name, direction = m.group(1), m.group(2), dir_map[m.group(3)]
            desc = neighbor_desc.get(neighbor_ip, "")
            label = f"BGP {neighbor_ip}"
            if desc:
                label += f" ({desc})"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": direction, "vrf": current_vrf}
            )
            continue

        # IOS XE: redistribute ... route-map NAME
        m = re.match(r"^\s+redistribute\s+(\S+).*\s+route-map\s+(\S+)", line)
        if m:
            proto, name = m.group(1), m.group(2)
            label = f"redistribute {proto}"
            bindings.setdefault(name, []).append(
                {"context": label, "direction": "outbound", "vrf": current_vrf}
            )
            continue

    return bindings


@router.get("/api/device/{hostname}/security-policies")
def get_security_policies(
    hostname: str,
    run_id: str = Query(..., description="Pipeline run ID"),
):
    """Return Cisco ACLs, route-maps/route-policies, and prefix-lists/sets.

    Sprint 19D (S19D-3): Reads genie_acl.json, parsed_route_policy.json,
    and parsed_prefix_list.json. Falls back to running_config.txt parsing
    for IOS XR route-policy/prefix-set blocks.
    """
    facts_dir = _resolve_facts_dir(run_id, hostname)

    # Parse bindings from running config
    acl_bindings = _parse_acl_interface_bindings(facts_dir)
    bgp_bindings = _parse_bgp_neighbor_context(facts_dir)
    _, pl_refs = _parse_route_policy_bindings(facts_dir)

    # Parse ACLs — sort: applied first, then alphabetical
    acls = []
    acl_path = facts_dir / "genie_acl.json"
    if acl_path.exists():
        try:
            data = json.loads(acl_path.read_text())
            acls = _parse_genie_acl(data)
            for acl in acls:
                acl["applied_to"] = acl_bindings.get(acl["name"], [])
            acls.sort(key=lambda a: (len(a["applied_to"]) == 0, a["name"]))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", acl_path, e)

    # Parse route-maps (IOS XE from parsed JSON, IOS XR from running config)
    route_maps = []
    rm_path = facts_dir / "parsed_route_policy.json"
    if rm_path.exists():
        try:
            data = json.loads(rm_path.read_text())
            for rm_name, rm_data in sorted(data.items()):
                if isinstance(rm_data, dict):
                    route_maps.append({
                        "name": rm_name,
                        "sequences": rm_data.get("sequences", []),
                        "applied_to": bgp_bindings.get(rm_name, []),
                    })
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", rm_path, e)

    # IOS XR fallback: parse route-policy/prefix-set from running config
    if not route_maps:
        xr_policies, xr_prefix_sets = _parse_xr_route_policies(facts_dir)
        for rp in xr_policies:
            route_maps.append({
                "name": rp["name"],
                "body": rp["body"],
                "applied_to": bgp_bindings.get(rp["name"], []),
            })

    route_maps.sort(key=lambda r: (len(r.get("applied_to", [])) == 0, r["name"]))

    # Parse prefix-lists (IOS XE from parsed JSON, IOS XR from running config)
    prefix_lists = []
    pl_path = facts_dir / "parsed_prefix_list.json"
    if pl_path.exists():
        try:
            data = json.loads(pl_path.read_text())
            for pl_name, pl_data in sorted(data.items()):
                if isinstance(pl_data, dict):
                    prefix_lists.append({
                        "name": pl_name,
                        "entries": pl_data.get("entries", []),
                        "referenced_by": pl_refs.get(pl_name, []),
                    })
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", pl_path, e)

    # IOS XR fallback: prefix-sets already parsed above
    if not prefix_lists:
        _, xr_prefix_sets = _parse_xr_route_policies(facts_dir)
        # Build XR prefix-set cross-references from route-policy bodies
        xr_ps_refs: dict[str, list[str]] = {}
        for rp in route_maps:
            for line in rp.get("body", []):
                for ps in xr_prefix_sets:
                    if ps["name"] in line:
                        xr_ps_refs.setdefault(ps["name"], [])
                        if rp["name"] not in xr_ps_refs[ps["name"]]:
                            xr_ps_refs[ps["name"]].append(rp["name"])
        for ps in xr_prefix_sets:
            prefix_lists.append({
                "name": ps["name"],
                "entries": ps["entries"],
                "referenced_by": xr_ps_refs.get(ps["name"], []),
            })

    prefix_lists.sort(key=lambda p: (len(p.get("referenced_by", [])) == 0, p["name"]))

    return {
        "hostname": hostname,
        "run_id": run_id,
        "acls": acls,
        "route_maps": route_maps,
        "prefix_lists": prefix_lists,
    }
