"""get_ospf_detail — OSPF process, area, neighbor, and authentication data.

Reads genie_ospf.json per device (from the run's facts dir) and queries Neo4j for
OSPF adjacencies and SharedService area membership. Returns structured OSPF state.
"""

import json
import logging
from pathlib import Path

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_ospf_detail(
    *,
    device: str | None = None,
    area: str | None = None,
    context: dict,
) -> str:
    """Get OSPF detail: processes, areas, interfaces, neighbors, authentication."""
    run_id = context.get("run_id", "")
    data_dir = context.get("data_dir", "")

    if not is_available():
        return "Neo4j unavailable. OSPF queries require the graph database."

    driver = get_driver()
    lines = []

    # If device specified, show that device's OSPF data
    if device:
        # Resolve device name
        import re
        filt = device.lower()
        if '-' not in filt:
            filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt "
                "RETURN d.name AS name LIMIT 1",
                run_id=run_id, filt=filt,
            )
            rec = result.single()
            if rec:
                device = rec["name"]
            else:
                return f"Device '{device}' not found."

        # Load genie_ospf.json
        ospf_path = Path(data_dir) / "facts" / device / "genie_ospf.json"
        if not ospf_path.exists():
            return f"No OSPF data for device '{device}'."

        try:
            data = json.loads(ospf_path.read_text())
        except (json.JSONDecodeError, OSError):
            return f"Failed to read OSPF data for '{device}'."

        lines.append(f"OSPF Detail — {device}")
        lines.append("")

        vrf_data = data.get("vrf", data)
        for vrf_name, vrf_info in vrf_data.items():
            for af_name, af_info in vrf_info.get("address_family", {}).items():
                for proc_id, proc_info in af_info.get("instance", {}).items():
                    rid = proc_info.get("router_id", "?")
                    lines.append(f"Process {proc_id} (Router ID: {rid}, VRF: {vrf_name})")

                    # Process-level settings
                    gr = proc_info.get("graceful_restart", {})
                    gr_enabled = gr.get("cisco", {}).get("enable", False) if isinstance(gr, dict) else False
                    spf = proc_info.get("spf_control", {}).get("throttle", {}).get("spf", {})
                    db = proc_info.get("database_control", {})
                    lines.append(f"  Graceful restart: {gr_enabled}")
                    if spf:
                        lines.append(f"  SPF throttle: start={spf.get('start','?')}ms hold={spf.get('hold','?')}ms max={spf.get('maximum','?')}ms")
                    if db.get("max_lsa"):
                        lines.append(f"  Max LSA: {db['max_lsa']}")
                    lines.append("")

                    # Areas
                    for area_id, area_info in proc_info.get("areas", {}).items():
                        if area and area_id != area:
                            continue
                        area_type = area_info.get("area_type", "normal")
                        stats = area_info.get("statistics", {})
                        lines.append(f"  Area {area_id} ({area_type})")
                        if stats:
                            lines.append(f"    SPF runs: {stats.get('spf_runs_count', '?')}, LSAs: {stats.get('area_scope_lsa_count', '?')}")

                        # Interfaces in this area
                        for intf_name, intf_info in area_info.get("interfaces", {}).items():
                            cost = intf_info.get("cost", "?")
                            net_type = intf_info.get("interface_type", intf_info.get("network_type", "?"))
                            state = intf_info.get("state", "?")
                            passive = intf_info.get("passive", False)
                            hello = intf_info.get("hello_interval", "?")
                            dead = intf_info.get("dead_interval", "?")
                            auth = "none"
                            auth_info = intf_info.get("authentication")
                            if auth_info and isinstance(auth_info, dict):
                                trailer_key = auth_info.get("auth_trailer_key")
                                if trailer_key and isinstance(trailer_key, dict):
                                    crypto = trailer_key.get("crypto_algorithm", "")
                                    if crypto:
                                        auth = crypto
                                key_chain = auth_info.get("auth_trailer_key_chain")
                                if auth == "none" and key_chain and isinstance(key_chain, dict):
                                    if key_chain.get("key_chain", ""):
                                        auth = "key-chain"

                            status = "passive" if passive else state
                            lines.append(f"    {intf_name}: cost={cost} type={net_type} status={status} hello={hello} dead={dead} auth={auth}")

                            # Neighbors on this interface
                            for neigh_id, neigh_info in intf_info.get("neighbors", {}).items():
                                n_state = neigh_info.get("state", "?")
                                n_addr = neigh_info.get("address", "?")
                                lines.append(f"      Neighbor {neigh_id} ({n_addr}): {n_state}")
                        lines.append("")

    # If area specified (without device), show area membership.
    # The same area number can exist in multiple VRFs (e.g. area 0 in RED and
    # BLUE are distinct OSPF backbones); group by VRF so the two are never
    # silently merged into one membership list (R1 Phase 2/O4).
    if area and not device:
        lines.append(f"OSPF Area {area} — Membership")
        lines.append("")
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id})-[:MEMBER_OF]->"
                "(s:SharedService {service_type: 'ospf_area', identifier: $area, run_id: $run_id}) "
                "RETURN d.name AS device, d.role AS role, "
                "coalesce(s.vrf, 'default') AS vrf, s.process_id AS process_id "
                "ORDER BY vrf, d.name",
                run_id=run_id, area=area,
            )
            members = [dict(r) for r in result]

        # OSPF adjacencies in this area
        with driver.session() as session:
            result = session.run(
                "MATCH (d1:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]->(d2:Device {run_id: $run_id}) "
                "WHERE r.protocol = 'ospf' AND r.area = $area "
                "RETURN d1.name AS src, d2.name AS dst, r.state AS state, "
                "r.interface_a AS intf_a, r.interface_b AS intf_b, "
                "coalesce(r.vrf, 'default') AS vrf "
                "ORDER BY vrf, d1.name",
                run_id=run_id, area=area,
            )
            adjs = [dict(r) for r in result]

        if not members and not adjs:
            lines.append(f"No devices found in OSPF area {area}.")
        else:
            # Group both members and adjacencies by VRF, then render per-VRF.
            vrfs = sorted({m["vrf"] for m in members} | {a["vrf"] for a in adjs})
            multi_vrf = len(vrfs) > 1
            for vrf in vrfs:
                v_members = [m for m in members if m["vrf"] == vrf]
                v_adjs = [a for a in adjs if a["vrf"] == vrf]
                if multi_vrf:
                    lines.append(f"VRF {vrf}:")
                proc = next((m.get("process_id") for m in v_members if m.get("process_id")), None)
                proc_label = f" — process {proc}" if proc else ""
                lines.append(f"Devices in area {area} ({len(v_members)}){proc_label}:")
                for m in v_members:
                    lines.append(f"  {m['device']} ({m.get('role', '?')})")
                if v_adjs:
                    lines.append(f"Adjacencies in area {area} ({len(v_adjs)}):")
                    for a in v_adjs:
                        lines.append(f"  {a['src']} ({a.get('intf_a','?')}) ↔ {a['dst']} ({a.get('intf_b','?')}): {a.get('state','?')}")
                lines.append("")

    # If neither device nor area, show all OSPF areas overview
    if not device and not area:
        lines.append("OSPF Areas Overview")
        lines.append("")
        with driver.session() as session:
            result = session.run(
                "MATCH (s:SharedService {service_type: 'ospf_area', run_id: $run_id}) "
                "OPTIONAL MATCH (d:Device)-[:MEMBER_OF]->(s) "
                "WITH s, collect(d.name) AS members "
                "RETURN s.identifier AS area_id, s.area_type AS area_type, "
                "s.vrf AS vrf, s.process_id AS process_id, "
                "s.spf_runs AS spf_runs, s.lsa_count AS lsa_count, "
                "members "
                "ORDER BY s.identifier",
                run_id=run_id,
            )
            areas = [dict(r) for r in result]

        if not areas:
            lines.append("No OSPF areas found.")
        else:
            lines.append(f"Total areas: {len(areas)}")
            lines.append("")
            for a in areas:
                member_list = ", ".join(sorted(a.get("members", [])))
                lines.append(f"  Area {a['area_id']} ({a.get('area_type', 'normal')})")
                lines.append(f"    VRF: {a.get('vrf', 'default')} | Process: {a.get('process_id', '?')}")
                lines.append(f"    SPF runs: {a.get('spf_runs', '?')} | LSAs: {a.get('lsa_count', '?')}")
                lines.append(f"    Members: {member_list}")
                lines.append("")

    return "\n".join(lines)
