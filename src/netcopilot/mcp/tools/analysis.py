"""blast_radius — impact of a device failure (directly affected devices + links lost).

Full-failure analysis. The source's cluster/HA member-level analysis is deferred to a
later phase (it needs cluster modelling the synthetic seed doesn't carry).
"""

from __future__ import annotations

import json
import logging

from netcopilot.correlation import blast_radius as _blast_radius
from netcopilot.graph.client import get_driver, is_available

from netcopilot.mcp.result import ToolResult

log = logging.getLogger(__name__)


async def blast_radius(
    *,
    device: str,
    member: int | None = None,
    interface: str | None = None,
    max_hops: int = 3,
    context: dict,
) -> ToolResult:
    """Analyse the impact of a device failure: directly affected devices + links lost."""
    run_id = context.get("run_id", "")

    if not is_available():
        return ToolResult("error", "Neo4j is unavailable. Blast radius analysis requires the topology graph.")

    driver = get_driver()
    with driver.session() as session:
        record = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $name}) RETURN d.name AS name",
            run_id=run_id, name=device,
        ).single()
        if not record:
            record = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS toLower($name) "
                "RETURN d.name AS name LIMIT 1",
                run_id=run_id, name=device,
            ).single()
            if not record:
                return ToolResult("not_found", (
                    f"Device '{device}' not found in run {run_id}. "
                    "Use query_topology to list available devices."
                ))
        device = record["name"]

    device_insights = [i for i in _blast_radius(run_id) if i.get("device") == device]

    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id, name: $name})-[link]-(n:Device {run_id: $run_id})
            WHERE type(link) IN ['PHYSICAL_CABLE', 'INFRASTRUCTURE_LINK', 'ROUTING_ADJACENCY']
            RETURN n.name AS neighbor, n.role AS role, type(link) AS link_type,
                   link.bgp_type AS bgp_type, link.local_as AS local_as,
                   link.remote_as AS remote_as
            ORDER BY n.name
            """,
            run_id=run_id, name=device,
        )
        all_links = [dict(r) for r in result]

    risk = device_insights[0].get("risk_score", 0) if device_insights else 0
    risk_level = "HIGH" if risk > 50 else "MODERATE" if risk > 20 else "LOW"

    # Affected neighbours + internet impact — already computed for the text;
    # surface them in the machine-readable verdict + the map highlight (the
    # blast area), not just the failed node.
    affected = sorted({n["neighbor"] for n in all_links})
    transit_losses = sorted({
        n["neighbor"] for n in all_links if n.get("bgp_type") == "transit"
    })

    highlight = {"device": device, "affected": affected}
    if member is not None:
        highlight["failedMember"] = member

    # Operator-named services (s16, ADR-0019): what actually DIES when this
    # device fails, in the operator's own words — services residing on the
    # failed device, plus services on the affected neighbours (at risk).
    with driver.session() as session:
        svc_total = session.run(
            "MATCH (s:Service {run_id: $run_id}) RETURN count(s) AS n",
            run_id=run_id,
        ).single()["n"]
        svc_rows = [dict(r) for r in session.run(
            "MATCH (s:Service {run_id: $run_id})-[:RESIDES_ON]->(d:Device {run_id: $run_id}) "
            "WHERE d.name IN $names "
            "OPTIONAL MATCH (s)-[:REACHED_VIA]->(i:Interface) "
            "RETURN s.name AS name, s.ip AS ip, s.location_method AS method, "
            "       d.name AS device, i.name AS port "
            "ORDER BY s.name",
            run_id=run_id, names=[device] + affected,
        )]

    svc_on_device = [s for s in svc_rows if s["device"] == device]
    svc_at_risk = [s for s in svc_rows if s["device"] != device]
    if interface is not None:
        # Port scoping: only port-precise services can be attributed to one
        # interface — approximate (arp/subnet) locations honestly can't.
        from netcopilot.model.interface_normalizer import normalize_interface_name
        want = normalize_interface_name(interface)
        svc_on_device = [s for s in svc_on_device if s.get("port") == want]

    svc_lines: list[str] = ["", "Operator-named services (NetBox × observed):"]
    if svc_total == 0:
        svc_lines.append(
            "  Service layer not joined for this run — impact on named services is "
            "unknown, not zero (run `netcopilot netbox services <run_id>`)."
        )
    else:
        if interface is not None:
            svc_lines.append(f"  On port {interface} of {device}: "
                             + (", ".join(f"{s['name']} ({s['ip']})" for s in svc_on_device)
                                or "none port-precise (approximate locations can't be "
                                   "attributed to a single port)"))
        elif svc_on_device:
            svc_lines.append(f"  LOST with {device}:")
            svc_lines.extend(f"    {s['name']} ({s['ip']}, {s['method']}"
                             + (f", port {s['port']}" if s.get("port") else "") + ")"
                             for s in svc_on_device)
        else:
            svc_lines.append(f"  None resides on {device}.")
        if svc_at_risk:
            svc_lines.append("  At risk on affected neighbours:")
            svc_lines.extend(f"    {s['name']} ({s['ip']}) on {s['device']}"
                             for s in svc_at_risk)

    # First-hop gateway redundancy (s20): if the failed device is an FHRP
    # member, a surviving peer keeps the gateway VIP alive on failover — the
    # blast to gateways is smaller than the link list suggests. If it is the
    # only member, the VIP is LOST: a distinct, often worse, impact than a
    # plain neighbour count conveys.
    with driver.session() as session:
        fhrp_rows = [dict(r) for r in session.run(
            "MATCH (d:Device {run_id: $run_id, name: $name})"
            "-[:MEMBER_OF]->(s:SharedService {service_type: 'fhrp_group', run_id: $run_id}) "
            "RETURN s.protocol AS protocol, s.group_number AS grp, s.vip AS vip, "
            "s.interface AS interface, s.members_json AS members_json "
            "ORDER BY s.interface, s.group_number",
            run_id=run_id, name=device,
        )]
    fhrp_protected: list[str] = []
    fhrp_lost: list[str] = []
    fhrp_lines: list[str] = []
    if fhrp_rows:
        fhrp_lines.append("")
        fhrp_lines.append("First-hop gateway redundancy (FHRP):")
        for g in fhrp_rows:
            try:
                members = json.loads(g["members_json"]) if g.get("members_json") else []
            except (json.JSONDecodeError, TypeError):
                members = []
            proto = (g.get("protocol") or "fhrp").upper()
            survivors = [m.get("hostname") for m in members if m.get("hostname") != device]
            label = f"{proto} group {g.get('grp')} (VIP {g.get('vip')}) on {g.get('interface')}"
            if survivors:
                fhrp_lines.append(
                    f"  ✓ {label}: PROTECTED — {', '.join(survivors)} still serve(s) the VIP on failover.")
                fhrp_protected.append(g.get("vip"))
            else:
                fhrp_lines.append(
                    f"  ⚠ {label}: GATEWAY LOST — {device} is the only FHRP member; "
                    "no standby survives the failure.")
                fhrp_lost.append(g.get("vip"))

    text = _analyze_full_failure(device, all_links, device_insights)
    text += "\n" + "\n".join(svc_lines)
    if fhrp_lines:
        text += "\n" + "\n".join(fhrp_lines)
    # Link/neighbour analysis still models a FULL device failure; interface=
    # scopes the service attribution only, max_hops remains unmodelled.
    disclosures = []
    if interface is not None:
        disclosures.append(f"interface={interface} scopes the service list only — "
                           "the link analysis models a full device failure")
    if max_hops != 3:
        disclosures.append(f"max_hops={max_hops} not applied (hop scoping is not "
                           "yet supported)")
    if disclosures:
        text = f"Note: {'; '.join(disclosures)}.\n\n" + text

    verdict = {
        "risk_level": risk_level,
        "score": risk,
        "affected_neighbors": len(affected),
        "internet_impact": len(transit_losses),
        "services_lost": len(svc_on_device),
        "services_at_risk": len(svc_at_risk),
        "service_layer_joined": svc_total > 0,
        "fhrp_gateways_protected": len(fhrp_protected),
        "fhrp_gateways_lost": len(fhrp_lost),
    }

    return ToolResult(
        "ok",
        text,
        verdict=verdict,
        highlight=highlight,
    )


def _analyze_full_failure(
    device: str,
    all_links: list[dict],
    device_insights: list[dict],
    related: list[dict] | None = None,
) -> str:
    """Analyse a full device failure: risk summary + directly affected neighbours."""
    related = related or []
    lines = [f"Blast radius — {device}"]

    if device_insights:
        insight = device_insights[0]
        risk = insight.get("risk_score", 0)
        risk_level = "HIGH" if risk > 50 else "MODERATE" if risk > 20 else "LOW"
        lines.append(f"Risk: {risk_level} (score: {risk})")
        lines.append(f"Findings: {insight.get('finding_count', 0)}")
        sev = insight.get("severity_breakdown", {})
        if sev:
            sev_str = ", ".join(
                f"{v} {k}"
                for k, v in sorted(
                    sev.items(),
                    key=lambda x: -{"critical": 5, "high": 4, "low": 2, "info": 0}.get(x[0], 0),
                )
            )
            lines.append(f"Severity: {sev_str}")
    else:
        lines.append("Risk: LOW (no significant findings)")

    if all_links:
        by_neighbor: dict[str, dict] = {}
        for n in all_links:
            name = n["neighbor"]
            if name not in by_neighbor:
                by_neighbor[name] = {
                    "role": n.get("role", ""),
                    "link_types": set(),
                    "bgp_type": None,
                    "remote_as": None,
                }
            by_neighbor[name]["link_types"].add(n["link_type"])
            if n.get("bgp_type"):
                by_neighbor[name]["bgp_type"] = n["bgp_type"]
                by_neighbor[name]["remote_as"] = n.get("local_as") or n.get("remote_as")

        unique_count = len(by_neighbor)
        lines.extend(["", f"Affected devices ({unique_count}):"])
        for name, info in sorted(by_neighbor.items()):
            role = f" ({info['role']})" if info["role"] else ""
            links = ", ".join(sorted(info["link_types"]))
            bgp_label = ""
            if info["bgp_type"] == "transit":
                bgp_label = f" [eBGP TRANSIT — AS{info['remote_as']}, internet provider]"
            elif info["bgp_type"] == "peering":
                bgp_label = f" [eBGP PEERING — AS{info['remote_as']}, direct interconnect]"
            lines.append(f"  {name}{role} — {links}{bgp_label}")

        transit_losses = [
            name for name, info in by_neighbor.items() if info["bgp_type"] == "transit"
        ]
        if transit_losses:
            lines.append("")
            lines.append(
                f"⚠ INTERNET IMPACT: losing {len(transit_losses)} eBGP transit "
                f"session(s) to: {', '.join(transit_losses)}. "
                "Check if other border routers provide redundant internet paths."
            )

        lines.append("")
        lines.append(
            f"If {device} fails, {unique_count} directly connected device(s) would be affected."
        )

    if related:
        lines.extend(["", "Related patterns:"])
        for r in related[:5]:
            lines.append(f"  [{r['type']}] {r.get('narrative_hint', '')}")

    if device_insights:
        rec = device_insights[0].get("recommendation", "")
        if rec:
            lines.extend(["", f"Recommendation: {rec}"])

    return "\n".join(lines)
