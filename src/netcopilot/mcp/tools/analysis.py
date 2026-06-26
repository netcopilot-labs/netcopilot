"""blast_radius — impact of a device failure (directly affected devices + links lost).

Full-failure analysis. The source's cluster/HA member-level analysis is deferred to a
later phase (it needs cluster modelling the synthetic seed doesn't carry).
"""

from __future__ import annotations

import logging

from netcopilot.correlation import blast_radius as _blast_radius
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def blast_radius(
    *,
    device: str,
    member: int | None = None,
    interface: str | None = None,
    max_hops: int = 3,
    context: dict,
) -> str:
    """Analyse the impact of a device failure: directly affected devices + links lost."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Blast radius analysis requires the topology graph."

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
                return (
                    f"Device '{device}' not found in run {run_id}. "
                    "Use query_topology to list available devices."
                )
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

    return _analyze_full_failure(device, all_links, device_insights)


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
