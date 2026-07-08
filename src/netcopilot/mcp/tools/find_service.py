"""find_service — where an operator-named service lives on the network (s16).

Reads the run's :Service rows (the NetBox×observation join, ADR-0019): the
declared meaning (dns_name/description/tenant) plus the observed location
(device/interface via ARP/FDB, gateway-approximate via subnet, or honestly
never-seen). ``no_data`` when the join has not run for the run — an absent
layer is not an empty network.
"""

from __future__ import annotations

import logging

from netcopilot.graph.client import get_driver, is_available
from netcopilot.mcp.result import ToolResult

log = logging.getLogger(__name__)

_METHOD_WORDING = {
    "arp+fdb": "port-precise (ARP + MAC table on the access port)",
    "arp": "gateway-resolved (ARP; the exact access port was not derivable)",
    "subnet": "approximate (no ARP seen — placed by the gateway's subnet)",
    "colocated": "approximate (placed on the switch its VLAN neighbours were "
                 "observed on — the host itself wasn't seen)",
    "gateway": "gateway (an interface serves exactly this network)",
    "gateway-containing": "approximate (a gateway serves part of this range — "
                          "the declared prefix is an aggregate)",
    "none": "NEVER SEEN by the network (documented in NetBox, no observation)",
}


def _render(svc: dict) -> list[str]:
    if svc.get("kind") == "network":
        return _render_network(svc)
    lines = [f"Service: {svc.get('name')}", ""]
    lines.append(f"  IP:          {svc.get('address') or svc.get('ip')}")
    if svc.get("dns_name"):
        lines.append(f"  DNS name:    {svc['dns_name']}")
    if svc.get("description"):
        lines.append(f"  Description: {svc['description']}")
    for label, key in (("Tenant", "tenant"), ("Role", "role"), ("VRF", "vrf")):
        if svc.get(key):
            lines.append(f"  {label + ':':<12} {svc[key]}")
    if svc.get("tags"):
        lines.append(f"  Tags:        {', '.join(svc['tags'])}")
    lines.append("")
    method = svc.get("location_method", "none")
    if svc.get("located"):
        where = f"{svc.get('device')}"
        if method == "arp+fdb" and svc.get("interface"):
            where += f", port {svc['interface']}"
        elif svc.get("interface"):
            where += f" (via {svc['interface']})"
        lines.append(f"  Location:    {where}")
        lines.append(f"  Confidence:  {_METHOD_WORDING.get(method, method)}")
        if svc.get("mac"):
            lines.append(f"  MAC:         {svc['mac']}")
        if svc.get("via_host"):   # s18: virtualized
            hv = svc.get("hypervisor") or "multi-endpoint"
            n = svc.get("host_endpoint_count")
            lines.append(f"  Virtualized: yes — {hv} host on {svc['via_host']}"
                         + (f" ({n} VMs behind this port)" if n else ""))
        if (svc.get("observer_count") or 0) > 1:
            lines.append(f"  Observers:   {svc['observer_count']} devices resolve this IP")
    else:
        lines.append(f"  Location:    {_METHOD_WORDING['none']}")
        lines.append("               Check whether the device is offline, moved, or the "
                     "NetBox record is stale.")
    if svc.get("joined_at"):
        lines.append(f"  Joined:      {svc['joined_at']} (re-run the service join after "
                     "changes in NetBox)")
    return lines


def _render_network(svc: dict) -> list[str]:
    """A client network (s17): a range the operator serves — located by its
    gateway(s), never by inner hosts (the operator declared they don't know
    them)."""
    lines = [f"Client network: {svc.get('name')}", ""]
    lines.append(f"  Prefix:      {svc.get('ip')}")
    for label, key in (("Role", "role"), ("VRF", "vrf")):
        if svc.get(key):
            lines.append(f"  {label + ':':<12} {svc[key]}")
    lines.append("")
    if svc.get("located"):
        gws = svc.get("gateways") or (
            [f"{svc.get('device')}/{svc.get('interface')}"] if svc.get("device") else [])
        lines.append(f"  Connected at: {', '.join(gws)}")
        lines.append(f"  Confidence:  {_METHOD_WORDING.get(svc.get('location_method'), svc.get('location_method'))}")
    else:
        lines.append(f"  Location:    {_METHOD_WORDING['none']}")
        lines.append("               No collected interface serves this range — check "
                     "whether the gateway device is collected, or the prefix is stale.")
    if svc.get("joined_at"):
        lines.append(f"  Joined:      {svc['joined_at']} (re-run the service join after "
                     "changes in NetBox)")
    return lines


async def find_service(
    *,
    name: str | None = None,
    ip: str | None = None,
    context: dict,
) -> ToolResult:
    """Locate an operator-named service by name or IP."""
    run_id = context.get("run_id", "")

    if not name and not ip:
        return ToolResult("error", "find_service needs a service name or an IP address.")
    if not is_available():
        return ToolResult("error", "Neo4j is unavailable. The service layer lives in the graph.")

    driver = get_driver()
    with driver.session() as session:
        total = session.run(
            "MATCH (s:Service {run_id: $run_id}) RETURN count(s) AS n",
            run_id=run_id,
        ).single()["n"]
        if total == 0:
            return ToolResult("no_data", (
                f"The service layer has not been joined for run {run_id} — no :Service "
                "rows exist (which is different from 'no services'). Run "
                "`netcopilot netbox services <run_id>` or POST /api/services/join, "
                "with NetBox reachable."
            ))

        if ip:
            rows = [dict(r["s"]) for r in session.run(
                "MATCH (s:Service {run_id: $run_id, ip: $ip}) RETURN s",
                run_id=run_id, ip=ip.strip().split("/")[0],
            )]
        else:
            rows = [dict(r["s"]) for r in session.run(
                "MATCH (s:Service {run_id: $run_id}) "
                "WHERE toLower(s.name) CONTAINS toLower($q) "
                "   OR toLower(coalesce(s.dns_name, '')) CONTAINS toLower($q) "
                "   OR toLower(coalesce(s.description, '')) CONTAINS toLower($q) "
                "RETURN s ORDER BY s.name",
                run_id=run_id, q=name.strip(),
            )]

        if not rows:
            known = [r["n"] for r in session.run(
                "MATCH (s:Service {run_id: $run_id}) RETURN s.name AS n ORDER BY s.name LIMIT 8",
                run_id=run_id,
            )]
            hint = f" Known services: {', '.join(known)}." if known else ""
            return ToolResult("not_found", (
                f"No service matches {(name or ip)!r} in run {run_id}.{hint}"
            ))

    if len(rows) > 1:
        lines = [f"{len(rows)} services match {(name or ip)!r}:", ""]
        for s in rows:
            loc = s.get("device") or "never seen"
            lines.append(f"  {s.get('name'):<32} {s.get('ip'):<16} → {loc} "
                         f"({s.get('location_method')})")
        lines.append("")
        lines.append("Narrow the name (or query by IP) for the full detail.")
        return ToolResult("ok", "\n".join(lines),
                          verdict={"matches": len(rows), "ambiguous": True})

    svc = rows[0]
    verdict = {
        "service": svc.get("name"),
        "ip": svc.get("ip"),
        "located": bool(svc.get("located")),
        "location_method": svc.get("location_method"),
        "device": svc.get("device"),
        "interface": svc.get("interface"),
    }
    highlight = {"device": svc["device"]} if svc.get("device") else None
    return ToolResult("ok", "\n".join(_render(svc)), verdict=verdict, highlight=highlight)
