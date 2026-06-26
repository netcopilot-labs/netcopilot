"""get_firewall_policies — query firewall policies from Neo4j.

Queries FirewallPolicy nodes created by the graph loader from
fortigate_firewall_policy.json (FortiGate) and genie_acl.json (Cisco ACLs).
Addresses, services, and zones are pre-resolved at load time.
"""

import json
import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_firewall_policies(
    *,
    device: str | None = None,
    source_zone: str | None = None,
    dest_zone: str | None = None,
    action: str | None = None,
    service: str | None = None,
    context: dict,
) -> str:
    """Query firewall policies from Neo4j FirewallPolicy nodes."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. Firewall policy queries require the graph database."

    driver = get_driver()

    # Build dynamic WHERE clauses
    conditions = ["p.run_id = $run_id"]
    params: dict = {"run_id": run_id}

    if device:
        # Substring match for shorthand names
        conditions.append("toLower(p.device) CONTAINS toLower($device)")
        params["device"] = device

    if action:
        conditions.append("toLower(p.action) = toLower($action)")
        params["action"] = action

    where = " AND ".join(conditions)

    # Scope Device by run_id so a multi-run Neo4j filters before traversing,
    # rather than walking all devices and filtering on p.run_id afterward.
    with driver.session() as session:
        result = session.run(
            f"MATCH (d:Device {{run_id: $run_id}})-[:HAS_POLICY]->(p:FirewallPolicy) "
            f"WHERE {where} "
            "RETURN p.policyid AS id, p.name AS name, p.status AS status, "
            "p.action AS action, p.policy_type AS type, "
            "p.srcintf AS srcintf, p.dstintf AS dstintf, "
            "p.src_zones AS src_zones, p.dst_zones AS dst_zones, "
            "p.srcaddr AS srcaddr, p.dstaddr AS dstaddr, "
            "p.service AS service, p.nat AS nat, "
            "p.src_negate AS src_negate, p.dst_negate AS dst_negate, "
            "p.service_negate AS service_negate, "
            "p.device AS device, p.comments AS comments "
            "ORDER BY p.device, p.seq",
            **params,
        )
        policies = [dict(r) for r in result]

    if not policies:
        filters = []
        if device:
            filters.append(f"device={device}")
        if action:
            filters.append(f"action={action}")
        return f"No firewall policies found{' for ' + ', '.join(filters) if filters else ''} in run {run_id}."

    # Post-filter by zone (stored as arrays on FortiGate, not on ACLs)
    if source_zone:
        sz_lower = source_zone.lower()
        policies = [
            p for p in policies
            if not p.get("src_zones") or any(sz_lower in z.lower() for z in p["src_zones"])
            or (p.get("srcintf") and sz_lower in p["srcintf"].lower())
        ]

    if dest_zone:
        dz_lower = dest_zone.lower()
        policies = [
            p for p in policies
            if not p.get("dst_zones") or any(dz_lower in z.lower() for z in p["dst_zones"])
            or (p.get("dstintf") and dz_lower in p["dstintf"].lower())
        ]

    # Post-filter by service
    if service:
        svc_lower = service.lower()
        policies = [
            p for p in policies
            if p.get("service") and svc_lower in p["service"].lower()
        ]

    if not policies:
        return f"No policies match the specified zone/service filters."

    # Format output
    lines = []

    # Group by device
    devices = {}
    for p in policies:
        dev = p.get("device", "?")
        devices.setdefault(dev, []).append(p)

    # If no device filter and many devices, show summary instead of full dump
    if not device and len(devices) > 2:
        lines.append(f"Firewall policy summary ({len(policies)} total across {len(devices)} devices):")
        lines.append("")
        for dev, dev_policies in sorted(devices.items()):
            fg = sum(1 for p in dev_policies if p["type"] == "fortigate")
            acl = sum(1 for p in dev_policies if p["type"] == "acl")
            deny = sum(1 for p in dev_policies if p["action"] in ("deny", "DENY"))
            permit = sum(1 for p in dev_policies if p["action"] in ("accept", "permit", "ACCEPT", "PERMIT"))
            type_str = f"{fg} FortiGate" if fg else f"{acl} ACL"
            # SF-DENY-1: FortiGate's implicit deny-all is not a policy row, so a
            # default-deny box would read "0 deny" — surface it explicitly.
            implicit = " + implicit deny-all" if fg else ""
            lines.append(f"  {dev}: {type_str} ({permit} permit, {deny} deny{implicit})")
        lines.append("")
        lines.append("Use get_firewall_policies(device='<name>') to see policies for a specific device.")
        return "\n".join(lines)

    # Cap output per device
    MAX_POLICIES_PER_DEVICE = 30

    for dev, dev_policies in sorted(devices.items()):
        fg_count = sum(1 for p in dev_policies if p["type"] == "fortigate")
        acl_count = sum(1 for p in dev_policies if p["type"] == "acl")
        type_label = []
        if fg_count:
            type_label.append(f"{fg_count} FortiGate")
        if acl_count:
            type_label.append(f"{acl_count} ACL")
        lines.append(f"Firewall policies on {dev} ({', '.join(type_label)}):")
        lines.append("")

        show_policies = dev_policies[:MAX_POLICIES_PER_DEVICE]
        truncated = len(dev_policies) - len(show_policies)

        for p in show_policies:
            pid = p.get("id", "?")
            name = p.get("name", "")
            act = p.get("action", "?")
            status = p.get("status", "")

            if p["type"] == "fortigate":
                # Parse srcintf/dstintf JSON for display
                try:
                    src_intfs = json.loads(p.get("srcintf", "[]"))
                    dst_intfs = json.loads(p.get("dstintf", "[]"))
                except (json.JSONDecodeError, TypeError):
                    src_intfs = []
                    dst_intfs = []

                src_display = ", ".join(
                    f"{i.get('name', '?')}" + (f" [{i['zone']}]" if i.get("zone") else "")
                    for i in src_intfs
                ) or "any"
                dst_display = ", ".join(
                    f"{i.get('name', '?')}" + (f" [{i['zone']}]" if i.get("zone") else "")
                    for i in dst_intfs
                ) or "any"

                srcaddr = p.get("srcaddr", "any")
                dstaddr = p.get("dstaddr", "any")
                svc = p.get("service", "ALL")
                nat_str = " [NAT]" if p.get("nat") == "enable" else ""
                status_str = " (disabled)" if status == "disable" else ""

                lines.append(
                    f"  [{act.upper()}] id:{pid} {name}{status_str}{nat_str}"
                )
                lines.append(f"    {src_display} → {dst_display}")
                # Truncate long addresses
                if len(srcaddr) > 80:
                    srcaddr = srcaddr[:77] + "..."
                if len(dstaddr) > 80:
                    dstaddr = dstaddr[:77] + "..."
                # SF-NEGATE-1: surface an enabled negate — it inverts the match
                # (everything EXCEPT the listed value), so it must not read as normal.
                src_neg = " [NEGATED: match all EXCEPT]" if p.get("src_negate") else ""
                dst_neg = " [NEGATED: match all EXCEPT]" if p.get("dst_negate") else ""
                svc_neg = " [NEGATED: match all EXCEPT]" if p.get("service_negate") else ""
                lines.append(f"    src: {srcaddr}{src_neg}")
                lines.append(f"    dst: {dstaddr}{dst_neg}")
                lines.append(f"    service: {svc}{svc_neg}")
            else:
                # ACL entry
                srcaddr = p.get("srcaddr", "any")
                dstaddr = p.get("dstaddr", "any")
                svc = p.get("service", "any")
                lines.append(f"  [{act.upper()}] seq:{pid} {name} — {srcaddr} → {dstaddr} svc:{svc}")

        if truncated:
            lines.append(f"  ... and {truncated} more policies (use action/zone/service filters to narrow)")
        # SF-DENY-1: make FortiGate's default-deny posture explicit in the detail view.
        if fg_count:
            lines.append("  [DENY] implicit deny-all (default — traffic not matched above is dropped)")
        lines.append("")

    return "\n".join(lines).strip()
