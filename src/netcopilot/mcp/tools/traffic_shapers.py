"""get_traffic_shapers — query QoS traffic shaping/policing from Neo4j.

Queries Interface nodes for qos_* properties populated by the graph loader
from genie policy-map facts. Shows policer/shaper type, CIR rates, and
drop/exceed counters.
"""

import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


def _format_bps(bps: int | None) -> str:
    """Format bps as human-readable Mbps or Gbps."""
    if bps is None:
        return "N/A"
    if bps >= 1_000_000_000:
        gbps = bps / 1_000_000_000
        return f"{gbps:g} Gbps"
    return f"{bps / 1_000_000:g} Mbps"


def _has_issues(rec: dict) -> bool:
    """Check if interface has non-zero drops or exceed."""
    return bool(rec.get("out_drops")) or bool(rec.get("in_exceed"))


async def get_traffic_shapers(
    *,
    device: str | None = None,
    policy_name: str | None = None,
    min_rate: int | None = None,
    context: dict,
) -> str:
    """Query QoS traffic shaping and policing policies from Interface nodes."""
    run_id = context.get("run_id", "")

    if not is_available():
        return "Neo4j is unavailable. QoS queries require the graph database."

    driver = get_driver()

    # Build dynamic WHERE clauses
    conditions = [
        "i.run_id = $run_id",
        "(i.qos_input_policy_name IS NOT NULL OR i.qos_output_policy_name IS NOT NULL)",
    ]
    params: dict = {"run_id": run_id}

    if device:
        conditions.append("toLower(d.name) CONTAINS toLower($device)")
        params["device"] = device

    if policy_name:
        conditions.append(
            "(toLower(i.qos_input_policy_name) CONTAINS toLower($policy) "
            "OR toLower(i.qos_output_policy_name) CONTAINS toLower($policy))"
        )
        params["policy"] = policy_name

    where = " AND ".join(conditions)

    with driver.session() as session:
        result = session.run(
            f"MATCH (d:Device {{run_id: $run_id}})-[:HAS_INTERFACE]->(i:Interface) "
            f"WHERE {where} "
            "RETURN d.name AS device, d.role AS role, "
            "i.name AS interface, i.description AS description, "
            "i.qos_input_policy_name AS in_policy, i.qos_input_cir_bps AS in_cir, "
            "i.qos_output_policy_name AS out_policy, i.qos_output_cir_bps AS out_cir, "
            "i.qos_output_queue_drops AS out_drops, "
            "i.qos_input_exceed_bytes AS in_exceed "
            "ORDER BY d.name, i.name",
            **params,
        )
        records = [dict(r) for r in result]

    # Post-filter: min_rate (Mbps)
    if min_rate is not None:
        threshold = min_rate * 1_000_000
        records = [
            r for r in records
            if (r.get("in_cir") and r["in_cir"] >= threshold)
            or (r.get("out_cir") and r["out_cir"] >= threshold)
        ]

    if not records:
        filters = []
        if device:
            filters.append(f"device={device}")
        if policy_name:
            filters.append(f"policy_name={policy_name}")
        if min_rate is not None:
            filters.append(f"min_rate={min_rate} Mbps")
        hint = f" for {', '.join(filters)}" if filters else ""
        return f"No QoS policies found{hint} in run {run_id}."

    # Group by device
    devices: dict[str, list[dict]] = {}
    for r in records:
        devices.setdefault(r["device"], []).append(r)

    # Summary mode: no device filter, >2 devices
    if not device and len(devices) > 2:
        return _format_summary(records, devices)

    return _format_detail(records, devices)


def _format_summary(records: list[dict], devices: dict[str, list[dict]]) -> str:
    """Per-policy aggregation for network-wide view."""
    lines = [f"QoS policy summary ({len(records)} interfaces across {len(devices)} devices):"]
    lines.append("")

    # Group by output policy name (most common direction for shaping)
    policies: dict[str, dict] = {}
    for r in records:
        for direction, key_policy, key_cir in [
            ("output", "out_policy", "out_cir"),
            ("input", "in_policy", "in_cir"),
        ]:
            pname = r.get(key_policy)
            if not pname:
                continue
            if pname not in policies:
                policies[pname] = {"count": 0, "devices": set(), "cir": r.get(key_cir), "issues": 0}
            policies[pname]["count"] += 1
            policies[pname]["devices"].add(r["device"])
            if _has_issues(r):
                policies[pname]["issues"] += 1

    # Sort by CIR descending
    for pname, info in sorted(policies.items(), key=lambda x: x[1].get("cir") or 0, reverse=True):
        cir = _format_bps(info["cir"])
        issue_flag = f" [!] {info['issues']} with drops/exceed" if info["issues"] else ""
        lines.append(
            f"  {pname}: {info['count']} interfaces on {len(info['devices'])} device(s) @ {cir}{issue_flag}"
        )

    # Count issues
    total_issues = sum(1 for r in records if _has_issues(r))
    lines.append("")
    if total_issues:
        lines.append(f"Interfaces with active drops/exceed: {total_issues}")
    lines.append("Use get_traffic_shapers(device='X') for per-interface detail.")

    return "\n".join(lines)


def _format_detail(records: list[dict], devices: dict[str, list[dict]]) -> str:
    """Per-interface QoS detail for one or few devices."""
    lines = []
    total_issues = 0
    MAX_PER_DEVICE = 50

    for dev, dev_records in sorted(devices.items()):
        role = dev_records[0].get("role", "")
        role_str = f" ({role})" if role else ""
        lines.append(f"QoS on {dev}{role_str} ({len(dev_records)} interfaces):")
        lines.append("")

        show = dev_records[:MAX_PER_DEVICE]
        truncated = len(dev_records) - len(show)

        for r in show:
            intf = r.get("interface", "?")
            desc = r.get("description") or ""
            if len(desc) > 40:
                desc = desc[:37] + "..."
            desc_str = f" \"{desc}\"" if desc else ""

            flag = " [!]" if _has_issues(r) else ""
            if _has_issues(r):
                total_issues += 1

            lines.append(f"  {intf}{desc_str}{flag}")

            # Input policy
            in_pol = r.get("in_policy")
            if in_pol:
                in_cir = _format_bps(r.get("in_cir"))
                in_exceed = r.get("in_exceed")
                exceed_str = f", exceed: {in_exceed} bytes" if in_exceed else ""
                lines.append(f"    IN:  {in_pol} @ {in_cir}{exceed_str}")

            # Output policy
            out_pol = r.get("out_policy")
            if out_pol:
                out_cir = _format_bps(r.get("out_cir"))
                out_drops = r.get("out_drops")
                drops_str = f", drops: {out_drops}" if out_drops else ""
                lines.append(f"    OUT: {out_pol} @ {out_cir}{drops_str}")

        if truncated:
            lines.append(f"  ... and {truncated} more (use policy_name filter to narrow)")
        lines.append("")

    if total_issues:
        lines.append(f"Interfaces with active drops/exceed: {total_issues}")

    return "\n".join(lines).strip()
