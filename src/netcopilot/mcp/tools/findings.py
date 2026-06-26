"""get_findings — deterministic rule-engine findings, queried from Neo4j."""

import logging

from netcopilot.findings import (
    SEVERITY_ORDER,
    device_from_finding,
    load_findings_enriched,
)

log = logging.getLogger(__name__)


# Category → rule_id prefix mapping
CATEGORY_PREFIXES: dict[str, list[str]] = {
    "bgp": ["BGP_"],
    "ospf": ["OSPF_"],
    "security": ["CIS_", "WEAK_", "NETCONF_", "SNMP_", "AUTH_"],
    "interface": ["INTF_"],
    "topology": ["TOPO_", "LINK_"],
    "routing": ["ROUTE_", "VRF_", "STATIC_"],
    "cluster": ["CLUSTER_", "HA_", "STACK_"],
    "qos": ["QOS_"],
}


def _matches_category(rule_id: str, category: str) -> bool:
    """Check if a rule_id matches the given category."""
    prefixes = CATEGORY_PREFIXES.get(category, [])
    return any(rule_id.startswith(p) for p in prefixes)


async def get_findings(
    *,
    device: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    acknowledged: bool | None = None,
    limit: int = 20,
    context: dict,
) -> str:
    """Get deterministic rule-engine findings with optional filters."""
    run_id = context.get("run_id", "")
    findings = load_findings_enriched(run_id)

    if findings is None:
        return f"No findings data found for run {run_id}."

    # Apply filters
    filtered = findings

    if device:
        filtered = [
            f for f in filtered
            if device_from_finding(f) == device
            or device in (f.get("evidence", {}).get("key_facts", {}).get("involved_devices", ""))
        ]

    if category == "cross_device":
        filtered = [f for f in filtered if f.get("cross_device")]
    elif category:
        filtered = [
            f for f in filtered
            if _matches_category(f.get("rule_id", ""), category)
        ]

    if acknowledged is not None:
        filtered = [
            f for f in filtered
            if f.get("acknowledged", False) == acknowledged
        ]

    # Snapshot before the severity filter so an empty severity result can report
    # which severities DO exist (deterministic anti-inflation: stops the model
    # relabelling a 'high' as 'critical' when zero criticals exist). Filters are
    # AND-composed, so applying severity last is identical.
    without_severity = filtered
    if severity:
        filtered = [f for f in filtered if f.get("severity") == severity]

    total = len(filtered)

    # Sort by severity weight (critical first), then stable secondary keys so the
    # top-N truncation is deterministic across runs. Without the tie-breakers,
    # same-severity findings come back in arbitrary Neo4j order, making the
    # "Showing 20 of N" cutoff non-reproducible.
    sev_order = SEVERITY_ORDER
    filtered.sort(
        key=lambda f: (
            sev_order.get(f.get("severity", "info"), 5),
            f.get("rule_id", ""),
            device_from_finding(f) or "",
            # element_id (or finding_id) as the final tiebreaker so multiple
            # findings of the same rule on the same device still order stably.
            f.get("evidence", {}).get("element_id", "") if isinstance(f.get("evidence"), dict) else "",
        )
    )

    # Compute counts from ALL filtered findings BEFORE applying limit
    all_filtered = filtered

    # Apply limit for individual display only
    truncated = total > limit
    displayed = filtered[:limit]

    if not all_filtered:
        parts = ["No findings found"]
        if device:
            parts.append(f"for device {device}")
        if severity:
            parts.append(f"with severity {severity}")
        if category:
            parts.append(f"in category {category}")
        msg = " ".join(parts) + f" in run {run_id}."
        if severity and without_severity:
            dist: dict[str, int] = {}
            for f in without_severity:
                s = f.get("severity", "info")
                dist[s] = dist.get(s, 0) + 1
            dist_str = ", ".join(
                f"{v} {k}" for k, v in sorted(
                    dist.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 5))
            )
            msg += (f" No finding is at severity '{severity}'. Severities "
                    f"actually present (matching other filters): {dist_str}.")
        return msg

    # Count by severity (from ALL filtered findings, not just limited)
    sev_counts: dict[str, int] = {}
    for f in all_filtered:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Count per device (from ALL filtered findings)
    dev_counts: dict[str, dict[str, int]] = {}
    for f in all_filtered:
        dev = device_from_finding(f) or "?"
        s = f.get("severity", "info")
        if dev not in dev_counts:
            dev_counts[dev] = {}
        dev_counts[dev][s] = dev_counts[dev].get(s, 0) + 1

    # Count per rule (from ALL filtered findings)
    rule_counts: dict[str, int] = {}
    for f in all_filtered:
        r = f.get("rule_id", "?")
        rule_counts[r] = rule_counts.get(r, 0) + 1

    # Count acked
    acked_count = sum(1 for f in all_filtered if f.get("acknowledged"))

    # Build header
    header_parts = [f"Findings — run: {run_id}"]
    if device:
        header_parts.append(f"device: {device}")
    if severity:
        header_parts.append(f"severity: {severity}")
    if category:
        header_parts.append(f"category: {category}")
    sev_summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items(),
                            key=lambda x: sev_order.get(x[0], 5)))
    ack_note = f", {acked_count} acknowledged" if acked_count else ""
    header_parts.append(f"total: {total} ({sev_summary}{ack_note})")

    lines = [" | ".join(header_parts), ""]

    # Per-device breakdown (always show, exact counts)
    lines.append("By device:")
    for dev, counts in sorted(dev_counts.items(),
                              key=lambda x: sum(x[1].values()), reverse=True):
        dev_total = sum(counts.values())
        sev_parts = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(),
                              key=lambda x: sev_order.get(x[0], 5)))
        lines.append(f"  {dev}: {dev_total} ({sev_parts})")
    lines.append("")

    # Per-rule breakdown
    lines.append("By rule:")
    sorted_rules = sorted(rule_counts.items(), key=lambda x: -x[1])
    for rule, count in sorted_rules[:15]:
        lines.append(f"  {rule}: {count}")
    if len(sorted_rules) > 15:
        lines.append(f"  ... and {len(sorted_rules) - 15} more rules")
    lines.append("")

    # Individual findings (limited)
    lines.append(f"Details ({len(displayed)} of {total}):")
    for f in displayed:
        sev = f.get("severity", "info").upper()
        rule = f.get("rule_id", "?")
        dev = device_from_finding(f) or "?"
        msg = f.get("message", "")
        ack = " [ACK]" if f.get("acknowledged") else ""

        lines.append(f"[{sev}] {rule}{ack}")
        lines.append(f"  Device: {dev}")
        if msg:
            lines.append(f"  {msg[:200]}{'...' if len(msg) > 200 else ''}")
        lines.append("")

    if truncated:
        lines.append(f"[Showing {limit} of {total} — add filters to narrow results]")

    return "\n".join(lines)
