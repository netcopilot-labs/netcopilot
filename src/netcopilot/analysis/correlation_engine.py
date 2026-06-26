"""Correlation engine — topology-aware risk analysis via Neo4j + findings.

Four analysis functions that cross-reference the network graph with findings
to surface patterns invisible in flat finding lists:

1. auth_surface_analysis  — devices with auth gaps across multiple planes
2. blast_radius           — high-finding devices weighted by neighbor count
3. redundancy_gaps        — device pairs sharing the same vulnerability
4. area_patterns          — OSPF areas where >50% of devices share a gap

Each function returns list[Insight] dicts. compute_insights() orchestrates
all four, merges, and sorts by risk_score descending.

These functions are standalone and tool-callable — they back the
get_systemic_patterns MCP tool.
"""

import logging
from collections import Counter, defaultdict
from typing import Any, TypeAlias

from netcopilot.findings import (
    device_from_finding as _device_from_finding,
    load_findings_enriched,
)
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)

Insight: TypeAlias = dict[str, Any]

# Auth-related rule prefixes for surface analysis
_AUTH_CONTROL_PLANE = {
    "OSPF_INTERFACE_NO_AUTHENTICATION",
    "BGP_NEIGHBOR_NO_PASSWORD",
    "NTP_NO_AUTHENTICATION",
}
_AUTH_MANAGEMENT_PLANE = {
    "NETCONF_NO_ACL",
    "CONFIG_PLAINTEXT_CREDENTIALS",
    "WEAK_PASSWORD_HASH",
    "CIS_XE_1_2_HTTP",
    "CIS_XE_1_2_PRIV",
    "CIS_XE_1_5_SNMP",
    "CIS_XR_1_5_SNMP",
    "CIS_FG_2_4_5",
}
_AUTH_RULES = _AUTH_CONTROL_PLANE | _AUTH_MANAGEMENT_PLANE

# Severity weights for risk scoring
_SEV_WEIGHTS = {"critical": 5, "high": 4, "low": 2, "cis": 1, "info": 0}


def _load_findings(run_id: str) -> list[dict]:
    """Load findings via the canonical Neo4j-first loader (acknowledgement-enriched)."""
    findings = load_findings_enriched(run_id)
    return findings if findings is not None else []


# device_from_finding is the canonical element_id parser shared with the loader.


def _findings_by_device(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by device name."""
    by_device: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        dev = _device_from_finding(f)
        if dev:
            by_device[dev].append(f)
    return dict(by_device)


def _severity_score(findings: list[dict]) -> int:
    """Compute weighted severity score for a list of findings."""
    return sum(_SEV_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)


# ── Analysis functions ───────────────────────────────────────────────────────


def auth_surface_analysis(run_id: str) -> list[Insight]:
    """Flag devices with authentication gaps across multiple security planes.

    A device with OSPF no-auth AND SNMP weak community AND plaintext creds
    has a systemic auth weakness — worse than any single finding suggests.
    """
    findings = _load_findings(run_id)
    by_device = _findings_by_device(findings)
    insights = []

    for device, dev_findings in by_device.items():
        auth_findings = [f for f in dev_findings if f["rule_id"] in _AUTH_RULES]
        if len(auth_findings) < 2:
            continue

        control = [f for f in auth_findings if f["rule_id"] in _AUTH_CONTROL_PLANE]
        mgmt = [f for f in auth_findings if f["rule_id"] in _AUTH_MANAGEMENT_PLANE]

        # Only flag if gaps span multiple planes
        planes_affected = []
        if control:
            planes_affected.append("control")
        if mgmt:
            planes_affected.append("management")

        if len(planes_affected) < 2:
            continue

        rule_ids = sorted(set(f["rule_id"] for f in auth_findings))
        insights.append({
            "type": "auth_surface_gap",
            "device": device,
            "risk_score": len(auth_findings) * 3 + len(planes_affected) * 5,
            "planes": planes_affected,
            "related_rules": rule_ids,
            "finding_count": len(auth_findings),
            "narrative_hint": (
                f"{device} has authentication gaps across {' and '.join(planes_affected)} "
                f"planes ({len(auth_findings)} findings: {', '.join(rule_ids[:3])})"
            ),
            "recommendation": (
                "Prioritize this device for auth hardening — "
                "multi-plane gaps enable lateral movement after initial compromise."
            ),
        })

    return sorted(insights, key=lambda i: -i["risk_score"])


def blast_radius(run_id: str) -> list[Insight]:
    """Calculate blast radius: high-finding devices weighted by neighbor count.

    A device with many findings AND many trusted neighbors is a higher risk
    than an isolated device with the same findings.
    """
    findings = _load_findings(run_id)
    by_device = _findings_by_device(findings)

    # Query Neo4j for neighbor counts
    if not is_available():
        log.warning("Neo4j unavailable — blast_radius skipped")
        return []

    driver = get_driver()
    neighbor_counts: dict[str, int] = {}

    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id})-[link]-(neighbor:Device {run_id: $run_id})
            WHERE link.confidence IN ["high", "very_high"]
              AND type(link) IN [
                "PHYSICAL_CABLE", "MGMT_LINK", "L3_REACHABILITY",
                "INFRASTRUCTURE_LINK", "ROUTING_ADJACENCY"
              ]
            RETURN d.name AS device, count(DISTINCT neighbor) AS neighbor_count
            """,
            run_id=run_id,
        )
        for record in result:
            neighbor_counts[record["device"]] = record["neighbor_count"]

    insights = []
    for device, dev_findings in by_device.items():
        sev_score = _severity_score(dev_findings)
        if sev_score < 5:
            continue

        neighbors = neighbor_counts.get(device, 0)
        risk = sev_score * (1 + neighbors * 0.5)

        sev_breakdown = Counter(f.get("severity", "info") for f in dev_findings)
        sev_str = ", ".join(
            f"{count} {sev}" for sev, count in
            sorted(sev_breakdown.items(), key=lambda x: -_SEV_WEIGHTS.get(x[0], 0))
        )

        insights.append({
            "type": "blast_radius",
            "device": device,
            "risk_score": round(risk),
            "finding_count": len(dev_findings),
            "neighbor_count": neighbors,
            "severity_breakdown": dict(sev_breakdown),
            "narrative_hint": (
                f"{device}: {len(dev_findings)} findings ({sev_str}), "
                f"{neighbors} trusted neighbor(s) — "
                f"compromise risk {'high' if risk > 50 else 'moderate'}"
            ),
            "recommendation": (
                f"Fix critical/high findings on {device} first — "
                f"it connects to {neighbors} device(s)."
            ),
        })

    return sorted(insights, key=lambda i: -i["risk_score"])


def redundancy_gaps(run_id: str) -> list[Insight]:
    """Find device pairs sharing the same vulnerability.

    If both members of a redundancy pair have OSPF_NO_AUTH, the redundancy
    doesn't protect against that attack vector.
    """
    findings = _load_findings(run_id)
    by_device = _findings_by_device(findings)

    if not is_available():
        log.warning("Neo4j unavailable — redundancy_gaps skipped")
        return []

    driver = get_driver()
    pairs: list[tuple[str, str]] = []

    with driver.session() as session:
        result = session.run(
            """
            MATCH (a:Device {run_id: $run_id})-[link]-(b:Device {run_id: $run_id})
            WHERE link.confidence IN ["high", "very_high"]
              AND a.name < b.name
            RETURN DISTINCT a.name AS device_a, b.name AS device_b
            """,
            run_id=run_id,
        )
        pairs = [(r["device_a"], r["device_b"]) for r in result]

    insights = []
    for dev_a, dev_b in pairs:
        rules_a = set(f["rule_id"] for f in by_device.get(dev_a, []))
        rules_b = set(f["rule_id"] for f in by_device.get(dev_b, []))
        shared = rules_a & rules_b

        # Only flag if shared rules include non-info severity
        critical_shared = set()
        for rid in shared:
            sev = next(
                (f.get("severity") for f in by_device.get(dev_a, [])
                 if f["rule_id"] == rid), "info"
            )
            if sev in ("critical", "high", "low", "cis"):
                critical_shared.add(rid)

        if len(critical_shared) < 2:
            continue

        insights.append({
            "type": "redundancy_gap",
            "device": f"{dev_a} / {dev_b}",
            "risk_score": len(critical_shared) * 4,
            "device_a": dev_a,
            "device_b": dev_b,
            "shared_rules": sorted(critical_shared),
            "narrative_hint": (
                f"Redundancy pair {dev_a} + {dev_b} shares "
                f"{len(critical_shared)} vulnerability(s): "
                f"{', '.join(sorted(critical_shared)[:3])}"
            ),
            "recommendation": (
                "Both devices in the pair need remediation — "
                "redundancy does not protect against shared vulnerabilities."
            ),
        })

    return sorted(insights, key=lambda i: -i["risk_score"])


def area_patterns(run_id: str) -> list[Insight]:
    """Find OSPF areas where >50% of devices share the same finding.

    If 4 out of 5 devices in area 0.0.0.10 all lack OSPF authentication,
    that's an area-wide systemic gap, not 4 individual problems.
    """
    findings = _load_findings(run_id)
    by_device = _findings_by_device(findings)

    if not is_available():
        log.warning("Neo4j unavailable — area_patterns skipped")
        return []

    driver = get_driver()
    areas: dict[str, set[str]] = defaultdict(set)

    with driver.session() as session:
        result = session.run(
            """
            MATCH (a:Device {run_id: $run_id})-[adj:ROUTING_ADJACENCY]-(b:Device {run_id: $run_id})
            WHERE adj.protocol = "ospf"
            RETURN adj.area AS area,
                   collect(DISTINCT a.name) + collect(DISTINCT b.name) AS devices
            """,
            run_id=run_id,
        )
        for record in result:
            area = record["area"]
            if area:
                areas[area].update(record["devices"])

    insights = []
    for area, devices in areas.items():
        if len(devices) < 2:
            continue

        # Check which rules affect >50% of area devices
        rule_coverage: dict[str, set[str]] = defaultdict(set)
        for dev in devices:
            for f in by_device.get(dev, []):
                rule_coverage[f["rule_id"]].add(dev)

        for rule_id, affected_devs in rule_coverage.items():
            ratio = len(affected_devs) / len(devices)
            if ratio < 0.5:
                continue

            # Get severity from first finding
            sev = next(
                (f.get("severity") for f in by_device.get(list(affected_devs)[0], [])
                 if f["rule_id"] == rule_id), "info"
            )
            if sev == "info":
                continue

            insights.append({
                "type": "area_pattern",
                "device": f"area {area}",
                "risk_score": round(len(affected_devs) * _SEV_WEIGHTS.get(sev, 1) * ratio * 3),
                "area": area,
                "rule_id": rule_id,
                "affected_count": len(affected_devs),
                "total_devices": len(devices),
                "affected_devices": sorted(affected_devs),
                "coverage_pct": round(ratio * 100),
                "narrative_hint": (
                    f"Area {area}: {rule_id} affects {len(affected_devs)}/{len(devices)} "
                    f"devices ({round(ratio*100)}%) — systemic gap"
                ),
                "recommendation": (
                    f"Fix {rule_id} area-wide in area {area} — "
                    f"individual device fixes won't address the systemic pattern."
                ),
            })

    return sorted(insights, key=lambda i: -i["risk_score"])


# ── Orchestrator ─────────────────────────────────────────────────────────────


def compute_insights(run_id: str) -> list[Insight]:
    """Run all four analysis functions and return merged, sorted insights."""
    all_insights: list[Insight] = []

    all_insights.extend(auth_surface_analysis(run_id))
    all_insights.extend(blast_radius(run_id))
    all_insights.extend(redundancy_gaps(run_id))
    all_insights.extend(area_patterns(run_id))

    # Sort by risk_score descending, deduplicate by narrative_hint
    seen = set()
    unique = []
    for insight in sorted(all_insights, key=lambda i: -i["risk_score"]):
        key = insight.get("narrative_hint", "")
        if key not in seen:
            seen.add(key)
            unique.append(insight)

    return unique
