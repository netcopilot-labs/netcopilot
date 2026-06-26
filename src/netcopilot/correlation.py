"""Correlation analysis — the blast-radius risk computation.

A subset of the source correlation engine: just the blast-radius insight used by the
blast_radius tool. Other insight families (auth surface, redundancy, area patterns)
land in later phases.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from .findings import device_from_finding, load_findings_enriched
from .graph.client import get_driver, is_available

log = logging.getLogger(__name__)

_SEV_WEIGHTS = {"critical": 5, "high": 4, "low": 2, "cis": 1, "info": 0}


def _load_findings(run_id: str) -> list[dict]:
    findings = load_findings_enriched(run_id)
    return findings if findings is not None else []


def _findings_by_device(findings: list[dict]) -> dict[str, list[dict]]:
    by_device: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        dev = device_from_finding(f)
        if dev:
            by_device[dev].append(f)
    return dict(by_device)


def _severity_score(findings: list[dict]) -> int:
    return sum(_SEV_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)


def blast_radius(run_id: str) -> list[dict]:
    """Risk insights: high-finding devices weighted by trusted-neighbor count.

    A device with many findings AND many trusted neighbors is higher risk than an
    isolated device with the same findings.
    """
    by_device = _findings_by_device(_load_findings(run_id))

    if not is_available():
        log.warning("Neo4j unavailable — blast_radius skipped")
        return []

    neighbor_counts: dict[str, int] = {}
    with get_driver().session() as session:
        result = session.run(
            """
            MATCH (d:Device {run_id: $run_id})-[link]-(neighbor:Device {run_id: $run_id})
            // Count high-confidence links; if a network doesn't tag confidence, count the link
            // anyway (BYO-robust — the source assumed a confidence property we don't require).
            WHERE (link.confidence IS NULL OR link.confidence IN ["high", "very_high"])
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

    insights: list[dict] = []
    for device, dev_findings in by_device.items():
        sev_score = _severity_score(dev_findings)
        if sev_score < 5:
            continue
        neighbors = neighbor_counts.get(device, 0)
        risk = sev_score * (1 + neighbors * 0.5)
        sev_breakdown = Counter(f.get("severity", "info") for f in dev_findings)
        sev_str = ", ".join(
            f"{count} {sev}"
            for sev, count in sorted(sev_breakdown.items(), key=lambda x: -_SEV_WEIGHTS.get(x[0], 0))
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
