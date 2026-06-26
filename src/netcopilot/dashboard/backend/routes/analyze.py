"""Analyze endpoint — deterministic per-rule analysis with CLI remediation.

GET /api/analyze/{run_id}/{rule_id}

Returns instant JSON (no LLM, no GPU, <500ms) with:
- All affected devices with per-device finding count
- Interpolated CLI remediation per device/OS
- Correlation insights (blast radius, area patterns)
- Priority ranking by topology-weighted risk

This is the "Analyze" button response in the Findings tab.
"""

import logging
import os
from collections import defaultdict
from pathlib import Path

from fastapi import APIRouter, HTTPException

from netcopilot.findings import device_from_finding
from netcopilot.analysis.correlation_engine import (
    _findings_by_device,
    _load_findings,
    blast_radius,
    area_patterns,
)
from netcopilot.analysis.remediation_loader import enrich_key_facts, get_remediation
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)
router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

# Cache device os_type per run_id
_OS_CACHE: dict[str, dict[str, str]] = {}


def _get_device_os_map(run_id: str) -> dict[str, str]:
    """Get os_type map for all devices from Neo4j, cached per run."""
    if run_id in _OS_CACHE:
        return _OS_CACHE[run_id]

    os_map: dict[str, str] = {}
    if is_available():
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "RETURN d.name AS name, d.os_type AS os_type",
                run_id=run_id,
            )
            for record in result:
                if record["name"] and record["os_type"]:
                    os_map[record["name"]] = record["os_type"]

    _OS_CACHE[run_id] = os_map
    return os_map


def _os_type_to_os_family(os_type: str) -> str:
    """Map os_type (from network_model) to remediation os_family key."""
    mapping = {
        "iosxe": "ios_xe",
        "ios-xe": "ios_xe",
        "ios_xe": "ios_xe",
        "iosxr": "iosxr",
        "ios-xr": "iosxr",
        "ios_xr": "iosxr",
        "nxos": "nxos",
        "fortios": "fortios",
        "fortigate": "fortios",
    }
    return mapping.get(os_type.lower(), os_type.lower()) if os_type else "generic"


@router.get("/api/analyze/{run_id}/{rule_id}")
async def analyze_rule(run_id: str, rule_id: str):
    """Return deterministic analysis for a specific rule across all devices."""
    findings = _load_findings(run_id)
    if not findings:
        raise HTTPException(status_code=404, detail=f"No findings for run {run_id}")

    # Filter findings for this rule
    rule_findings = [f for f in findings if f["rule_id"] == rule_id]
    if not rule_findings:
        raise HTTPException(status_code=404, detail=f"No findings for rule {rule_id}")

    # Group by device
    devices_data = defaultdict(list)
    for f in rule_findings:
        dev = device_from_finding(f)
        if dev:
            devices_data[dev].append(f)

    # Get severity from first finding
    severity = rule_findings[0].get("severity", "info")

    # Build per-device response with remediation
    os_map = _get_device_os_map(run_id)
    devices_response = []
    for device_name, dev_findings in sorted(devices_data.items()):
        os_type = os_map.get(device_name, "unknown")
        os_family = _os_type_to_os_family(os_type)

        # Get remediation for first finding (templates are per-rule, not per-finding)
        first_kf = dev_findings[0].get("evidence", {}).get("key_facts", {})
        remediation_cli = get_remediation(rule_id, os_family, first_kf)

        # If os_family-specific template missing, try generic
        if not remediation_cli:
            remediation_cli = get_remediation(rule_id, "generic", first_kf)

        devices_response.append({
            "device_id": device_name,
            "os_family": os_family,
            "finding_count": len(dev_findings),
            "findings": [
                {
                    "finding_id": f.get("finding_id"),
                    "message": f.get("message"),
                    "key_facts": f.get("evidence", {}).get("key_facts", {}),
                }
                for f in dev_findings[:10]  # Limit to 10 per device for response size
            ],
            "remediation_cli": remediation_cli,
        })

    # Get correlation insights for affected devices
    affected_device_names = set(devices_data.keys())
    br_insights = blast_radius(run_id)
    ap_insights = area_patterns(run_id)

    # Filter to relevant insights
    device_insights = [
        i for i in br_insights
        if i.get("device") in affected_device_names
    ]
    pattern_insights = [
        i for i in ap_insights
        if i.get("rule_id") == rule_id
    ]

    # Priority ranking: sort devices by blast_radius risk_score
    risk_scores = {i["device"]: i["risk_score"] for i in br_insights}
    priority = sorted(
        affected_device_names,
        key=lambda d: -risk_scores.get(d, 0),
    )

    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": rule_findings[0].get("title", rule_id),
        "findings_count": len(rule_findings),
        "devices": devices_response,
        "device_insights": device_insights[:5],
        "pattern_insights": pattern_insights[:5],
        "priority": priority,
    }
