"""get_systemic_patterns — systemic security patterns across the network.

Detects patterns that span multiple devices — not individual findings,
but how findings interact across redundant pairs, security domains,
and OSPF/BGP areas. blast_radius is excluded (has its own tool).
"""

import logging

from netcopilot.analysis.correlation_engine import compute_insights
from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_systemic_patterns(
    *,
    insight_type: str | None = None,
    device: str | None = None,
    context: dict,
) -> str:
    """Get systemic security patterns across the network."""
    run_id = context.get("run_id", "")

    # Resolve device name if provided
    if device:
        if not is_available():
            return "Neo4j unavailable."
        import re
        filt = device.lower()
        if '-' not in filt:
            filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
        driver = get_driver()
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

    # Get all insights from correlation engine
    try:
        all_insights = compute_insights(run_id)
    except Exception as exc:
        log.warning("Correlation engine failed: %s", exc)
        return f"Correlation engine error: {exc}"

    if not all_insights:
        return "No correlation insights available for this run."

    # Filter out blast_radius (has its own tool)
    insights = [i for i in all_insights if i.get("type") != "blast_radius"]

    # Map user-friendly names to engine type names
    _TYPE_MAP = {
        "auth_surface": "auth_surface_gap",
        "shared_vulnerabilities": "redundancy_gap",
        "area_patterns": "area_pattern",
    }
    valid_types = set(_TYPE_MAP.keys())

    if insight_type:
        if insight_type not in valid_types:
            return (
                f"Unknown insight type '{insight_type}'. "
                f"Valid types: {', '.join(sorted(valid_types))}"
            )
        engine_type = _TYPE_MAP[insight_type]
        insights = [i for i in insights if i.get("type") == engine_type]

    # Filter by device
    if device:
        insights = [i for i in insights
                    if device in str(i.get("device", ""))
                    or device in str(i.get("narrative_hint", ""))]

    if not insights:
        msg = "No correlation insights found"
        if insight_type:
            msg += f" for type '{insight_type}'"
        if device:
            msg += f" for device '{device}'"
        return msg + "."

    # Group by type
    by_type: dict[str, list] = {}
    for i in insights:
        by_type.setdefault(i.get("type", "other"), []).append(i)

    lines = [f"Correlation insights — {len(insights)} total"]
    if device:
        lines[0] += f" (filtered to {device})"
    lines.append("")

    type_labels = {
        "auth_surface_gap": "Multi-Plane Authentication Gaps",
        "redundancy_gap": "Shared Vulnerabilities Between Redundant Pairs",
        "area_pattern": "Area-Wide Systemic Patterns (OSPF/BGP)",
    }

    for itype, items in sorted(by_type.items()):
        label = type_labels.get(itype, itype)
        lines.append(f"{label} ({len(items)}):")

        # Sort by risk score descending
        items.sort(key=lambda x: -(x.get("risk_score", 0) or 0))

        for item in items[:15]:
            dev = item.get("device", "")
            risk = item.get("risk_score", 0)
            hint = item.get("narrative_hint", "")
            rec = item.get("recommendation", "")

            lines.append(f"  {dev} (risk: {risk})")
            if hint:
                lines.append(f"    {hint}")
            if rec:
                lines.append(f"    → {rec}")

        if len(items) > 15:
            lines.append(f"  ... and {len(items) - 15} more")
        lines.append("")

    return "\n".join(lines)
