"""explain_finding — rule explanation and OS-specific remediation CLI.

Uses the remediation loader to interpolate CLI templates from the rule catalog.
"""

import logging

from netcopilot.analysis.remediation_loader import _load_catalog, get_remediation
from netcopilot.findings import get_os_family, load_findings_enriched

log = logging.getLogger(__name__)


async def explain_finding(
    *,
    rule_id: str,
    device: str | None = None,
    context: dict,
) -> str:
    """Get explanation and OS-specific remediation CLI for a finding rule."""
    run_id = context.get("run_id", "")
    catalog = _load_catalog()

    rule = catalog.get(rule_id)
    if not rule:
        # Suggest similar rules — match rule_id prefix (e.g., BGP_ matches BGP_*)
        rule_prefix = rule_id.split("_")[0] + "_" if "_" in rule_id else rule_id
        similar = [
            rid for rid in catalog
            if rid.startswith(rule_prefix) or any(
                part in rid for part in rule_id.split("_") if len(part) > 3
            )
        ]
        if similar:
            suggestions = ", ".join(sorted(similar)[:10])
            return (
                f"Rule '{rule_id}' not found in catalog.\n"
                f"Similar rules: {suggestions}\n"
                "Use get_findings() to discover active rule IDs in this run."
            )
        return (
            f"Rule '{rule_id}' not found in catalog.\n"
            "Use get_findings(category='...') to discover active rule IDs."
        )

    # Build explanation
    lines = [
        f"Rule: {rule_id}",
        f"  Title: {rule.get('title', rule_id)}",
        f"  Severity: {rule.get('severity', '?')}",
    ]

    if rule.get("description"):
        lines.append(f"  Description: {rule['description']}")

    if rule.get("impact"):
        lines.append(f"  Impact: {rule['impact']}")

    if rule.get("references"):
        refs = rule["references"]
        if isinstance(refs, list):
            lines.append(f"  References: {', '.join(refs[:3])}")

    # Get active findings via the canonical Neo4j-first loader.
    all_findings = load_findings_enriched(run_id) or []
    active_findings = [f for f in all_findings if f.get("rule_id") == rule_id]
    if device:
        active_for_device = [
            f for f in active_findings
            if device in str(f.get("evidence", {}).get("element_id", ""))
            or device in str(f.get("finding_id", ""))
        ]
    else:
        active_for_device = active_findings

    if active_for_device:
        lines.extend(["", f"Active in this run ({len(active_for_device)} finding(s)):"])
        for f in active_for_device[:5]:
            eid = f.get("evidence", {}).get("element_id", "?")
            msg = f.get("message", "")
            lines.append(f"  {eid}: {msg[:150]}{'...' if len(msg) > 150 else ''}")

    # Get remediation CLI
    if "remediation" in rule:
        os_family = "generic"
        if device:
            os_family = get_os_family(device, run_id)

        # key_facts from first matching finding for template interpolation
        key_facts = {}
        if active_for_device:
            key_facts = active_for_device[0].get("evidence", {}).get("key_facts", {})

        cli = get_remediation(rule_id, os_family, key_facts)
        if not cli and os_family != "generic":
            cli = get_remediation(rule_id, "generic", key_facts)

        if cli:
            os_label = os_family if device else "generic"
            lines.extend(["", f"Remediation CLI ({os_label}):", cli])
        else:
            lines.extend(["", "Remediation: template available but no CLI for this OS."])
            available_os = list(rule["remediation"].keys())
            lines.append(f"  Available for: {', '.join(available_os)}")
    else:
        lines.extend(["", "Remediation: no CLI template in catalog for this rule."])

    return "\n".join(lines)
