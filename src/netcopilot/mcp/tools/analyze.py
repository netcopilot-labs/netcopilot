"""analyze_findings — deterministic rule analysis with remediation CLI.

Returns three sections:
  1. SUMMARY: what the rule detects, severity, scope
  2. ANALYSIS: per-device priority ranking with impact and messages
  3. REMEDIATION: OS-specific CLI templates with interpolated values

No LLM — pure deterministic.
"""

import logging
from pathlib import Path

import yaml

from netcopilot.analysis.correlation_engine import area_patterns, blast_radius
from netcopilot.analysis.remediation_loader import get_remediation
from netcopilot.findings import (
    device_from_finding,
    get_device_role,
    get_os_family,
    get_os_map,
    load_findings_enriched,
)

log = logging.getLogger(__name__)

# Cache rule catalog
_RULE_CATALOG: dict[str, dict] | None = None

# The rule catalog shipped as package data alongside the rules engine.
_CATALOG_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "rule-catalog.yaml"


def _get_rule_catalog() -> dict[str, dict]:
    global _RULE_CATALOG
    if _RULE_CATALOG is not None:
        return _RULE_CATALOG
    _RULE_CATALOG = {}
    try:
        import os

        env_path = os.environ.get("RULE_CATALOG_PATH")
        catalog_path = Path(env_path) if env_path else _CATALOG_PATH
        if catalog_path.exists():
            with open(catalog_path) as f:
                rules = yaml.safe_load(f)
            if isinstance(rules, list):
                for r in rules:
                    _RULE_CATALOG[r.get("rule_id", "")] = r
    except Exception as exc:
        log.warning("Failed to load rule catalog: %s", exc)
    return _RULE_CATALOG


async def analyze_findings(
    *,
    rule_id: str,
    device: str | None = None,
    context: dict,
) -> str:
    """Analyze a finding rule: priority ranking, remediation CLI, correlation insights."""
    run_id = context.get("run_id", "")

    findings = load_findings_enriched(run_id)
    if not findings:
        return f"No findings data for run {run_id}."

    # Filter by rule_id — exclude acknowledged findings
    all_rule = [f for f in findings if f.get("rule_id") == rule_id]
    rule_findings = [f for f in all_rule if not f.get("acknowledged")]
    acked_count = len(all_rule) - len(rule_findings)
    if not rule_findings:
        if acked_count > 0:
            return (
                f"All {acked_count} finding(s) for rule '{rule_id}' have been acknowledged "
                f"by the operator. No active (unacknowledged) findings remain for this rule."
            )
        # Suggest similar rules — match prefix (BGP_ → BGP_*) or keyword
        all_rules = sorted(set(f.get("rule_id", "") for f in findings))
        rule_prefix = rule_id.split("_")[0] + "_" if "_" in rule_id else rule_id
        similar = [r for r in all_rules if r.startswith(rule_prefix) or any(
            part in r for part in rule_id.split("_") if len(part) > 3
        )][:10]
        suggestion = f"\nSimilar rules: {', '.join(similar)}" if similar else ""
        return f"Rule '{rule_id}' not found in this run.{suggestion}\nUse get_findings() to discover active rules."

    # Filter by device if specified
    if device:
        rule_findings = [f for f in rule_findings if device_from_finding(f) == device]
        if not rule_findings:
            return f"No {rule_id} findings on device {device}."

    # Group by device
    devices_data: dict[str, list] = {}
    for f in rule_findings:
        dev = device_from_finding(f) or "?"
        devices_data.setdefault(dev, []).append(f)

    severity = rule_findings[0].get("severity", "info")
    title = rule_findings[0].get("title", rule_id)

    # Get OS map and blast radius for priority ranking
    os_map = get_os_map(run_id)
    risk_scores: dict[str, int] = {}
    try:
        br = blast_radius(run_id)
        risk_scores = {i["device"]: i["risk_score"] for i in br}
    except Exception as exc:
        log.warning("Blast radius computation failed for %s: %s", run_id, exc)

    # Sort devices by risk score (highest first)
    priority = sorted(devices_data.keys(), key=lambda d: -risk_scores.get(d, 0))

    # Load rule catalog for description and check_logic
    catalog = _get_rule_catalog()
    rule_info = catalog.get(rule_id, {})

    # ── SECTION 1: SUMMARY ──────────────────────────────────────────
    lines = [
        "═══ SUMMARY ═══",
        f"Rule: {rule_id}",
        f"Title: {title}",
        f"Severity: {severity}",
        f"Scope: {len(rule_findings)} active finding(s) across {len(devices_data)} device(s)"
        + (f" ({acked_count} acknowledged, excluded from analysis)" if acked_count else ""),
        "",
    ]

    desc = rule_info.get("description", "")
    if desc:
        lines.append("What this rule detects:")
        lines.append(f"  {desc}")
        lines.append("")

    check = rule_info.get("check_logic", "")
    if check:
        lines.append("How it works:")
        for cl in check.strip().split("\n"):
            lines.append(f"  {cl.strip()}")
        lines.append("")

    notes = rule_info.get("notes", "")
    if notes:
        lines.append(f"Notes: {notes}")
        lines.append("")

    # ── SECTION 2: ANALYSIS ─────────────────────────────────────────
    lines.append("═══ ANALYSIS ═══")
    lines.append("Priority ranking by blast radius risk (highest impact first):")
    lines.append("")

    for rank, dev_name in enumerate(priority, 1):
        dev_findings = devices_data[dev_name]
        risk = risk_scores.get(dev_name, 0)
        fam = get_os_family(dev_name, run_id)
        dev_role = get_device_role(dev_name, run_id)
        role = f", role: {dev_role}" if dev_role != "unknown" else ""

        lines.append(f"  {rank}. {dev_name} (OS: {fam}{role})")
        lines.append(f"     Findings: {len(dev_findings)} | Risk score: {risk}")

        for f_item in dev_findings[:5]:
            msg = f_item.get("message", "")
            if msg:
                lines.append(f"     • {msg[:200]}{'...' if len(msg) > 200 else ''}")
        if len(dev_findings) > 5:
            lines.append(f"     ... and {len(dev_findings) - 5} more")
        lines.append("")

    # Correlation insights
    try:
        ap = area_patterns(run_id)
        relevant = [i for i in ap if i.get("rule_id") == rule_id][:5]
        if relevant:
            lines.append("Correlation patterns:")
            for ins in relevant:
                lines.append(f"  [{ins.get('type', '?')}] {ins.get('narrative_hint', '')}")
            lines.append("")
    except Exception as exc:
        log.warning("Correlation patterns failed for %s: %s", run_id, exc)

    # ── SECTION 3: REMEDIATION ──────────────────────────────────────
    lines.append("═══ REMEDIATION ═══")

    os_families_seen = set()
    for dev_name in priority:
        os_families_seen.add(get_os_family(dev_name, run_id))

    has_remediation = False
    for fam in sorted(os_families_seen):
        sample_dev = next((d for d in priority if get_os_family(d, run_id) == fam), None)
        key_facts = {}
        if sample_dev:
            key_facts = devices_data[sample_dev][0].get("evidence", {}).get("key_facts", {})

        cli = get_remediation(rule_id, fam, key_facts)
        if not cli:
            cli = get_remediation(rule_id, "generic", key_facts)

        if cli:
            has_remediation = True
            affected = [d for d in priority if get_os_family(d, run_id) == fam]
            lines.append("")
            lines.append(f"For {fam} devices ({', '.join(affected)}):")
            lines.append("```")
            for cli_line in cli.strip().split("\n"):
                lines.append(cli_line)
            lines.append("```")

    if not has_remediation:
        lines.append("  No remediation template available for this rule.")
        lines.append("  Manual investigation required.")

    return "\n".join(lines)
