"""
STP Topology Change — Deep Python rule for the hybrid rule engine.

Replace surface YAML eval block with threshold-based
Python rule. One topology change is normal (maintenance, reload). Many
changes suggest instability. Add time decay — only fire if the last topology
change was within MAX_AGE (default 24 hours). Old events (weeks/months ago)
are historical, not actionable.

Detection Logic:
    Iterates over STP VLAN instances. Only fires when:
    1. topology_changes > 3 (count threshold), AND
    2. time_since_topology_change < 24 hours (recency check)
    Severity scales with count: 4-10 → medium, >10 → high.

Rule ID: STP_TOPOLOGY_CHANGE_RECENT
Severity: medium or high (threshold-based)
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


# Topology change count thresholds
_TC_MIN_THRESHOLD = 3      # No finding at or below this count
_TC_HIGH_THRESHOLD = 10    # Above this → high severity

# Time decay: only fire if last topology change was within this window
_MAX_AGE_SECONDS = 86400   # 24 hours


def _parse_time_since_to_seconds(time_str: str) -> int | None:
    """
    Parse Genie time_since_topology_change to seconds.

    Observed formats:
        "15w0d"     → 15 weeks + 0 days = 9,072,000 seconds
        "2d5h"      → 2 days + 5 hours
        "00:12:35"  → HH:MM:SS = 755 seconds
        "never"     → None
        "unknown"   → None

    Returns:
        Seconds since last topology change, or None if unparseable.
    """
    if not time_str:
        return None
    s = str(time_str).strip().lower()
    if s in ("unknown", "never", ""):
        return None

    # Format: "XwYd" (weeks and days)
    m = re.match(r"(\d+)w(\d+)d", s)
    if m:
        weeks, days = int(m.group(1)), int(m.group(2))
        return (weeks * 7 * 86400) + (days * 86400)

    # Format: "XdYh" (days and hours)
    m = re.match(r"(\d+)d(\d+)h", s)
    if m:
        days, hours = int(m.group(1)), int(m.group(2))
        return (days * 86400) + (hours * 3600)

    # Format: "XhYm" (hours and minutes)
    m = re.match(r"(\d+)h(\d+)m", s)
    if m:
        hours, mins = int(m.group(1)), int(m.group(2))
        return (hours * 3600) + (mins * 60)

    # Format: "HH:MM:SS"
    parts = s.split(":")
    if len(parts) == 3:
        try:
            h, mi, sec = int(parts[0]), int(parts[1]), int(parts[2])
            return h * 3600 + mi * 60 + sec
        except ValueError:
            return None

    return None


class StpTopologyChangeRule(BaseRule):
    """Detects STP VLANs with excessive recent topology changes."""

    rule_id = "STP_TOPOLOGY_CHANGE_RECENT"
    severity = "low"
    title = "STP Excessive Topology Changes"
    description = "STP VLAN has recent topology changes above normal threshold"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_stp")
            if not data:
                continue

            # Genie STP structure: {rapid_pvst: {<default>: {vlans: {<id>: {...}}}}}
            # Also handles: {mstp: {<id>: {vlans: ...}}} or similar
            for mode_name, mode_data in data.items():
                if not isinstance(mode_data, dict):
                    continue
                for inst_name, inst_data in mode_data.items():
                    if not isinstance(inst_data, dict):
                        continue
                    vlans = inst_data.get("vlans", {})
                    if not isinstance(vlans, dict):
                        continue
                    for vlan_id, vlan_data in vlans.items():
                        if not isinstance(vlan_data, dict):
                            continue
                        tc_count = vlan_data.get("topology_changes", 0)
                        try:
                            tc_count = int(tc_count)
                        except (ValueError, TypeError):
                            continue

                        if tc_count <= _TC_MIN_THRESHOLD:
                            continue

                        # time decay — skip old events
                        time_since = vlan_data.get(
                            "time_since_topology_change", "unknown"
                        )
                        age_seconds = _parse_time_since_to_seconds(
                            str(time_since)
                        )
                        if age_seconds is not None and age_seconds > _MAX_AGE_SECONDS:
                            continue  # Historical event, not actionable

                        # Scale severity by count
                        sev = "high" if tc_count > _TC_HIGH_THRESHOLD else "low"

                        findings.append(Finding.create(
                            rule_id=self.rule_id,
                            severity=sev,
                            title=self.title,
                            element_type="device",
                            element_id=f"{hostname}/stp/vlan/{vlan_id}/topology-change",
                            message=(
                                f"STP VLAN {vlan_id} has {tc_count} topology "
                                f"changes (threshold: >{_TC_MIN_THRESHOLD})"
                            ),
                            key_facts={
                                "vlan_id": vlan_id,
                                "topology_changes": tc_count,
                                "time_since_topology_change": str(time_since),
                                "mode": mode_name,
                            },
                            recommendation=(
                                "Investigate cause of frequent STP topology changes — "
                                "check for flapping ports, misconfigured BPDUs, or loops"
                            ),
                        ))

        return findings
