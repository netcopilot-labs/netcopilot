"""
SVL Degraded Rule — Detect C9500 SVL operating with partial link loss.

When a C9500 SVL stack has multiple SVL links and some (but not all) are
down, the stack is degraded — still functional but at reduced bandwidth
and without full redundancy.

Detection Logic:
    For each device in model["devices"]:
        Collect all SVL entries from stack_ports[]
        If total SVL entries > 1 AND some are down but not all:
            Generate high-severity finding (per device, not per port)

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class SvlDegradedRule(BaseRule):
    """Detect C9500 SVL stacks with partial link loss."""

    rule_id = "SVL_DEGRADED"
    severity = "high"
    title = "SVL Degraded"
    description = "C9500 StackWise Virtual stack has partial SVL link loss"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            stack_ports = device.get("stack_ports", [])

            svl_entries = [
                e for e in stack_ports if e.get("port_type") == "svl"
            ]
            if len(svl_entries) < 2:
                continue

            up_count = sum(
                1 for e in svl_entries if e.get("link_status") == "Up"
            )
            down_count = len(svl_entries) - up_count

            # Degraded = some down but not all (all-down is SVL_LINK_DOWN)
            if 0 < down_count < len(svl_entries):
                down_intfs = [
                    e.get("interface", "?")
                    for e in svl_entries
                    if e.get("link_status") != "Up"
                ]
                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"SVL stack is degraded: "
                        f"{down_count} of {len(svl_entries)} SVL links are "
                        f"down ({', '.join(down_intfs)}). Operating at "
                        f"reduced inter-switch bandwidth."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "total_svl_links": len(svl_entries),
                        "up_count": up_count,
                        "down_count": down_count,
                        "down_interfaces": down_intfs,
                    },
                    recommendation=(
                        "Restore the failed SVL links to recover full "
                        "inter-switch bandwidth. Check cables, transceivers, "
                        "and port status on both switches. Schedule "
                        "maintenance to replace failed components."
                    ),
                )
                findings.append(finding)

        return findings
