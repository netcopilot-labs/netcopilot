"""
Stack Bandwidth Degraded Rule — Detect SVL bandwidth reduction.

When SVL links go down on a C9500, the available inter-switch bandwidth
is reduced. This rule fires when the device has SVL links but some are
down, indicating reduced bandwidth capacity.

This is separate from SVL_DEGRADED because it focuses on the bandwidth
impact rather than the link-level status.

Detection Logic:
    For each device with SVL entries:
        Count total vs up SVL links
        If any SVL links are down: bandwidth is degraded

Note: Actual bandwidth values from genie_svl_bandwidth.json are not yet
parsed into stack_ports. When available, this rule can compare against
expected bandwidth thresholds. For now, it infers degradation from
link status.

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class StackBandwidthDegradedRule(BaseRule):
    """Detect SVL bandwidth degradation from down SVL links."""

    rule_id = "STACK_BANDWIDTH_DEGRADED"
    severity = "low"
    title = "Stack Bandwidth Degraded"
    description = "C9500 SVL inter-switch bandwidth is reduced due to down links"

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
            if not svl_entries:
                continue

            up_count = sum(
                1 for e in svl_entries if e.get("link_status") == "Up"
            )
            total = len(svl_entries)
            down_count = total - up_count

            if down_count > 0 and up_count > 0:
                # Estimate bandwidth: each SVL link contributes equal share
                bandwidth_pct = round(up_count / total * 100)
                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"SVL stack is operating at "
                        f"~{bandwidth_pct}% inter-switch bandwidth "
                        f"({up_count}/{total} SVL links up). "
                        f"{down_count} link(s) down."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "total_svl_links": total,
                        "up_count": up_count,
                        "down_count": down_count,
                        "estimated_bandwidth_pct": bandwidth_pct,
                    },
                    recommendation=(
                        "Restore failed SVL links to recover full "
                        "inter-switch bandwidth. The stack is functional "
                        "but performance-sensitive workloads may be affected "
                        "by the reduced capacity."
                    ),
                )
                findings.append(finding)

        return findings
