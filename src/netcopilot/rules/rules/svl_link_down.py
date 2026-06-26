"""
SVL Link Down Rule — Detect C9500 StackWise Virtual links that are down.

An SVL link with link_status "Down" means that specific port has lost
connectivity to the peer switch. If this is the only SVL link, the
stack has lost all inter-switch communication — a critical failure.

Detection Logic:
    For each device in model["devices"]:
        Filter stack_ports[] for port_type == "svl"
        For each SVL entry with link_status == "Down":
            Generate critical finding

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class SvlLinkDownRule(BaseRule):
    """Detect C9500 SVL links with Down status."""

    rule_id = "SVL_LINK_DOWN"
    severity = "critical"
    title = "SVL Link Down"
    description = "C9500 StackWise Virtual link is down"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            stack_ports = device.get("stack_ports", [])

            for entry in stack_ports:
                if entry.get("port_type") != "svl":
                    continue

                link_status = entry.get("link_status", "")
                if link_status == "Down":
                    member_id = entry.get("member_id", 0)
                    interface = entry.get("interface", "unknown")
                    svl_id = entry.get("svl_id", 0)
                    finding = Finding.create(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        element_type="device",
                        element_id=hostname,
                        message=(
                            f"SVL link {interface} (SVL {svl_id}) "
                            f"member {member_id} is Down. "
                            f"Inter-switch connectivity may be lost."
                        ),
                        key_facts={
                            "hostname": hostname,
                            "member_id": member_id,
                            "svl_id": svl_id,
                            "interface": interface,
                            "link_status": link_status,
                            "protocol_status": entry.get("protocol_status", ""),
                        },
                        recommendation=(
                            "Check the SVL link cable and transceiver on both "
                            "ends. Verify the peer switch is operational. If "
                            "this is the only SVL link, the stack has lost "
                            "inter-switch connectivity — restore immediately."
                        ),
                        member_id=member_id,
                    )
                    findings.append(finding)

        return findings
