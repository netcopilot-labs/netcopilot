"""
DAD Link Down Rule — Detect C9500 Dual Active Detection links that are down.

DAD (Dual Active Detection) prevents split-brain scenarios in StackWise
Virtual. If all DAD links are down, the stack has no way to detect a
dual-active condition after an SVL failure — both switches could become
active simultaneously, causing network loops and conflicts.

Detection Logic:
    For each device in model["devices"]:
        Filter stack_ports[] for port_type == "dad"
        For each DAD entry with link_status == "Down":
            Generate high-severity finding

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class DadLinkDownRule(BaseRule):
    """Detect C9500 Dual Active Detection links that are down."""

    rule_id = "DAD_LINK_DOWN"
    severity = "high"
    title = "DAD Link Down"
    description = "C9500 Dual Active Detection link is down (split-brain risk)"

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
                if entry.get("port_type") != "dad":
                    continue

                link_status = entry.get("link_status", "")
                if link_status == "Down":
                    member_id = entry.get("member_id", 0)
                    interface = entry.get("interface", "unknown")
                    finding = Finding.create(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        element_type="device",
                        element_id=hostname,
                        message=(
                            f"DAD link {interface} member "
                            f"{member_id} is Down. If SVL also fails, the "
                            f"stack cannot detect dual-active condition — "
                            f"split-brain risk."
                        ),
                        key_facts={
                            "hostname": hostname,
                            "member_id": member_id,
                            "interface": interface,
                            "link_status": link_status,
                            "protocol_status": entry.get("protocol_status", ""),
                        },
                        recommendation=(
                            "Restore the DAD link to ensure split-brain "
                            "protection. Check the dedicated DAD cable or "
                            "interface on both switches. DAD is critical for "
                            "preventing dual-active scenarios after SVL failure."
                        ),
                        member_id=member_id,
                    )
                    findings.append(finding)

        return findings
