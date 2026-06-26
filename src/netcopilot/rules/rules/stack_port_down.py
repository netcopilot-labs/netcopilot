"""
Stack Port Down Rule — Detect C9300 stack cable ports with DOWN status.

A stack port in DOWN state means the physical stack cable is disconnected,
damaged, or the neighboring member has failed. This immediately halves
the stack ring bandwidth and removes one redundancy path.

Detection Logic:
    For each device in model["devices"]:
        For each entry in stack_ports[] where port_type == "cable":
            If status == "DOWN": generate critical finding

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class StackPortDownRule(BaseRule):
    """Detect C9300 stack cable ports with DOWN status."""

    rule_id = "STACK_PORT_DOWN"
    severity = "critical"
    title = "Stack Port Down"
    description = "C9300 stack cable port is in DOWN state"

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
                if entry.get("port_type") != "cable":
                    continue

                status = entry.get("status", "")
                if status.upper() == "DOWN":
                    member_id = entry.get("member_id", 0)
                    port_id = entry.get("port_id", 0)
                    finding = Finding.create(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        element_type="device",
                        element_id=hostname,
                        message=(
                            f"Stack port {member_id}/{port_id} "
                            f"is DOWN. The stack cable may be disconnected or "
                            f"damaged, reducing ring bandwidth and redundancy."
                        ),
                        key_facts={
                            "hostname": hostname,
                            "member_id": member_id,
                            "port_id": port_id,
                            "status": status,
                            "neighbor_member": entry.get("neighbor_member", 0),
                            "link_active": entry.get("link_active", False),
                        },
                        recommendation=(
                            "Check the stack cable between members. Verify the "
                            "cable is properly seated at both ends. If the cable "
                            "is damaged, replace it. Check the neighboring stack "
                            "member is powered on and operational."
                        ),
                        member_id=member_id,
                    )
                    findings.append(finding)

        return findings
