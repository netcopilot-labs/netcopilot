"""
Stack Half Ring Rule — Detect C9300 members with only one active stack port.

A C9300 stack member normally has 2 stack ports forming a bidirectional ring.
If only one port is OK and the other is DOWN/ABSENT, the ring is broken and
the stack operates at half bandwidth through a single cable path.

This is a high-severity degradation — the stack is still functional but has
lost redundancy on that member. If the remaining cable fails, the member
becomes isolated from the stack.

Detection Logic:
    For each device in model["devices"]:
        Group cable entries by member_id
        Per member: count ports with status "OK"
        If member has 2+ ports but only 1 is OK: half ring detected

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class StackHalfRingRule(BaseRule):
    """Detect C9300 stack members operating with only one active cable."""

    rule_id = "STACK_HALF_RING"
    severity = "high"
    title = "Stack Half Ring"
    description = "C9300 stack member has only one active stack cable (ring broken)"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            stack_ports = device.get("stack_ports", [])

            # Only evaluate cable entries (C9300)
            cable_entries = [
                e for e in stack_ports if e.get("port_type") == "cable"
            ]
            if not cable_entries:
                continue

            # Group by member and count OK vs total ports
            ports_by_member: dict[int, dict] = {}
            for entry in cable_entries:
                mid = entry.get("member_id", 0)
                if mid not in ports_by_member:
                    ports_by_member[mid] = {"total": 0, "ok": 0, "statuses": []}

                ports_by_member[mid]["total"] += 1
                status = entry.get("status", "").upper()
                ports_by_member[mid]["statuses"].append(status)
                if status == "OK":
                    ports_by_member[mid]["ok"] += 1

            for member_id, counts in ports_by_member.items():
                # Half ring: 2+ ports present but only 1 is OK
                if counts["total"] >= 2 and counts["ok"] == 1:
                    finding = Finding.create(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        element_type="device",
                        element_id=hostname,
                        message=(
                            f"Stack member {member_id} has only "
                            f"1 of {counts['total']} stack ports active (OK). "
                            f"The stack ring is broken and operating at half "
                            f"bandwidth through a single cable."
                        ),
                        key_facts={
                            "hostname": hostname,
                            "member_id": member_id,
                            "total_ports": counts["total"],
                            "ok_ports": counts["ok"],
                            "port_statuses": counts["statuses"],
                        },
                        recommendation=(
                            "Check the non-OK stack cable on this member. "
                            "The stack is still functional but has lost half its "
                            "inter-member bandwidth and ring redundancy. "
                            "Replace the failed cable during the next maintenance "
                            "window to restore full ring operation."
                        ),
                        member_id=member_id,
                    )
                    findings.append(finding)

        return findings
