"""
Stack Port Absent Rule — Detect C9300 stack ports that are absent or missing.

An absent stack port means either:
  - The port hardware is not detected (ABSENT status)
  - A member is expected to have 2 stack ports but fewer are present in data

C9300 stack members always have 2 stack ports (1/1, 1/2 for member 1, etc.).
If a member appears in the data with fewer than 2 ports, the missing port
is treated as absent.

Detection Logic:
    For each device in model["devices"]:
        For each cable entry in stack_ports[]:
            If status == "ABSENT": generate critical finding
        Per member: if fewer than 2 cable entries exist, report missing ports

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

# C9300 always has 2 stack ports per member
_EXPECTED_PORTS_PER_MEMBER = 2


class StackPortAbsentRule(BaseRule):
    """Detect C9300 stack ports with ABSENT status or missing from output."""

    rule_id = "STACK_PORT_ABSENT"
    severity = "critical"
    title = "Stack Port Absent"
    description = "C9300 stack cable port is absent or not detected"

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

            # Check explicit ABSENT status
            for entry in cable_entries:
                status = entry.get("status", "")
                if status.upper() == "ABSENT":
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
                            f"is ABSENT. The port hardware is not detected."
                        ),
                        key_facts={
                            "hostname": hostname,
                            "member_id": member_id,
                            "port_id": port_id,
                            "status": status,
                        },
                        recommendation=(
                            "Verify the stack port hardware is functional. "
                            "Check for hardware failure on the affected member. "
                            "If the member was recently added, ensure it is fully "
                            "seated in the chassis."
                        ),
                        member_id=member_id,
                    )
                    findings.append(finding)

            # Check for missing ports per member
            ports_by_member: dict[int, list[int]] = {}
            for entry in cable_entries:
                mid = entry.get("member_id", 0)
                pid = entry.get("port_id", 0)
                ports_by_member.setdefault(mid, []).append(pid)

            for member_id, port_ids in ports_by_member.items():
                if len(port_ids) < _EXPECTED_PORTS_PER_MEMBER:
                    # Find which port IDs are missing
                    expected = set(range(1, _EXPECTED_PORTS_PER_MEMBER + 1))
                    present = set(port_ids)
                    missing = expected - present

                    for pid in sorted(missing):
                        finding = Finding.create(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            element_type="device",
                            element_id=hostname,
                            message=(
                                f"Stack port {member_id}/{pid} "
                                f"is missing from stack port data. Expected "
                                f"{_EXPECTED_PORTS_PER_MEMBER} ports per member."
                            ),
                            key_facts={
                                "hostname": hostname,
                                "member_id": member_id,
                                "port_id": pid,
                                "status": "MISSING",
                                "present_ports": sorted(port_ids),
                            },
                            recommendation=(
                                "Investigate why this stack port is not reported. "
                                "The member may have a hardware issue or the port "
                                "may not be initialized."
                            ),
                            member_id=member_id,
                        )
                        findings.append(finding)

        return findings
