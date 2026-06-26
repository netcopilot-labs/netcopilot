"""
Cluster Member Not Ready Rule — Detect members in unhealthy state.

Checks each member in cluster_members[] for a healthy operational state.
Members that are initializing, in version mismatch, or in any non-ready
state indicate a degraded cluster that may not failover correctly.

Detection Logic:
    For each device in model["devices"]:
        For each member in cluster_members[]:
            If member.state is not null AND not in HEALTHY_STATES:
                Generate finding (high severity)

    Members with state: null are skipped — we don't flag what we can't
    verify.

Healthy States:
    Cisco IOS XE: "Ready"
    FortiGate: "HA synchronized"
    See HEALTHY_STATES set for the full list.

Example Finding:
    {
        "finding_id": "CLUSTER_MEMBER_NOT_READY::core-rtr-01/member-2",
        "rule_id": "CLUSTER_MEMBER_NOT_READY",
        "severity": "high",
        "message": "Member 2 of 'core-rtr-01' is in state 'Initializing'..."
    }

Related ADRs:
    - Three-Tier Redundancy Model
    - cluster_members Schema
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
from typing import Any

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

# -------------------------------------------------------------------------
# Healthy state values (case-sensitive, vendor-native)
# -------------------------------------------------------------------------
# These are the states that indicate a member is fully operational.
# Any other non-null state triggers a finding.
HEALTHY_STATES = {
    # Cisco IOS XE stack states (lowercase for case-insensitive comparison)
    "ready",
    # FortiGate HA states (from ha_peer API response)
    "ha synchronized",
}


class ClusterMemberNotReadyRule(BaseRule):
    """
    Detect cluster members that are not in a healthy operational state.

    Iterates cluster_members[] for each device and checks the state field
    against a known set of healthy values.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "CLUSTER_MEMBER_NOT_READY"
    severity = "high"
    title = "Cluster Member Not Ready"
    description = "A cluster member is in an unhealthy operational state"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Check each cluster member's state against healthy values.

        Args:
            model: Network model with devices containing cluster_members.
            context: Run context (not used by this rule).

        Returns:
            List of findings for members in unhealthy states.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            members = device.get("cluster_members", [])

            for member in members:
                state = member.get("state")

                # Skip members with null state — insufficient evidence
                if state is None:
                    continue

                # Skip healthy members (case-insensitive comparison)
                if state.lower() in HEALTHY_STATES:
                    continue

                member_id = member.get("member_id", "?")

                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=f"{hostname}/member-{member_id}",
                    message=(
                        f"Member {member_id} is in state "
                        f"'{state}'. Expected one of: {sorted(HEALTHY_STATES)}. "
                        f"This member may not participate in failover."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "member_id": member_id,
                        "state": state,
                        "role": member.get("role"),
                        "serial_number": member.get("serial_number"),
                    },
                    recommendation=(
                        "Check the member's operational status on the device. "
                        "For Cisco stacks: 'show switch detail'. "
                        "For FortiGate HA: 'diagnose sys ha status'. "
                        "Common causes: firmware upgrade in progress, "
                        "version mismatch, hardware fault."
                    ),
                )
                findings.append(finding)

        return findings
