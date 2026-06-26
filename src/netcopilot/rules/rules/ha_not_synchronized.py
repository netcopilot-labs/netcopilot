"""
HA Not Synchronized Rule — Detect FortiGate HA pairs that are not synchronized.

FortiGate HA clusters require synchronization between members for proper
failover. When a member is not synchronized, configuration or session state
may not replicate, causing service disruption during failover.

This rule specifically targets FortiGate HA devices (member_type ==
"ha_active_passive"). It does NOT fire for Cisco stacks, which use a
different redundancy mechanism checked by CLUSTER_MEMBER_NOT_READY.

Detection Logic:
    For each device in model["devices"]:
        For each member in cluster_members[]:
            If member_type == "ha_active_passive":
                If state is not null AND state not in HA_SYNCHRONIZED_STATES:
                    Generate finding (high severity)

    Members with state: null are skipped — insufficient evidence.
    Cisco stack members (member_type != "ha_active_passive") are ignored.

Synchronized States:
    "HA synchronized" — the standard FortiGate synchronized state from
    the ha-peer API response.

Example Finding:
    {
        "finding_id": "HA_NOT_SYNCHRONIZED::core-rtr-01/member-1",
        "rule_id": "HA_NOT_SYNCHRONIZED",
        "severity": "high",
        "message": "FortiGate HA member 1 of 'core-rtr-01' is
                    not synchronized (state: 'HA out of sync'). ..."
    }

Related ADRs:
    - FortiGate HA as Single Logical Device
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
# States that indicate HA synchronization is healthy
# -------------------------------------------------------------------------
HA_SYNCHRONIZED_STATES = {
    "HA synchronized",
}


class HANotSynchronizedRule(BaseRule):
    """
    Detect FortiGate HA members that are not in a synchronized state.

    Only applies to devices with member_type "ha_active_passive" — Cisco
    stacks are handled by the generic CLUSTER_MEMBER_NOT_READY rule.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "HA_NOT_SYNCHRONIZED"
    severity = "high"
    title = "HA Not Synchronized"
    description = "FortiGate HA member is not synchronized with its peer"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Check FortiGate HA members for synchronization state.

        Args:
            model: Network model with devices containing cluster_members.
            context: Run context (not used by this rule).

        Returns:
            List of findings for HA members not synchronized.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            members = device.get("cluster_members", [])

            for member in members:
                # Only check FortiGate HA members — skip Cisco stacks
                if member.get("member_type") != "ha_active_passive":
                    continue

                state = member.get("state")

                # Skip members with null state — insufficient evidence
                if state is None:
                    continue

                # Skip synchronized members
                if state in HA_SYNCHRONIZED_STATES:
                    continue

                member_id = member.get("member_id", "?")

                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=f"{hostname}/member-{member_id}",
                    message=(
                        f"FortiGate HA member {member_id} is "
                        f"not synchronized (state: '{state}'). Configuration "
                        f"and session state may not be replicated to this member, "
                        f"risking service disruption during failover."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "member_id": member_id,
                        "state": state,
                        "role": member.get("role"),
                        "serial_number": member.get("serial_number"),
                        "member_type": "ha_active_passive",
                    },
                    recommendation=(
                        "Check FortiGate HA synchronization status: "
                        "'diagnose sys ha status' and 'diagnose sys ha checksum "
                        "cluster'. Common causes: large configuration change in "
                        "progress, network connectivity issue between HA heartbeat "
                        "interfaces, or firmware version mismatch between members."
                    ),
                )
                findings.append(finding)

        return findings
