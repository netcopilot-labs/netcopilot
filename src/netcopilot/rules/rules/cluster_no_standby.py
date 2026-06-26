"""
Cluster No Standby Rule — Detect clusters with no standby/passive member.

A healthy cluster should have at least one member in a standby or passive
role to provide failover capability. If all members are active (or have
unknown roles), the cluster cannot fail over if the active member goes down.

Detection Logic:
    For each device in model["devices"]:
        If cluster_members has 2+ members:
            Collect all role values
            If any role is null: skip (insufficient evidence)
            If no role matches STANDBY_ROLES: generate finding (high)

Why Skip on Null Roles:
    If we can't determine a member's role, we can't conclusively say
    there's no standby. Flagging would produce false positives.

Standby Role Values (vendor-native per ):
    Cisco: "Standby", "Member"
    FortiGate: "slave"

Example Finding:
    {
        "finding_id": "CLUSTER_NO_STANDBY::core-rtr-01",
        "rule_id": "CLUSTER_NO_STANDBY",
        "severity": "high",
        "message": "Cluster 'core-rtr-01' has no standby member.
                    Roles found: Active, Active"
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
# Roles that indicate standby/passive readiness (vendor-native values)
# -------------------------------------------------------------------------
# A member with any of these roles can take over if the active fails.
STANDBY_ROLES = {
    # Cisco IOS XE stack roles (lowercase for case-insensitive comparison)
    "standby",
    "member",
    # FortiGate HA roles (vendor-native)
    "slave",
}


class ClusterNoStandbyRule(BaseRule):
    """
    Detect clusters where no member has a standby or passive role.

    A cluster without standby members has no failover capability.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "CLUSTER_NO_STANDBY"
    severity = "high"
    title = "Cluster No Standby"
    description = "No cluster member has a standby or passive role"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Check each cluster for the presence of a standby member.

        Args:
            model: Network model with devices containing cluster_members.
            context: Run context (not used by this rule).

        Returns:
            List of findings for clusters without a standby member.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            members = device.get("cluster_members", [])

            # Only meaningful for devices with 2+ members
            if len(members) < 2:
                continue

            # Collect roles — skip if any role is null (insufficient evidence)
            roles = [m.get("role") for m in members]
            if any(r is None for r in roles):
                continue

            # Check if any member has a standby role (case-insensitive)
            has_standby = any(r.lower() in STANDBY_ROLES for r in roles)
            if has_standby:
                continue

            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="device",
                element_id=hostname,
                message=(
                    f"Cluster has no standby member. "
                    f"Roles found: {', '.join(roles)}. Without a standby, "
                    f"the cluster cannot fail over if the active member fails."
                ),
                key_facts={
                    "hostname": hostname,
                    "roles": roles,
                    "member_count": len(members),
                },
                recommendation=(
                    "Investigate why no member is in standby role. "
                    "For Cisco stacks: check 'show switch detail' for member "
                    "state. A member may have failed election. "
                    "For FortiGate HA: check 'diagnose sys ha status' for "
                    "HA synchronization issues."
                ),
            )
            findings.append(finding)

        return findings
