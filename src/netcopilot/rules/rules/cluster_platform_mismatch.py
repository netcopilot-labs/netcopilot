"""
Cluster Platform Mismatch Rule — Detect mixed hardware in a cluster.

All members of a stack or HA cluster should ideally be the same hardware
platform. Mixed platforms can lead to feature inconsistency, capacity
imbalance, or licensing complications.

This is informational (medium severity) — mixed stacks are technically
supported by both Cisco StackWise and FortiGate HA, but are worth noting
for operational awareness.

Detection Logic:
    For each device in model["devices"]:
        Collect all non-null platform values from cluster_members[]
        If there are 2+ unique platforms:
            Generate finding (medium severity)

Example Finding:
    {
        "finding_id": "CLUSTER_PLATFORM_MISMATCH::core-rtr-01",
        "rule_id": "CLUSTER_PLATFORM_MISMATCH",
        "severity": "low",
        "message": "Members of 'core-rtr-01' have different platforms:
                    member 1 = C9300-24T, member 2 = C9300-48P"
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


class ClusterPlatformMismatchRule(BaseRule):
    """
    Detect clusters with members running on different hardware platforms.

    Compares the platform field across all cluster_members[]. If any
    non-null platforms differ, a finding is generated.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "CLUSTER_PLATFORM_MISMATCH"
    severity = "low"
    title = "Cluster Platform Mismatch"
    description = "Cluster members are running on different hardware platforms"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Compare platform fields across cluster members.

        Args:
            model: Network model with devices containing cluster_members.
            context: Run context (not used by this rule).

        Returns:
            List of findings for clusters with platform mismatch.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            members = device.get("cluster_members", [])

            # Need at least 2 members to compare
            if len(members) < 2:
                continue

            # Collect non-null platforms with their member IDs
            platform_pairs = [
                (m.get("member_id"), m.get("platform"))
                for m in members
                if m.get("platform") is not None
            ]

            # Skip if fewer than 2 non-null platforms to compare
            if len(platform_pairs) < 2:
                continue

            # Check for unique platforms
            unique_platforms = {p for _, p in platform_pairs}
            if len(unique_platforms) <= 1:
                continue

            # Build detail string
            detail_parts = [
                f"member {mid} = {plat}" for mid, plat in platform_pairs
            ]

            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="device",
                element_id=hostname,
                message=(
                    f"Members have different hardware platforms: "
                    f"{', '.join(detail_parts)}. Mixed platforms may cause "
                    f"feature or capacity imbalance."
                ),
                key_facts={
                    "hostname": hostname,
                    "platforms": {
                        str(mid): plat for mid, plat in platform_pairs
                    },
                    "unique_platform_count": len(unique_platforms),
                },
                recommendation=(
                    "Verify that mixed platform operation is intentional. "
                    "For Cisco stacks: check switch compatibility matrix for "
                    "the stack model. For FortiGate HA: ensure both units are "
                    "the same model for proper HA failover."
                ),
            )
            findings.append(finding)

        return findings
