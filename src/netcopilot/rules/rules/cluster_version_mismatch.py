"""
Cluster Version Mismatch Rule — Detect members running different firmware.

All members of a stack or HA cluster should run the same software version.
Version mismatch can cause unpredictable failover behavior, feature
incompatibility, or a member stuck in "Version Mismatch" state.

Detection Logic:
    For each device in model["devices"]:
        Collect all non-null version values from cluster_members[]
        If there are 2+ unique versions:
            Generate finding (high severity)

    Devices with fewer than 2 members or all-null versions are skipped.

Example Finding:
    {
        "finding_id": "CLUSTER_VERSION_MISMATCH::core-rtr-01",
        "rule_id": "CLUSTER_VERSION_MISMATCH",
        "severity": "high",
        "message": "Members of 'core-rtr-01' are running different
                    software versions: member 1 = 17.12.5, member 2 = 17.09.4"
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


class ClusterVersionMismatchRule(BaseRule):
    """
    Detect clusters where members run different software versions.

    Compares the version field across all cluster_members[]. If any
    non-null versions differ, a finding is generated.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "CLUSTER_VERSION_MISMATCH"
    severity = "high"
    title = "Cluster Version Mismatch"
    description = "Cluster members are running different software versions"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Compare version fields across cluster members.

        Args:
            model: Network model with devices containing cluster_members.
            context: Run context (not used by this rule).

        Returns:
            List of findings for clusters with version mismatch.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            members = device.get("cluster_members", [])

            # Need at least 2 members to compare
            if len(members) < 2:
                continue

            # Collect non-null versions with their member IDs
            version_pairs = [
                (m.get("member_id"), m.get("version"))
                for m in members
                if m.get("version") is not None
            ]

            # Skip if fewer than 2 non-null versions to compare
            if len(version_pairs) < 2:
                continue

            # Check for unique versions
            unique_versions = {v for _, v in version_pairs}
            if len(unique_versions) <= 1:
                continue

            # Build detail string: "member 1 = 17.12.5, member 2 = 17.09.4"
            detail_parts = [
                f"member {mid} = {ver}" for mid, ver in version_pairs
            ]

            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="device",
                element_id=hostname,
                message=(
                    f"Members are running different software "
                    f"versions: {', '.join(detail_parts)}. Version mismatch "
                    f"can cause unpredictable failover behavior."
                ),
                key_facts={
                    "hostname": hostname,
                    "versions": {
                        str(mid): ver for mid, ver in version_pairs
                    },
                    "unique_version_count": len(unique_versions),
                },
                recommendation=(
                    "Upgrade all cluster members to the same software version. "
                    "For Cisco stacks: use 'install add' with the same image on "
                    "all members. For FortiGate HA: upgrade the primary — the "
                    "secondary should auto-sync the firmware."
                ),
            )
            findings.append(finding)

        return findings
