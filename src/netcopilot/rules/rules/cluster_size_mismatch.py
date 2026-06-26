"""
Cluster Size Mismatch Rule — Detect when observed members ≠ declared size.

Compares the inventory-declared cluster size (cluster_declared_size in the
model, sourced from inventory cluster.size) against the actual number of
members observed by collection (len(cluster_members[])).

A mismatch usually means a stack member is down, removed, or not yet added.
This is critical because reduced redundancy may go unnoticed until a
failover event.

Detection Logic:
    For each device in model["devices"]:
        If cluster_declared_size is set AND cluster_members is non-empty:
            If len(cluster_members) != cluster_declared_size:
                Generate finding (critical severity)

Why Critical:
    A missing stack member means the device is operating without its
    declared redundancy level. If the remaining active member fails,
    there is no standby to take over. This is the highest-priority
    cluster health check.

Example Finding:
    {
        "finding_id": "CLUSTER_SIZE_MISMATCH::core-rtr-01",
        "rule_id": "CLUSTER_SIZE_MISMATCH",
        "severity": "critical",
        "title": "Cluster Size Mismatch",
        "message": "Device 'core-rtr-01' declares cluster size 2 but
                    only 1 member was observed.",
        "evidence": { ... },
        "recommendation": "Verify all cluster members are powered on ..."
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


class ClusterSizeMismatchRule(BaseRule):
    """
    Detect devices where observed cluster member count differs from declared size.

    Compares model cluster_declared_size (from inventory) against the actual
    number of cluster_members observed during collection.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "CLUSTER_SIZE_MISMATCH"
    severity = "critical"
    title = "Cluster Size Mismatch"
    description = "Observed cluster member count differs from inventory-declared size"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Compare declared cluster size against observed member count.

        Args:
            model: Network model with devices containing cluster_members
                   and cluster_declared_size.
            context: Run context (not used by this rule).

        Returns:
            List of findings for devices with size mismatch.
        """
        findings: list[Finding] = []

        for device in model.get("devices", []):
            hostname = device.get("hostname", "unknown")
            declared_size = device.get("cluster_declared_size")
            members = device.get("cluster_members", [])

            # Skip devices without a cluster declaration in inventory
            if declared_size is None:
                continue

            # Skip if no members observed — a separate issue (no evidence)
            if not members:
                continue

            observed_count = len(members)

            if observed_count != declared_size:
                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"Declares cluster size {declared_size} "
                        f"but {observed_count} member(s) were observed. "
                        f"A missing member reduces redundancy and may indicate "
                        f"hardware failure or misconfiguration."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "declared_size": declared_size,
                        "observed_count": observed_count,
                        "member_ids": [m.get("member_id") for m in members],
                    },
                    recommendation=(
                        "Verify all cluster members are powered on and connected. "
                        "Check stack cables (Cisco StackWise) or HA heartbeat links "
                        "(FortiGate). Review device logs for member join/leave events. "
                        "If the inventory declaration is wrong, update your inventory configuration."
                    ),
                )
                findings.append(finding)

        return findings
