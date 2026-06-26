"""
Collection Failure Rule - Detect devices that failed collection.

This rule compares the manifest (what we tried to collect) with
the model (what we actually got). Any device in manifest but
missing from model indicates a collection failure.

Detection Logic:
    For each device in manifest["devices"]:
        If device hostname not in model["devices"]:
            Generate finding (critical severity)

Why This Matters:
    Collection failures mean we have incomplete visibility.
    A device might be:
    - Unreachable (network issue)
    - Authentication failed (wrong credentials)
    - SSH timeout (device overloaded)
    - Not responding (crashed/rebooting)

Example Finding:
    {
        "finding_id": "COLLECTION_FAILURE::core-sw-01",
        "rule_id": "COLLECTION_FAILURE",
        "severity": "critical",
        "title": "Collection Failure",
        "message": "Device 'core-sw-01' (192.0.2.103) was in inventory but collection failed",
        "evidence": {
            "element_type": "device",
            "element_id": "core-sw-01",
            "key_facts": {
                "hostname": "core-sw-01",
                "management_ip": "192.0.2.103",
                "expected_os": "iosxe"
            }
        },
        "recommendation": "Check device reachability and SSH credentials"
    }
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


class CollectionFailureRule(BaseRule):
    """
    Detect devices that were in the manifest but failed collection.

    This rule uses the context (which contains the manifest) to compare
    against the model. Devices in manifest but not in model indicate
    collection failures.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "COLLECTION_FAILURE"
    severity = "critical"
    title = "Collection Failure"
    description = "Device listed in manifest but no facts collected"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Compare manifest devices against model devices.

        Args:
            model: The network model (devices that were successfully collected)
            context: Contains manifest with all attempted devices

        Returns:
            List of findings for devices that failed collection
        """
        findings: list[Finding] = []

        # -------------------------------------------------------------------------
        # Get manifest from context
        # -------------------------------------------------------------------------
        manifest = context.get("manifest", {})
        manifest_devices = manifest.get("devices", [])

        # -------------------------------------------------------------------------
        # Build set of hostnames in model for fast lookup
        # -------------------------------------------------------------------------
        # Using a set gives O(1) lookup instead of O(n) list search
        model_hostnames: set[str] = {
            device["hostname"]
            for device in model.get("devices", [])
        }

        # -------------------------------------------------------------------------
        # Check each manifest device
        # -------------------------------------------------------------------------
        for manifest_device in manifest_devices:
            hostname = manifest_device.get("hostname", "")
            inventory_name = manifest_device.get("inventory_name", "")

            # Skip if device is in model (collection succeeded)
            # Check both hostname and inventory_name to handle remapping
            # (e.g., FortiGate reports fw-01a but model uses fw-01)
            if hostname in model_hostnames or inventory_name in model_hostnames:
                continue

            # Device is missing from model - collection failed
            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="device",
                element_id=hostname,
                message=(
                    f"Collection failed "
                    f"(IP: {manifest_device.get('target', 'unknown')})"
                ),
                key_facts={
                    "hostname": hostname,
                    "management_ip": manifest_device.get("target"),
                    "expected_os": manifest_device.get("os"),
                },
                recommendation=(
                    "Check device reachability, verify SSH credentials, "
                    "and ensure the device is powered on and responsive"
                ),
            )

            findings.append(finding)

        return findings
