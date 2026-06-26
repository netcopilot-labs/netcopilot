"""
Isolated Device Rule - Detect devices with no CDP neighbors.

This rule identifies devices that have no connections to other
devices in the network. While this might be intentional (e.g.,
an access switch at the edge), it could also indicate:
- CDP disabled on the device
- Physical disconnection
- All neighbors have CDP disabled

Detection Logic:
    Build set of devices that appear in links (as local or remote)
    For each device in model["devices"]:
        If device_id not in set:
            Generate finding (medium severity)

Why Medium Severity:
    Isolated devices are often intentional (edge devices, labs).
    But they're worth noting because they could indicate problems.

Example Finding:
    {
        "finding_id": "ISOLATED_DEVICE::core-sw-01",
        "rule_id": "ISOLATED_DEVICE",
        "severity": "low",
        "title": "Isolated Device",
        "message": "Device 'core-sw-01' has no discovered CDP neighbors",
        "evidence": {
            "element_type": "device",
            "element_id": "core-sw-01",
            "key_facts": {
                "hostname": "core-sw-01",
                "platform": "C9300-24T",
                "os_family": "iosxe"
            }
        },
        "recommendation": "Verify CDP is enabled and check physical connectivity"
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


class IsolatedDeviceRule(BaseRule):
    """
    Detect devices that have no CDP neighbors.

    This rule builds a set of all devices that appear in links,
    then identifies any devices not in that set.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "ISOLATED_DEVICE"
    severity = "low"
    title = "Isolated Device"
    description = "Device has no discovered CDP neighbors"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Find devices that don't appear in any links.

        Args:
            model: The network model
            context: Additional context (not used by this rule)

        Returns:
            List of findings for isolated devices
        """
        findings: list[Finding] = []

        # -------------------------------------------------------------------------
        # Build set of devices that appear in links
        # -------------------------------------------------------------------------
        # A device is "connected" if it appears as local or remote in any link
        connected_devices: set[str] = set()

        for link in model.get("links", []):
            # Add both endpoints to the connected set
            local_device = link.get("local_device_id")
            remote_device = link.get("remote_device_id")

            if local_device:
                connected_devices.add(local_device)
            if remote_device:
                connected_devices.add(remote_device)

        # -------------------------------------------------------------------------
        # Check each device for isolation
        # -------------------------------------------------------------------------
        for device in model.get("devices", []):
            device_id = device.get("device_id", "")

            # Skip if device is connected
            if device_id in connected_devices:
                continue

            # Device is isolated - no links
            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="device",
                element_id=device_id,
                message=(
                    f"No discovered CDP neighbors"
                ),
                key_facts={
                    "hostname": device.get("hostname"),
                    "platform": device.get("platform"),
                    "os_family": device.get("os_family"),
                },
                recommendation=(
                    "Verify CDP is enabled on the device and its neighbors. "
                    "Check physical connectivity if this device should have neighbors."
                ),
            )

            findings.append(finding)

        return findings
