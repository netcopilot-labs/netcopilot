"""
Unidirectional Link Rule - Detect links seen from only one endpoint.

This rule identifies CDP relationships where only one device reports
seeing the other. In a healthy network, both endpoints should report
each other (bidirectional).

Detection Logic:
    For each link in model["links"]:
        If link["direction"] == "unidirectional":
            Generate finding (medium severity)

Why This Matters:
    Unidirectional links could indicate:
    - CDP disabled on one device
    - One device not in our collection scope
    - Interface name mismatch in CDP data
    - Asymmetric CDP configuration

Note:
    The model builder already calculates direction during link
    correlation. This rule simply reports unidirectional findings.

Example Finding:
    {
        "finding_id": "UNIDIRECTIONAL_LINK::dist-sw-01:Twe 1/0/8--core-sw-01:Te2/1/8",
        "rule_id": "UNIDIRECTIONAL_LINK",
        "severity": "low",
        "title": "Unidirectional Link",
        "message": "CDP relationship seen from only one endpoint",
        "evidence": {
            "element_type": "link",
            "element_id": "dist-sw-01:Twe 1/0/8--core-sw-01:Te2/1/8",
            "key_facts": {
                "local_device": "dist-sw-01",
                "local_interface": "dist-sw-01:Twe 1/0/8",
                "remote_device": "core-sw-01",
                "remote_interface": "core-sw-01:Te2/1/8",
                "direction": "unidirectional"
            }
        },
        "recommendation": "Check if remote device is in inventory and has CDP enabled"
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


class UnidirectionalLinkRule(BaseRule):
    """
    Detect links where CDP is seen from only one endpoint.

    This rule checks the 'direction' field set by the model builder
    during link correlation.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "UNIDIRECTIONAL_LINK"
    severity = "low"
    title = "Unidirectional Link"
    description = "CDP relationship seen from only one endpoint"

    # Only check links discovered via bilateral protocols.
    # L3/L4/L5 links (ARP, MAC, subnet overlap) are inherently one-sided.
    _BILATERAL_PROTOCOLS = {"cdp", "lldp"}

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Find links with unidirectional CDP/LLDP visibility.

        Only fires on L1 (CDP) and L2 (LLDP) links.
        L3/L4/L5 inferred links are inherently asymmetric and skipped.

        Args:
            model: The network model
            context: Additional context (not used by this rule)

        Returns:
            List of findings for unidirectional links
        """
        findings: list[Finding] = []

        # Build set of collected device hostnames so we can skip links to
        # uncollected peers (cameras, sub-switches, unmanaged gear).
        collected_hostnames: set[str] = {
            d["hostname"] for d in model.get("devices", []) if d.get("hostname")
        }

        # -------------------------------------------------------------------------
        # Check each link for unidirectional status
        # -------------------------------------------------------------------------
        for link in model.get("links", []):
            direction = link.get("direction", "")

            # Skip bidirectional links (healthy)
            if direction != "unidirectional":
                continue

            # Only check CDP/LLDP links
            discovery = str(link.get("discovery_protocol", "")).lower()
            if discovery and discovery not in self._BILATERAL_PROTOCOLS:
                continue

            # Skip links to uncollected remote devices (cameras, unmanaged
            # switches, sub-switches). CDP sees them but we can't verify the far end.
            # Guard: only apply when inventory is non-empty (avoids test regression).
            if collected_hostnames and link.get("remote_device_id") not in collected_hostnames:
                continue

            # Unidirectional link found
            link_id = link.get("link_id", "")

            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="link",
                element_id=link_id,
                message=(
                    f"Link between {link.get('local_device_id')} and "
                    f"{link.get('remote_device_id')} is only seen from one side"
                ),
                key_facts={
                    "local_device": link.get("local_device_id"),
                    "local_interface": link.get("local_interface_id"),
                    "remote_device": link.get("remote_device_id"),
                    "remote_interface": link.get("remote_interface_id"),
                    "direction": direction,
                    "discovery_protocol": discovery,
                },
                recommendation=(
                    "Check if the remote device is in the inventory. "
                    "Verify CDP is enabled on both endpoints. "
                    "This may be expected if the remote device is outside collection scope."
                ),
            )

            findings.append(finding)

        return findings
