"""
Link Down Rule - Detect links with operational issues.

This rule identifies links where the operational status is not "up".
It handles two cases with different severities:
- "down": High severity (unexpected failure)
- "admin_down": Low severity (intentionally disabled)

Detection Logic:
    For each link in model["links"]:
        If link["status"] == "down":
            Generate finding (severity: high)
        Elif link["status"] == "admin_down":
            Generate finding (severity: low)

Why Different Severities:
    - "down": Something is wrong - cable unplugged, port error, etc.
              Needs immediate attention.
    - "admin_down": Intentionally disabled by administrator.
              Usually expected, but worth noting for completeness.

Note:
    Links with status "up" or "unknown" are not flagged.
    "unknown" means we couldn't determine status (e.g., interface
    not found in model) - this is already covered by other warnings.

Example Findings:
    # High severity - operational failure
    {
        "finding_id": "LINK_DOWN::core-rtr-01:Hu1/0/1--edge-rtr-01:Hu0/0/1/0",
        "severity": "high",
        "title": "Link Down",
        "message": "Link is operationally down"
    }

    # Low severity - administratively disabled
    {
        "finding_id": "LINK_DOWN::core-rtr-01:Hu1/0/2--edge-rtr-02:Hu0/0/1/0",
        "severity": "info",
        "title": "Link Admin Down",
        "message": "Link is administratively disabled"
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


class LinkDownRule(BaseRule):
    """
    Detect links that are down (operationally or administratively).

    This rule checks the 'status' field set by the model builder
    based on interface states.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "LINK_DOWN"
    severity = "high"  # Default severity, overridden for admin_down
    title = "Link Down"
    description = "Link with operational status not up"

    # Confidence levels that warrant high severity for down links.
    # Low-confidence links (subnet_only, arp_subnet, mac_subnet) are inferred
    # from shared IP subnets — "down" often just means an unused L3 segment.
    _HIGH_CONF = {"very_high", "high"}

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Find links with down or admin_down status.

        Severity depends on link confidence:
        - high/very_high confidence + down → high severity (real cable failure)
        - medium/low confidence + down → info severity (subnet-inferred, likely unused)
        - admin_down → always info severity

        Args:
            model: The network model
            context: Additional context (not used by this rule)

        Returns:
            List of findings for down links
        """
        findings: list[Finding] = []

        # -------------------------------------------------------------------------
        # Check each link for down status
        # -------------------------------------------------------------------------
        for link in model.get("links", []):
            status = link.get("status", "")
            link_id = link.get("link_id", "")
            confidence = link.get("confidence", "")
            discovery = link.get("discovery_method", "")

            # Build descriptive context for message
            local_intf = link.get("local_interface_id", "")
            remote_intf = link.get("remote_interface_id", "")
            local_port = local_intf.split(":", 1)[-1] if ":" in local_intf else local_intf
            remote_port = remote_intf.split(":", 1)[-1] if ":" in remote_intf else remote_intf

            # -------------------------------------------------------------------------
            # Case 1: Operationally down
            # -------------------------------------------------------------------------
            if status == "down":
                # High-confidence links (CDP, LACP, FDB) are real cables —
                # down is a genuine failure. Low-confidence links (subnet_only,
                # arp_subnet) are inferred from shared subnets — down often
                # means an unused L3 segment, not a cable problem.
                severity = "high" if confidence in self._HIGH_CONF else "info"

                msg = (
                    f"{local_port} \u2194 {remote_port} is operationally down"
                    f" ({discovery}, {confidence} confidence)"
                )

                recommendation = (
                    "Check physical connectivity (cables, transceivers). "
                    "Look for interface errors (CRC, input errors). "
                    "Verify speed/duplex settings match on both ends."
                ) if confidence in self._HIGH_CONF else (
                    "This is a low-confidence link inferred from shared IP subnets. "
                    "The down status likely indicates an unused L3 segment, "
                    "not a physical cable problem."
                )

                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=severity,
                    title="Link Down",
                    element_type="link",
                    element_id=link_id,
                    message=msg,
                    key_facts={
                        "local_device": link.get("local_device_id"),
                        "local_interface": link.get("local_interface_id"),
                        "remote_device": link.get("remote_device_id"),
                        "remote_interface": link.get("remote_interface_id"),
                        "status": status,
                        "discovery_method": discovery,
                        "confidence": confidence,
                    },
                    recommendation=recommendation,
                )
                findings.append(finding)

            # -------------------------------------------------------------------------
            # Case 2: Administratively down (info severity)
            # -------------------------------------------------------------------------
            elif status == "admin_down":
                msg = (
                    f"{local_port} \u2194 {remote_port} is administratively disabled"
                    f" ({discovery}, {confidence} confidence)"
                )

                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity="info",  # Intentionally disabled
                    title="Link Admin Down",
                    element_type="link",
                    element_id=link_id,
                    message=msg,
                    key_facts={
                        "local_device": link.get("local_device_id"),
                        "local_interface": link.get("local_interface_id"),
                        "remote_device": link.get("remote_device_id"),
                        "remote_interface": link.get("remote_interface_id"),
                        "status": status,
                        "discovery_method": discovery,
                        "confidence": confidence,
                    },
                    recommendation=(
                        "This link is intentionally disabled. "
                        "If connectivity is needed, enable the interface with 'no shutdown'."
                    ),
                )
                findings.append(finding)

            # Skip "up" and "unknown" - not problems

        return findings
