"""
Duplicate IP Rule - Detect IP address conflicts.

This rule identifies cases where the same IP address is assigned
to multiple interfaces across the network. IP conflicts can cause:
- Routing problems
- Intermittent connectivity
- ARP issues
- Hard-to-diagnose network problems

Detection Logic:
    Build dict: ip_address -> [interface_ids]
    For each ip, interfaces in dict:
        If len(interfaces) > 1:
            Generate finding (critical severity)

Why Critical Severity:
    Duplicate IPs are serious configuration errors that can
    cause unpredictable network behavior and are often difficult
    to diagnose without automated detection.

Ignored IPs:
    - null/None (no IP assigned)
    - "unassigned" (explicit no-IP marker)

Example Finding:
    {
        "finding_id": "DUPLICATE_IP::192.0.2.100",
        "rule_id": "DUPLICATE_IP",
        "severity": "critical",
        "title": "Duplicate IP Address",
        "message": "IP address 192.0.2.100 is assigned to 2 interfaces",
        "evidence": {
            "element_type": "interface",
            "element_id": "192.0.2.100",
            "key_facts": {
                "ip_address": "192.0.2.100",
                "interfaces": [
                    {"interface_id": "core-rtr-01:Gi1/0/1", "device_id": "core-rtr-01"},
                    {"interface_id": "dist-sw-01:Gi1/0/1", "device_id": "dist-sw-01"}
                ],
                "count": 2
            }
        },
        "recommendation": "Review IP assignments and resolve the conflict"
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


class DuplicateIpRule(BaseRule):
    """
    Detect IP addresses assigned to multiple interfaces.

    This rule groups interfaces by IP address and reports
    any IPs that appear more than once.
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "DUPLICATE_IP"
    severity = "critical"
    title = "Duplicate IP Address"
    description = "Same IP address assigned to multiple interfaces"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Find IP addresses assigned to multiple interfaces.

        Args:
            model: The network model
            context: Additional context (not used by this rule)

        Returns:
            List of findings for duplicate IPs
        """
        findings: list[Finding] = []

        # -------------------------------------------------------------------------
        # Build mapping: IP address -> list of interfaces
        # -------------------------------------------------------------------------
        ip_to_interfaces: dict[str, list[dict[str, str]]] = {}

        for interface in model.get("interfaces", []):
            ip_address = interface.get("ip_address")

            # Skip interfaces without IP or with placeholder values
            if not ip_address:
                continue
            if ip_address.lower() in ("unassigned", "none", "null", ""):
                continue

            # Add interface to the IP's list
            if ip_address not in ip_to_interfaces:
                ip_to_interfaces[ip_address] = []

            ip_to_interfaces[ip_address].append({
                "interface_id": interface.get("interface_id"),
                "device_id": interface.get("device_id"),
            })

        # -------------------------------------------------------------------------
        # Find IPs with multiple interfaces
        # -------------------------------------------------------------------------
        for ip_address, interfaces in sorted(ip_to_interfaces.items()):
            # Skip if only one interface has this IP (normal)
            if len(interfaces) <= 1:
                continue

            # Duplicate IP found!
            # A duplicate IP spans multiple devices, so it has no single owning
            # node. Use a global element_id ("duplicate_ip::<ip>") and list the
            # owning devices in key_facts.devices so the loader attaches the
            # finding to every real device. (A bare IP as element_id mapped to no
            # Device node, so the finding was silently dropped on load.)
            owning_devices = sorted({
                i.get("device_id") for i in interfaces if i.get("device_id")
            })
            finding = Finding.create(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                element_type="interface",
                element_id=f"duplicate_ip::{ip_address}",
                message=(
                    f"IP address {ip_address} is assigned to {len(interfaces)} interfaces"
                ),
                key_facts={
                    "ip_address": ip_address,
                    "devices": owning_devices,
                    "interfaces": interfaces,
                    "count": len(interfaces),
                },
                recommendation=(
                    "Review IP address assignments and resolve the conflict. "
                    "Each IP should be unique within a broadcast domain."
                ),
            )

            findings.append(finding)

        return findings
