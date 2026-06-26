"""
QoS No Input Policy Rule — Detect switchports missing input QoS.

Physical interfaces with a switchport mode (access/trunk) that lack
an input service-policy. These are user-facing ports that should
typically have ingress policing for traffic control.

Skip criteria:
    - Non-physical interfaces (SVIs, loopbacks, port-channels, tunnels)
    - Management interfaces (type "management")
    - Admin-down interfaces (intentionally disabled)
    - Interfaces without switchport_mode set

Note: This rule may generate many findings in lab environments where
QoS isn't universally deployed. Low severity reflects informational nature.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

# Interface types and name prefixes to skip
_SKIP_TYPES = {"management", "vlan", "logical", "aggregated"}
_SKIP_NAME_PREFIXES = ("Loopback", "Tunnel", "Port-channel", "Vlan", "BDI")


class QosNoInputPolicyRule(BaseRule):
    """Detect switchport interfaces missing input QoS policy."""

    rule_id = "QOS_NO_INPUT_POLICY"
    severity = "info"
    title = "No Input QoS Policy"
    description = (
        "Physical switchport interface has no input service-policy. "
        "Ingress traffic is not being policed or shaped."
    )

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for intf in model.get("interfaces", []):
            if not _is_candidate(intf):
                continue

            qos = intf.get("qos")
            # Has output but no input → asymmetric coverage
            if qos and qos.get("output") and not qos.get("input"):
                device_id = intf.get("device_id", "")
                intf_name = intf.get("name", "")
                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="interface",
                    element_id=f"{device_id}/{intf_name}",
                    message=(
                        f"{intf_name} has output QoS policy "
                        f"but no input service-policy"
                    ),
                    key_facts={
                        "device": device_id,
                        "interface": intf_name,
                        "switchport_mode": intf.get("switchport_mode"),
                        "output_policy": qos["output"].get("policy_name"),
                    },
                    recommendation=(
                        "Consider adding an input service-policy to police "
                        "ingress traffic on this interface."
                    ),
                ))

        return findings


def _is_candidate(intf: dict[str, Any]) -> bool:
    """Check if interface is a candidate for QoS coverage rules."""
    # Must be physical type
    if intf.get("type") in _SKIP_TYPES:
        return False
    # Skip by name prefix
    name = intf.get("name", "")
    if any(name.startswith(p) for p in _SKIP_NAME_PREFIXES):
        return False
    # Must be admin up
    if intf.get("admin_status") == "down":
        return False
    # Must have switchport_mode set (access or trunk)
    mode = intf.get("switchport_mode")
    if mode not in ("access", "trunk"):
        return False
    return True
