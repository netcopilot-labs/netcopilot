"""
QoS No Output Policy Rule — Detect switchports missing output QoS.

Physical interfaces with a switchport mode (access/trunk) that lack
an output service-policy. These are user-facing ports that should
typically have egress shaping for traffic control.

Same skip criteria as QOS_NO_INPUT_POLICY.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

# Interface types and name prefixes to skip
_SKIP_TYPES = {"management", "vlan", "logical", "aggregated"}
_SKIP_NAME_PREFIXES = ("Loopback", "Tunnel", "Port-channel", "Vlan", "BDI")


class QosNoOutputPolicyRule(BaseRule):
    """Detect switchport interfaces missing output QoS policy."""

    rule_id = "QOS_NO_OUTPUT_POLICY"
    severity = "info"
    title = "No Output QoS Policy"
    description = (
        "Physical switchport interface has no output service-policy. "
        "Egress traffic is not being shaped or queued."
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
            # Has input but no output → asymmetric coverage
            if qos and qos.get("input") and not qos.get("output"):
                device_id = intf.get("device_id", "")
                intf_name = intf.get("name", "")
                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="interface",
                    element_id=f"{device_id}/{intf_name}",
                    message=(
                        f"{intf_name} has input QoS policy "
                        f"but no output service-policy"
                    ),
                    key_facts={
                        "device": device_id,
                        "interface": intf_name,
                        "switchport_mode": intf.get("switchport_mode"),
                        "input_policy": qos["input"].get("policy_name"),
                    },
                    recommendation=(
                        "Consider adding an output service-policy to shape "
                        "egress traffic on this interface."
                    ),
                ))

        return findings


def _is_candidate(intf: dict[str, Any]) -> bool:
    """Check if interface is a candidate for QoS coverage rules."""
    if intf.get("type") in _SKIP_TYPES:
        return False
    name = intf.get("name", "")
    if any(name.startswith(p) for p in _SKIP_NAME_PREFIXES):
        return False
    if intf.get("admin_status") == "down":
        return False
    mode = intf.get("switchport_mode")
    if mode not in ("access", "trunk"):
        return False
    return True
