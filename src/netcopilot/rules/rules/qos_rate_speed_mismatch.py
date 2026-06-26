"""
QoS Rate-Speed Mismatch Rule — Detect CIR exceeding interface speed.

Compares the QoS policy CIR (committed information rate) against the
interface's operational speed. A CIR higher than the interface speed
means the policer/shaper can't enforce the configured rate — likely
a misconfiguration (e.g., 10G policy on a 1G interface).

Speed parsing:
    - "1000mbps" → 1,000,000,000 bps
    - "1000mb/s" → 1,000,000,000 bps
    - "10000mbps" → 10,000,000,000 bps
    - "auto" / "auto speed" → skip (unknown speed)
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

# -------------------------------------------------------------------------
# Speed parsing
# -------------------------------------------------------------------------
# Matches numeric speed values in Mbps format: "1000mbps", "1000mb/s"
_SPEED_RE = re.compile(r"^(\d+)\s*(?:mb/?s|mbps)$", re.IGNORECASE)


def _parse_speed_bps(speed: str | None) -> int | None:
    """Convert interface speed string to bits per second.

    Returns None if speed is unknown, auto, or unparseable.
    """
    if not speed:
        return None

    m = _SPEED_RE.match(speed.strip())
    if m:
        return int(m.group(1)) * 1_000_000  # Mbps → bps

    return None


class QosRateSpeedMismatchRule(BaseRule):
    """Detect QoS CIR exceeding interface operational speed."""

    rule_id = "QOS_RATE_SPEED_MISMATCH"
    severity = "low"
    title = "QoS Rate-Speed Mismatch"
    description = (
        "QoS policy CIR exceeds the interface operational speed. "
        "The policer/shaper cannot enforce the configured rate."
    )

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for intf in model.get("interfaces", []):
            qos = intf.get("qos")
            if not qos:
                continue

            speed_bps = _parse_speed_bps(intf.get("speed"))
            if not speed_bps:
                continue

            device_id = intf.get("device_id", "")
            intf_name = intf.get("name", "")

            for direction in ("input", "output"):
                dir_data = qos.get(direction)
                if not dir_data:
                    continue

                cir_bps = dir_data.get("cir_bps")
                if not cir_bps:
                    continue

                # Allow up to 10% overhead (e.g. INPUT_1000Mb intentionally set
                # at 1.04 Gbps on 1 Gbps ports as an overhead allowance).
                if cir_bps > speed_bps * 1.10:
                    policy_name = dir_data.get("policy_name", "unknown")
                    # Use 3 decimal places so "1.040 Gbps vs 1.000 Gbps" is legible.
                    cir_gbps = cir_bps / 1_000_000_000
                    spd_gbps = speed_bps / 1_000_000_000
                    decimals = 3 if abs(cir_gbps - spd_gbps) < 0.5 else 1
                    fmt = f".{decimals}f"
                    findings.append(Finding.create(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        element_type="interface",
                        element_id=f"{device_id}/{intf_name}",
                        message=(
                            f"{direction.capitalize()} policy '{policy_name}' on "
                            f"{intf_name} has CIR "
                            f"{cir_gbps:{fmt}} Gbps but interface "
                            f"speed is {spd_gbps:{fmt}} Gbps"
                        ),
                        key_facts={
                            "device": device_id,
                            "interface": intf_name,
                            "direction": direction,
                            "policy_name": policy_name,
                            "cir_bps": cir_bps,
                            "interface_speed_bps": speed_bps,
                            "interface_speed": intf.get("speed"),
                        },
                        recommendation=(
                            "Review the QoS policy rate configuration. "
                            "The CIR should not exceed the physical interface speed."
                        ),
                    ))

        return findings
