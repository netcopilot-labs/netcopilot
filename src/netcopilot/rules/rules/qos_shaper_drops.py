"""
QoS Shaper Drops Rule — Detect interfaces with shaper queue drops.

Evaluates each interface's QoS shaper counters and fires when
queue drops are present with sufficient traffic, indicating the
shaper is congesting and dropping packets.

Threshold:
    - MIN_CONFORM_PACKETS: 1000 — minimum sample to avoid false positives

Design:
    - Any queue_drops > 0 with sufficient traffic triggers the finding
    - Lower severity than policer exceed (medium vs high) because
      shaper drops are a softer signal — shapers buffer before dropping
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules._qos_helpers import fmt_count, fmt_rate

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------
MIN_CONFORM_PACKETS = 1000  # minimum sample size to avoid noise


class QosShaperDropsRule(BaseRule):
    """Detect interfaces where the shaper is dropping packets."""

    rule_id = "QOS_SHAPER_DROPS"
    severity = "info"
    title = "QoS Shaper Drops"
    description = (
        "Interface shaper is dropping packets from the queue. "
        "This indicates sustained congestion above the shaped rate."
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

            device_id = intf.get("device_id", "")
            intf_name = intf.get("name", "")

            for direction in ("input", "output"):
                dir_data = qos.get(direction)
                if not dir_data:
                    continue

                if dir_data.get("type") != "shaper":
                    continue

                # Prefer packet counters; fall back to byte counters when
                # packets aren't available (varies by IOS XE version).
                conform = dir_data.get("conform_packets") or 0
                unit = "packets"

                if conform == 0:
                    conform = dir_data.get("conform_bytes") or 0
                    unit = "bytes"

                drops = dir_data.get("queue_drops") or 0

                # Skip: insufficient traffic
                if conform < MIN_CONFORM_PACKETS:
                    continue

                # Skip: no drops (healthy)
                if drops == 0:
                    continue

                policy_name = dir_data.get("policy_name", "unknown")
                cir_bps = dir_data.get("cir_bps")

                # Drop ratio only meaningful when both values are in
                # the same unit (packets). When using byte fallback,
                # queue_drops is a count but conform is in bytes.
                if unit == "packets":
                    drop_ratio_pct = f"{drops / conform * 100:.2f}%"
                    ratio_detail = f"{drop_ratio_pct} drop ratio, "
                else:
                    drop_ratio_pct = None
                    ratio_detail = ""

                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="interface",
                    element_id=f"{device_id}/{intf_name}",
                    message=(
                        f"{intf_name} {direction} shaper '{policy_name}': "
                        f"{fmt_count(drops)} queue drops "
                        f"({ratio_detail}"
                        f"{fmt_count(conform)} conform {unit}, "
                        f"CIR {fmt_rate(cir_bps)}) "
                        f"[cumulative — counters since last clear]"
                    ),
                    key_facts={
                        "device": device_id,
                        "interface": intf_name,
                        "direction": direction,
                        "policy_name": policy_name,
                        "cir_bps": cir_bps,
                        "queue_drops": drops,
                        "conform_count": conform,
                        "counter_unit": unit,
                        "drop_ratio": drop_ratio_pct,
                    },
                    recommendation=(
                        "Note: counters are cumulative since last 'clear counters' "
                        "and may span an unknown time window. Run 'clear counters' "
                        "before collection for a bounded measurement. "
                        "Review traffic profile against the configured shape rate. "
                        "Consider increasing the shaper rate or implementing "
                        "traffic prioritization within the policy."
                    ),
                ))

        return findings
