"""
QoS Policer Exceed Rule — Detect interfaces with high policer drop ratio.

Evaluates each interface's QoS policer counters and fires when the
exceed-to-conform packet ratio exceeds the threshold, indicating
traffic is being policed (dropped) at a significant rate.

Thresholds:
    - EXCEED_RATIO_THRESHOLD: 1% — ratio of exceed/conform packets
    - MIN_CONFORM_PACKETS: 1000 — minimum sample to avoid false positives

Design:
    - Deterministic: integer counter ratio, no time-series needed
    - Reports mechanism of packet loss, not root cause
    - One finding per interface per direction (input/output separate)
    - Skips interfaces with zero or insufficient traffic
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules._qos_helpers import fmt_count, fmt_rate

# -------------------------------------------------------------------------
# Constants — tunable defaults.
# -------------------------------------------------------------------------
EXCEED_RATIO_THRESHOLD = 0.01   # 1% exceed ratio triggers finding
MIN_CONFORM_PACKETS = 1000      # minimum sample size to avoid noise


class QosPolicerExceedRule(BaseRule):
    """Detect interfaces where policer exceed ratio is above threshold."""

    rule_id = "QOS_POLICER_EXCEED"
    severity = "low"
    title = "QoS Policer Exceed"
    description = (
        "Interface policer is dropping more than 1% of traffic. "
        "This may indicate oversubscription or CIR misconfiguration."
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

                if dir_data.get("type") != "policer":
                    continue

                # Prefer packet counters; fall back to byte counters when
                # packets aren't available (varies by IOS XE version).
                conform = dir_data.get("conform_packets") or 0
                exceed = dir_data.get("exceed_packets") or 0
                unit = "packets"

                if conform == 0 and exceed == 0:
                    conform = dir_data.get("conform_bytes") or 0
                    exceed = dir_data.get("exceed_bytes") or 0
                    unit = "bytes"

                # Skip: no traffic or insufficient sample
                if conform < MIN_CONFORM_PACKETS:
                    continue

                # Skip: no exceeds (healthy)
                if exceed == 0:
                    continue

                ratio = exceed / conform
                if ratio <= EXCEED_RATIO_THRESHOLD:
                    continue

                ratio_pct = f"{ratio * 100:.2f}%"
                policy_name = dir_data.get("policy_name", "unknown")
                cir_bps = dir_data.get("cir_bps")

                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="interface",
                    element_id=f"{device_id}/{intf_name}",
                    message=(
                        f"{intf_name} {direction} policer '{policy_name}': "
                        f"{ratio_pct} exceed ratio "
                        f"({fmt_count(exceed)} exceed / "
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
                        "conform_count": conform,
                        "exceed_count": exceed,
                        "counter_unit": unit,
                        "exceed_ratio": ratio_pct,
                    },
                    recommendation=(
                        "Note: counters are cumulative since last 'clear counters' "
                        "and may span an unknown time window. Run 'clear counters' "
                        "before collection for a bounded measurement. "
                        "Review traffic profile against the configured CIR. "
                        "Consider increasing the policer rate if the traffic "
                        "is legitimate, or investigate the source of excess traffic."
                    ),
                ))

        return findings
