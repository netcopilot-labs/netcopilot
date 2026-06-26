"""
NTP Clock Offset Excessive — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: NTP_OFFSET_EXCESSIVE
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class NtpOffsetRule(BaseRule):
    """Detects NTP clock offset exceeding acceptable threshold."""

    rule_id = "NTP_OFFSET_EXCESSIVE"
    severity = "high"
    title = "NTP Clock Offset Excessive"
    description = "Detects NTP clock offset exceeding acceptable threshold"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_ntp")
            if not data:
                continue
            clock = data.get("clock_state", {}).get("system_status", {})
            offset_str = clock.get("actual_freq", "") or clock.get("clock_offset", "")
            if not offset_str:
                continue
            try:
                offset = abs(float(str(offset_str)))
            except (ValueError, TypeError):
                continue
            # default; tune per deployment — threshold 500ms offset
            threshold_ms = 500.0
            if offset > threshold_ms:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"NTP clock offset {offset}ms exceeds threshold",
                    key_facts={"offset_ms": offset, "threshold_ms": threshold_ms},
                    recommendation="Verify NTP server reachability and network latency to NTP sources",
                ))

        return findings
