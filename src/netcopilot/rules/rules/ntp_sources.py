"""
Insufficient NTP Sources — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: NTP_INSUFFICIENT_SOURCES
Severity: medium
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class NtpInsufficientSourcesRule(BaseRule):
    """Detects devices with fewer than 2 NTP sources configured."""

    rule_id = "NTP_INSUFFICIENT_SOURCES"
    severity = "info"
    title = "Insufficient NTP Sources"
    description = "Detects devices with fewer than 2 NTP sources configured"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_ntp")
            if not data:
                continue
            # Count NTP associations
            associations = data.get("vrf", {})
            peer_count = 0
            for vrf_name, vrf_data in associations.items():
                if not isinstance(vrf_data, dict):
                    continue
                assoc = vrf_data.get("associations", {}).get("address", {})
                peer_count += len(assoc)
            # Also check peer_status at top level
            peer_status = data.get("peer_status", {})
            if peer_status:
                peer_count = max(peer_count, len(peer_status))
            # default; tune per deployment — minimum 2 sources
            if 0 < peer_count < 2:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Only {peer_count} NTP source(s) configured (minimum 2)",
                    key_facts={"ntp_sources": peer_count, "minimum": 2},
                    recommendation="Configure at least 2 NTP sources for redundancy",
                ))

        return findings
