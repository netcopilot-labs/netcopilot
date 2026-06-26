"""
XR Key Chain Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_2_1_KEYCHAINS
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrKeychainsRule(BaseRule):
    """CIS IOS XR 2.1: Routing protocol authentication should use key chains."""

    rule_id = "CIS_XR_2_1_KEYCHAINS"
    severity = "info"
    title = "XR Key Chain Not Configured"
    description = "CIS IOS XR 2.1: Routing protocol authentication should use key chains"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxr":
                continue
            config = load_running_config(run_path, hostname)
            if config is None:
                continue
            # Only check if routing protocols are present
            has_routing = any(p in config for p in ["router ospf", "router eigrp", "router isis"])
            if has_routing and "key chain" not in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Routing protocols configured without key chains",
                    key_facts={"check": "key chain"},
                    recommendation="Configure key chains for routing protocol authentication",
                ))

        return findings
