"""
XR OSPF Authentication Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_2_1_OSPF_AUTH
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrOspfAuthRule(BaseRule):
    """CIS IOS XR 2.1: OSPF routing authentication must be enabled when OSPF is configured."""

    rule_id = "CIS_XR_2_1_OSPF_AUTH"
    severity = "info"
    title = "XR OSPF Authentication Not Configured"
    description = "CIS IOS XR 2.1: OSPF routing authentication must be enabled when OSPF is configured"

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
            if "router ospf" in config and "authentication" not in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"OSPF configured without authentication",
                    key_facts={"protocol": "ospf", "auth": "missing"},
                    recommendation="Configure OSPF authentication (message-digest) on all OSPF interfaces",
                ))

        return findings
