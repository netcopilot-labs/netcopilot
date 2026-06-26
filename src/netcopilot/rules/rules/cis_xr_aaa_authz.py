"""
XR AAA Authorization Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_1_1_AUTHZ
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrAaaAuthzRule(BaseRule):
    """CIS IOS XR 1.1: AAA authorization for exec must be configured."""

    rule_id = "CIS_XR_1_1_AUTHZ"
    severity = "info"
    title = "XR AAA Authorization Not Configured"
    description = "CIS IOS XR 1.1: AAA authorization for exec must be configured"

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
            if "aaa authorization exec" not in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"AAA authorization exec not configured",
                    key_facts={"check": "aaa authorization exec"},
                    recommendation="Configure 'aaa authorization exec' for command authorization",
                ))

        return findings
