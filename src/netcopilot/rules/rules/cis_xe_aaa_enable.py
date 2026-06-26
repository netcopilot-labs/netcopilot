"""
AAA New-Model Not Enabled — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_1_1_ENABLE
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeAaaEnableRule(BaseRule):
    """CIS IOS XE 1.1: AAA new-model must be enabled for centralized authentication."""

    rule_id = "CIS_XE_1_1_ENABLE"
    severity = "high"
    title = "AAA New-Model Not Enabled"
    description = "CIS IOS XE 1.1: AAA new-model must be enabled for centralized authentication"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxe":
                continue
            config = load_running_config(run_path, hostname)
            if config is None:
                continue
            if "aaa new-model" not in config or "no aaa new-model" in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"AAA new-model not enabled",
                    key_facts={"check": "aaa new-model", "status": "missing"},
                    recommendation="Configure 'aaa new-model' to enable AAA services",
                ))

        return findings
