"""
AAA Authentication Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_1_1_AUTH
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeAaaAuthRule(BaseRule):
    """CIS IOS XE 1.1: AAA authentication for login and enable must be configured."""

    rule_id = "CIS_XE_1_1_AUTH"
    severity = "high"
    title = "AAA Authentication Not Configured"
    description = "CIS IOS XE 1.1: AAA authentication for login and enable must be configured"

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
            missing = []
            if "aaa authentication login" not in config:
                missing.append("aaa authentication login")
            if "aaa authentication enable" not in config:
                missing.append("aaa authentication enable")
            if missing:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"AAA authentication not fully configured",
                    key_facts={"missing": missing},
                    recommendation="Configure AAA authentication for login and enable modes",
                ))

        return findings
