"""
Local Logging Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_2_2_LOCAL_LOG
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeLocalLogRule(BaseRule):
    """CIS IOS XE 2.2: Local logging must be enabled with buffered storage."""

    rule_id = "CIS_XE_2_2_LOCAL_LOG"
    severity = "high"
    title = "Local Logging Not Configured"
    description = "CIS IOS XE 2.2: Local logging must be enabled with buffered storage"

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
            issues = []
            if "no logging on" in config:
                issues.append("logging explicitly disabled")
            if "logging buffered" not in config:
                issues.append("logging buffered not configured")
            if "logging console critical" not in config and "logging console" not in config:
                issues.append("logging console level not set")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Local logging not properly configured",
                    key_facts={"issues": issues},
                    recommendation="Configure 'logging on', 'logging buffered', and 'logging console critical'",
                ))

        return findings
