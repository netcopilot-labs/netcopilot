"""
XR Logging Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_1_4_LOGGING
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrLoggingRule(BaseRule):
    """CIS IOS XR 1.4: Logging must be enabled with remote host and appropriate levels."""

    rule_id = "CIS_XR_1_4_LOGGING"
    severity = "high"
    title = "XR Logging Not Configured"
    description = "CIS IOS XR 1.4: Logging must be enabled with remote host and appropriate levels"

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
            issues = []
            if "logging" not in config:
                issues.append("logging not configured at all")
            else:
                sec = load_device_facts(run_path, hostname, "security_config")
                hosts = sec.get("logging", {}).get("hosts", []) if sec else []
                if not hosts:
                    issues.append("no remote logging host configured")
                if "logging buffered" not in config:
                    issues.append("logging buffered not configured")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Logging configuration incomplete",
                    key_facts={"issues": issues},
                    recommendation="Configure logging with remote host and buffered storage",
                ))

        return findings
