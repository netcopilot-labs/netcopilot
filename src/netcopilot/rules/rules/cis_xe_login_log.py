"""
Login Event Logging Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_2_2_LOGIN_LOG
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeLoginLogRule(BaseRule):
    """CIS IOS XE 2.2: Login success and failure events must be logged."""

    rule_id = "CIS_XE_2_2_LOGIN_LOG"
    severity = "high"
    title = "Login Event Logging Not Configured"
    description = "CIS IOS XE 2.2: Login success and failure events must be logged"

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
            if "login on-success log" not in config:
                missing.append("login on-success log")
            if "login on-failure log" not in config:
                missing.append("login on-failure log")
            if missing:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Login event logging not configured",
                    key_facts={"missing": missing},
                    recommendation="Configure login success/failure logging for audit trail",
                ))

        return findings
