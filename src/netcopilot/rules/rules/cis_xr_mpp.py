"""
XR Management Plane Protection Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_1_9_MPP
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrMppRule(BaseRule):
    """CIS IOS XR 1.9: Control-plane and management-plane protection should be configured."""

    rule_id = "CIS_XR_1_9_MPP"
    severity = "info"
    title = "XR Management Plane Protection Not Configured"
    description = "CIS IOS XR 1.9: Control-plane and management-plane protection should be configured"

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
            if "control-plane" not in config:
                issues.append("control-plane configuration missing")
            if "management-plane" not in config:
                issues.append("management-plane configuration missing")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Management plane protection not configured",
                    key_facts={"issues": issues},
                    recommendation="Configure control-plane and management-plane protection",
                ))

        return findings
