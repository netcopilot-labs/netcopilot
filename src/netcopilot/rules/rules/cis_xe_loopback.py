"""
No Loopback Interface Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_2_4_LOOPBACK
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeLoopbackRule(BaseRule):
    """CIS IOS XE 2.4: A loopback interface should exist for management and routing stability."""

    rule_id = "CIS_XE_2_4_LOOPBACK"
    severity = "high"
    title = "No Loopback Interface Configured"
    description = "CIS IOS XE 2.4: A loopback interface should exist for management and routing stability"

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
            if "interface Loopback" not in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"No loopback interface configured",
                    key_facts={"check": "interface Loopback"},
                    recommendation="Configure a loopback interface for management and routing protocols",
                ))

        return findings
