"""
XR Access Restrictions Incomplete — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_1_6_ACCESS
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrAccessRule(BaseRule):
    """CIS IOS XR 1.6: Telnet must be disabled and VTY access restricted."""

    rule_id = "CIS_XR_1_6_ACCESS"
    severity = "high"
    title = "XR Access Restrictions Incomplete"
    description = "CIS IOS XR 1.6: Telnet must be disabled and VTY access restricted"

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
            if "telnet" in config.lower() and "no telnet" not in config.lower():
                issues.append("telnet may be enabled")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"Access restrictions incomplete",
                    key_facts={"issues": issues},
                    recommendation="Disable telnet and restrict VTY access to SSH with ACLs",
                ))

        return findings
