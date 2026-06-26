"""
SSH Configuration Incomplete — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_2_1_SSH
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeSshRule(BaseRule):
    """CIS IOS XE 2.1: SSH must be configured with v2, proper timeout, and crypto key."""

    rule_id = "CIS_XE_2_1_SSH"
    severity = "high"
    title = "SSH Configuration Incomplete"
    description = "CIS IOS XE 2.1: SSH must be configured with v2, proper timeout, and crypto key"

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
            if "ip ssh version 2" not in config:
                issues.append("SSH version 2 not explicitly configured")
            if "ip domain" not in config:
                issues.append("no domain name configured (required for SSH key generation)")
            # Check SSH timeout — tunable default — 60s
            import re
            m = re.search(r"ip ssh time-out\s+(\d+)", config)
            if m:
                timeout = int(m.group(1))
                if timeout > 60:
                    issues.append(f"SSH timeout {timeout}s exceeds 60s")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"SSH configuration incomplete",
                    key_facts={"issues": issues},
                    recommendation="Configure 'ip ssh version 2', domain name, and SSH timeout ≤ 60s",
                ))

        return findings
