"""
XR SSH Configuration Incomplete — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XR_1_2_SSH
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrSshRule(BaseRule):
    """CIS IOS XR 1.2: SSH must have hostname set and appropriate timeout."""

    rule_id = "CIS_XR_1_2_SSH"
    severity = "high"
    title = "XR SSH Configuration Incomplete"
    description = "CIS IOS XR 1.2: SSH must have hostname set and appropriate timeout"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        import re
        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxr":
                continue
            config = load_running_config(run_path, hostname)
            if config is None:
                continue
            issues = []
            if not re.search(r"^hostname\s+\S+", config, re.MULTILINE):
                issues.append("hostname not configured")
            # Check SSH timeout — tunable default — 60s
            m = re.search(r"ssh\s+server\s+.*?timeout\s+(\d+)", config)
            if m and int(m.group(1)) > 60:
                issues.append(f"SSH timeout {m.group(1)}s exceeds 60s")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"SSH configuration issues",
                    key_facts={"issues": issues},
                    recommendation="Configure hostname and SSH timeout ≤ 60s",
                ))

        return findings
