"""
Remote Logging Not Configured — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_2_2_REMOTE_LOG
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeRemoteLogRule(BaseRule):
    """CIS IOS XE 2.2: Remote syslog host must be configured."""

    rule_id = "CIS_XE_2_2_REMOTE_LOG"
    severity = "high"
    title = "Remote Logging Not Configured"
    description = "CIS IOS XE 2.2: Remote syslog host must be configured"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxe":
                continue
            sec = load_device_facts(run_path, hostname, "security_config")
            if sec is None:
                continue
            hosts = sec.get("logging", {}).get("hosts", [])
            if not hosts:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"No remote syslog host configured",
                    key_facts={"logging_hosts": []},
                    recommendation="Configure 'logging host <ip>' for centralized log collection",
                ))

        return findings
