"""
SNMP Security Misconfiguration — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: CIS_XE_1_5_SNMP
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeSnmpRule(BaseRule):
    """CIS IOS XE 1.5: SNMP communities must not use defaults, must have ACLs, prefer SNMPv3."""

    rule_id = "CIS_XE_1_5_SNMP"
    severity = "high"
    title = "SNMP Security Misconfiguration"
    description = "CIS IOS XE 1.5: SNMP communities must not use defaults, must have ACLs, prefer SNMPv3"

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
            snmp = sec.get("snmp", {})
            issues = []
            # Check communities for insecure settings
            default_names = {"public", "private"}
            for comm in snmp.get("communities", []):
                name = comm.get("name", "")
                if name.lower() in default_names:
                    issues.append(f"default community '{name}'")
                if comm.get("mode", "").upper() == "RW":
                    issues.append(f"community '{name}' has RW access")
                acl = comm.get("acl", "")
                if not acl or acl == "!":
                    issues.append(f"community '{name}' has no ACL")
            # Check for SNMPv3 users
            if not snmp.get("v3_users"):
                issues.append("no SNMPv3 users configured")
            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device", element_id=hostname,
                    message=f"SNMP security issues detected",
                    key_facts={"issues": issues},
                    recommendation="Remove default communities, restrict to RO with ACLs, configure SNMPv3",
                ))

        return findings
