"""
CIS IOS XE Line/Console Security Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    CIS_XE_1_2_PRIV: Checks local user privileges (should be 1)
    CIS_XE_1_2_VTY:  Checks VTY transport SSH-only + access-class ACL

Severity: medium
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


class CisXeUserPrivilegeRule(BaseRule):
    """CIS 1.2.1: Local users should have minimum privilege (level 1)."""

    rule_id = "CIS_XE_1_2_PRIV"
    severity = "low"
    title = "Local User Has Elevated Privilege"
    description = "CIS XE 1.2.1: Set 'privilege 1' for all local users (least privilege)"

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

            for m in re.finditer(r"username\s+(\S+)\s+privilege\s+(\d+)", config):
                user, priv = m.group(1), int(m.group(2))
                if priv > 1:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/xe/1.2.1/user/{user}",
                        message=f"User '{user}' has privilege {priv} (should be 1)",
                        key_facts={"user": user, "privilege": priv},
                        recommendation="Set 'username <user> privilege 1'; use AAA/TACACS+ for admin access",
                    ))

        return findings


class CisXeVtySecurityRule(BaseRule):
    """CIS 1.2.2/1.2.4/1.2.5: VTY lines must use SSH-only transport with ACL."""

    rule_id = "CIS_XE_1_2_VTY"
    severity = "low"
    title = "VTY Line Security Incomplete"
    description = "CIS XE 1.2.2/1.2.4/1.2.5: VTY lines need SSH-only transport and access-class ACL"

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

            # Extract VTY line blocks
            vty_blocks = re.findall(
                r"(line vty \d+ \d+.*?)(?=\nline |\n!|\Z)",
                config, re.DOTALL,
            )
            if not vty_blocks:
                continue

            for block in vty_blocks:
                line_match = re.match(r"line vty (\d+ \d+)", block)
                line_id = line_match.group(1) if line_match else "?"
                issues = []

                transport = re.search(r"transport input\s+(.+)", block)
                if transport:
                    val = transport.group(1).strip()
                    if val != "ssh":
                        issues.append(f"transport input is '{val}' (should be 'ssh')")
                else:
                    issues.append("no 'transport input ssh' configured")

                if "access-class" not in block:
                    issues.append("no access-class ACL configured")

                if issues:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/xe/1.2/vty/{line_id.replace(' ', '-')}",
                        message=f"VTY {line_id} — {'; '.join(issues)}",
                        key_facts={"vty_line": line_id, "issues": issues},
                        recommendation="Configure 'transport input ssh' and 'access-class <ACL> in' on all VTY lines",
                    ))

        return findings
