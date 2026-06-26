"""
CIS IOS XR System Hardening Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    CIS_XR_1_1_LOCAL_USERS: Check for users in root-lr group
    CIS_XR_1_3_SERVICES:   Check CDP, small servers
    CIS_XR_1_8_PASSWORDS:  Check password encryption
    CIS_XR_2_2_NTP_AUTH:   Check NTP authentication
    CIS_XR_3_1_URPF:       Check unicast RPF on interfaces

Severity: varies
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXrLocalUsersRule(BaseRule):
    """CIS XR 1.1.5: Local users should not have root-lr group (full admin)."""

    rule_id = "CIS_XR_1_1_LOCAL_USERS"
    severity = "info"
    title = "Local User Has Root Admin Group"
    description = "CIS XR 1.1.5: Local users should use minimal task groups, not root-lr"

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

            # Parse XR username blocks using line-by-line approach
            # (avoids regex catastrophic backtracking on large configs).
            lines = config.splitlines()
            user_blocks: list[tuple[str, str]] = []
            for i, line in enumerate(lines):
                m = re.match(r"username\s+(\S+)", line)
                if m:
                    block_lines = []
                    for j in range(i + 1, len(lines)):
                        next_line = lines[j]
                        if next_line and (next_line[0] == ' ' or next_line[0] == '\t'):
                            block_lines.append(next_line)
                        else:
                            break
                    user_blocks.append((m.group(1), "\n".join(block_lines)))

            for user, block in user_blocks:
                groups = re.findall(r"\s+group\s+(\S+)", block)
                if "root-lr" in groups:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/xr/1.1.5/user/{user}",
                        message=f"User '{user}' is in root-lr group (full admin)",
                        key_facts={"user": user, "groups": groups},
                        recommendation="Assign minimal task groups instead of root-lr; use AAA for admin access",
                    ))

        return findings


class CisXrServicesRule(BaseRule):
    """CIS XR 1.3.1/1.3.2: Disable CDP and TCP/UDP small servers."""

    rule_id = "CIS_XR_1_3_SERVICES"
    severity = "low"
    title = "Unnecessary Services Enabled"
    description = "CIS XR 1.3.1/1.3.2: Disable CDP and TCP/UDP small servers"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxr":
                continue

            sec = load_device_facts(run_path, hostname, "security_config")
            config = load_running_config(run_path, hostname)
            if sec is None and config is None:
                continue

            issues = []

            if sec:
                cdp = sec.get("cdp_lldp", {})
                if cdp.get("cdp_enabled", False):
                    issues.append("CDP enabled")

            if config:
                if re.search(r"service\s+tcp-small-servers", config):
                    issues.append("TCP small servers enabled")
                if re.search(r"service\s+udp-small-servers", config):
                    issues.append("UDP small servers enabled")

            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xr/1.3/services",
                    message=f"Unnecessary services — {'; '.join(issues)}",
                    key_facts={"issues": issues},
                    recommendation="Disable CDP with 'no cdp'; remove small servers configuration",
                ))

        return findings


class CisXrPasswordsRule(BaseRule):
    """CIS XR 1.8: Password encryption and policy."""

    rule_id = "CIS_XR_1_8_PASSWORDS"
    severity = "info"
    title = "Password Policy Incomplete"
    description = "CIS XR 1.8.1-1.8.3: AES password encryption and password policy required"

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

            if "service password-encryption aes" not in config:
                issues.append("AES password encryption not enabled (type-6)")
            if "aaa password-policy" not in config:
                issues.append("no AAA password policy configured")
            # Check for users with 'password' instead of 'secret'
            if re.search(r"username\s+\S+\n\s+password\s+", config):
                issues.append("user configured with 'password' instead of 'secret'")

            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xr/1.8/passwords",
                    message=f"Password policy issues — {'; '.join(issues)}",
                    key_facts={"issues": issues},
                    recommendation=(
                        "Enable 'service password-encryption aes', use 'username secret', "
                        "configure 'aaa password-policy'"
                    ),
                ))

        return findings


class CisXrNtpAuthRule(BaseRule):
    """CIS XR 2.2: NTP must use authentication with keys."""

    rule_id = "CIS_XR_2_2_NTP_AUTH"
    severity = "info"
    title = "NTP Authentication Not Configured"
    description = "CIS XR 2.2.1-2.2.2: NTP authentication with trusted keys required"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxr":
                continue

            sec = load_device_facts(run_path, hostname, "security_config")
            config = load_running_config(run_path, hostname)
            if sec is None and config is None:
                continue

            issues = []

            if sec:
                ntp = sec.get("ntp", {})
                if not ntp.get("authentication_enabled", False):
                    issues.append("NTP authentication not enabled")
                if not ntp.get("trusted_keys", []):
                    issues.append("no NTP trusted keys configured")
            elif config:
                if "ntp authenticate" not in config:
                    issues.append("NTP authentication not enabled")
                if "ntp authentication-key" not in config:
                    issues.append("no NTP authentication keys")
                if "ntp trusted-key" not in config:
                    issues.append("no NTP trusted keys")

            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xr/2.2/ntp-auth",
                    message=f"NTP authentication issues — {'; '.join(issues)}",
                    key_facts={"issues": issues},
                    recommendation=(
                        "Configure NTP authenticate, authentication-key, trusted-key, "
                        "and add keys to server entries"
                    ),
                ))

        return findings


class CisXrUrpfRule(BaseRule):
    """CIS XR 3.1: Enable uRPF on external interfaces."""

    rule_id = "CIS_XR_3_1_URPF"
    severity = "info"
    title = "uRPF Not Configured"
    description = "CIS XR 3.1: Enable unicast Reverse Path Forwarding to prevent IP spoofing"

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

            # Only flag if device is a router (has routing config)
            if not re.search(r"router (bgp|ospf|isis|eigrp)", config):
                continue

            if "ipv4 verify unicast source reachable-via" not in config:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xr/3.1/urpf",
                    message=f"URPF not configured on any interface",
                    key_facts={"urpf_configured": False},
                    recommendation="Configure 'ipv4 verify unicast source reachable-via' on external interfaces",
                ))

        return findings
