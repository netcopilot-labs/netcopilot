"""
CIS IOS XE Service Hardening Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    CIS_XE_2_1_SERVICES: Checks CDP, BOOTP, pad, TCP keepalives
    CIS_XE_2_3_NTP:      Checks NTP authentication
    CIS_XE_3_1_ROUTING:  Checks IP source-routing

Severity: medium
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class CisXeServicesRule(BaseRule):
    """CIS 2.1.2-2.1.7: Disable unused services, enable TCP keepalives."""

    rule_id = "CIS_XE_2_1_SERVICES"
    severity = "low"
    title = "Unnecessary Services Enabled"
    description = "CIS XE 2.1.2-2.1.7: Disable CDP/BOOTP/pad; enable TCP keepalives"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxe":
                continue

            sec = load_device_facts(run_path, hostname, "security_config")
            config = load_running_config(run_path, hostname)
            if sec is None and config is None:
                continue

            issues = []

            if sec:
                services = sec.get("services", {})
                cdp = sec.get("cdp_lldp", {})
                if cdp.get("cdp_enabled", False):
                    issues.append("CDP globally enabled")
                if not services.get("tcp_keepalives_in", False):
                    issues.append("TCP keepalives-in not enabled")
                if not services.get("tcp_keepalives_out", False):
                    issues.append("TCP keepalives-out not enabled")

            if config:
                if "ip bootp server" in config and "no ip bootp server" not in config:
                    issues.append("IP BOOTP server enabled")
                if "service pad" in config and "no service pad" not in config:
                    issues.append("PAD service enabled")

            if issues:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xe/2.1/services",
                    message=f"Service hardening issues — {'; '.join(issues)}",
                    key_facts={"issues": issues},
                    recommendation=(
                        "Run 'no cdp run', 'no ip bootp server', 'no service pad', "
                        "'service tcp-keepalives-in', 'service tcp-keepalives-out'"
                    ),
                ))

        return findings


class CisXeNtpAuthRule(BaseRule):
    """CIS 2.3: NTP must use authentication with keys.

    DISABLED — duplicated by NTP_NO_AUTHENTICATION (cross-platform, Genie-based).
    CIS_XR_2_2_NTP_AUTH remains active for XR (no Genie NTP data on XR devices).
    """

    rule_id = "CIS_XE_2_3_NTP"
    severity = "low"
    title = "NTP Authentication Not Configured"
    description = "CIS XE 2.3: NTP authentication with trusted keys required"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        # Superseded by NTP_NO_AUTHENTICATION which uses Genie NTP facts.
        # XR devices keep CIS_XR_2_2_NTP_AUTH since they lack Genie NTP data.
        return []


class CisXeSourceRoutingRule(BaseRule):
    """CIS 3.1.1: IP source routing must be disabled."""

    rule_id = "CIS_XE_3_1_ROUTING"
    severity = "low"
    title = "IP Source Routing Enabled"
    description = "CIS XE 3.1.1: Disable IP source routing"

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

            src_routing = sec.get("ip_source_routing", {})
            if src_routing.get("enabled", False):
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xe/3.1/source-routing",
                    message=f"IP source routing is enabled",
                    key_facts={"source_routing_enabled": True},
                    recommendation="Configure 'no ip source-route' to disable source routing",
                ))

        return findings
