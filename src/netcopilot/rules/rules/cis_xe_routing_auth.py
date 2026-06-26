"""
CIS IOS XE Routing Protocol Authentication — Deep Python rules for the hybrid rule engine.

Detection Logic:
    CIS_XE_3_3_OSPF_AUTH:  OSPF area message-digest auth
    CIS_XE_3_3_BGP_AUTH:   BGP neighbor password
    CIS_XE_3_2_BORDER_ACL: Border ACL for RFC1918 sources

Severity: low
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


class CisXeOspfAuthRule(BaseRule):
    """CIS 3.3.2: OSPF must use message-digest authentication."""

    rule_id = "CIS_XE_3_3_OSPF_AUTH"
    severity = "info"
    title = "OSPF Authentication Not Configured"
    description = "CIS XE 3.3.2: OSPF area authentication with message-digest required"

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

            ospf_procs = re.findall(r"router ospf (\d+)", config)
            if not ospf_procs:
                continue

            for proc in ospf_procs:
                # Extract the OSPF router block
                ospf_block = re.search(
                    rf"router ospf {proc}\n(.*?)(?=\nrouter |\n!|\Z)",
                    config, re.DOTALL,
                )
                if not ospf_block:
                    continue
                block_text = ospf_block.group(1)

                if "authentication message-digest" not in block_text:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/xe/3.3.2/ospf/{proc}",
                        message=f"OSPF process {proc} missing area authentication message-digest",
                        key_facts={"ospf_process": proc},
                        recommendation="Configure 'area <id> authentication message-digest' under OSPF process",
                    ))

        return findings


class CisXeBgpAuthRule(BaseRule):
    """CIS 3.3.3: BGP neighbors must use MD5 authentication.

    DISABLED — duplicated by BGP_NEIGHBOR_NO_PASSWORD (cross-platform, Genie-based).
    """

    rule_id = "CIS_XE_3_3_BGP_AUTH"
    severity = "info"
    title = "BGP Neighbor Without Authentication"
    description = "CIS XE 3.3.3: BGP MD5 authentication on all neighbors"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        # Superseded by BGP_NEIGHBOR_NO_PASSWORD which uses Genie BGP facts
        # and covers all platforms (XE, XR, FortiGate) in a single rule.
        return []


class CisXeBorderAclRule(BaseRule):
    """CIS 3.2.1/3.2.2: Border routers should have ACLs denying RFC1918 sources."""

    rule_id = "CIS_XE_3_2_BORDER_ACL"
    severity = "info"
    title = "Border ACL Review Required"
    description = "CIS XE 3.2.1/3.2.2: Border ACL should deny RFC1918 private addresses"

    RFC1918 = ["10.0.0.0", "172.16.0.0", "192.168.0.0"]

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

            # Only check devices that appear to be border routers (have BGP)
            if "router bgp" not in config:
                continue

            missing = [p for p in self.RFC1918 if p not in config]
            if missing:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xe/3.2/border-acl",
                    message=f"No ACL entries found for RFC1918 prefixes: {missing}",
                    key_facts={"missing_rfc1918": missing},
                    recommendation="Create ACL denying RFC1918 sources and apply inbound on external interfaces",
                ))

        return findings
