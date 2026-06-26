"""
CIS IOS XR Routing/FHRP Protocol Authentication — Deep Python rules.

Detection Logic:
    CIS_XR_2_1_BGP_AUTH:  BGP neighbor password
    CIS_XR_2_3_VRRP_AUTH: VRRP authentication
    CIS_XR_2_4_HSRP_AUTH: HSRP authentication

Severity: low
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


def _extract_indented_block(lines: list[str], start_idx: int) -> str:
    """Extract contiguous indented lines following start_idx.

    Returns the concatenated text of all lines with deeper indentation
    than the start line, stopping at the first line with equal or lesser
    indentation (or end of lines).
    """
    if start_idx >= len(lines):
        return ""
    base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    block_lines = []
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped:
            continue
        indent = len(line) - len(stripped)
        if indent <= base_indent:
            break
        block_lines.append(line)
    return "\n".join(block_lines)


class CisXrBgpAuthRule(BaseRule):
    """CIS XR 2.1.3.1: BGP neighbors must use MD5 authentication.

    DISABLED — duplicated by BGP_NEIGHBOR_NO_PASSWORD (cross-platform, Genie-based).
    """

    rule_id = "CIS_XR_2_1_BGP_AUTH"
    severity = "info"
    title = "BGP Neighbor Without Authentication"
    description = "CIS XR 2.1.3.1: BGP MD5 authentication on all neighbors"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        # Superseded by BGP_NEIGHBOR_NO_PASSWORD which uses Genie BGP facts
        # and covers all platforms (XE, XR, FortiGate) in a single rule.
        return []


class CisXrVrrpAuthRule(BaseRule):
    """CIS XR 2.3.1: VRRP authentication must be configured."""

    rule_id = "CIS_XR_2_3_VRRP_AUTH"
    severity = "info"
    title = "VRRP Authentication Not Configured"
    description = "CIS XR 2.3.1: VRRP authentication to prevent router spoofing"

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

            vrrp_matches = re.findall(r"vrrp\s+(\d+)", config)
            if not vrrp_matches:
                continue

            lines = config.splitlines()
            for group_id in sorted(set(vrrp_matches)):
                for i, line in enumerate(lines):
                    if re.match(rf"\s*vrrp\s+{group_id}\b", line):
                        block = _extract_indented_block(lines, i)
                        if "authentication" not in block:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="device",
                                element_id=f"{hostname}/cis/xr/2.3/vrrp/{group_id}",
                                message=f"VRRP group {group_id} has no authentication",
                                key_facts={"vrrp_group": group_id},
                                recommendation="Configure VRRP authentication to prevent spoofing",
                            ))
                        break

        return findings


class CisXrHsrpAuthRule(BaseRule):
    """CIS XR 2.4.1: HSRP must use MD5 authentication."""

    rule_id = "CIS_XR_2_4_HSRP_AUTH"
    severity = "info"
    title = "HSRP Authentication Not Configured"
    description = "CIS XR 2.4.1: HSRP MD5 authentication to prevent gateway hijacking"

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

            hsrp_matches = re.findall(r"hsrp\s+(\d+)", config)
            if not hsrp_matches:
                continue

            lines = config.splitlines()
            for group_id in sorted(set(hsrp_matches)):
                for i, line in enumerate(lines):
                    if re.match(rf"\s*hsrp\s+{group_id}\b", line):
                        block = _extract_indented_block(lines, i)
                        if "authentication md5" not in block:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="device",
                                element_id=f"{hostname}/cis/xr/2.4/hsrp/{group_id}",
                                message=f"HSRP group {group_id} has no MD5 authentication",
                                key_facts={"hsrp_group": group_id},
                                recommendation="Configure 'authentication md5 key-string <key>' under HSRP group",
                            ))
                        break

        return findings
