"""
Config NETCONF/RESTCONF ACL Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Scans running-config for NETCONF/RESTCONF services enabled without
    access-list restrictions. Unrestricted programmable interfaces are a
    security risk — they should be limited to management subnets.

Rule IDs: NETCONF_NO_ACL
Severity: low

audit: new rule to detect bare netconf-yang/restconf
without ACL protection.
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


class NetconfNoAclRule(BaseRule):
    """Flags NETCONF/RESTCONF services without access-list restrictions."""

    rule_id = "NETCONF_NO_ACL"
    severity = "low"
    title = "NETCONF/RESTCONF Without ACL"
    description = "Programmable interface enabled without access-list restriction"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            config = load_running_config(run_path, hostname)
            if not config:
                continue

            unprotected = []

            # NETCONF check — IOS XE: "netconf-yang" without "netconf-yang ssh ... access-list"
            if re.search(r"^netconf-yang\s*$", config, re.MULTILINE):
                has_acl = bool(re.search(
                    r"netconf-yang\s+ssh\s+.*access-list", config, re.MULTILINE
                ))
                if not has_acl:
                    unprotected.append("NETCONF")

            # IOS XR: "netconf agent ssh" or "netconf-yang agent ssh"
            if re.search(r"^netconf(?:-yang)?\s+agent\s+ssh", config, re.MULTILINE):
                has_acl = bool(re.search(
                    r"netconf.*agent.*access-list", config, re.MULTILINE
                ))
                if not has_acl:
                    unprotected.append("NETCONF")

            # RESTCONF check — IOS XE: "restconf" without "ip http access-class"
            if re.search(r"^restconf\s*$", config, re.MULTILINE):
                has_acl = bool(re.search(
                    r"ip\s+http\s+access-class", config, re.MULTILINE
                ))
                if not has_acl:
                    unprotected.append("RESTCONF")

            # Deduplicate (XE + XR could both match for NETCONF)
            unprotected = sorted(set(unprotected))

            if unprotected:
                protocols = " and ".join(unprotected)
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/config/netconf-no-acl",
                    message=(
                        f"{protocols} enabled without ACL restriction"
                    ),
                    key_facts={"unprotected_protocols": unprotected},
                    recommendation=(
                        "Restrict access with ACL: 'netconf-yang ssh access-list <acl>' "
                        "and/or 'ip http access-class <acl>'"
                    ),
                ))

        return findings
