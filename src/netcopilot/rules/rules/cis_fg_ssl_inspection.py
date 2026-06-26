"""
CIS FortiGate SSL Inspection Rule — Deep Python rule for the hybrid engine. Detects firewall policies using "no-inspection" SSL profile.

Detection Logic:
    Iterates enabled accept policies. If ssl-ssh-profile contains
    "no-inspection" (case-insensitive), the policy allows encrypted traffic
    to pass without inspection. Reports a single summary finding per device
    with the count and list of affected policy IDs.

Rule ID: CIS_FG_SSL_NO_INSPECTION
Severity: high (overridden to cis by engine)
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


_NO_INSPECTION_PATTERNS = ("no-inspection", "noinspection")


class CisFgSslNoInspectionRule(BaseRule):
    """Flags FortiGate policies with SSL/SSH inspection disabled."""

    rule_id = "CIS_FG_SSL_NO_INSPECTION"
    severity = "high"
    title = "FortiGate SSL Inspection Disabled on Policies"
    description = "CIS: Active accept policies should use SSL deep inspection, not no-inspection"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            policies = load_fg_json(device_dir, "fortigate_firewall_policy")
            if not isinstance(policies, list):
                continue

            no_inspection_ids: list[str] = []
            for policy in policies:
                status = str(policy.get("status", "")).lower()
                action = str(policy.get("action", "")).lower()
                if status != "enable" or action != "accept":
                    continue

                ssl_profile = str(policy.get("ssl-ssh-profile", "")).lower()
                # Only flag policies that EXPLICITLY use a no-inspection profile.
                # An empty ssl-ssh-profile is normal on L4/management policies that
                # carry no web traffic — flagging those was a false positive.
                if any(p in ssl_profile for p in _NO_INSPECTION_PATTERNS):
                    pid = str(policy.get("policyid", "?"))
                    name = policy.get("name", "")
                    label = f"{pid}" if not name else f"{pid} ({name})"
                    no_inspection_ids.append(label)

            if no_inspection_ids:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/ssl-no-inspection",
                    message=(
                        f"{len(no_inspection_ids)} active accept "
                        f"policies have SSL inspection disabled — encrypted "
                        f"malware can pass through uninspected"
                    ),
                    key_facts={
                        "no_inspection_count": len(no_inspection_ids),
                        "policy_ids": ", ".join(no_inspection_ids[:10]),
                    },
                    recommendation=(
                        "Apply SSL deep inspection or certificate inspection "
                        "profile to active accept policies"
                    ),
                ))

        return findings
