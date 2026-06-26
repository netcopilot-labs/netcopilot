"""
FortiGate Stale Policy Rule — Deep Python rule for the hybrid engine. Detects active firewall policies with [OLD] in name.

Detection Logic:
    Scans enabled policy names for "[OLD]" (case-insensitive).
    These are policies that operators have marked as obsolete but
    not yet disabled or removed.

Rule ID: FW_STALE_POLICY
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


class FwStalePolicyRule(BaseRule):
    """Flags active FortiGate policies with [OLD] in their name."""

    rule_id = "FW_STALE_POLICY"
    severity = "info"
    title = "Stale Firewall Policy Still Active"
    description = "Active firewall policy is marked as old/obsolete by name but not disabled"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            policies = load_fg_json(device_dir, "fortigate_firewall_policy")
            if not isinstance(policies, list):
                continue

            for policy in policies:
                status = str(policy.get("status", "")).lower()
                if status != "enable":
                    continue

                name = str(policy.get("name", ""))
                if "[old]" in name.lower():
                    pid = policy.get("policyid", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/fw/stale-policy/{pid}",
                        message=(
                            f"Firewall policy {pid} '{name}' "
                            f"is marked [OLD] but still enabled"
                        ),
                        key_facts={
                            "policyid": pid,
                            "name": name,
                            "status": "enable",
                        },
                        recommendation=(
                            "Review and disable or remove obsolete policies "
                            "to reduce attack surface and config complexity"
                        ),
                    ))

        return findings
