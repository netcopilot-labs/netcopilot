"""
STP Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie STP learn() output for spanning-tree configuration
    anomalies across VLANs.

Rule IDs: STP_PRIORITY_DEFAULT
Severity: low

audit: new rule to detect default STP bridge priority
(32768) which indicates no deliberate root bridge election.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


class StpPriorityDefaultRule(BaseRule):
    """Flags switches where all VLANs use the default STP bridge priority (32768).

    When bridge_priority is left at 32768 on every VLAN, no deliberate root
    bridge election has been configured, which can lead to suboptimal or
    unpredictable spanning-tree topology.
    """

    rule_id = "STP_PRIORITY_DEFAULT"
    severity = "info"
    title = "STP Priority Default"
    description = "All VLANs use default STP bridge priority (32768) — no root bridge election configured"

    DEFAULT_PRIORITY = 32768

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_stp")
            if not data:
                continue

            # Check rapid_pvst (most common), then pvst, then mstp
            for stp_mode in ("rapid_pvst", "pvst", "mstp"):
                mode_data = data.get(stp_mode, {})
                if not mode_data:
                    continue
                for domain_name, domain in mode_data.items():
                    if not isinstance(domain, dict):
                        continue
                    vlans = domain.get("vlans", {})
                    if not vlans:
                        continue
                    default_count = 0
                    total_count = 0
                    for vlan_id, vlan_data in vlans.items():
                        if not isinstance(vlan_data, dict):
                            continue
                        total_count += 1
                        bp = vlan_data.get("bridge_priority", 0)
                        if bp == self.DEFAULT_PRIORITY:
                            default_count += 1

                    if total_count > 0 and default_count == total_count:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/stp/priority-default",
                            message=(
                                f"All {total_count} VLANs use default STP "
                                f"priority {self.DEFAULT_PRIORITY} — no root bridge election"
                            ),
                            key_facts={
                                "stp_mode": stp_mode,
                                "vlan_count": total_count,
                                "default_priority_count": default_count,
                            },
                            recommendation=(
                                "Configure explicit STP priority on designated root bridges "
                                "(e.g., 'spanning-tree vlan <id> priority 4096')"
                            ),
                        ))

        return findings
