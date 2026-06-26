"""
CIS FortiGate SNMP Rule — Deep Python rule for the hybrid rule engine.

Replaces the single-source surface rule CIS_FG_2_3_1, which fired whenever the
SNMP agent was enabled. The CIS control (2.3.1/2.3.2) is satisfied when SNMP is
either disabled OR restricted to SNMPv3 (no v1/v2c communities). A box that is
already SNMPv3-only was a false positive under the old check; this rule
cross-checks the community list and only fires when an insecure v1/v2c community
is actually present.

Rule ID: CIS_FG_2_3_1
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


class CisFgSnmpV3OnlyRule(BaseRule):
    """CIS 2.3.1/2.3.2: SNMP must be disabled or SNMPv3-only (no v1/v2c communities)."""

    rule_id = "CIS_FG_2_3_1"
    severity = "info"  # overridden to 'cis' by engine._apply_cis_severity()
    title = "SNMP Not Restricted to v3"
    description = (
        "CIS 2.3.1/2.3.2: SNMP must be disabled or restricted to SNMPv3 "
        "(no v1/v2c communities)"
    )

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            sysinfo = load_fg_json(device_dir, "fortigate_snmp_sysinfo")
            if not isinstance(sysinfo, dict):
                continue
            if str(sysinfo.get("status", "")).lower() != "enable":
                continue  # SNMP agent disabled → compliant

            communities = load_fg_json(device_dir, "fortigate_snmp_community")
            v1v2c_count = len(communities) if isinstance(communities, list) else 0
            if v1v2c_count == 0:
                continue  # SNMPv3-only (no v1/v2c communities) → compliant

            findings.append(Finding.create_from_rule(
                rule=self, element_type="device",
                element_id=f"{hostname}/cis/fg/2.3.1/snmp",
                message=(
                    f"SNMP agent enabled with {v1v2c_count} SNMP v1/v2c "
                    f"community(ies) — not restricted to SNMPv3"
                ),
                key_facts={
                    "snmp_status": "enable",
                    "v1v2c_community_count": v1v2c_count,
                },
                recommendation=(
                    "Disable SNMP, or remove all v1/v2c communities and use "
                    "SNMPv3 users only (CIS 2.3.2)"
                ),
            ))

        return findings
