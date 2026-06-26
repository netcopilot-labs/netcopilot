"""
VLAN SVI Shutdown — Deep Python rule for the hybrid engine. Detects active VLANs whose SVI (Vlan interface) is
administratively shutdown, indicating a possible stale or misconfigured SVI.

Detection Logic:
    For IOS XE/IOS devices, cross-references genie_vlan (active VLANs) with
    genie_interface (SVI status). Flags VLANs where:
    1. VLAN state is "active" in genie_vlan
    2. A corresponding SVI (Vlan<id>) exists in genie_interface
    3. The SVI is admin-down (enabled=False or shutdown=True)
    4. VLAN is not 1 or in reserved range 1002-1005

Rule ID: VLAN_SVI_SHUTDOWN
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


_SKIP_VLANS = {1, 1002, 1003, 1004, 1005}


class VlanSviShutdownRule(BaseRule):
    """Flags active VLANs with shutdown SVIs."""

    rule_id = "VLAN_SVI_SHUTDOWN"
    severity = "info"
    title = "Active VLAN Has Shutdown SVI"
    description = "Active VLAN has a Switched Virtual Interface that is administratively down"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            os_family = device.get("os_family", "")

            if os_family not in ("iosxe", "ios"):
                continue

            vlan_data = load_device_facts(run_path, hostname, "genie_vlan")
            if not vlan_data:
                continue

            intf_data = load_device_facts(run_path, hostname, "genie_interface")
            if not intf_data:
                continue

            vlans = vlan_data.get("vlans", {})
            for vlan_id_str, vlan_info in vlans.items():
                if not isinstance(vlan_info, dict):
                    continue

                try:
                    vlan_id = int(vlan_id_str)
                except ValueError:
                    continue

                if vlan_id in _SKIP_VLANS:
                    continue

                state = str(vlan_info.get("state", "")).lower()
                if state != "active":
                    continue

                # Check for corresponding SVI
                svi_name = f"Vlan{vlan_id}"
                svi = intf_data.get(svi_name)
                if svi is None:
                    continue  # No SVI for this VLAN — not this rule's concern

                # Check if SVI is admin-down
                enabled = svi.get("enabled", True)
                if enabled is False:
                    vlan_name = vlan_info.get("name", "")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/vlan/{vlan_id_str}/svi-shutdown",
                        message=(
                            f"VLAN {vlan_id_str} ({vlan_name}) is active "
                            f"but its SVI {svi_name} is administratively shutdown"
                        ),
                        key_facts={
                            "vlan_id": vlan_id_str,
                            "vlan_name": vlan_name,
                            "vlan_state": state,
                            "svi_name": svi_name,
                            "svi_enabled": False,
                        },
                        recommendation=(
                            "Either enable the SVI if the VLAN is in use, "
                            "or remove the SVI if the VLAN no longer needs L3"
                        ),
                    ))

        return findings
