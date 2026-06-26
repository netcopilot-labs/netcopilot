"""
Interface VLAN 1 Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Checks for access ports assigned to VLAN 1 (default) that are admin-up
    but operationally down — unused ports left unsecured on the default VLAN.

Rule IDs: INTF_UNUSED_VLAN1_NOT_SHUTDOWN
Severity: low

audit: new rule to detect unused VLAN 1 ports that
should be shut down per CIS/security best practice.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


class IntfUnusedVlan1NotShutdownRule(BaseRule):
    """Flags admin-up interfaces on VLAN 1 that are operationally down.

    Unused ports left on the default VLAN without shutdown are a security
    risk — they allow unauthorized access to the network.
    """

    rule_id = "INTF_UNUSED_VLAN1_NOT_SHUTDOWN"
    severity = "info"
    title = "Unused VLAN 1 Port Not Shutdown"
    description = "Access port on VLAN 1 is admin-up but oper-down — should be shut down"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            vlans = load_device_facts(run_path, hostname, "genie_vlan")
            intfs = load_device_facts(run_path, hostname, "genie_interface")
            if not vlans or not intfs:
                continue

            # Get interfaces on VLAN 1
            vlan1 = vlans.get("vlans", {}).get("1", {})
            vlan1_intfs = vlan1.get("interfaces", [])
            if not vlan1_intfs:
                continue

            unused_ports: list[str] = []
            for intf_name in vlan1_intfs:
                intf_data = intfs.get(intf_name, {})
                if not isinstance(intf_data, dict):
                    continue
                enabled = intf_data.get("enabled", True)
                oper = str(intf_data.get("oper_status", "up")).lower()
                # Admin-up (enabled=True) but oper-down = unused, should be shut
                if enabled and oper == "down":
                    unused_ports.append(intf_name)

            if unused_ports:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/intf/vlan1-unused",
                    message=(
                        f"{len(unused_ports)} port(s) on VLAN 1 admin-up "
                        f"but oper-down — {', '.join(unused_ports[:5])}"
                        f"{'...' if len(unused_ports) > 5 else ''}"
                    ),
                    key_facts={
                        "unused_port_count": len(unused_ports),
                        "sample_ports": unused_ports[:10],
                    },
                    recommendation=(
                        "Shutdown unused ports: 'interface range <ports>' + 'shutdown' "
                        "and move to a dedicated unused VLAN"
                    ),
                ))

        return findings
