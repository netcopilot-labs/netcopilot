"""
STP Port Role Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Iterates all devices → all VLANs → all interfaces in genie_stp.json.
    Detects unusual STP port roles that warrant operator attention.

Rule IDs:
    STP_PORT_ROLE_DISABLED  — low   (active interface excluded from STP)
    STP_BACKUP_PORT_DETECTED — info  (two connections to same segment)

Addendum: STP Rules.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts

# Skip virtual/management interfaces with null port_state
_VIRTUAL_PREFIXES = ("AppGigabitEthernet", "Bluetooth", "Tunnel", "Loopback", "Vlan")


def _is_virtual_intf(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL_PREFIXES)


class StpPortRoleDisabledRule(BaseRule):
    """Flags interfaces that have STP role 'disabled' while the port is active.

    A disabled STP role means the port is excluded from spanning-tree participation,
    typically via 'spanning-tree bpduguard enable' err-disable or explicit STP disable.
    This can leave the port in an unexpected state or create loop exposure.
    """

    rule_id = "STP_PORT_ROLE_DISABLED"
    severity = "low"
    title = "STP Port Role Disabled"
    description = "Interface has STP role 'disabled' — port is excluded from spanning-tree"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            if device.get("os_family") not in ("iosxe",):
                continue
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_stp")
            if not data:
                continue

            seen: set[tuple[str, str]] = set()  # (vlan_id, intf_name) dedup

            for mode_data in data.values():
                if not isinstance(mode_data, dict):
                    continue
                for inst_data in mode_data.values():
                    if not isinstance(inst_data, dict):
                        continue
                    vlans = inst_data.get("vlans", {})
                    if not isinstance(vlans, dict):
                        continue
                    for vlan_id, vlan_data in vlans.items():
                        if not isinstance(vlan_data, dict):
                            continue
                        for intf_name, intf in (vlan_data.get("interfaces") or {}).items():
                            if not isinstance(intf, dict):
                                continue
                            if _is_virtual_intf(intf_name):
                                continue
                            port_state = intf.get("port_state")
                            if port_state is None:
                                continue
                            role = intf.get("role", "")
                            if role != "disabled":
                                continue
                            key = (str(vlan_id), intf_name)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(Finding.create_from_rule(
                                rule=self,
                                element_type="device",
                                element_id=f"{hostname}/stp/vlan/{vlan_id}/{intf_name}/disabled",
                                message=(
                                    f"{hostname} VLAN {vlan_id}: interface {intf_name} "
                                    f"has STP role 'disabled' (state: {port_state})"
                                ),
                                key_facts={
                                    "vlan_id": vlan_id,
                                    "interface": intf_name,
                                    "role": role,
                                    "port_state": port_state,
                                },
                                recommendation=(
                                    "Verify the interface is intentionally excluded from STP. "
                                    "If err-disabled, investigate the root cause and clear with "
                                    "'shutdown / no shutdown' after resolving the trigger."
                                ),
                            ))

        return findings


class StpBackupPortDetectedRule(BaseRule):
    """Flags interfaces with STP role 'backup'.

    A backup port means two or more connections from this switch reach the
    same LAN segment. This is unusual in production and may indicate a wiring
    mistake or misconfigured port-channel.
    """

    rule_id = "STP_BACKUP_PORT_DETECTED"
    severity = "info"
    title = "STP Backup Port Detected"
    description = (
        "Interface has STP role 'backup' — multiple connections to the same LAN segment detected"
    )

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            if device.get("os_family") not in ("iosxe",):
                continue
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_stp")
            if not data:
                continue

            seen: set[tuple[str, str]] = set()

            for mode_data in data.values():
                if not isinstance(mode_data, dict):
                    continue
                for inst_data in mode_data.values():
                    if not isinstance(inst_data, dict):
                        continue
                    vlans = inst_data.get("vlans", {})
                    if not isinstance(vlans, dict):
                        continue
                    for vlan_id, vlan_data in vlans.items():
                        if not isinstance(vlan_data, dict):
                            continue
                        for intf_name, intf in (vlan_data.get("interfaces") or {}).items():
                            if not isinstance(intf, dict):
                                continue
                            if _is_virtual_intf(intf_name):
                                continue
                            port_state = intf.get("port_state")
                            if port_state is None:
                                continue
                            role = intf.get("role", "")
                            if role != "backup":
                                continue
                            key = (str(vlan_id), intf_name)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(Finding.create_from_rule(
                                rule=self,
                                element_type="device",
                                element_id=f"{hostname}/stp/vlan/{vlan_id}/{intf_name}/backup",
                                message=(
                                    f"{hostname} VLAN {vlan_id}: interface {intf_name} "
                                    f"has STP role 'backup' — duplicate connection to same segment"
                                ),
                                key_facts={
                                    "vlan_id": vlan_id,
                                    "interface": intf_name,
                                    "role": role,
                                    "port_state": port_state,
                                },
                                recommendation=(
                                    "Verify wiring — backup role indicates two ports on this "
                                    "switch are connected to the same LAN segment. "
                                    "Consider bundling into a port-channel or removing the duplicate link."
                                ),
                            ))

        return findings
