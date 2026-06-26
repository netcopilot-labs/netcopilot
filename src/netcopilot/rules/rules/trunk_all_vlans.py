"""
Trunk All VLANs Allowed Rule — flags trunk ports without explicit VLAN pruning.

Detection Logic:
    Checks for interfaces with switchport_mode=trunk that have no explicit
    `switchport trunk allowed vlan` configuration. This means ALL VLANs
    traverse the trunk, which is a security and operational risk.

Rule ID: TRUNK_ALL_VLANS_ALLOWED
Severity: low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class TrunkAllVlansAllowedRule(BaseRule):
    """Flags trunk ports that allow all VLANs (no explicit pruning).

    Best practice is to explicitly configure allowed VLANs on trunk ports
    to limit broadcast domain scope and reduce attack surface.
    """

    rule_id = "TRUNK_ALL_VLANS_ALLOWED"
    severity = "low"
    title = "Trunk Allows All VLANs"
    description = "Trunk port has no explicit VLAN pruning — all VLANs are allowed"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        links = model.get("links", [])

        for intf in model.get("interfaces", []):
            if intf.get("switchport_mode") != "trunk":
                continue
            # trunk_vlans is None or absent = no explicit allowed-vlan filter
            trunk_vlans = intf.get("trunk_vlans")
            if trunk_vlans:
                continue
            hostname = intf.get("device_id", "")
            intf_name = intf.get("name", "")
            if not hostname or not intf_name:
                continue
            # Suppress on uplinks: an all-VLAN trunk is EXPECTED on inter-switch
            # links and port-channel bundles — the finding only matters on
            # access-facing trunks. Port-channels and any interface that
            # terminates a discovered link to another collected device = uplink.
            iname_l = intf_name.lower()
            if iname_l.startswith(("po", "port-channel", "bundle-ether", "be")):
                continue
            full_id = f"{hostname}:{intf_name}".lower()
            is_uplink = any(
                full_id in str(link.get("local_interface_id", "")).lower()
                or full_id in str(link.get("remote_interface_id", "")).lower()
                for link in links
            )
            if is_uplink:
                continue
            findings.append(Finding.create_from_rule(
                rule=self,
                element_type="interface",
                element_id=f"{hostname}:{intf_name}/trunk-all-allowed",
                message=(
                    f"{hostname} {intf_name} is a trunk with all VLANs "
                    f"allowed — no explicit 'switchport trunk allowed vlan'"
                ),
                key_facts={
                    "interface": intf_name,
                    "device": hostname,
                },
                recommendation=(
                    "Configure explicit VLAN pruning: "
                    "'switchport trunk allowed vlan <list>' to limit "
                    "broadcast domain scope and reduce attack surface"
                ),
            ))

        return findings
