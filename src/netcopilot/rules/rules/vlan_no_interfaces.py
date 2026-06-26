"""
VLAN No Interfaces — Deep Python rule for the hybrid rule engine. Replaces the YAML eval block with a comprehensive
Python rule that cross-references multiple data sources.

Detection Logic:
    A VLAN is only flagged as "no interfaces" if ALL of these are true:
    1. No access port is assigned to this VLAN (genie_vlan interfaces field)
    2. No SVI (Vlan interface) exists for this VLAN (genie_interface)
    3. No trunk port carries this VLAN (running_config trunk allowed VLANs;
       if any trunk has no explicit filter, ALL VLANs are considered in-use)
    4. VLAN is not 1 (default — always exists, never actionable)
    5. VLAN is not in reserved range 1002-1005 (FDDI/Token Ring defaults)
    6. VLAN state is "active" (skip "unsupport" legacy VLANs)

Rule ID: VLAN_NO_INTERFACES
Severity: low
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


# VLANs to always skip — never actionable
_SKIP_VLANS = {1, 1002, 1003, 1004, 1005}


def _get_trunk_vlans_from_config(config: str) -> set[int] | None:
    """
    Parse running config for trunk allowed VLANs.

    Mirrors the model's ``_parse_switchport_from_config`` so the two producers
    agree (R2-VLAN-1): collects the base ``switchport trunk allowed vlan <list>``
    line **and** any ``... allowed vlan add <list>`` continuation lines (the "add "
    keyword is stripped), unioning them. The previous ``re.search`` read only the
    FIRST line, dropping every ``add`` continuation → under-counted carried VLANs →
    false-positive "VLAN has no interfaces" findings.

    Returns:
        Set of VLAN IDs carried on trunk ports, or None if any trunk
        port carries ALL VLANs (no explicit filter → default behavior).
    """
    has_trunk = False
    trunk_vlans: set[int] = set()

    # Split config into interface blocks
    intf_blocks = re.split(r"^(?=interface )", config, flags=re.MULTILINE)

    for block in intf_blocks:
        if "switchport mode trunk" not in block:
            continue
        has_trunk = True

        # ALL allowed-vlan lines in the block (base + every "add" continuation).
        allowed = re.findall(r"switchport trunk allowed vlan\s+(.+)", block)
        if not allowed:
            # Trunk with no explicit filter → all VLANs allowed
            return None

        for spec in allowed:
            spec = spec.strip()
            # Continuation lines carry an "add " keyword (matches the model parser).
            if spec.startswith("add "):
                spec = spec[4:]
            # Parse VLAN list: "200,201,209-215,300"
            for part in spec.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        lo, hi = part.split("-", 1)
                        for v in range(int(lo), int(hi) + 1):
                            trunk_vlans.add(v)
                    except ValueError:
                        continue
                elif part:
                    try:
                        trunk_vlans.add(int(part))
                    except ValueError:
                        continue

    if not has_trunk:
        return set()  # No trunks at all → no VLANs carried

    return trunk_vlans


class VlanNoInterfacesRule(BaseRule):
    """Flags active VLANs that are truly orphaned (no access, trunk, or SVI)."""

    rule_id = "VLAN_NO_INTERFACES"
    severity = "info"
    title = "VLAN Has No Interfaces"
    description = "Active VLAN has no access ports, trunk ports, or SVI — possible stale config"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            os_family = device.get("os_family", "")

            # Only applies to L2 switches (IOS XE/IOS)
            if os_family not in ("iosxe", "ios"):
                continue

            vlan_data = load_device_facts(run_path, hostname, "genie_vlan")
            if not vlan_data:
                continue

            vlans = vlan_data.get("vlans", {})
            if not vlans:
                continue

            # Build set of VLANs that have SVIs
            intf_data = load_device_facts(run_path, hostname, "genie_interface")
            svi_vlans: set[int] = set()
            if intf_data:
                for intf_name in intf_data:
                    if intf_name.startswith("Vlan"):
                        try:
                            svi_vlans.add(int(intf_name[4:]))
                        except ValueError:
                            continue

            # Build set of VLANs carried on trunks, and locally configured VLANs
            config = load_running_config(run_path, hostname)
            trunk_vlans = None  # None = all VLANs in use (unfiltered trunk)
            local_vlan_ids: set[int] = set()
            if config:
                trunk_vlans = _get_trunk_vlans_from_config(config)
                # None means "all VLANs carried" → skip all
                # Parse locally defined VLANs: "vlan <n>" at start of line.
                # VTP-inherited VLANs appear in genie_vlan.json but NOT here.
                # Flagging VTP-inherited VLANs as orphaned is a false positive.
                for m in re.finditer(r"^vlan (\d+)$", config, re.MULTILINE):
                    local_vlan_ids.add(int(m.group(1)))

            if trunk_vlans is None:
                # Device has an unfiltered trunk — all VLANs are in transit
                continue

            # Check each VLAN
            for vlan_id_str, vlan_info in vlans.items():
                if not isinstance(vlan_info, dict):
                    continue

                try:
                    vlan_id = int(vlan_id_str)
                except ValueError:
                    continue

                # Skip reserved/default VLANs
                if vlan_id in _SKIP_VLANS:
                    continue

                # Skip VTP-inherited VLANs: only evaluate VLANs explicitly
                # defined in the running config ("vlan <n>" entry). Devices
                # with no local vlan entries (VTP clients/legacy VTP servers)
                # inherit the full network database — those are not orphaned.
                # config being non-None means we successfully read the config.
                if config is not None and vlan_id not in local_vlan_ids:
                    continue

                # Skip non-active VLANs
                state = str(vlan_info.get("state", "")).lower()
                if state != "active":
                    continue

                # Check 1: access ports from genie_vlan
                interfaces = vlan_info.get("interfaces")
                if interfaces:
                    continue

                # Check 2: SVI exists
                if vlan_id in svi_vlans:
                    continue

                # Check 3: carried on a trunk
                if vlan_id in trunk_vlans:
                    continue

                # VLAN is truly orphaned
                vlan_name = vlan_info.get("name", "")
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/vlan/{vlan_id_str}/no-interfaces",
                    message=(
                        f"VLAN {vlan_id_str} ({vlan_name}) has no "
                        f"interfaces assigned — possible stale config"
                    ),
                    key_facts={
                        "vlan_id": vlan_id_str,
                        "name": vlan_name,
                        "state": state,
                    },
                    recommendation=(
                        "Remove unused VLANs to reduce STP overhead and "
                        "configuration complexity"
                    ),
                ))

        return findings
