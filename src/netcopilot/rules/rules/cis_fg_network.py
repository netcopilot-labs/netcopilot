"""
CIS FortiGate Network & System Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines zone configuration, WAN management services, SNMP communities,
    HA monitors, and firmware version.

Severity: varies
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


# -------------------------------------------------------------------------
# CIS_FG_1_2 — Ensure intra-zone traffic is not always allowed
# -------------------------------------------------------------------------

class CisFgZoneIntraRule(BaseRule):
    """Flags zones where intra-zone traffic is allowed (should be deny)."""

    rule_id = "CIS_FG_1_2"
    severity = "low"
    title = "Zone Allows Intra-Zone Traffic"
    description = "CIS 1.2: Ensure intra-zone traffic is not always allowed"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            zones = load_fg_json(device_dir, "fortigate_system_zone")
            if not isinstance(zones, list):
                continue

            for zone in zones:
                name = zone.get("name", "?")
                intrazone = str(zone.get("intrazone", "")).lower()
                if intrazone == "allow":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/1.2/zone/{name}",
                        message=f"Zone '{name}' allows intra-zone traffic",
                        key_facts={"zone": name, "intrazone": intrazone},
                        recommendation="Set intra-zone traffic to 'deny' and use explicit policies",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_1_3 — Disable management services on WAN interfaces
# -------------------------------------------------------------------------

class CisFgWanMgmtRule(BaseRule):
    """Flags WAN-facing interfaces with management services enabled."""

    rule_id = "CIS_FG_1_3"
    severity = "high"
    title = "Management Services on WAN Interface"
    description = "CIS 1.3: Disable all management services on WAN-facing interfaces"

    # Management protocols that should be disabled on WAN interfaces
    MGMT_PROTOCOLS = {"https", "http", "ssh", "telnet", "fgfm", "snmp"}

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            interfaces = load_fg_json(device_dir, "fortigate_system_interface")
            if not isinstance(interfaces, list):
                continue

            for intf in interfaces:
                intf_name = str(intf.get("name", ""))
                # Heuristic: WAN interfaces typically have "wan" in name
                # or are the external/ISP-facing interfaces
                role = str(intf.get("role", "")).lower()
                intf_type = str(intf.get("type", "")).lower()

                # Only check WAN-facing interfaces
                is_wan = (
                    "wan" in intf_name.lower()
                    or role == "wan"
                    or intf_type == "tunnel"
                )
                if not is_wan:
                    continue

                allowaccess = str(intf.get("allowaccess", "")).lower().split()
                mgmt_found = [p for p in allowaccess if p in self.MGMT_PROTOCOLS]

                if mgmt_found:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/1.3/intf/{intf_name}",
                        message=(
                            f"WAN interface '{intf_name}' has "
                            f"management services: {mgmt_found}"
                        ),
                        key_facts={
                            "interface": intf_name,
                            "role": role,
                            "mgmt_services": mgmt_found,
                        },
                        recommendation="Remove management services from WAN-facing interfaces",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_1_6 — Ensure firmware is not outdated
# -------------------------------------------------------------------------

class CisFgFirmwareRule(BaseRule):
    """Reports firmware version for review (cannot verify 'latest' without FortiGuard)."""

    rule_id = "CIS_FG_2_1_6"
    severity = "info"
    title = "Firmware Version Review Required"
    description = "CIS 2.1.6: Ensure the latest firmware is installed"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            status = load_fg_json(device_dir, "fortigate_system_status")
            if not isinstance(status, dict):
                continue

            # Also check the version from the top-level JSON metadata
            path = device_dir / "fortigate_system_status.json"
            version = "unknown"
            build = "unknown"
            try:
                import json
                with open(path) as f:
                    raw = json.load(f)
                version = raw.get("version", "unknown")
                build = raw.get("build", "unknown")
            except Exception:
                pass

            # Always emit an informational finding for firmware review
            findings.append(Finding.create_from_rule(
                rule=self, element_type="device",
                element_id=f"{hostname}/cis/fg/2.1.6/firmware",
                message=f"Firmware {version} build {build} — manual review required",
                key_facts={"version": version, "build": build},
                recommendation="Verify firmware is current via FortiGuard advisory; update if needed",
            ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_3_2 — Ensure only SNMPv3 is enabled (no v1/v2c communities)
# -------------------------------------------------------------------------

class CisFgSnmpv3OnlyRule(BaseRule):
    """Flags when SNMPv1/v2c communities are configured (should use v3 only)."""

    rule_id = "CIS_FG_2_3_2"
    severity = "high"
    title = "SNMPv1/v2c Community Configured"
    description = "CIS 2.3.2: Ensure only SNMPv3 is enabled, no v1/v2c communities"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            communities = load_fg_json(device_dir, "fortigate_snmp_community")
            if not isinstance(communities, list):
                continue

            # Each entry in the communities array is a v1/v2c community
            for community in communities:
                comm_id = community.get("id", "?")
                comm_name = community.get("name", "?")
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/2.3.2/snmp-community/{comm_id}",
                    message=f"SNMPv1/v2c community '{comm_name}' configured",
                    key_facts={"community_id": comm_id, "name": comm_name},
                    recommendation="Remove SNMPv1/v2c communities; use SNMPv3 with auth-priv only",
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_5_2 — Ensure Monitor Interfaces for HA are configured
# -------------------------------------------------------------------------

class CisFgHaMonitorRule(BaseRule):
    """Flags HA configurations with no monitored interfaces."""

    rule_id = "CIS_FG_2_5_2"
    severity = "low"
    title = "HA Monitor Interfaces Not Configured"
    description = "CIS 2.5.2: Ensure monitor interfaces are configured for HA failover"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            ha = load_fg_json(device_dir, "fortigate_system_ha")
            if not isinstance(ha, dict):
                continue

            mode = str(ha.get("mode", "")).lower()
            if mode == "standalone":
                # HA not configured, skip monitor check
                continue

            # Check if any interfaces are monitored
            monitor = str(ha.get("monitor", "")).strip()
            if not monitor:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/2.5.2/ha-monitor",
                    message=f"HA mode={mode} but no interfaces monitored",
                    key_facts={"mode": mode, "monitor": "(empty)"},
                    recommendation="Configure monitor interfaces for HA failover detection",
                ))

        return findings
