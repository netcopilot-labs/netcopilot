"""
L2 edge-security rules (S10, ADR-0012) — DHCP snooping, port-security, BPDU-guard.

Reads the **model** (not raw config): interfaces carry `port_security` /
`bpduguard` / `protected`, devices carry `dhcp_snooping` / `bpduguard_default`
(from `security_config.l2_security` via the model enricher). The model is the
single source of truth, so parser and rules cannot disagree.

Tiered, low-false-positive by construction:
  - Precise misconfiguration (HIGH/low): fire only where a feature is configured
    but wrong — DHCP-snooping trust on a host-facing access port, port-security
    violation-mode `protect` (silent drop), an active access VLAN not snooped.
  - Absence (low/info): aggregated per device — a switch with host-facing access
    ports that lacks DHCP-snooping / port-security / BPDU-guard.

Over-fire guard: "host-facing access port" = `switchport mode access` AND not an
endpoint of any inter-device link. Uplinks / trunks / port-channels are excluded,
so an access-port absence rule never fires on infrastructure links.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


def _uplink_interface_ids(model: dict[str, Any]) -> set[str]:
    """Interface_ids that are an endpoint of some inter-device link (uplinks)."""
    ids: set[str] = set()
    for link in model.get("links", []):
        for key in ("local_interface_id", "remote_interface_id"):
            iid = link.get(key)
            if iid:
                ids.add(iid)
    return ids


def _host_access_ports(
    interfaces: list[dict[str, Any]], device_id: str, uplinks: set[str]
) -> list[dict[str, Any]]:
    """Host-facing access ports on a device: switchport access, not an uplink."""
    return [
        i for i in interfaces
        if i.get("device_id") == device_id
        and i.get("switchport_mode") == "access"
        and i.get("interface_id") not in uplinks
    ]


def _devices_with_access(model: dict[str, Any]):
    """Yield (device, host_access_ports) for every device that has ≥1 host port."""
    uplinks = _uplink_interface_ids(model)
    interfaces = model.get("interfaces", [])
    for device in model.get("devices", []):
        ports = _host_access_ports(interfaces, device.get("device_id", ""), uplinks)
        if ports:
            yield device, ports


# =========================================================================
# Precise misconfiguration rules
# =========================================================================

class L2SecDhcpTrustOnAccessRule(BaseRule):
    """DHCP-snooping trust on a host-facing access port — a trust-boundary
    violation (a rogue DHCP server on that port is trusted)."""

    rule_id = "L2SEC_DHCP_TRUST_ON_ACCESS"
    severity = "high"
    title = "DHCP Snooping Trust on Access Port"
    description = "DHCP-snooping trust is set on a host-facing access port — rogue DHCP servers would be trusted"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        uplinks = _uplink_interface_ids(model)
        intf_by_id = {i.get("interface_id"): i for i in model.get("interfaces", [])}
        for device in model.get("devices", []):
            hostname = device.get("hostname", device.get("device_id", ""))
            snoop = device.get("dhcp_snooping") or {}
            for tname in snoop.get("trust_interfaces", []):
                iid = f"{device.get('device_id','')}:{tname}"
                intf = intf_by_id.get(iid)
                # Only flag a trust interface that is a host-facing access port.
                if intf and intf.get("switchport_mode") == "access" and iid not in uplinks:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/l2sec/dhcp-trust/{tname}",
                        message=f"DHCP-snooping trust on access port {tname} — trust-boundary violation",
                        key_facts={"interface": tname, "device": hostname},
                        recommendation="Remove 'ip dhcp snooping trust' from access ports; keep it on uplinks only",
                    ))
        return findings


class L2SecPortSecurityWeakViolationRule(BaseRule):
    """port-security violation-mode `protect` silently drops offending frames
    (no log, no err-disable) — the weakest of the three modes."""

    rule_id = "L2SEC_PORT_SECURITY_WEAK_VIOLATION"
    severity = "low"
    title = "Port-Security Weak Violation Mode"
    description = "port-security violation-mode 'protect' silently drops frames (no log/err-disable) — restrict or shutdown is stronger"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for device in model.get("devices", []):
            hostname = device.get("hostname", device.get("device_id", ""))
            for intf in model.get("interfaces", []):
                if intf.get("device_id") != device.get("device_id"):
                    continue
                ps = intf.get("port_security") or {}
                if ps.get("violation") == "protect":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/l2sec/ps-violation/{intf.get('name','')}",
                        message=f"Port-security on {intf.get('name','')} uses violation-mode 'protect' (silent drop)",
                        key_facts={"interface": intf.get("name", ""), "device": hostname, "violation": "protect"},
                        recommendation="Use 'switchport port-security violation restrict' (logs) or 'shutdown' (err-disable)",
                    ))
        return findings


class L2SecAccessVlanNotSnoopedRule(BaseRule):
    """DHCP snooping is enabled, but a host-facing access port lives in a VLAN
    that is not in the snooping VLAN list — the VLAN carries hosts unprotected."""

    rule_id = "L2SEC_ACCESS_VLAN_NOT_SNOOPED"
    severity = "low"
    title = "Access VLAN Not DHCP-Snooped"
    description = "A user access VLAN (≥2 host ports) is not in the DHCP-snooping VLAN list while snooping is on — hosts on it are unprotected"

    #: Minimum host access ports on an unsnooped VLAN before it counts as a
    #: user VLAN worth flagging. A single access port on an unsnooped VLAN is
    #: usually a one-off management/infra port where snooping is deliberately
    #: omitted — flagging it is noise, not a gap. (S10 FP-tuning, Carlos.)
    MIN_HOST_PORTS = 2

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        from collections import Counter
        findings: list[Finding] = []
        uplinks = _uplink_interface_ids(model)
        for device in model.get("devices", []):
            hostname = device.get("hostname", device.get("device_id", ""))
            snoop = device.get("dhcp_snooping") or {}
            if not snoop.get("enabled"):
                continue  # only meaningful where snooping IS on
            snooped = set(snoop.get("vlans", []))
            ports = _host_access_ports(model.get("interfaces", []), device.get("device_id", ""), uplinks)
            vlan_counts = Counter(
                v for i in ports
                if (v := i.get("access_vlan")) is not None and v not in snooped
            )
            for vlan, count in sorted(vlan_counts.items()):
                if count < self.MIN_HOST_PORTS:
                    continue  # one-off mgmt/infra port — not a user VLAN, skip
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/l2sec/vlan-not-snooped/{vlan}",
                    message=f"Access VLAN {vlan} carries {count} host port(s) but is not DHCP-snooped",
                    key_facts={"vlan": vlan, "device": hostname, "host_ports": count},
                    recommendation=f"Add VLAN {vlan} to 'ip dhcp snooping vlan'",
                ))
        return findings


# =========================================================================
# Absence rules — aggregated per device, LOW/info (visible, not screaming)
# =========================================================================

class L2SecNoDhcpSnoopingRule(BaseRule):
    """A switch with host-facing access ports has DHCP snooping disabled."""

    rule_id = "L2SEC_NO_DHCP_SNOOPING"
    severity = "low"
    title = "No DHCP Snooping on Access Switch"
    description = "A switch with host-facing access ports has DHCP snooping globally disabled — no rogue-DHCP protection"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for device, ports in _devices_with_access(model):
            hostname = device.get("hostname", device.get("device_id", ""))
            snoop = device.get("dhcp_snooping") or {}
            if not snoop.get("enabled"):
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/l2sec/no-dhcp-snooping",
                    message=f"{len(ports)} host-facing access port(s) but DHCP snooping is disabled",
                    key_facts={"device": hostname, "access_ports": len(ports)},
                    recommendation="Enable 'ip dhcp snooping' + 'ip dhcp snooping vlan <access-vlans>'",
                ))
        return findings


class L2SecAccessPortsNoPortSecurityRule(BaseRule):
    """Host-facing access ports without port-security (aggregated per device)."""

    rule_id = "L2SEC_ACCESS_PORTS_NO_PORT_SECURITY"
    severity = "info"
    title = "Access Ports Without Port-Security"
    description = "Host-facing access ports lack port-security — no MAC-flooding / rogue-host limit"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for device, ports in _devices_with_access(model):
            hostname = device.get("hostname", device.get("device_id", ""))
            unprotected = [p for p in ports if not p.get("port_security")]
            if unprotected:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/l2sec/no-port-security",
                    message=f"{len(unprotected)}/{len(ports)} host-facing access port(s) lack port-security",
                    key_facts={"device": hostname, "unprotected": len(unprotected), "access_ports": len(ports)},
                    recommendation="Apply 'switchport port-security' (with maximum + violation) on host access ports",
                ))
        return findings


class L2SecAccessPortsNoBpduGuardRule(BaseRule):
    """Host-facing access ports without BPDU-guard (and no global default)."""

    rule_id = "L2SEC_ACCESS_PORTS_NO_BPDUGUARD"
    severity = "info"
    title = "Access Ports Without BPDU-Guard"
    description = "Host-facing access ports lack BPDU-guard (and no 'portfast bpduguard default') — a rogue switch could hijack STP"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for device, ports in _devices_with_access(model):
            if device.get("bpduguard_default"):
                continue  # global default covers all access ports
            hostname = device.get("hostname", device.get("device_id", ""))
            unguarded = [p for p in ports if not p.get("bpduguard")]
            if unguarded:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/l2sec/no-bpduguard",
                    message=f"{len(unguarded)}/{len(ports)} host-facing access port(s) lack BPDU-guard",
                    key_facts={"device": hostname, "unguarded": len(unguarded), "access_ports": len(ports)},
                    recommendation="Enable 'spanning-tree bpduguard enable' on access ports or 'spanning-tree portfast bpduguard default' globally",
                ))
        return findings
