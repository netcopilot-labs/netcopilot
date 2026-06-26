"""
Interface Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie interface learn() output for status, counter, and
    configuration anomalies.

Rule IDs: INTF_OPER_DOWN_ADMIN_UP, INTF_UNUSED_PORTS_NOT_SHUTDOWN,
          INTF_ADMIN_DOWN (disabled), INTF_NO_DESCRIPTION,
          INTF_BANDWIDTH_SPEED_MISMATCH, INTF_INPUT_ERROR_RATE_HIGH,
          INTF_INPUT_UTILIZATION_HIGH, INTF_OUTPUT_UTILIZATION_HIGH,
          INTF_LAST_CHANGE_RECENT
Severity: varies

Noise Reduction:
    Fix 1: INTF_OPER_DOWN_ADMIN_UP — two-tier (connected=critical, unused=aggregated low)
    Fix 2: INTF_NO_DESCRIPTION — only fire on oper-up interfaces
    Fix 3: INTF_ADMIN_DOWN — disabled (no intent data available)
    Fix 4: INTF_BANDWIDTH_SPEED_MISMATCH — exclude non-physical interfaces Fix A: INTF_BANDWIDTH_SPEED_MISMATCH — proper unit parsing for gb/s, mb/s, auto
"""

import json
import re
from pathlib import Path
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


def _load_interfaces(run_path: str, hostname: str) -> dict | None:
    """Load and return Genie interface facts, or None."""
    return load_device_facts(run_path, hostname, "genie_interface")


def _is_physical(intf_name: str) -> bool:
    """Return True if interface name looks like a physical interface."""
    lower = intf_name.lower()
    for prefix in (
        "gigabitethernet", "ge", "gi",
        "tengigabitethernet", "te",
        "hundredgige", "hu",
        "fortygige", "fo",
        "twentyfivegige", "tw",
        "ethernet", "eth",
        "fastethernet", "fa",
        "port-channel", "po",
    ):
        if lower.startswith(prefix):
            return True
    return False


# Prefixes for non-physical interfaces excluded from bandwidth/speed checks
_NON_PHYSICAL_PREFIXES = (
    "loopback", "vlan", "bvi", "null", "nve",
    "port-channel", "bundle-ether",
    "mgmteth", "mgmt", "management",
    "tunnel", "bdi", "embedded-service-engine",
)


def _is_non_physical_for_bw(intf_name: str) -> bool:
    """Return True if interface should be excluded from bandwidth/speed checks."""
    lower = intf_name.lower()
    return any(lower.startswith(p) for p in _NON_PHYSICAL_PREFIXES)


def _interface_has_evidence(
    intf_name: str,
    intf_data: dict,
    model: dict,
    hostname: str,
    lldp_data: dict | None,
    lag_members: set[str] | None = None,
) -> str | None:
    """
    Check if an interface has evidence of intended use.

    Returns:
        "hard"  — active evidence: IP assigned, model link, LLDP/CDP neighbor,
                   or LACP port-channel member
        "soft"  — planned intent only: description set but no active evidence
        None    — no evidence at all (unused port)
    """
    has_hard = False

    # Check IP address — hard evidence (active L3 config)
    ipv4 = intf_data.get("ipv4")
    ipv6 = intf_data.get("ipv6")
    if ipv4 and isinstance(ipv4, dict):
        has_hard = True
    if not has_hard and ipv6 and isinstance(ipv6, dict) and ipv6.get("enabled") is not True:
        if len(ipv6) > 1 or "enabled" not in ipv6:
            has_hard = True

    # Check LACP membership — hard evidence (configured port-channel member)
    # genie_lag.json lists members even when not bundled (partner down).
    # genie_interface port_channel_member is unreliable (false when unbundled).
    if not has_hard and lag_members and intf_name in lag_members:
        has_hard = True

    # Check model links — hard evidence (active discovery)
    # Must match hostname:interface to avoid cross-device false positives
    # (e.g., sw-a Hu1/0/52 matching sw-b's SVL link on Hu1/0/52)
    if not has_hard:
        full_id = f"{hostname}:{intf_name}".lower()
        host_lower = hostname.lower()
        for link in model.get("links", []):
            local_dev = str(link.get("local_device_id", "")).lower()
            remote_dev = str(link.get("remote_device_id", "")).lower()
            local_intf = str(link.get("local_interface_id", "")).lower()
            remote_intf = str(link.get("remote_interface_id", "")).lower()
            if (local_dev == host_lower and full_id in local_intf) or \
               (remote_dev == host_lower and full_id in remote_intf):
                has_hard = True
                break

    # Check LLDP neighbors — hard evidence (active L2 discovery)
    if not has_hard and lldp_data:
        lldp_intfs = lldp_data.get("interfaces", {})
        if intf_name in lldp_intfs:
            has_hard = True

    if has_hard:
        return "hard"

    # Check description — soft evidence (planned intent, may be stale)
    desc = intf_data.get("description", "")
    if desc:
        return "soft"

    return None


# -------------------------------------------------------------------------
# INTF_OPER_DOWN_ADMIN_UP — Two-tier: connected (critical) + unused (aggregated)
# Fix 1
# -------------------------------------------------------------------------

class IntfOperDownAdminUpRule(BaseRule):
    """
    Three-tier interface down detection.

    Tier A — Hard evidence (CRITICAL, per-interface):
        IP assigned, model link, or LLDP/CDP neighbor — active config/discovery
        proves this port should be connected. Being down is a real outage.

    Tier B — Soft evidence (HIGH, per-interface):
        Description only — planned intent suggests a connection, but no active
        evidence. Could be stale description or device not yet deployed.

    Tier C — No evidence (LOW, aggregated):
        Handled by IntfUnusedPortsRule below.
    """

    rule_id = "INTF_OPER_DOWN_ADMIN_UP"
    severity = "critical"
    title = "Interface Oper Down / Admin Up"
    description = "Connected interface is administratively enabled but operationally down"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            lldp_data = load_device_facts(run_path, hostname, "genie_lldp")

            # Build LACP member set from genie_lag.json — includes members
            # even when unbundled (partner down), unlike genie_interface.
            lag_data = load_device_facts(run_path, hostname, "genie_lag")
            lag_members: set[str] = set()
            if lag_data:
                for po_info in lag_data.get("interfaces", {}).values():
                    for member_name in po_info.get("members", {}):
                        lag_members.add(member_name)

            for intf_name in sorted(data.keys()):
                intf = data[intf_name]
                if not isinstance(intf, dict):
                    continue
                if not _is_physical(intf_name):
                    continue
                enabled = intf.get("enabled", False)
                oper = str(intf.get("oper_status", "")).lower()
                if not (enabled and oper == "down"):
                    continue

                evidence = _interface_has_evidence(
                    intf_name, intf, model, hostname, lldp_data, lag_members
                )
                if evidence == "hard":
                    severity = "critical"
                    message = f"{intf_name}: connected interface admin up but operationally down"
                elif evidence == "soft":
                    # Description-only is weak evidence (planned intent, may be
                    # stale) — not proof the port is connected. Surface it low,
                    # not high, to avoid alarm fatigue on unused described ports.
                    severity = "low"
                    message = (
                        f"{intf_name}: admin up but operationally down with only a "
                        f"description (possibly planned/unused or stale) — verify"
                    )
                else:
                    continue  # no evidence → handled by IntfUnusedPortsRule

                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=severity,
                    title=self.title,
                    element_type="interface",
                    element_id=f"{hostname}/{intf_name}/oper-down",
                    message=message,
                    key_facts={
                        "interface": intf_name, "enabled": True,
                        "oper_status": "down",
                        "evidence": evidence,
                        "has_description": bool(intf.get("description")),
                        "has_ip": bool(intf.get("ipv4")),
                        "lag_member": intf_name in lag_members,
                    },
                    recommendation="Check physical cabling, transceiver, and far-end device status",
                ))

        return findings


class IntfUnusedPortsRule(BaseRule):
    """
    Aggregated unused port hygiene.

    Counts interfaces per device that are admin-up but oper-down with no
    evidence of use (no IP, no description, no link, no LLDP neighbor).
    Emits ONE aggregated finding per device instead of per-interface.
    """

    rule_id = "INTF_UNUSED_PORTS_NOT_SHUTDOWN"
    severity = "info"
    title = "Unused Ports Not Shutdown"
    description = "Device has unused ports that are admin-up but operationally down"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            lldp_data = load_device_facts(run_path, hostname, "genie_lldp")
            unused_ports: list[str] = []

            for intf_name in sorted(data.keys()):
                intf = data[intf_name]
                if not isinstance(intf, dict):
                    continue
                if not _is_physical(intf_name):
                    continue
                enabled = intf.get("enabled", False)
                oper = str(intf.get("oper_status", "")).lower()
                if not (enabled and oper == "down"):
                    continue

                # No evidence of use → unused port
                if _interface_has_evidence(intf_name, intf, model, hostname, lldp_data) is None:
                    unused_ports.append(intf_name)

            if unused_ports:
                count = len(unused_ports)
                display_list = ", ".join(unused_ports[:10])
                suffix = f"... ({count} total)" if count > 10 else ""
                findings.append(Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=f"{hostname}/interfaces/unused-ports-summary",
                    message=(
                        f"{count} interfaces admin-up but "
                        f"operationally down with no evidence of use. "
                        f"Best practice: shut unused ports."
                    ),
                    key_facts={
                        "count": count,
                        "interfaces": display_list + suffix,
                    },
                    recommendation="Shutdown unused ports with 'shutdown' command for security and operational hygiene",
                ))

        return findings


# -------------------------------------------------------------------------
# INTF_ADMIN_DOWN — Disabled in Fix 3
# Without NetBox intent data, admin-down is an intentional operator action.
# -------------------------------------------------------------------------

class IntfAdminDownRule(BaseRule):
    """Flags physical interfaces that are administratively shutdown."""

    rule_id = "INTF_ADMIN_DOWN"
    severity = "info"
    title = "Interface Administratively Down"
    description = "Physical interface is administratively shutdown — verify it is intentional"

    def is_enabled(self) -> bool:
        """Disabled in — no intent data to validate admin-down."""
        return False

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        return []


# -------------------------------------------------------------------------
# INTF_NO_DESCRIPTION — only oper-up interfaces
# -------------------------------------------------------------------------

class IntfNoDescriptionRule(BaseRule):
    """Flags physical interfaces without a description (oper-up only)."""

    rule_id = "INTF_NO_DESCRIPTION"
    severity = "info"
    title = "Interface No Description"
    description = "Physical interface has no description — hinders troubleshooting"

    # System/virtual interfaces that don't need descriptions
    _SKIP_PREFIXES = ("null", "embedded-service-engine")

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            # LAG members inherit the port-channel's description — flagging them
            # individually double-counts, so skip them.
            lag_data = load_device_facts(run_path, hostname, "genie_lag")
            lag_members: set[str] = set()
            if lag_data:
                for po_info in lag_data.get("interfaces", {}).values():
                    for member_name in po_info.get("members", {}):
                        lag_members.add(member_name)

            for intf_name in sorted(data.keys()):
                intf = data[intf_name]
                if not isinstance(intf, dict):
                    continue
                # Skip non-physical and system interfaces
                lower = intf_name.lower()
                if any(lower.startswith(p) for p in self._SKIP_PREFIXES):
                    continue
                if intf_name in lag_members:
                    continue
                # only flag oper-up interfaces
                oper = str(intf.get("oper_status", "")).lower()
                if oper != "up":
                    continue
                desc = intf.get("description", "")
                if not desc:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}/no-desc",
                        message=f"{intf_name}: no interface description configured",
                        key_facts={"interface": intf_name, "oper_status": "up"},
                        recommendation="Add descriptive label for operational documentation",
                    ))

        return findings


# -------------------------------------------------------------------------
# INTF_BANDWIDTH_SPEED_MISMATCH Fix 4 + # -------------------------------------------------------------------------


def _parse_speed_to_kbps(port_speed_str: str) -> int | None:
    """
    Parse Genie port_speed string to kbps.

    Handles formats observed in real Genie output:
        "10gb/s"     → 10,000,000 kbps
        "100gb/s"    → 100,000,000 kbps
        "1000mb/s"   → 1,000,000 kbps
        "100mbps"    → 100,000 kbps
        "auto"       → None (skip comparison)
        ""           → None

    Returns:
        Speed in kbps, or None if unparseable or auto-negotiate.
    """
    s = port_speed_str.lower().strip()
    if not s or s == "auto":
        return None

    # Match number + unit: "10gb/s", "1000mb/s", "100mbps", "10gbps"
    m = re.match(r"(\d+)\s*(gb|mb|kb)", s)
    if m:
        val = int(m.group(1))
        unit = m.group(2)
        if val == 0:
            return None
        if unit == "gb":
            return val * 1_000_000  # Gbps → kbps
        if unit == "mb":
            return val * 1_000  # Mbps → kbps
        if unit == "kb":
            return val  # already kbps
        return None

    # Plain integer string — infer unit from magnitude
    try:
        val = int(s)
    except ValueError:
        return None
    if val == 0:
        return None
    if val >= 1_000_000:
        return val // 1_000  # bps → kbps
    # Small numbers (1-999999): assume Mbps (common Genie/IOS speed value)
    return val * 1_000  # Mbps → kbps


class IntfBandwidthSpeedMismatchRule(BaseRule):
    """Flags physical interfaces where configured bandwidth differs from port speed."""

    rule_id = "INTF_BANDWIDTH_SPEED_MISMATCH"
    severity = "info"
    title = "Interface Bandwidth/Speed Mismatch"
    description = "Configured bandwidth differs from port speed — may affect routing metrics"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            for intf_name, intf in data.items():
                if not isinstance(intf, dict):
                    continue
                # exclude all non-physical interfaces
                if _is_non_physical_for_bw(intf_name):
                    continue
                if not _is_physical(intf_name):
                    continue
                # Skip oper-down interfaces: IOS XE resets bandwidth to native
                # port capacity when the port goes down but retains stale port_speed.
                if intf.get("oper_status") == "down":
                    continue
                bandwidth = intf.get("bandwidth")
                port_speed_str = str(intf.get("port_speed", ""))
                if not bandwidth or not port_speed_str:
                    continue
                # proper unit-aware speed parsing
                speed_kbps = _parse_speed_to_kbps(port_speed_str)
                if speed_kbps is None:
                    continue
                if bandwidth != speed_kbps and bandwidth != 0:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}/bw-mismatch",
                        message=(
                            f"{intf_name}: bandwidth {bandwidth}kbps "
                            f"differs from port speed {port_speed_str}"
                        ),
                        key_facts={
                            "interface": intf_name, "bandwidth_kbps": bandwidth,
                            "port_speed": port_speed_str,
                        },
                        recommendation="Align bandwidth statement with actual port speed for correct routing metrics",
                    ))

        return findings


# -------------------------------------------------------------------------
# INTF_INPUT_ERROR_RATE_HIGH
# -------------------------------------------------------------------------

class IntfInputErrorRateHighRule(BaseRule):
    """Flags interfaces with high input error rates."""

    rule_id = "INTF_INPUT_ERROR_RATE_HIGH"
    severity = "low"
    title = "Interface High Input Error Rate"
    description = "Interface has elevated input errors relative to total packets"

    ERROR_PERCENT = 1.0  # default; tune per deployment — >1% error rate

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            for intf_name, intf in data.items():
                if not isinstance(intf, dict):
                    continue
                counters = intf.get("counters", {})
                in_errors = int(counters.get("in_errors", 0) or 0)
                in_pkts = int(counters.get("in_pkts", 0) or 0)
                if in_pkts < 100:  # Too few packets to compute meaningful rate
                    continue
                error_pct = (in_errors / in_pkts) * 100
                if error_pct > self.ERROR_PERCENT:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}/in-errors",
                        message=(
                            f"{intf_name}: input error rate "
                            f"{error_pct:.2f}% ({in_errors}/{in_pkts})"
                        ),
                        key_facts={
                            "interface": intf_name, "in_errors": in_errors,
                            "in_pkts": in_pkts, "error_percent": round(error_pct, 2),
                        },
                        recommendation="Check physical layer, duplex, and speed settings",
                    ))

        return findings


# -------------------------------------------------------------------------
# INTF_INPUT_UTILIZATION_HIGH
# -------------------------------------------------------------------------

class IntfInputUtilizationHighRule(BaseRule):
    """Flags interfaces with high input utilization."""

    rule_id = "INTF_INPUT_UTILIZATION_HIGH"
    severity = "low"
    title = "Interface High Input Utilization"
    description = "Interface input utilization exceeds threshold — may indicate congestion"

    UTIL_THRESHOLD = 80  # default; tune per deployment — percent

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            for intf_name, intf in data.items():
                if not isinstance(intf, dict):
                    continue
                if not _is_physical(intf_name):
                    continue
                rate_info = intf.get("counters", {}).get("rate", {})
                in_rate = rate_info.get("in_rate", 0)
                bandwidth = intf.get("bandwidth", 0)
                if not bandwidth or not in_rate:
                    continue
                # in_rate is in bits/sec, bandwidth in kbps
                util = (in_rate / (bandwidth * 1000)) * 100 if bandwidth else 0
                if util > self.UTIL_THRESHOLD:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}/in-util",
                        message=(
                            f"{intf_name}: input utilization "
                            f"{util:.1f}% (threshold: {self.UTIL_THRESHOLD}%)"
                        ),
                        key_facts={
                            "interface": intf_name, "in_rate_bps": in_rate,
                            "bandwidth_kbps": bandwidth, "utilization": round(util, 1),
                        },
                        recommendation="Investigate traffic patterns; consider link upgrade or QoS",
                    ))

        return findings


# -------------------------------------------------------------------------
# INTF_OUTPUT_UTILIZATION_HIGH
# -------------------------------------------------------------------------

class IntfOutputUtilizationHighRule(BaseRule):
    """Flags interfaces with high output utilization."""

    rule_id = "INTF_OUTPUT_UTILIZATION_HIGH"
    severity = "low"
    title = "Interface High Output Utilization"
    description = "Interface output utilization exceeds threshold — may indicate congestion"

    UTIL_THRESHOLD = 80  # default; tune per deployment — percent

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            for intf_name, intf in data.items():
                if not isinstance(intf, dict):
                    continue
                if not _is_physical(intf_name):
                    continue
                rate_info = intf.get("counters", {}).get("rate", {})
                out_rate = rate_info.get("out_rate", 0)
                bandwidth = intf.get("bandwidth", 0)
                if not bandwidth or not out_rate:
                    continue
                util = (out_rate / (bandwidth * 1000)) * 100 if bandwidth else 0
                if util > self.UTIL_THRESHOLD:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}/out-util",
                        message=(
                            f"{intf_name}: output utilization "
                            f"{util:.1f}% (threshold: {self.UTIL_THRESHOLD}%)"
                        ),
                        key_facts={
                            "interface": intf_name, "out_rate_bps": out_rate,
                            "bandwidth_kbps": bandwidth, "utilization": round(util, 1),
                        },
                        recommendation="Investigate traffic patterns; consider link upgrade or QoS",
                    ))

        return findings


# -------------------------------------------------------------------------
# INTF_LAST_CHANGE_RECENT — Recent interface state change
# -------------------------------------------------------------------------

class IntfLastChangeRecentRule(BaseRule):
    """Flags interfaces that changed state recently."""

    rule_id = "INTF_LAST_CHANGE_RECENT"
    severity = "info"
    title = "Interface Recent State Change"
    description = "Interface changed state recently — may indicate instability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = _load_interfaces(run_path, hostname)
            if not data:
                continue

            for intf_name, intf in data.items():
                if not isinstance(intf, dict):
                    continue
                if not _is_physical(intf_name):
                    continue
                last_change = str(intf.get("last_change", ""))
                if not last_change or last_change == "never":
                    continue
                # Genie format: "HH:MM:SS" or similar
                # Flag if change was within the last hour (no "d" or "w" in timestamp)
                if "d" in last_change or "w" in last_change or "y" in last_change:
                    continue  # Stable for days/weeks
                # Parse HH:MM:SS — flag if < 1 hour
                parts = last_change.split(":")
                if len(parts) == 3:
                    try:
                        hours = int(parts[0])
                        if hours < 1:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="interface",
                                element_id=f"{hostname}/{intf_name}/recent-change",
                                message=(
                                    f"{intf_name}: state changed "
                                    f"{last_change} ago"
                                ),
                                key_facts={"interface": intf_name, "last_change": last_change},
                                recommendation="Monitor for flapping; investigate if changes are unexpected",
                            ))
                    except ValueError:
                        continue

        return findings
