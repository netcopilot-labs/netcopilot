"""
NTP Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie NTP learn() output for synchronization, reachability,
    and stratum anomalies.

Rule IDs: NTP_NOT_SYNCHRONIZED, NTP_HIGH_STRATUM, NTP_PEER_UNREACHABLE,
          NTP_NO_AUTHENTICATION, NTP_REACHABILITY_DEGRADED
Severity: varies
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


def _load_ntp(run_path: str, hostname: str) -> dict | None:
    """Load and return Genie NTP facts, or None."""
    return load_device_facts(run_path, hostname, "genie_ntp")


def _iter_ntp_peers(ntp_data: dict):
    """Yield (vrf, peer_addr, peer_dict) from Genie NTP associations.

    Genie NTP structure varies — handles nested local_mode/isconfigured.
    """
    for vrf_name, vrf in ntp_data.get("vrf", {}).items():
        if not isinstance(vrf, dict):
            continue
        assoc = vrf.get("associations", {}).get("address", {})
        for peer_addr, peer_data in assoc.items():
            if not isinstance(peer_data, dict):
                continue
            # Genie wraps in: local_mode → client → isconfigured → true → {actual data}
            local_modes = peer_data.get("local_mode", {})
            for mode_name, mode_data in local_modes.items():
                if not isinstance(mode_data, dict):
                    continue
                for cfg_key, cfg_data in mode_data.get("isconfigured", {}).items():
                    if isinstance(cfg_data, dict):
                        yield vrf_name, peer_addr, cfg_data


# -------------------------------------------------------------------------
# NTP_NOT_SYNCHRONIZED — Critical: clock not synced
# -------------------------------------------------------------------------

class NtpNotSynchronizedRule(BaseRule):
    """Flags devices whose NTP clock is not synchronized."""

    rule_id = "NTP_NOT_SYNCHRONIZED"
    severity = "critical"
    title = "NTP Not Synchronized"
    description = "Device clock is not synchronized to any NTP source"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ntp = _load_ntp(run_path, hostname)
            if ntp is None:
                continue

            clock = ntp.get("clock_state", {}).get("system_status", {})
            state = str(clock.get("clock_state", "")).lower()
            if state and "unsynchronized" in state:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/ntp/not-synced",
                    message=f"NTP clock is unsynchronized",
                    key_facts={"clock_state": state},
                    recommendation="Check NTP server reachability and network connectivity to time sources",
                ))

        return findings


# -------------------------------------------------------------------------
# NTP_HIGH_STRATUM — NTP source at high stratum
# -------------------------------------------------------------------------

class NtpHighStratumRule(BaseRule):
    """Flags NTP associations with stratum >= 10 (unreliable time source)."""

    rule_id = "NTP_HIGH_STRATUM"
    severity = "low"
    title = "NTP High Stratum"
    description = "NTP source has high stratum value — low accuracy time source"

    STRATUM_THRESHOLD = 10  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ntp = _load_ntp(run_path, hostname)
            if ntp is None:
                continue

            for vrf, peer_addr, peer in _iter_ntp_peers(ntp):
                stratum = peer.get("stratum", 0)
                try:
                    stratum = int(stratum)
                except (ValueError, TypeError):
                    continue
                if stratum >= self.STRATUM_THRESHOLD:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ntp/{peer_addr}/high-stratum",
                        message=(
                            f"NTP peer {peer_addr} at stratum "
                            f"{stratum} (>= {self.STRATUM_THRESHOLD})"
                        ),
                        key_facts={
                            "peer": peer_addr, "stratum": stratum,
                            "threshold": self.STRATUM_THRESHOLD,
                        },
                        recommendation="Use a lower-stratum NTP source for more accurate time",
                    ))

        return findings


# -------------------------------------------------------------------------
# NTP_PEER_UNREACHABLE
# -------------------------------------------------------------------------

class NtpPeerUnreachableRule(BaseRule):
    """Flags NTP peers with zero reachability."""

    rule_id = "NTP_PEER_UNREACHABLE"
    severity = "low"
    title = "NTP Peer Unreachable"
    description = "NTP peer has zero reachability — no successful polls"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ntp = _load_ntp(run_path, hostname)
            if ntp is None:
                continue

            for vrf, peer_addr, peer in _iter_ntp_peers(ntp):
                reach = peer.get("reach", None)
                if reach is not None and int(reach) == 0:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ntp/{peer_addr}/unreachable",
                        message=f"NTP peer {peer_addr} is unreachable (reach=0)",
                        key_facts={"peer": peer_addr, "reach": 0},
                        recommendation="Verify NTP server connectivity, firewall rules, and routing",
                    ))

        return findings


# -------------------------------------------------------------------------
# NTP_NO_AUTHENTICATION
# -------------------------------------------------------------------------

class NtpNoAuthenticationRule(BaseRule):
    """Flags devices with NTP configured but no authentication."""

    rule_id = "NTP_NO_AUTHENTICATION"
    severity = "info"
    title = "NTP No Authentication"
    description = "NTP is configured without authentication — vulnerable to time spoofing"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ntp = _load_ntp(run_path, hostname)
            if ntp is None:
                continue

            # Check if any NTP peers exist
            has_peers = False
            for vrf, peer_addr, peer in _iter_ntp_peers(ntp):
                has_peers = True
                break
            if not has_peers:
                continue

            # Check for authentication config at top level
            auth_enabled = ntp.get("authenticate", False)
            if not auth_enabled:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/ntp/no-auth",
                    message=f"NTP configured without authentication",
                    key_facts={"authenticate": False},
                    recommendation="Enable NTP authentication with 'ntp authenticate' and trusted keys",
                ))

        return findings


# -------------------------------------------------------------------------
# NTP_REACHABILITY_DEGRADED — Partial reachability
# -------------------------------------------------------------------------

class NtpReachabilityDegradedRule(BaseRule):
    """Flags NTP peers with partial reachability (some polls failing)."""

    rule_id = "NTP_REACHABILITY_DEGRADED"
    severity = "info"
    title = "NTP Reachability Degraded"
    description = "NTP peer has intermittent reachability — some polls failing"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ntp = _load_ntp(run_path, hostname)
            if ntp is None:
                continue

            for vrf, peer_addr, peer in _iter_ntp_peers(ntp):
                reach = peer.get("reach")
                if reach is None:
                    continue
                try:
                    reach_val = int(reach)
                except (ValueError, TypeError):
                    continue
                # reach is octal bitmask (0-377). 377 = all 8 polls OK, 0 = none
                # Flag partial (not 0 and not 377/255)
                if 0 < reach_val < 255:
                    # Count bits set in the octal value
                    bits = bin(reach_val).count("1")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ntp/{peer_addr}/degraded",
                        message=(
                            f"NTP peer {peer_addr} partial reachability "
                            f"({bits}/8 polls successful, reach={reach_val})"
                        ),
                        key_facts={
                            "peer": peer_addr, "reach": reach_val,
                            "successful_polls": bits,
                        },
                        recommendation="Investigate intermittent NTP connectivity issues",
                    ))

        return findings
