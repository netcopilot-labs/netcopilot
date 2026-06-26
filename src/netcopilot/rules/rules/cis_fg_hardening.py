"""
CIS FortiGate System Hardening Rules — Deep Python rules for the hybrid engine. New rules to close false negative gaps identified in
compliance gap analysis.

Detection Logic:
    Examines FortiGate system_global, system_ntp, and system_dns settings.

Severity: medium/low (overridden to cis by engine)
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


# CIS recommended maximum lockout threshold
_CIS_LOCKOUT_MAX = 5


# -------------------------------------------------------------------------
# CIS_FG_LOCKOUT_THRESHOLD — Admin lockout threshold too high
# -------------------------------------------------------------------------

class CisFgLockoutThresholdRule(BaseRule):
    """Flags FortiGate with admin lockout threshold above CIS recommendation."""

    rule_id = "CIS_FG_LOCKOUT_THRESHOLD"
    severity = "low"
    title = "FortiGate Admin Lockout Threshold Too High"
    description = "CIS: admin-lockout-threshold should be 3-5 to limit brute-force attempts"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            global_cfg = load_fg_json(device_dir, "fortigate_system_global")
            if not isinstance(global_cfg, dict):
                continue

            threshold = global_cfg.get("admin-lockout-threshold", 0)
            try:
                threshold = int(threshold)
            except (ValueError, TypeError):
                continue

            if threshold > _CIS_LOCKOUT_MAX:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/lockout-threshold",
                    message=(
                        f"Admin-lockout-threshold is {threshold} "
                        f"(CIS recommends ≤{_CIS_LOCKOUT_MAX})"
                    ),
                    key_facts={
                        "admin-lockout-threshold": threshold,
                        "cis_max": _CIS_LOCKOUT_MAX,
                    },
                    recommendation=(
                        "Lower admin lockout threshold: "
                        "'config system global / set admin-lockout-threshold 3'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_PRIVATE_DATA_ENCRYPTION — Private data encryption disabled
# -------------------------------------------------------------------------

class CisFgPrivateDataEncryptionRule(BaseRule):
    """Flags FortiGate with private-data-encryption disabled."""

    rule_id = "CIS_FG_PRIVATE_DATA_ENCRYPTION"
    severity = "low"
    title = "FortiGate Private Data Encryption Disabled"
    description = "CIS: private-data-encryption should be enabled to protect config secrets at rest"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            global_cfg = load_fg_json(device_dir, "fortigate_system_global")
            if not isinstance(global_cfg, dict):
                continue

            pde = str(global_cfg.get("private-data-encryption", "")).lower()
            if pde == "disable" or pde == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/private-data-encryption",
                    message=(
                        f"Private-data-encryption is disabled — "
                        f"config secrets stored in plaintext"
                    ),
                    key_facts={"private-data-encryption": pde or "not configured"},
                    recommendation=(
                        "Enable private data encryption: "
                        "'config system global / set private-data-encryption enable'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_NTP_AUTH — NTP authentication disabled
# -------------------------------------------------------------------------

class CisFgNtpAuthRule(BaseRule):
    """Flags FortiGate with NTP authentication disabled."""

    rule_id = "CIS_FG_NTP_AUTH"
    severity = "low"
    title = "FortiGate NTP Authentication Disabled"
    description = "CIS: NTP authentication should be enabled to prevent time-source spoofing"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            ntp_cfg = load_fg_json(device_dir, "fortigate_system_ntp")
            if not isinstance(ntp_cfg, dict):
                continue

            auth = str(ntp_cfg.get("authentication", "")).lower()
            if auth == "disable" or auth == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/ntp-auth",
                    message=(
                        f"NTP authentication is disabled — "
                        f"time source can be spoofed"
                    ),
                    key_facts={
                        "authentication": auth or "not configured",
                        "ntp_type": str(ntp_cfg.get("type", "")),
                    },
                    recommendation=(
                        "Enable NTP authentication: "
                        "'config system ntp / set authentication enable / "
                        "set key-type MD5 / set key <key>'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_DNS_LOGGING — DNS logging disabled
# -------------------------------------------------------------------------

class CisFgDnsLoggingRule(BaseRule):
    """Flags FortiGate with DNS query logging disabled."""

    rule_id = "CIS_FG_DNS_LOGGING"
    severity = "info"
    title = "FortiGate DNS Logging Disabled"
    description = "CIS: DNS logging should be enabled for visibility into DNS queries"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            dns_cfg = load_fg_json(device_dir, "fortigate_system_dns")
            if not isinstance(dns_cfg, dict):
                continue

            log = str(dns_cfg.get("log", "")).lower()
            if log == "disable" or log == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/dns-logging",
                    message=(
                        f"DNS query logging is disabled — "
                        f"no visibility into DNS resolution activity"
                    ),
                    key_facts={"dns-log": log or "not configured"},
                    recommendation=(
                        "Enable DNS logging: "
                        "'config system dns / set log enable'"
                    ),
                ))

        return findings
