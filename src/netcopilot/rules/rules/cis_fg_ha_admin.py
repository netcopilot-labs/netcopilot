"""
CIS FortiGate HA & Admin Hardening Rules — Deep Python rules for the hybrid engine. New rules to capture FortiGate false negatives
identified through compliance gap analysis.

Detection Logic:
    Examines FortiGate HA configuration, admin-maintainer setting,
    admin account expiry, and CLI audit logging.

Severity: high/medium (overridden to cis by engine)
"""

from datetime import datetime, timezone
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


# -------------------------------------------------------------------------
# CIS_FG_HA_AUTH_DISABLED — HA authentication not enabled
# -------------------------------------------------------------------------

class CisFgHaAuthRule(BaseRule):
    """Flags FortiGate HA clusters with authentication disabled."""

    rule_id = "CIS_FG_HA_AUTH_DISABLED"
    severity = "high"
    title = "FortiGate HA Authentication Disabled"
    description = "CIS: HA authentication should be enabled to prevent rogue HA peer injection"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            ha = load_fg_json(device_dir, "fortigate_system_ha")
            if not isinstance(ha, dict):
                continue

            mode = str(ha.get("mode", "standalone")).lower()
            if mode == "standalone":
                continue  # No HA, rule not applicable

            auth = str(ha.get("authentication", "")).lower()
            if auth == "disable" or auth == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/ha-auth",
                    message=(
                        f"HA authentication is disabled — "
                        f"rogue devices can join the HA cluster"
                    ),
                    key_facts={
                        "ha_mode": mode,
                        "authentication": auth or "not configured",
                    },
                    recommendation=(
                        "Enable HA authentication with a strong password: "
                        "'config system ha / set authentication enable / set password <pass>'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_HA_ENCRYPTION_DISABLED — HA heartbeat encryption not enabled
# -------------------------------------------------------------------------

class CisFgHaEncryptionRule(BaseRule):
    """Flags FortiGate HA clusters with heartbeat encryption disabled."""

    rule_id = "CIS_FG_HA_ENCRYPTION_DISABLED"
    severity = "high"
    title = "FortiGate HA Encryption Disabled"
    description = "CIS: HA heartbeat encryption should be enabled to protect sync traffic"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            ha = load_fg_json(device_dir, "fortigate_system_ha")
            if not isinstance(ha, dict):
                continue

            mode = str(ha.get("mode", "standalone")).lower()
            if mode == "standalone":
                continue

            encryption = str(ha.get("encryption", "")).lower()
            if encryption == "disable" or encryption == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/ha-encryption",
                    message=(
                        f"HA heartbeat encryption is disabled — "
                        f"HA sync traffic can be intercepted"
                    ),
                    key_facts={
                        "ha_mode": mode,
                        "encryption": encryption or "not configured",
                    },
                    recommendation=(
                        "Enable HA encryption: "
                        "'config system ha / set encryption enable'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_ADMIN_MAINTAINER_ENABLED — Physical console backdoor enabled
# -------------------------------------------------------------------------

class CisFgAdminMaintainerRule(BaseRule):
    """Flags FortiGate with admin-maintainer enabled (physical console backdoor)."""

    rule_id = "CIS_FG_ADMIN_MAINTAINER_ENABLED"
    severity = "high"
    title = "FortiGate Admin-Maintainer Enabled"
    description = "CIS: admin-maintainer allows console access within 60s of reboot — should be disabled"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            global_cfg = load_fg_json(device_dir, "fortigate_system_global")
            if not isinstance(global_cfg, dict):
                continue

            maintainer = str(global_cfg.get("admin-maintainer", "")).lower()
            if maintainer == "enable":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/admin-maintainer",
                    message=(
                        f"Admin-maintainer is enabled — "
                        f"allows passwordless console access within 60s of reboot"
                    ),
                    key_facts={"admin-maintainer": "enable"},
                    recommendation=(
                        "Disable admin-maintainer: "
                        "'config system global / set admin-maintainer disable'"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_ADMIN_ACCOUNT_EXPIRED — Admin accounts with expired passwords
# -------------------------------------------------------------------------

class CisFgAdminExpiredRule(BaseRule):
    """Flags FortiGate admin accounts with expired passwords."""

    rule_id = "CIS_FG_ADMIN_ACCOUNT_EXPIRED"
    severity = "low"
    title = "FortiGate Admin Account Password Expired"
    description = "CIS: Admin accounts should not have expired passwords"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for hostname, device_dir in find_fortigate_devices(run_path):
            admins = load_fg_json(device_dir, "fortigate_system_admin")
            if not isinstance(admins, list):
                continue

            expired_accounts: list[str] = []
            for admin in admins:
                name = admin.get("name", "?")
                expire_str = str(admin.get("password-expire", "")).strip()
                if not expire_str:
                    continue
                try:
                    expire_dt = datetime.strptime(expire_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                if expire_dt < now:
                    expired_accounts.append(f"{name} (expired {expire_str})")

            if expired_accounts:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/admin-expired",
                    message=(
                        f"{len(expired_accounts)} admin account(s) "
                        f"have expired passwords"
                    ),
                    key_facts={
                        "expired_count": len(expired_accounts),
                        "accounts": ", ".join(expired_accounts[:5]),
                    },
                    recommendation=(
                        "Reset expired admin passwords and enforce password "
                        "rotation policy"
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_CLI_AUDIT_LOG_DISABLED — CLI audit logging not enabled
# -------------------------------------------------------------------------

class CisFgCliAuditLogRule(BaseRule):
    """Flags FortiGate with CLI audit logging disabled."""

    rule_id = "CIS_FG_CLI_AUDIT_LOG_DISABLED"
    severity = "low"
    title = "FortiGate CLI Audit Logging Disabled"
    description = "CIS: CLI audit logging should be enabled for admin command accountability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            global_cfg = load_fg_json(device_dir, "fortigate_system_global")
            if not isinstance(global_cfg, dict):
                continue

            audit_log = str(global_cfg.get("cli-audit-log", "")).lower()
            if audit_log == "disable" or audit_log == "":
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/cli-audit-log",
                    message=(
                        f"CLI audit logging is disabled — "
                        f"no audit trail for admin commands"
                    ),
                    key_facts={"cli-audit-log": audit_log or "not configured"},
                    recommendation=(
                        "Enable CLI audit logging: "
                        "'config system global / set cli-audit-log enable'"
                    ),
                ))

        return findings
