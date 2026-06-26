"""
CIS FortiGate Admin & Access Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines admin accounts, trusted hosts, access profiles, local-in policies,
    and interface management access settings.

Severity: high/medium
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


# -------------------------------------------------------------------------
# CIS_FG_2_4_2 — Ensure all admin accounts have trusted hosts configured
# -------------------------------------------------------------------------

class CisFgAdminTrustedHostsRule(BaseRule):
    """Flags admin accounts where all trusted hosts are 0.0.0.0 (unrestricted)."""

    rule_id = "CIS_FG_2_4_2"
    severity = "high"
    title = "Admin Account Missing Trusted Hosts"
    description = "CIS 2.4.2: Ensure all admin accounts have specific trusted hosts configured"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            admins = load_fg_json(device_dir, "fortigate_system_admin")
            if not isinstance(admins, list):
                continue

            for admin in admins:
                name = admin.get("name", "?")
                # Check trusthost1 through trusthost10
                all_open = True
                for i in range(1, 11):
                    th = str(admin.get(f"trusthost{i}", "0.0.0.0 0.0.0.0")).strip()
                    if th and th != "0.0.0.0 0.0.0.0":
                        all_open = False
                        break

                if all_open:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/2.4.2/admin/{name}",
                        message=f"Admin '{name}' has no trusted hosts configured",
                        key_facts={"admin": name, "trusthosts": "all 0.0.0.0"},
                        recommendation="Configure trusted hosts to restrict admin access by source IP",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_4_3 — Ensure admin accounts have correct privilege profiles
# -------------------------------------------------------------------------

class CisFgAdminProfileRule(BaseRule):
    """Flags admin accounts with super_admin profile that may be overprivileged."""

    rule_id = "CIS_FG_2_4_3"
    severity = "low"
    title = "Admin Account with Super Admin Profile"
    description = "CIS 2.4.3: Ensure admin accounts use least-privilege access profiles"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            admins = load_fg_json(device_dir, "fortigate_system_admin")
            if not isinstance(admins, list):
                continue

            super_admin_count = 0
            for admin in admins:
                profile = str(admin.get("accprofile", "")).lower()
                if profile == "super_admin":
                    super_admin_count += 1

            # Flag if more than 1 admin has super_admin — at least one is
            # expected (the break-glass account)
            if super_admin_count > 1:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/2.4.3/super-admin-count",
                    message=(
                        f"{super_admin_count} admin accounts have "
                        f"super_admin profile (expected ≤1)"
                    ),
                    key_facts={"super_admin_count": super_admin_count},
                    recommendation="Assign least-privilege profiles; limit super_admin to break-glass account only",
                ))

            # SF-ADMIN-THRESH-1: the >1 check above misses the worse case — when
            # EVERY admin is super_admin, no least-privilege account exists at
            # all (the classic CIS gap). Distinct finding (orthogonal to count).
            if admins and super_admin_count == len(admins):
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/2.4.3/no-least-privilege-admin",
                    message=(
                        f"All {len(admins)} admin account(s) use the super_admin "
                        f"profile — no least-privilege account exists"
                    ),
                    key_facts={"admin_count": len(admins), "super_admin_count": super_admin_count},
                    recommendation="Create scoped (non-super_admin) accounts for day-to-day administration",
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_4_5 — Ensure only encrypted access channels are enabled
# -------------------------------------------------------------------------

class CisFgEncryptedAccessRule(BaseRule):
    """Flags interfaces allowing unencrypted management (HTTP, TELNET)."""

    rule_id = "CIS_FG_2_4_5"
    severity = "high"
    title = "Interface Allows Unencrypted Management Access"
    description = "CIS 2.4.5: Ensure only encrypted access channels (HTTPS, SSH) are enabled"

    # Unencrypted protocols that should not be in allowaccess
    UNSAFE_PROTOCOLS = {"http", "telnet"}

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            interfaces = load_fg_json(device_dir, "fortigate_system_interface")
            if not isinstance(interfaces, list):
                continue

            for intf in interfaces:
                allowaccess = str(intf.get("allowaccess", "")).lower().split()
                unsafe_found = [p for p in allowaccess if p in self.UNSAFE_PROTOCOLS]
                if unsafe_found:
                    intf_name = intf.get("name", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/2.4.5/intf/{intf_name}",
                        message=(
                            f"Interface '{intf_name}' allows "
                            f"unencrypted protocols: {unsafe_found}"
                        ),
                        key_facts={
                            "interface": intf_name,
                            "allowaccess": allowaccess,
                            "unsafe": unsafe_found,
                        },
                        recommendation="Remove HTTP and TELNET from allowaccess; use HTTPS and SSH only",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_2_4_6 — Apply Local-in Policies to restrict management access
# -------------------------------------------------------------------------

class CisFgLocalInPolicyRule(BaseRule):
    """Flags when no local-in policies exist to restrict management access."""

    rule_id = "CIS_FG_2_4_6"
    severity = "low"
    title = "No Local-In Policies Configured"
    description = "CIS 2.4.6: Apply local-in policies to restrict management plane access"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            policies = load_fg_json(device_dir, "fortigate_local_in_policy")
            # policies is a list; empty or None means no local-in policies
            if not isinstance(policies, list) or len(policies) == 0:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/2.4.6/local-in-policy",
                    message=f"No local-in policies configured",
                    key_facts={"local_in_policy_count": 0},
                    recommendation="Configure local-in policies to restrict management access by source",
                ))

        return findings
