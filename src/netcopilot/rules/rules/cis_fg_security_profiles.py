"""
CIS FortiGate Security Profile Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines antivirus profiles, DNS filter profiles, and application control
    lists for CIS compliance checks.

Severity: medium/low
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import (
    find_fortigate_devices,
    load_fg_json,
    referenced_profile_names,
)


# -------------------------------------------------------------------------
# CIS_FG_4_2_3 — Enable Outbreak Prevention Database in AV profiles
# -------------------------------------------------------------------------

class CisFgAvOutbreakRule(BaseRule):
    """Flags AV profiles with outbreak prevention disabled on HTTP."""

    rule_id = "CIS_FG_4_2_3"
    severity = "low"
    title = "AV Profile Outbreak Prevention Disabled"
    description = "CIS 4.2.3: Enable outbreak prevention in all antivirus profiles"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            profiles = load_fg_json(device_dir, "fortigate_antivirus_profile")
            if not isinstance(profiles, list):
                continue

            referenced = referenced_profile_names(device_dir, "av-profile")
            for profile in profiles:
                name = profile.get("name", "?")
                if name not in referenced:
                    continue  # not applied to any enabled accept policy
                # Check HTTP protocol section for outbreak-prevention
                http_section = profile.get("http", {})
                if not isinstance(http_section, dict):
                    continue
                ob = str(http_section.get("outbreak-prevention", "")).lower()
                if ob == "disable":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.2.3/av-profile/{name}",
                        message=f"AV profile '{name}' has HTTP outbreak prevention disabled",
                        key_facts={"profile": name, "outbreak-prevention": ob},
                        recommendation="Enable outbreak prevention in all AV profiles",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_2_4 — Enable AI/heuristic malware detection (emulator)
# -------------------------------------------------------------------------

class CisFgAvHeuristicRule(BaseRule):
    """Flags AV profiles with heuristic engine (emulator) disabled."""

    rule_id = "CIS_FG_4_2_4"
    severity = "info"
    title = "AV Profile Heuristic Engine Disabled"
    description = "CIS 4.2.4: Enable heuristic-based malware detection in AV profiles"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            profiles = load_fg_json(device_dir, "fortigate_antivirus_profile")
            if not isinstance(profiles, list):
                continue

            for profile in profiles:
                name = profile.get("name", "?")
                # Check emulator across protocol sections
                for proto in ("http", "ftp", "imap", "smtp"):
                    section = profile.get(proto, {})
                    if not isinstance(section, dict):
                        continue
                    emulator = str(section.get("emulator", "")).lower()
                    if emulator == "disable":
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/cis/fg/4.2.4/av-profile/{name}/{proto}",
                            message=f"AV profile '{name}' has {proto} emulator disabled",
                            key_facts={"profile": name, "protocol": proto, "emulator": emulator},
                            recommendation="Enable emulator (heuristic engine) in AV profiles",
                        ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_2_5 — Enable grayware detection on antivirus
# -------------------------------------------------------------------------

class CisFgAvGraywareRule(BaseRule):
    """Flags AV profiles with analytics-db (grayware/sandbox) disabled."""

    rule_id = "CIS_FG_4_2_5"
    severity = "info"
    title = "AV Profile Grayware Detection Disabled"
    description = "CIS 4.2.5: Enable grayware detection in antivirus profiles"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            profiles = load_fg_json(device_dir, "fortigate_antivirus_profile")
            if not isinstance(profiles, list):
                continue

            referenced = referenced_profile_names(device_dir, "av-profile")
            for profile in profiles:
                name = profile.get("name", "?")
                if name not in referenced:
                    continue  # not applied to any enabled accept policy
                analytics = str(profile.get("analytics-db", "")).lower()
                if analytics == "disable":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.2.5/av-profile/{name}",
                        message=f"AV profile '{name}' has analytics-db disabled",
                        key_facts={"profile": name, "analytics-db": analytics},
                        recommendation="Enable analytics-db for grayware detection",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_3_1 — Enable Botnet C&C domain blocking in DNS Filter
# -------------------------------------------------------------------------

class CisFgDnsBotnetRule(BaseRule):
    """Flags DNS filter profiles without botnet C&C blocking enabled."""

    rule_id = "CIS_FG_4_3_1"
    severity = "low"
    title = "DNS Filter Missing Botnet Blocking"
    description = "CIS 4.3.1: Enable botnet C&C domain blocking in DNS filter profiles"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            profiles = load_fg_json(device_dir, "fortigate_dnsfilter_profile")
            if not isinstance(profiles, list):
                continue

            for profile in profiles:
                name = profile.get("name", "?")
                ftgd = profile.get("ftgd-dns", {})
                if not isinstance(ftgd, dict):
                    continue
                # Check if any filter has action=block (not just monitor)
                filters = ftgd.get("filters", [])
                has_block = any(
                    str(f.get("action", "")).lower() == "block"
                    for f in filters if isinstance(f, dict)
                )
                if not has_block:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.3.1/dnsfilter/{name}",
                        message=f"DNS filter '{name}' has no block actions (only monitor)",
                        key_facts={"profile": name, "filter_count": len(filters)},
                        recommendation="Configure block action for botnet C&C categories in DNS filter",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_3_2 — Ensure DNS Filter logs all DNS queries and responses
# -------------------------------------------------------------------------

class CisFgDnsFilterLogRule(BaseRule):
    """Flags DNS filter profiles with logging disabled on any filter entry."""

    rule_id = "CIS_FG_4_3_2"
    severity = "info"
    title = "DNS Filter Logging Incomplete"
    description = "CIS 4.3.2: Ensure DNS filter logs all queries and responses"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            profiles = load_fg_json(device_dir, "fortigate_dnsfilter_profile")
            if not isinstance(profiles, list):
                continue

            for profile in profiles:
                name = profile.get("name", "?")
                ftgd = profile.get("ftgd-dns", {})
                if not isinstance(ftgd, dict):
                    continue
                filters = ftgd.get("filters", [])
                unlogged = [
                    f.get("id", "?") for f in filters
                    if isinstance(f, dict) and str(f.get("log", "")).lower() != "enable"
                ]
                if unlogged:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.3.2/dnsfilter/{name}",
                        message=f"DNS filter '{name}' has {len(unlogged)} filters without logging",
                        key_facts={"profile": name, "unlogged_filter_ids": unlogged},
                        recommendation="Enable logging on all DNS filter entries",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_4_1 — Block high-risk application categories
# -------------------------------------------------------------------------

class CisFgAppBlockHighRiskRule(BaseRule):
    """Flags application control lists that don't block unknown applications."""

    rule_id = "CIS_FG_4_4_1"
    severity = "low"
    title = "Application Control Not Blocking Unknown Apps"
    description = "CIS 4.4.1: Block high-risk and unknown application categories"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            app_lists = load_fg_json(device_dir, "fortigate_application_list")
            if not isinstance(app_lists, list):
                continue

            referenced = referenced_profile_names(device_dir, "application-list")
            for app in app_lists:
                name = app.get("name", "?")
                if name not in referenced:
                    continue  # not applied to any enabled accept policy
                unknown_action = str(app.get("unknown-application-action", "")).lower()
                if unknown_action != "block":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.4.1/app-list/{name}",
                        message=f"App control '{name}' does not block unknown apps ({unknown_action})",
                        key_facts={"list": name, "unknown-application-action": unknown_action},
                        recommendation="Set unknown-application-action to 'block' in application control profiles",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_4_2 — Block applications running on non-default ports
# -------------------------------------------------------------------------

class CisFgAppNonDefaultPortRule(BaseRule):
    """Flags application lists not enforcing default port restriction."""

    rule_id = "CIS_FG_4_4_2"
    severity = "info"
    title = "Application Control Not Enforcing Default Ports"
    description = "CIS 4.4.2: Block applications running on non-default ports"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            app_lists = load_fg_json(device_dir, "fortigate_application_list")
            if not isinstance(app_lists, list):
                continue

            referenced = referenced_profile_names(device_dir, "application-list")
            for app in app_lists:
                name = app.get("name", "?")
                if name not in referenced:
                    continue  # not applied to any enabled accept policy
                enforce = str(app.get("enforce-default-app-port", "")).lower()
                if enforce != "enable":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.4.2/app-list/{name}",
                        message=f"App control '{name}' does not enforce default ports",
                        key_facts={"list": name, "enforce-default-app-port": enforce},
                        recommendation="Enable enforce-default-app-port in application control profiles",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_4_3 — Ensure all Application Control traffic is logged
# -------------------------------------------------------------------------

class CisFgAppControlLogRule(BaseRule):
    """Flags application lists with logging disabled for other/unknown apps."""

    rule_id = "CIS_FG_4_4_3"
    severity = "info"
    title = "Application Control Logging Incomplete"
    description = "CIS 4.4.3: Ensure all application control traffic is logged"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            app_lists = load_fg_json(device_dir, "fortigate_application_list")
            if not isinstance(app_lists, list):
                continue

            referenced = referenced_profile_names(device_dir, "application-list")
            for app in app_lists:
                name = app.get("name", "?")
                if name not in referenced:
                    continue  # not applied to any enabled accept policy
                other_log = str(app.get("other-application-log", "")).lower()
                unknown_log = str(app.get("unknown-application-log", "")).lower()
                if other_log != "enable" or unknown_log != "enable":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.4.3/app-list/{name}",
                        message=f"App control '{name}' has incomplete logging",
                        key_facts={
                            "list": name,
                            "other-application-log": other_log,
                            "unknown-application-log": unknown_log,
                        },
                        recommendation="Enable logging for all application categories",
                    ))

        return findings
