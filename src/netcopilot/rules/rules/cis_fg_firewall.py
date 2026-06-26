"""
CIS FortiGate Firewall Policy Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Iterates over firewall policies in fortigate_firewall_policy.json.
    Each rule checks a specific CIS benchmark requirement.

Severity: varies (medium/high)
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.rules.cis_fg_helpers import find_fortigate_devices, load_fg_json


# -------------------------------------------------------------------------
# Helper: load policies once per device
# -------------------------------------------------------------------------

def _load_policies(device_dir) -> list[dict]:
    """Load firewall policies, returning empty list if unavailable."""
    results = load_fg_json(device_dir, "fortigate_firewall_policy")
    if not isinstance(results, list):
        return []
    return results


# -------------------------------------------------------------------------
# CIS_FG_3_1 — Ensure unused firewall policies are reviewed/removed
# -------------------------------------------------------------------------

class CisFgUnusedPolicyRule(BaseRule):
    """Flags disabled firewall policies that should be reviewed or removed."""

    rule_id = "CIS_FG_3_1"
    severity = "info"
    title = "Disabled Firewall Policy"
    description = "CIS 3.1: Ensure unused firewall policies are reviewed and removed"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            # Aggregate: a disabled policy is often intentional, so emit ONE
            # review finding per device listing them, not N separate ones.
            disabled = [
                {"policyid": p.get("policyid", "?"), "name": p.get("name", "(unnamed)")}
                for p in _load_policies(device_dir)
                if str(p.get("status", "")).lower() == "disable"
            ]
            if disabled:
                ids = ", ".join(str(d["policyid"]) for d in disabled)
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/3.1/disabled-policies",
                    message=(
                        f"{len(disabled)} disabled firewall policies "
                        f"(ids: {ids}) — review and remove if unused"
                    ),
                    key_facts={"disabled_count": len(disabled), "policies": disabled},
                    recommendation="Review and remove unused firewall policies",
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_3_2 — Ensure firewall accept policies do not use 'all' for
#               source and destination
# -------------------------------------------------------------------------

class CisFgAnyAnyPolicyRule(BaseRule):
    """Flags accept policies with both source and destination set to 'all'."""

    rule_id = "CIS_FG_3_2"
    severity = "high"
    title = "Firewall Policy Allows Any-to-Any"
    description = "CIS 3.2: Ensure accept policies do not use 'all' for source and destination"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            for policy in _load_policies(device_dir):
                if str(policy.get("action", "")).lower() != "accept":
                    continue
                if str(policy.get("status", "")).lower() == "disable":
                    continue

                src_all = any(
                    a.get("name", "").lower() == "all"
                    for a in policy.get("srcaddr", [])
                )
                dst_all = any(
                    a.get("name", "").lower() == "all"
                    for a in policy.get("dstaddr", [])
                )

                if src_all and dst_all:
                    pid = policy.get("policyid", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/3.2/policy/{pid}",
                        message=f"Policy {pid} allows any source to any destination",
                        key_facts={"policyid": pid, "srcaddr": "all", "dstaddr": "all"},
                        recommendation="Restrict source and destination addresses in accept policies",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_3_3 — Ensure firewall policies are uniquely named
# -------------------------------------------------------------------------

class CisFgDuplicatePolicyNameRule(BaseRule):
    """Flags firewall policies with duplicate or empty names."""

    rule_id = "CIS_FG_3_3"
    severity = "info"
    title = "Firewall Policy Naming Issue"
    description = "CIS 3.3: Ensure firewall policies are uniquely named"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            policies = _load_policies(device_dir)
            # Track names to find duplicates
            seen_names: dict[str, list[int]] = {}
            unnamed_ids: list[int] = []

            for policy in policies:
                pid = policy.get("policyid", 0)
                name = str(policy.get("name", "")).strip()
                if not name:
                    unnamed_ids.append(pid)
                else:
                    seen_names.setdefault(name, []).append(pid)

            # Flag unnamed policies
            for pid in unnamed_ids:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/3.3/policy/{pid}/unnamed",
                    message=f"Policy {pid} has no name",
                    key_facts={"policyid": pid, "issue": "unnamed"},
                    recommendation="Assign descriptive names to all firewall policies",
                ))

            # Flag duplicate names
            for name, pids in seen_names.items():
                if len(pids) > 1:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/3.3/duplicate/{name}",
                        message=f"Duplicate policy name '{name}' on policies {pids}",
                        key_facts={"name": name, "policyids": pids, "issue": "duplicate"},
                        recommendation="Ensure each firewall policy has a unique name",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_3_5 — Ensure deny policies exist for all traffic not explicitly
#               allowed
# -------------------------------------------------------------------------

class CisFgDenyAllPolicyRule(BaseRule):
    """Checks that at least one explicit deny policy exists."""

    rule_id = "CIS_FG_3_5"
    severity = "high"
    title = "No Explicit Deny-All Policy"
    description = "CIS 3.5: Ensure explicit deny policies exist for unmatched traffic"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            policies = _load_policies(device_dir)
            if not policies:
                continue

            has_deny = any(
                str(p.get("action", "")).lower() == "deny"
                for p in policies
                if str(p.get("status", "")).lower() != "disable"
            )

            if not has_deny:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/fg/3.5/no-deny-policy",
                    message=f"No explicit deny policy found",
                    key_facts={"total_policies": len(policies)},
                    recommendation="Add an explicit deny-all policy at the end of the policy list",
                ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_3_6 — Ensure logging is enabled on all firewall policies
# -------------------------------------------------------------------------

class CisFgPolicyLoggingRule(BaseRule):
    """Flags active policies with logging disabled."""

    rule_id = "CIS_FG_3_6"
    severity = "low"
    title = "Firewall Policy Logging Disabled"
    description = "CIS 3.6: Ensure logging is enabled on all firewall policies"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            for policy in _load_policies(device_dir):
                if str(policy.get("status", "")).lower() == "disable":
                    continue
                logtraffic = str(policy.get("logtraffic", "")).lower()
                if logtraffic == "disable":
                    pid = policy.get("policyid", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/3.6/policy/{pid}",
                        message=f"Policy {pid} has logging disabled",
                        key_facts={"policyid": pid, "logtraffic": logtraffic},
                        recommendation="Enable logging on all firewall policies (logtraffic=all or utm)",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_1_1 — Ensure IPS sensors on accept policies
# -------------------------------------------------------------------------

class CisFgIpsOnAcceptRule(BaseRule):
    """Flags active accept policies without an IPS sensor assigned."""

    rule_id = "CIS_FG_4_1_1"
    severity = "low"
    title = "Accept Policy Missing IPS Sensor"
    description = "CIS 4.1.1: Ensure IPS sensors are applied to accept policies"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            for policy in _load_policies(device_dir):
                if str(policy.get("action", "")).lower() != "accept":
                    continue
                if str(policy.get("status", "")).lower() == "disable":
                    continue
                ips = str(policy.get("ips-sensor", "")).strip()
                if not ips:
                    pid = policy.get("policyid", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.1.1/policy/{pid}",
                        message=f"Accept policy {pid} has no IPS sensor",
                        key_facts={"policyid": pid, "ips-sensor": "(empty)"},
                        recommendation="Apply an IPS sensor to all accept policies",
                    ))

        return findings


# -------------------------------------------------------------------------
# CIS_FG_4_2_2 — Apply Antivirus Security Profile to all accept policies
# -------------------------------------------------------------------------

class CisFgAvOnAcceptRule(BaseRule):
    """Flags active accept policies without an antivirus profile assigned."""

    rule_id = "CIS_FG_4_2_2"
    severity = "low"
    title = "Accept Policy Missing Antivirus Profile"
    description = "CIS 4.2.2: Apply antivirus profile to all accept policies"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for hostname, device_dir in find_fortigate_devices(run_path):
            for policy in _load_policies(device_dir):
                if str(policy.get("action", "")).lower() != "accept":
                    continue
                if str(policy.get("status", "")).lower() == "disable":
                    continue
                av = str(policy.get("av-profile", "")).strip()
                if not av:
                    pid = policy.get("policyid", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/cis/fg/4.2.2/policy/{pid}",
                        message=f"Accept policy {pid} has no antivirus profile",
                        key_facts={"policyid": pid, "av-profile": "(empty)"},
                        recommendation="Apply an antivirus profile to all accept policies",
                    ))

        return findings
