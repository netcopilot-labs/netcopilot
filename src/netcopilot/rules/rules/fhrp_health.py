"""FHRP (HSRP + VRRP) health rules — Phase-1 model rules.

All 14 catalog FHRP rules (9 HSRP + 5 VRRP), previously prose-only, made
executable. They read the `fhrp_group` shared services built by
`link_builder._discover_fhrp_groups` — because that construct already joins the
peer routers with their per-member state, even the "peer comparison" checks
(priority conflict, timer/version/adv-interval mismatch) are expressed as
single Phase-1 rules over one group's members; no cross-device machinery needed.

Catalog severities map to the rule-declaration set: critical→critical,
warning→low, informational→info.
"""
from ipaddress import ip_address, ip_interface
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding

_ACTIVE_STATES = {"active", "master"}


def _iface_index(model: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """(hostname, interface_name) -> interface dict, for VIP-subnet checks."""
    host_by_devid = {d.get("device_id"): d.get("hostname") for d in model.get("devices", [])}
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for i in model.get("interfaces", []):
        host = host_by_devid.get(i.get("device_id"))
        if host and i.get("name"):
            idx[(host, i["name"])] = i
    return idx


def _fhrp_groups(model: dict[str, Any], protocol: str) -> list[dict[str, Any]]:
    return [
        s for s in model.get("shared_services", [])
        if s.get("service_type") == "fhrp_group" and s.get("protocol") == protocol
    ]


def _anchor(group: dict[str, Any]) -> str:
    members = group.get("members", [])
    return group.get("active_device") or (members[0]["hostname"] if members else "unknown")


def _vip_in_subnet(group: dict[str, Any], idx: dict) -> tuple[bool | None, str | None]:
    """(True/False/None, subnet_str). None = unknown (no interface IP found)."""
    for m in group.get("members", []):
        iface = idx.get((m["hostname"], m["interface"]))
        if iface and iface.get("ip_address") and iface.get("prefix_length"):
            try:
                net = ip_interface(f"{iface['ip_address']}/{iface['prefix_length']}").network
                return (ip_address(group["vip"]) in net, str(net))
            except ValueError:
                return (None, None)
    return (None, None)


class _FhrpRule:
    """Mixin: iterate this protocol's fhrp_group services, delegate to check().

    A plain mixin (NOT a BaseRule subclass) so BaseRule's __init_subclass__
    contract check does not fire on it. Concrete rules inherit
    ``(_FhrpRule, BaseRule)``: they get evaluate() here and declare the required
    rule_id/severity/title/description themselves.
    """

    protocol: str = ""

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        idx = _iface_index(model)
        out: list[Finding] = []
        for group in _fhrp_groups(model, self.protocol):
            out.extend(self.check(group, idx))
        return out

    def check(self, group: dict[str, Any], idx: dict) -> list[Finding]:  # overridden
        raise NotImplementedError

    def _finding(self, host: str, suffix: str, message: str,
                 key_facts: dict, recommendation: str,
                 element_type: str = "device") -> Finding:
        return Finding.create_from_rule(
            rule=self, element_type=element_type,
            element_id=f"{host}/fhrp/{self.protocol}/{suffix}",
            message=message, key_facts=key_facts, recommendation=recommendation,
        )


def _grp_key_facts(group: dict) -> dict:
    return {
        "vip": group.get("vip"),
        "group": group.get("group_number"),
        "interface": group.get("interface"),
        "members": [m["hostname"] for m in group.get("members", [])],
    }


# --------------------------------------------------------------------------- #
# HSRP (9 rules)
# --------------------------------------------------------------------------- #
class HsrpGroupNotActiveRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_GROUP_NOT_ACTIVE"
    severity = "critical"
    title = "HSRP Group Not Active"
    description = "HSRP group has no router in the Active state — first-hop redundancy is down"
    protocol = "hsrp"

    def check(self, group, idx):
        if any(m.get("state") in _ACTIVE_STATES for m in group.get("members", [])):
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/not-active",
            f"HSRP group {group['group_number']} (VIP {group['vip']}) has no Active router",
            _grp_key_facts(group),
            "Check HSRP state and interface status — the gateway VIP is unowned",
        )]


class HsrpNoStandbyPeerRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_NO_STANDBY_PEER"
    severity = "critical"
    title = "HSRP No Standby Peer"
    description = "HSRP group has no Standby peer — the gateway is unprotected"
    protocol = "hsrp"

    def check(self, group, idx):
        if any(m.get("state") == "standby" for m in group.get("members", [])):
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/no-standby",
            f"HSRP group {group['group_number']} (VIP {group['vip']}) has no Standby peer",
            _grp_key_facts(group),
            "Add a second router to the HSRP group for gateway redundancy",
        )]


class HsrpPreemptDisabledRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_PREEMPT_DISABLED"
    severity = "info"
    title = "HSRP Preempt Disabled"
    description = "HSRP member has preempt disabled — will not reclaim Active after recovery"
    protocol = "hsrp"

    def check(self, group, idx):
        out = []
        for m in group.get("members", []):
            if not m.get("preempt"):
                out.append(self._finding(
                    m["hostname"], f"{group['group_number']}/{m['hostname']}/preempt",
                    f"HSRP group {group['group_number']} on {m['hostname']} has preempt disabled",
                    {**_grp_key_facts(group), "device": m["hostname"]},
                    "Enable 'standby <grp> preempt' so the primary reclaims Active after recovery",
                ))
        return out


class HsrpTrackingMissingRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_TRACKING_MISSING"
    severity = "low"
    title = "HSRP Tracking Missing"
    description = "HSRP member has no interface/object tracking — no failover on uplink loss"
    protocol = "hsrp"

    def check(self, group, idx):
        out = []
        for m in group.get("members", []):
            if m.get("tracked") is False:
                out.append(self._finding(
                    m["hostname"], f"{group['group_number']}/{m['hostname']}/tracking",
                    f"HSRP group {group['group_number']} on {m['hostname']} has no tracking",
                    {**_grp_key_facts(group), "device": m["hostname"]},
                    "Add interface/object tracking so HSRP fails over on upstream loss",
                ))
        return out


class HsrpAuthMissingRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_AUTH_MISSING"
    severity = "low"
    title = "HSRP Authentication Missing"
    description = "HSRP member has no authentication — vulnerable to a rogue HSRP speaker"
    protocol = "hsrp"

    def check(self, group, idx):
        out = []
        for m in group.get("members", []):
            if m.get("authenticated") is False:
                out.append(self._finding(
                    m["hostname"], f"{group['group_number']}/{m['hostname']}/auth",
                    f"HSRP group {group['group_number']} on {m['hostname']} has no authentication",
                    {**_grp_key_facts(group), "device": m["hostname"]},
                    "Configure HSRP MD5 authentication to prevent a rogue active takeover",
                ))
        return out


class HsrpVipNotInSubnetRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_VIP_NOT_IN_SUBNET"
    severity = "critical"
    title = "HSRP VIP Not In Subnet"
    description = "HSRP virtual IP is outside the interface subnet — unreachable to hosts"
    protocol = "hsrp"

    def check(self, group, idx):
        ok, subnet = _vip_in_subnet(group, idx)
        if ok is not False:
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/vip-subnet",
            f"HSRP VIP {group['vip']} is not within interface subnet {subnet}",
            {**_grp_key_facts(group), "subnet": subnet},
            "Correct the virtual IP to sit inside the SVI subnet",
        )]


class HsrpPriorityConflictRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_PRIORITY_CONFLICT"
    severity = "low"
    title = "HSRP Priority Conflict"
    description = "Two HSRP peers share the same priority — non-deterministic election"
    protocol = "hsrp"

    def check(self, group, idx):
        members = group.get("members", [])
        prios = [m.get("priority") for m in members if m.get("priority") is not None]
        if len(members) < 2 or len(prios) == len(set(prios)):
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/priority-conflict",
            f"HSRP group {group['group_number']} peers share priority {prios[0]}",
            {**_grp_key_facts(group), "priorities": prios},
            "Give the peers distinct priorities for a deterministic Active election",
        )]


class HsrpHelloTimerMismatchRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_HELLO_TIMER_MISMATCH"
    severity = "low"
    title = "HSRP Hello Timer Mismatch"
    description = "HSRP peers have mismatched hello/hold timers"
    protocol = "hsrp"

    def check(self, group, idx):
        members = group.get("members", [])
        if len(members) < 2:
            return []
        timers = {(m.get("hello_sec"), m.get("hold_sec")) for m in members}
        if len(timers) <= 1:
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/timer-mismatch",
            f"HSRP group {group['group_number']} peers have mismatched hello/hold timers",
            {**_grp_key_facts(group), "timers": sorted(str(t) for t in timers)},
            "Align hello/hold timers across all HSRP peers",
        )]


class HsrpVersionMismatchRule(_FhrpRule, BaseRule):
    rule_id = "HSRP_VERSION_MISMATCH"
    severity = "low"
    title = "HSRP Version Mismatch"
    description = "HSRP peers run different versions (v1 vs v2) — cannot form the group"
    protocol = "hsrp"

    def check(self, group, idx):
        members = group.get("members", [])
        versions = {m.get("version") for m in members if m.get("version") is not None}
        if len(members) < 2 or len(versions) <= 1:
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/version-mismatch",
            f"HSRP group {group['group_number']} peers run different versions {sorted(versions)}",
            {**_grp_key_facts(group), "versions": sorted(versions)},
            "Configure the same HSRP version on all peers",
        )]


# --------------------------------------------------------------------------- #
# VRRP (5 rules)
# --------------------------------------------------------------------------- #
class VrrpGroupNotMasterRule(_FhrpRule, BaseRule):
    rule_id = "VRRP_GROUP_NOT_MASTER"
    severity = "critical"
    title = "VRRP Group Not Master"
    description = "VRRP group has no router in the Master state — first-hop redundancy is down"
    protocol = "vrrp"

    def check(self, group, idx):
        if any(m.get("state") in _ACTIVE_STATES for m in group.get("members", [])):
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/not-master",
            f"VRRP group {group['group_number']} (VIP {group['vip']}) has no Master router",
            _grp_key_facts(group),
            "Check VRRP state and interface status — the gateway VIP is unowned",
        )]


class VrrpPriorityConflictRule(_FhrpRule, BaseRule):
    rule_id = "VRRP_PRIORITY_CONFLICT"
    severity = "low"
    title = "VRRP Priority Conflict"
    description = "Two VRRP peers share the same priority — non-deterministic master election"
    protocol = "vrrp"

    def check(self, group, idx):
        members = group.get("members", [])
        prios = [m.get("priority") for m in members if m.get("priority") is not None]
        if len(members) < 2 or len(prios) == len(set(prios)):
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/priority-conflict",
            f"VRRP group {group['group_number']} peers share priority {prios[0]}",
            {**_grp_key_facts(group), "priorities": prios},
            "Give the peers distinct priorities for a deterministic Master election",
        )]


class VrrpAdvIntervalMismatchRule(_FhrpRule, BaseRule):
    rule_id = "VRRP_ADVERTISEMENT_INTERVAL_MISMATCH"
    severity = "low"
    title = "VRRP Advertisement Interval Mismatch"
    description = "VRRP peers have mismatched advertisement intervals"
    protocol = "vrrp"

    def check(self, group, idx):
        members = group.get("members", [])
        intervals = {m.get("adv_interval") for m in members if m.get("adv_interval") is not None}
        if len(members) < 2 or len(intervals) <= 1:
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/adv-mismatch",
            f"VRRP group {group['group_number']} peers have mismatched advertisement intervals",
            {**_grp_key_facts(group), "adv_intervals": sorted(intervals)},
            "Align the advertisement interval across all VRRP peers",
        )]


class VrrpPreemptDisabledRule(_FhrpRule, BaseRule):
    rule_id = "VRRP_PREEMPT_DISABLED"
    severity = "info"
    title = "VRRP Preempt Disabled"
    description = "VRRP member has preempt disabled — will not reclaim Master after recovery"
    protocol = "vrrp"

    def check(self, group, idx):
        out = []
        for m in group.get("members", []):
            if not m.get("preempt"):
                out.append(self._finding(
                    m["hostname"], f"{group['group_number']}/{m['hostname']}/preempt",
                    f"VRRP group {group['group_number']} on {m['hostname']} has preempt disabled",
                    {**_grp_key_facts(group), "device": m["hostname"]},
                    "Enable VRRP preempt so the primary reclaims Master after recovery",
                ))
        return out


class VrrpVipNotInSubnetRule(_FhrpRule, BaseRule):
    rule_id = "VRRP_VIP_NOT_IN_SUBNET"
    severity = "critical"
    title = "VRRP VIP Not In Subnet"
    description = "VRRP virtual IP is outside the interface subnet — unreachable to hosts"
    protocol = "vrrp"

    def check(self, group, idx):
        ok, subnet = _vip_in_subnet(group, idx)
        if ok is not False:
            return []
        return [self._finding(
            _anchor(group), f"{group['group_number']}/vip-subnet",
            f"VRRP VIP {group['vip']} is not within interface subnet {subnet}",
            {**_grp_key_facts(group), "subnet": subnet},
            "Correct the virtual IP to sit inside the SVI subnet",
        )]
