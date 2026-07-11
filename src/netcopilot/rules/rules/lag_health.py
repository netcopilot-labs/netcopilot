"""LAG / port-channel health rules — Phase-1, facts-first (s22, ADR-0025).

8 of the 9 catalog LAG-family rules made executable, reading each device's
``genie_lag.json`` (the catalog's own ``device.lag.*`` field paths) plus the
model where a check needs it (member speeds, the bundle-to-bundle link for the
cross-end member-count compare). The 9th (``LAG_LACP_ERRORS``) needs a
``lacp_errors`` counter that is not collected (live capture carries only
in/out pkt counts) AND an inter-run delta — it is marked ``manual_review`` in
the catalog rather than faked.

Catalog severities map to the rule-declaration set: critical→critical,
warning→low, low→low.
"""
from __future__ import annotations

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config

_HEALTHY_PROTOCOLS = {"lacp", "pagp"}
_NULL_PARTNER = "0000.0000.0000"


class _LagRule:
    """Mixin: iterate devices with LAG facts, delegate to check() per device.

    A plain mixin (NOT a BaseRule subclass) — same pattern as ``_FhrpRule``:
    BaseRule's ``__init_subclass__`` contract check must not fire on it.
    """

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        run_path = context.get("run_path", "")
        out: list[Finding] = []
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            lag = load_device_facts(run_path, hostname, "genie_lag") if run_path else None
            bundles = (lag or {}).get("interfaces") or {}
            if not bundles:
                continue
            out.extend(self.check(hostname, bundles, model, context))
        return out

    def check(self, hostname: str, bundles: dict, model: dict,
              context: dict) -> list[Finding]:  # overridden
        raise NotImplementedError

    def _finding(self, hostname: str, suffix: str, message: str,
                 key_facts: dict, recommendation: str) -> Finding:
        return Finding.create_from_rule(
            rule=self, element_type="device",
            element_id=f"{hostname}/lag/{suffix}",
            message=message, key_facts=key_facts, recommendation=recommendation,
        )


class LagBundleOperDownRule(_LagRule, BaseRule):
    rule_id = "LAG_BUNDLE_OPER_DOWN"
    severity = "critical"
    title = "LAG Bundle Operationally Down"
    description = "Port-channel bundle is operationally down — the entire aggregated link is unavailable"

    def check(self, hostname, bundles, model, context):
        out = []
        for po, pd in bundles.items():
            status = pd.get("oper_status")
            if status is not None and status != "up":
                out.append(self._finding(
                    hostname, f"{po}/oper-down",
                    f"{hostname}: bundle {po} is operationally {status}",
                    {"bundle": po, "oper_status": status,
                     "members": sorted(pd.get("members", {}))},
                    "Check member link state and LACP negotiation; the whole bundle is down",
                ))
        return out


class LagMemberNotBundledRule(_LagRule, BaseRule):
    rule_id = "LAG_MEMBER_NOT_BUNDLED"
    severity = "low"
    title = "LAG Member Not Bundled"
    description = "A configured port-channel member failed to bundle — reduced or no aggregation"

    def check(self, hostname, bundles, model, context):
        out = []
        for po, pd in bundles.items():
            for member, md in (pd.get("members") or {}).items():
                if md.get("bundled") is False:
                    out.append(self._finding(
                        hostname, f"{po}/{member}/not-bundled",
                        f"{hostname}: {member} is configured in {po} but NOT bundled",
                        {"bundle": po, "member": member,
                         "activity": md.get("activity")},
                        "Check LACP mode/keys and member link state; the member carries no traffic",
                    ))
        return out


class LagStaticBundleRule(_LagRule, BaseRule):
    rule_id = "LAG_STATIC_BUNDLE"
    severity = "low"
    title = "Static (mode on) Port-Channel"
    description = "Bundle runs without LACP/PAgP — no negotiation protocol to detect miscabling or unidirectional links"

    def check(self, hostname, bundles, model, context):
        out = []
        for po, pd in bundles.items():
            proto = (pd.get("protocol") or "").lower()
            if proto not in _HEALTHY_PROTOCOLS:
                out.append(self._finding(
                    hostname, f"{po}/static",
                    f"{hostname}: bundle {po} runs without a negotiation protocol "
                    f"(protocol: {pd.get('protocol') or 'static/on'})",
                    {"bundle": po, "protocol": pd.get("protocol")},
                    "Configure LACP (channel-group N mode active) so miscabling is detected",
                ))
        return out


class LagMemberSpeedInconsistentRule(_LagRule, BaseRule):
    rule_id = "LAG_MEMBER_SPEED_INCONSISTENT"
    severity = "critical"
    title = "LAG Member Speed Inconsistent"
    description = "Bundle members run at different speeds — unequal load distribution and possible member suspension"

    def check(self, hostname, bundles, model, context):
        # Member speeds come from the MODEL interfaces (L1 enrichment) —
        # genie_lag itself carries no speed.
        from netcopilot.model.interface_normalizer import normalize_interface_name
        speeds_by_name: dict[str, Any] = {}
        for i in model.get("interfaces", []):
            if i.get("device_id") == hostname and i.get("speed"):
                speeds_by_name[i["name"]] = i["speed"]
        out = []
        for po, pd in bundles.items():
            member_speeds = {}
            for member in (pd.get("members") or {}):
                short = normalize_interface_name(member) or member
                if short in speeds_by_name:
                    member_speeds[short] = speeds_by_name[short]
            if len(set(member_speeds.values())) > 1:
                out.append(self._finding(
                    hostname, f"{po}/speed-mismatch",
                    f"{hostname}: bundle {po} members run at different speeds: {member_speeds}",
                    {"bundle": po, "member_speeds": member_speeds},
                    "Bundle only equal-speed members; replace or re-home the odd member",
                ))
        return out


class LagMinLinksNotMetRule(_LagRule, BaseRule):
    rule_id = "LAG_MIN_LINKS_NOT_MET"
    severity = "critical"
    title = "LAG Min-Links Not Met"
    description = "Bundled member count is below the configured port-channel min-links — the bundle is (or will go) down"

    # interface Port-channelN ... port-channel min-links <N>
    _MIN_LINKS_RE = re.compile(
        r"^interface (Port-channel\d+)\n(?:.*\n)*?\s+port-channel min-links (\d+)",
        re.MULTILINE,
    )

    def check(self, hostname, bundles, model, context):
        config = load_running_config(context.get("run_path", ""), hostname) or ""
        declared: dict[str, int] = {}
        for block in re.split(r"\n(?=interface )", config):
            m = re.match(r"interface (Port-channel\d+)", block)
            if not m:
                continue
            ml = re.search(r"port-channel min-links (\d+)", block)
            if ml:
                declared[m.group(1)] = int(ml.group(1))
        if not declared:
            return []   # no minimum declared — nothing to be "not met"
        out = []
        for po, minimum in declared.items():
            pd = bundles.get(po)
            if pd is None:
                continue
            bundled = sum(1 for md in (pd.get("members") or {}).values()
                          if md.get("bundled"))
            if bundled < minimum:
                out.append(self._finding(
                    hostname, f"{po}/min-links",
                    f"{hostname}: {po} has {bundled} bundled member(s), below the "
                    f"configured min-links {minimum}",
                    {"bundle": po, "bundled": bundled, "min_links": minimum},
                    "Restore failed members or lower min-links; below the minimum the bundle goes down",
                ))
        return out


class LagLacpSystemIdMismatchRule(_LagRule, BaseRule):
    rule_id = "LAG_LACP_SYSTEM_ID_MISMATCH"
    severity = "low"
    title = "LACP Partner System-ID Mismatch"
    description = "Members of one bundle see different LACP partner system-IDs — the bundle spans two remote systems (miscabling)"

    def check(self, hostname, bundles, model, context):
        out = []
        for po, pd in bundles.items():
            partners = {md.get("partner_id") for md in (pd.get("members") or {}).values()
                        if md.get("partner_id") and md.get("partner_id") != _NULL_PARTNER}
            if len(partners) > 1:
                out.append(self._finding(
                    hostname, f"{po}/partner-mismatch",
                    f"{hostname}: bundle {po} members see {len(partners)} different "
                    f"LACP partner system-IDs: {sorted(partners)}",
                    {"bundle": po, "partner_ids": sorted(partners)},
                    "The members are cabled to different remote systems — fix the cabling",
                ))
        return out


class LagMemberCountMismatchRule(_LagRule, BaseRule):
    rule_id = "LAG_MEMBER_COUNT_MISMATCH"
    severity = "low"
    title = "LAG Member Count Mismatch"
    description = "The two ends of a port-channel bundle different member counts — asymmetric aggregation"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        # Cross-END check: pair the two bundle ends via the model link whose
        # both endpoints are port-channels (the lacp/cdp link already joins
        # them) — the FHRP precedent: the join lives in the model, the rule
        # stays Phase-1. Deduped on the sorted device pair.
        run_path = context.get("run_path", "")
        out: list[Finding] = []
        if not run_path:
            return out
        lag_cache: dict[str, dict] = {}

        def bundles_of(host: str) -> dict:
            if host not in lag_cache:
                lag_cache[host] = (load_device_facts(run_path, host, "genie_lag")
                                   or {}).get("interfaces") or {}
            return lag_cache[host]

        def po_of(interface_id: str | None) -> tuple[str, str] | None:
            # "host:Po1" → (host, "Po1") when the interface is a port-channel.
            if not interface_id or ":" not in interface_id:
                return None
            host, _, intf = interface_id.partition(":")
            return (host, intf) if intf.startswith("Po") else None

        seen: set[tuple] = set()
        for link in model.get("links", []):
            a = po_of(link.get("local_interface_id"))
            b = po_of(link.get("remote_interface_id"))
            if not a or not b:
                continue
            key = tuple(sorted((a, b)))
            if key in seen:
                continue
            seen.add(key)
            counts = {}
            for host, po_short in (a, b):
                full = next((po for po in bundles_of(host)
                             if po.replace("Port-channel", "Po") == po_short
                             or po == po_short), None)
                if full is None:
                    counts = {}
                    break
                counts[f"{host}:{po_short}"] = len(
                    bundles_of(host)[full].get("members") or {})
            if counts and len(set(counts.values())) > 1:
                anchor = sorted(h for h, _ in (a, b))[0]
                out.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{anchor}/lag/{a[1]}/member-count-mismatch",
                    message=f"Bundle ends disagree on member count: {counts}",
                    key_facts={"ends": counts},
                    recommendation="Add/remove members so both ends aggregate the same links",
                ))
        return out


class StpEtherchannelMisconfigGuardDisabledRule(_LagRule, BaseRule):
    rule_id = "STP_ETHERCHANNEL_MISCONFIG_GUARD_DISABLED"
    severity = "low"
    title = "EtherChannel Misconfig Guard Disabled"
    description = "spanning-tree etherchannel guard misconfig is disabled on a device running bundles — mis-bundled ports can loop"

    def check(self, hostname, bundles, model, context):
        stp = load_device_facts(context.get("run_path", ""), hostname, "genie_stp")
        if not stp:
            return []
        guard = (stp.get("global") or {}).get("etherchannel_misconfig_guard")
        if guard is False:
            return [self._finding(
                hostname, "etherchannel-guard",
                f"{hostname}: etherchannel misconfig guard is disabled while "
                f"{len(bundles)} bundle(s) are configured",
                {"bundles": sorted(bundles), "etherchannel_misconfig_guard": False},
                "Enable 'spanning-tree etherchannel guard misconfig'",
            )]
        return []
