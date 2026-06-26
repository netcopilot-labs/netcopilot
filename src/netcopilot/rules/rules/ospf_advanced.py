"""
OSPF Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie OSPF learn() output for process-level, area-level,
    interface-level, and neighbor-level anomalies.

Rule IDs: OSPF_AREA_HIGH_SPF_RUNS, OSPF_MAX_LSA_APPROACHING,
          OSPF_PASSIVE_INTERFACE_UNEXPECTED, OSPF_STUB_ROUTER_PERMANENT,
          OSPF_REDISTRIBUTION_FROM_BGP, OSPF_NEIGHBOR_HIGH_RETRANS_QUEUE,
          OSPF_NEIGHBOR_EVENT_RATE_HIGH, OSPF_INTERFACE_PRIORITY_ZERO,
          OSPF_SPF_THROTTLE_NOT_CONFIGURED, OSPF_LSA_THROTTLE_NOT_CONFIGURED,
          OSPF_AREA_HIGH_LSA_COUNT, OSPF_NEIGHBOR_DEAD_TIMER_EXPIRING,
          OSPF_LDP_IGP_SYNC_DISABLED, OSPF_ROUTER_ID_DUPLICATE
Severity: varies
"""

from typing import Any, Iterator

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


# -------------------------------------------------------------------------
# OSPF data navigation helpers
# -------------------------------------------------------------------------

def _iter_ospf_processes(
    ospf_data: dict,
) -> Iterator[tuple[str, str, dict]]:
    """Yield (vrf_name, process_id, process_dict) from Genie OSPF output."""
    for vrf_name, vrf_data in ospf_data.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for pid, pdata in instances.items():
            yield vrf_name, pid, pdata


def _iter_ospf_areas(
    process: dict,
) -> Iterator[tuple[str, dict]]:
    """Yield (area_id, area_dict) from an OSPF process."""
    for area_id, area_data in process.get("areas", {}).items():
        yield area_id, area_data


def _iter_ospf_interfaces(
    area: dict,
) -> Iterator[tuple[str, dict]]:
    """Yield (interface_name, intf_dict) from an OSPF area."""
    for intf_name, intf_data in area.get("interfaces", {}).items():
        yield intf_name, intf_data


def _iter_ospf_neighbors(
    interface: dict,
) -> Iterator[tuple[str, dict]]:
    """Yield (neighbor_id, neighbor_dict) from an OSPF interface."""
    for nbr_id, nbr_data in interface.get("neighbors", {}).items():
        yield nbr_id, nbr_data


def _load_ospf(run_path: str, hostname: str) -> dict | None:
    """Load and return Genie OSPF facts, or None if unavailable."""
    return load_device_facts(run_path, hostname, "genie_ospf")


# -------------------------------------------------------------------------
# OSPF_AREA_HIGH_SPF_RUNS — High SPF run count indicates instability
# -------------------------------------------------------------------------

class OspfAreaHighSpfRunsRule(BaseRule):
    """Flags OSPF areas with an unusually high SPF run count."""

    rule_id = "OSPF_AREA_HIGH_SPF_RUNS"
    severity = "low"
    title = "OSPF Area High SPF Run Count"
    description = "High SPF run count in an OSPF area may indicate network instability"

    SPF_THRESHOLD = 100  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    stats = area.get("statistics", {})
                    spf_runs = stats.get("spf_runs_count", 0)
                    if spf_runs > self.SPF_THRESHOLD:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/ospf/{pid}/area/{area_id}/spf-runs",
                            message=(
                                f"OSPF {pid} area {area_id} has "
                                f"{spf_runs} SPF runs (threshold: {self.SPF_THRESHOLD})"
                            ),
                            key_facts={
                                "vrf": vrf, "process": pid, "area": area_id,
                                "spf_runs": spf_runs, "threshold": self.SPF_THRESHOLD,
                            },
                            recommendation="Investigate route flapping; consider SPF throttle tuning",
                        ))

        return findings


# -------------------------------------------------------------------------
# OSPF_MAX_LSA_APPROACHING — LSA count nearing configured limit
# -------------------------------------------------------------------------

class OspfMaxLsaApproachingRule(BaseRule):
    """Flags when total LSA count approaches the configured max-LSA limit."""

    rule_id = "OSPF_MAX_LSA_APPROACHING"
    severity = "high"
    title = "OSPF LSA Count Approaching Limit"
    description = "Area LSA count is approaching the configured max-LSA threshold"

    WARN_PERCENT = 80  # default; tune per deployment — alert at 80% of max_lsa

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                max_lsa = (
                    process.get("database_control", {}).get("max_lsa", 0)
                )
                if not max_lsa:
                    continue  # No limit configured

                # Sum LSA counts across all areas in this process
                total_lsa = 0
                for _, area in _iter_ospf_areas(process):
                    total_lsa += area.get("statistics", {}).get(
                        "area_scope_lsa_count", 0,
                    )

                pct = (total_lsa / max_lsa) * 100 if max_lsa else 0
                if pct >= self.WARN_PERCENT:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/max-lsa",
                        message=(
                            f"OSPF {pid} has {total_lsa} LSAs "
                            f"({pct:.0f}% of max {max_lsa})"
                        ),
                        key_facts={
                            "vrf": vrf, "process": pid,
                            "total_lsa": total_lsa, "max_lsa": max_lsa,
                            "percent": round(pct, 1),
                        },
                        recommendation="Review OSPF domain size; consider area summarization or increasing max-lsa",
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_PASSIVE_INTERFACE_UNEXPECTED — Passive interface with neighbors
# -------------------------------------------------------------------------

class OspfPassiveInterfaceUnexpectedRule(BaseRule):
    """Flags interfaces marked passive that still have OSPF neighbors."""

    rule_id = "OSPF_PASSIVE_INTERFACE_UNEXPECTED"
    severity = "low"
    title = "Passive OSPF Interface Has Neighbors"
    description = "Interface is passive but has active OSPF neighbors — possible misconfiguration"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    for intf_name, intf in _iter_ospf_interfaces(area):
                        is_passive = intf.get("passive", False)
                        neighbors = intf.get("neighbors", {})
                        if is_passive and neighbors:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="interface",
                                element_id=(
                                    f"{hostname}/ospf/{pid}/area/{area_id}"
                                    f"/intf/{intf_name}/passive-with-neighbors"
                                ),
                                message=(
                                    f"Interface {intf_name} is passive "
                                    f"but has {len(neighbors)} OSPF neighbor(s)"
                                ),
                                key_facts={
                                    "interface": intf_name, "area": area_id,
                                    "passive": True,
                                    "neighbor_count": len(neighbors),
                                },
                                recommendation=(
                                    "Remove 'passive-interface' if adjacency is intended, "
                                    "or investigate stale neighbor entries"
                                ),
                            ))

        return findings


# -------------------------------------------------------------------------
# OSPF_STUB_ROUTER_PERMANENT — Stub router always on
# -------------------------------------------------------------------------

class OspfStubRouterPermanentRule(BaseRule):
    """Flags OSPF processes with permanent stub-router (max-metric) enabled."""

    rule_id = "OSPF_STUB_ROUTER_PERMANENT"
    severity = "low"
    title = "OSPF Stub Router Permanently Enabled"
    description = "Permanent stub-router (max-metric) prevents transit traffic — usually temporary"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                stub_router = process.get("stub_router", {}).get("always", {})
                if stub_router.get("always", False):
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/stub-router-permanent",
                        message=(
                            f"OSPF {pid} has permanent stub-router "
                            f"(max-metric router-lsa always)"
                        ),
                        key_facts={"vrf": vrf, "process": pid, "permanent": True},
                        recommendation=(
                            "Remove 'max-metric router-lsa always' unless this device "
                            "should permanently avoid carrying transit traffic"
                        ),
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_REDISTRIBUTION_FROM_BGP — BGP redistribution into OSPF
# -------------------------------------------------------------------------

class OspfRedistributionFromBgpRule(BaseRule):
    """Flags OSPF processes that redistribute from BGP (potential route leaking)."""

    rule_id = "OSPF_REDISTRIBUTION_FROM_BGP"
    severity = "info"
    title = "OSPF Redistributing from BGP"
    description = "BGP routes redistributed into OSPF — verify route filtering is applied"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                redist = process.get("redistribution", {})
                bgp_redist = redist.get("bgp", {})
                if bgp_redist:
                    bgp_procs = list(bgp_redist.keys())
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/redist-bgp",
                        message=(
                            f"OSPF {pid} redistributes from "
                            f"BGP {bgp_procs}"
                        ),
                        key_facts={
                            "vrf": vrf, "process": pid,
                            "bgp_processes": bgp_procs,
                        },
                        recommendation=(
                            "Ensure route-map filter is applied to BGP redistribution "
                            "to prevent route leaking into the OSPF domain"
                        ),
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_NEIGHBOR_HIGH_RETRANS_QUEUE — High retransmission queue
# -------------------------------------------------------------------------

class OspfNeighborHighRetransQueueRule(BaseRule):
    """Flags OSPF neighbors with high retransmission queue length."""

    rule_id = "OSPF_NEIGHBOR_HIGH_RETRANS_QUEUE"
    severity = "high"
    title = "OSPF Neighbor High Retransmission Queue"
    description = "High retransmission queue indicates link/MTU issues with OSPF neighbor"

    RETRANS_THRESHOLD = 10  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    for intf_name, intf in _iter_ospf_interfaces(area):
                        for nbr_id, nbr in _iter_ospf_neighbors(intf):
                            stats = nbr.get("statistics", {})
                            qlen = stats.get("nbr_retrans_qlen", 0)
                            if qlen > self.RETRANS_THRESHOLD:
                                findings.append(Finding.create_from_rule(
                                    rule=self, element_type="interface",
                                    element_id=(
                                        f"{hostname}/ospf/{pid}/{intf_name}"
                                        f"/nbr/{nbr_id}/retrans"
                                    ),
                                    message=(
                                        f"OSPF neighbor {nbr_id} on "
                                        f"{intf_name} has retrans queue {qlen}"
                                    ),
                                    key_facts={
                                        "interface": intf_name, "neighbor": nbr_id,
                                        "retrans_qlen": qlen,
                                        "threshold": self.RETRANS_THRESHOLD,
                                    },
                                    recommendation=(
                                        "Check for MTU mismatches, link errors, or "
                                        "congestion on the OSPF adjacency"
                                    ),
                                ))

        return findings


# -------------------------------------------------------------------------
# OSPF_NEIGHBOR_EVENT_RATE_HIGH — Excessive neighbor state changes
# -------------------------------------------------------------------------

class OspfNeighborEventRateHighRule(BaseRule):
    """Flags OSPF neighbors with excessive state-change events."""

    rule_id = "OSPF_NEIGHBOR_EVENT_RATE_HIGH"
    severity = "low"
    title = "OSPF Neighbor Excessive State Changes"
    description = "High neighbor event count suggests adjacency flapping or instability"

    EVENT_THRESHOLD = 50  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    for intf_name, intf in _iter_ospf_interfaces(area):
                        for nbr_id, nbr in _iter_ospf_neighbors(intf):
                            stats = nbr.get("statistics", {})
                            events = stats.get("nbr_event_count", 0)
                            if events > self.EVENT_THRESHOLD:
                                findings.append(Finding.create_from_rule(
                                    rule=self, element_type="interface",
                                    element_id=(
                                        f"{hostname}/ospf/{pid}/{intf_name}"
                                        f"/nbr/{nbr_id}/events"
                                    ),
                                    message=(
                                        f"OSPF neighbor {nbr_id} on "
                                        f"{intf_name} has {events} state-change events"
                                    ),
                                    key_facts={
                                        "interface": intf_name, "neighbor": nbr_id,
                                        "event_count": events,
                                        "threshold": self.EVENT_THRESHOLD,
                                    },
                                    recommendation=(
                                        "Investigate adjacency flapping — check for "
                                        "link instability, MTU issues, or timer mismatches"
                                    ),
                                ))

        return findings


# -------------------------------------------------------------------------
# OSPF_INTERFACE_PRIORITY_ZERO — Priority 0 on broadcast network
# -------------------------------------------------------------------------

class OspfInterfacePriorityZeroRule(BaseRule):
    """Flags broadcast/NBMA interfaces with OSPF priority 0 (no DR election)."""

    rule_id = "OSPF_INTERFACE_PRIORITY_ZERO"
    severity = "info"
    title = "OSPF Interface Priority Zero"
    description = "Interface has priority 0 on a broadcast/NBMA network — will never become DR/BDR"

    # Only relevant for network types that elect a DR
    DR_NETWORK_TYPES = {"broadcast", "non-broadcast"}

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    for intf_name, intf in _iter_ospf_interfaces(area):
                        net_type = str(intf.get("interface_type", "")).lower()
                        priority = intf.get("priority", -1)

                        if net_type in self.DR_NETWORK_TYPES and priority == 0:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="interface",
                                element_id=(
                                    f"{hostname}/ospf/{pid}/area/{area_id}"
                                    f"/intf/{intf_name}/priority-zero"
                                ),
                                message=(
                                    f"{intf_name} has priority 0 on "
                                    f"{net_type} network — will never become DR/BDR"
                                ),
                                key_facts={
                                    "interface": intf_name, "area": area_id,
                                    "network_type": net_type, "priority": 0,
                                },
                                recommendation=(
                                    "Set priority > 0 if this router should participate "
                                    "in DR/BDR election, or convert to point-to-point"
                                ),
                            ))

        return findings


# -------------------------------------------------------------------------
# OSPF_SPF_THROTTLE_NOT_CONFIGURED — No SPF throttle timers
# -------------------------------------------------------------------------

class OspfSpfThrottleNotConfiguredRule(BaseRule):
    """Flags OSPF processes without SPF throttle timers configured."""

    rule_id = "OSPF_SPF_THROTTLE_NOT_CONFIGURED"
    severity = "info"   # downgraded 2026-06-26: tuning default, advisory only
    title = "OSPF SPF Throttle Not Configured"
    description = "SPF throttle timers prevent excessive SPF recalculations during instability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                throttle = (
                    process.get("spf_control", {})
                    .get("throttle", {})
                    .get("spf", {})
                )
                if not throttle:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/spf-throttle",
                        message=f"OSPF {pid} has no SPF throttle configured",
                        key_facts={"vrf": vrf, "process": pid},
                        recommendation=(
                            "Configure 'timers throttle spf <start> <hold> <max>' "
                            "to dampen SPF recalculations"
                        ),
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_LSA_THROTTLE_NOT_CONFIGURED — No LSA throttle timers
# -------------------------------------------------------------------------

class OspfLsaThrottleNotConfiguredRule(BaseRule):
    """Flags OSPF processes without LSA throttle timers configured."""

    rule_id = "OSPF_LSA_THROTTLE_NOT_CONFIGURED"
    severity = "info"   # downgraded 2026-06-26: tuning default, advisory only
    title = "OSPF LSA Throttle Not Configured"
    description = "LSA throttle timers prevent excessive LSA generation during instability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                throttle = (
                    process.get("spf_control", {})
                    .get("throttle", {})
                    .get("lsa", {})
                )
                if not throttle:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/lsa-throttle",
                        message=f"OSPF {pid} has no LSA throttle configured",
                        key_facts={"vrf": vrf, "process": pid},
                        recommendation=(
                            "Configure 'timers throttle lsa <start> <hold> <max>' "
                            "to dampen LSA origination"
                        ),
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_AREA_HIGH_LSA_COUNT — High per-area LSA count
# -------------------------------------------------------------------------

class OspfAreaHighLsaCountRule(BaseRule):
    """Flags OSPF areas with a high LSA count (potential scaling concern)."""

    rule_id = "OSPF_AREA_HIGH_LSA_COUNT"
    severity = "low"
    title = "OSPF Area High LSA Count"
    description = "High LSA count in an OSPF area may indicate scaling concerns"

    LSA_THRESHOLD = 5000  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    stats = area.get("statistics", {})
                    lsa_count = stats.get("area_scope_lsa_count", 0)
                    if lsa_count > self.LSA_THRESHOLD:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/ospf/{pid}/area/{area_id}/lsa-count",
                            message=(
                                f"OSPF {pid} area {area_id} has "
                                f"{lsa_count} LSAs (threshold: {self.LSA_THRESHOLD})"
                            ),
                            key_facts={
                                "vrf": vrf, "process": pid, "area": area_id,
                                "lsa_count": lsa_count, "threshold": self.LSA_THRESHOLD,
                            },
                            recommendation=(
                                "Consider area summarization or splitting to reduce "
                                "LSDB size and SPF computation time"
                            ),
                        ))

        return findings


# -------------------------------------------------------------------------
# OSPF_NEIGHBOR_DEAD_TIMER_EXPIRING — Dead timer critically low
# -------------------------------------------------------------------------

def _parse_timer(timer_str: str) -> int:
    """Parse 'HH:MM:SS' timer string to total seconds. Returns -1 on error."""
    try:
        parts = str(timer_str).split(":")
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
    except (ValueError, TypeError):
        pass
    return -1


class OspfNeighborDeadTimerExpiringRule(BaseRule):
    """Flags OSPF neighbors whose dead timer is critically low."""

    rule_id = "OSPF_NEIGHBOR_DEAD_TIMER_EXPIRING"
    severity = "high"
    title = "OSPF Neighbor Dead Timer Expiring"
    description = "Neighbor dead timer is critically low — missed hellos may cause adjacency loss"

    WARN_PERCENT = 15  # default; tune per deployment — alert when <15% of dead_interval remains

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                for area_id, area in _iter_ospf_areas(process):
                    for intf_name, intf in _iter_ospf_interfaces(area):
                        dead_interval = intf.get("dead_interval", 40)
                        for nbr_id, nbr in _iter_ospf_neighbors(intf):
                            remaining = _parse_timer(
                                nbr.get("dead_timer", ""),
                            )
                            if remaining < 0:
                                continue
                            pct = (remaining / dead_interval) * 100 if dead_interval else 0
                            if pct < self.WARN_PERCENT:
                                findings.append(Finding.create_from_rule(
                                    rule=self, element_type="interface",
                                    element_id=(
                                        f"{hostname}/ospf/{pid}/{intf_name}"
                                        f"/nbr/{nbr_id}/dead-timer"
                                    ),
                                    message=(
                                        f"Neighbor {nbr_id} on {intf_name} "
                                        f"dead timer {remaining}s ({pct:.0f}% of "
                                        f"{dead_interval}s interval)"
                                    ),
                                    key_facts={
                                        "interface": intf_name, "neighbor": nbr_id,
                                        "remaining_seconds": remaining,
                                        "dead_interval": dead_interval,
                                        "percent_remaining": round(pct, 1),
                                    },
                                    recommendation=(
                                        "Neighbor may be about to expire — check link "
                                        "connectivity and hello packet delivery"
                                    ),
                                ))

        return findings


# -------------------------------------------------------------------------
# OSPF_LDP_IGP_SYNC_DISABLED — LDP autoconfig without IGP sync
# -------------------------------------------------------------------------

class OspfLdpIgpSyncDisabledRule(BaseRule):
    """Flags OSPF processes with LDP autoconfig but IGP sync disabled."""

    rule_id = "OSPF_LDP_IGP_SYNC_DISABLED"
    severity = "info"
    title = "OSPF LDP IGP Sync Disabled"
    description = "LDP autoconfig enabled without IGP sync may cause traffic black-holing"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                ldp = process.get("mpls", {}).get("ldp", {})
                autoconfig = ldp.get("autoconfig", False)
                igp_sync = ldp.get("igp_sync", False)

                if autoconfig and not igp_sync:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/ospf/{pid}/ldp-igp-sync",
                        message=(
                            f"OSPF {pid} has LDP autoconfig "
                            f"but IGP sync is disabled"
                        ),
                        key_facts={
                            "vrf": vrf, "process": pid,
                            "ldp_autoconfig": True, "igp_sync": False,
                        },
                        recommendation=(
                            "Enable 'mpls ldp igp sync' to prevent traffic "
                            "black-holing during LDP convergence"
                        ),
                    ))

        return findings


# -------------------------------------------------------------------------
# OSPF_ROUTER_ID_DUPLICATE — Same router-id on multiple devices
# -------------------------------------------------------------------------

class OspfRouterIdDuplicateRule(BaseRule):
    """Flags duplicate OSPF router-IDs across devices in the same domain."""

    rule_id = "OSPF_ROUTER_ID_DUPLICATE"
    severity = "critical"
    title = "Duplicate OSPF Router ID"
    description = "Multiple devices with the same OSPF router-ID causes routing instability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        # Collect: {router_id: [(hostname, vrf, pid), ...]}
        router_ids: dict[str, list[tuple[str, str, str]]] = {}

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            ospf = _load_ospf(run_path, hostname)
            if ospf is None:
                continue

            for vrf, pid, process in _iter_ospf_processes(ospf):
                rid = process.get("router_id")
                if rid:
                    router_ids.setdefault(rid, []).append(
                        (hostname, vrf, pid),
                    )

        for rid, entries in router_ids.items():
            if len(entries) > 1:
                hostnames = [e[0] for e in entries]
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"ospf/router-id-dup/{rid}",
                    message=(
                        f"Duplicate OSPF router-id {rid} on: "
                        f"{', '.join(hostnames)}"
                    ),
                    key_facts={
                        "router_id": rid,
                        "devices": [
                            {"hostname": h, "vrf": v, "process": p}
                            for h, v, p in entries
                        ],
                    },
                    recommendation="Each OSPF router must have a unique router-id",
                ))

        return findings
