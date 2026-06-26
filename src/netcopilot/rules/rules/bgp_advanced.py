"""
BGP Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie BGP learn() output for neighbor-level, session-level,
    and policy-level anomalies.

Rule IDs: BGP_NEIGHBOR_NOT_ESTABLISHED, BGP_NEIGHBOR_NO_PASSWORD,
          BGP_NEIGHBOR_MISSING_INBOUND_POLICY, BGP_NEIGHBOR_MISSING_OUTBOUND_POLICY,
          BGP_NEIGHBOR_SHUTDOWN, BGP_PEER_SESSION_SHUTDOWN,
          BGP_NEIGHBOR_NO_FOUR_OCTET_ASN, BGP_NEIGHBOR_NO_GRACEFUL_RESTART,
          BGP_NEIGHBOR_NO_ROUTE_REFRESH, BGP_ROUTE_DAMPENING_ENABLED,
          BGP_HOLD_TIME_TOO_SHORT, BGP_EBGP_MULTIHOP_EXCESSIVE,
          BGP_MESSAGE_QUEUE_BACKED_UP, BGP_NEIGHBOR_FREQUENT_RESET,
          BGP_NEIGHBOR_HIGH_NOTIFICATION_RATE, BGP_PREFIX_LIMIT_APPROACHING,
          BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID
Severity: varies
"""

import re
from typing import Any, Iterator

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


# -------------------------------------------------------------------------
# BGP data navigation helpers
# -------------------------------------------------------------------------

def _load_bgp(run_path: str, hostname: str) -> dict | None:
    """Load and return Genie BGP facts, or None if unavailable."""
    return load_device_facts(run_path, hostname, "genie_bgp")


def _iter_bgp_neighbors(
    bgp_data: dict,
) -> Iterator[tuple[str, str, str, dict]]:
    """Yield (instance, vrf, neighbor_addr, neighbor_dict) from Genie BGP."""
    for inst_name, inst in bgp_data.get("instance", {}).items():
        if not isinstance(inst, dict):
            continue
        for vrf_name, vrf in inst.get("vrf", {}).items():
            if not isinstance(vrf, dict):
                continue
            for nbr_addr, nbr in vrf.get("neighbor", {}).items():
                if not isinstance(nbr, dict):
                    continue
                yield inst_name, vrf_name, nbr_addr, nbr


def _get_local_as(bgp_data: dict) -> str | None:
    """Extract the local AS number from Genie BGP data."""
    for inst in bgp_data.get("instance", {}).values():
        if isinstance(inst, dict) and inst.get("bgp_id"):
            return str(inst["bgp_id"])
    return None


def _is_ebgp(nbr: dict, local_as: str | None) -> bool:
    """Return True if the neighbor is eBGP (different AS)."""
    if not local_as:
        return True  # conservative: treat as eBGP if we can't determine
    remote_as = nbr.get("remote_as")
    return str(remote_as) != local_as if remote_as else True


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_NOT_ESTABLISHED — Critical: peer not in Established state
# -------------------------------------------------------------------------

class BgpNeighborNotEstablishedRule(BaseRule):
    """Flags BGP neighbors not in Established state."""

    rule_id = "BGP_NEIGHBOR_NOT_ESTABLISHED"
    severity = "critical"
    title = "BGP Neighbor Not Established"
    description = "BGP neighbor session is not in Established state"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state and state != "established":
                    remote_as = nbr.get("remote_as", "?")
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/not-established",
                        message=(
                            f"BGP neighbor {nbr_addr} (AS {remote_as}) "
                            f"state: {state}"
                        ),
                        key_facts={
                            "neighbor": nbr_addr, "vrf": vrf,
                            "remote_as": remote_as, "state": state,
                        },
                        recommendation="Check peer reachability, authentication, and BGP configuration",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_NO_PASSWORD — Missing MD5 authentication
# -------------------------------------------------------------------------

class BgpNeighborNoPasswordRule(BaseRule):
    """Flags BGP neighbors without password authentication."""

    rule_id = "BGP_NEIGHBOR_NO_PASSWORD"
    severity = "low"
    title = "BGP Neighbor No Password"
    description = "BGP neighbor has no MD5 password authentication configured"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                # Genie: "password_text" key presence or nbr_transport auth
                has_password = nbr.get("password_text") or nbr.get("password")
                if not has_password:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/no-password",
                        message=f"BGP neighbor {nbr_addr} has no password configured",
                        key_facts={"neighbor": nbr_addr, "vrf": vrf},
                        recommendation="Configure 'neighbor <ip> password <key>' for MD5 authentication",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_MISSING_INBOUND_POLICY
# -------------------------------------------------------------------------

class BgpNeighborMissingInboundPolicyRule(BaseRule):
    """Flags established BGP neighbors without an inbound route policy."""

    rule_id = "BGP_NEIGHBOR_MISSING_INBOUND_POLICY"
    severity = "low"
    title = "BGP Neighbor Missing Inbound Policy"
    description = "Established BGP neighbor has no inbound route-map or prefix-list"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            local_as = _get_local_as(bgp)

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                if not _is_ebgp(nbr, local_as):
                    continue  # iBGP doesn't need inbound filtering
                for af_name, af in nbr.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    has_in = af.get("route_map_name_in") or af.get("policy_in")
                    if not has_in:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/{af_name}/no-in-policy",
                            message=(
                                f"BGP neighbor {nbr_addr} ({af_name}) "
                                f"has no inbound route policy"
                            ),
                            key_facts={"neighbor": nbr_addr, "vrf": vrf, "af": af_name},
                            recommendation="Apply an inbound route-map to filter received prefixes",
                        ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_MISSING_OUTBOUND_POLICY
# -------------------------------------------------------------------------

class BgpNeighborMissingOutboundPolicyRule(BaseRule):
    """Flags established eBGP neighbors without an outbound route policy."""

    rule_id = "BGP_NEIGHBOR_MISSING_OUTBOUND_POLICY"
    severity = "low"
    title = "BGP Neighbor Missing Outbound Policy"
    description = "Established eBGP neighbor has no outbound route-map or prefix-list"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            local_as = _get_local_as(bgp)

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                if not _is_ebgp(nbr, local_as):
                    continue  # iBGP doesn't need outbound filtering
                for af_name, af in nbr.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    has_out = af.get("route_map_name_out") or af.get("policy_out")
                    if not has_out:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/{af_name}/no-out-policy",
                            message=(
                                f"BGP neighbor {nbr_addr} ({af_name}) "
                                f"has no outbound route policy"
                            ),
                            key_facts={"neighbor": nbr_addr, "vrf": vrf, "af": af_name},
                            recommendation="Apply an outbound route-map to control advertised prefixes",
                        ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_SHUTDOWN
# -------------------------------------------------------------------------

class BgpNeighborShutdownRule(BaseRule):
    """Flags BGP neighbors in administratively shutdown state."""

    rule_id = "BGP_NEIGHBOR_SHUTDOWN"
    severity = "low"
    title = "BGP Neighbor Shutdown"
    description = "BGP neighbor is administratively shutdown"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                if nbr.get("shutdown", False):
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/shutdown",
                        message=f"BGP neighbor {nbr_addr} is administratively shutdown",
                        key_facts={"neighbor": nbr_addr, "vrf": vrf},
                        recommendation="Remove 'neighbor shutdown' if this peer should be active",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_PEER_SESSION_SHUTDOWN — Session template shutdown
# -------------------------------------------------------------------------

class BgpPeerSessionShutdownRule(BaseRule):
    """Flags BGP peer-session templates in shutdown state."""

    rule_id = "BGP_PEER_SESSION_SHUTDOWN"
    severity = "low"
    title = "BGP Peer Session Shutdown"
    description = "BGP peer-session template is shutdown, disabling all associated neighbors"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst_name, inst in bgp.get("instance", {}).items():
                if not isinstance(inst, dict):
                    continue
                for ps_name, ps in inst.get("peer_session", {}).items():
                    if not isinstance(ps, dict):
                        continue
                    if ps.get("shutdown", False):
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/peer-session/{ps_name}/shutdown",
                            message=f"BGP peer-session '{ps_name}' is shutdown",
                            key_facts={"peer_session": ps_name},
                            recommendation="Remove shutdown from peer-session template if peers should be active",
                        ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_NO_FOUR_OCTET_ASN
# -------------------------------------------------------------------------

class BgpNeighborNoFourOctetAsnRule(BaseRule):
    """Flags BGP neighbors not negotiating 4-octet ASN capability."""

    rule_id = "BGP_NEIGHBOR_NO_FOUR_OCTET_ASN"
    severity = "info"
    title = "BGP Neighbor No 4-Octet ASN Support"
    description = "BGP neighbor has not negotiated 4-octet ASN capability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                caps = nbr.get("bgp_negotiated_capabilities", {})
                four_octet = caps.get("four_octets_asn", "")
                if four_octet and "received" not in str(four_octet).lower():
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/no-4octet",
                        message=f"BGP neighbor {nbr_addr} lacks 4-octet ASN capability",
                        key_facts={"neighbor": nbr_addr, "vrf": vrf, "four_octets_asn": four_octet},
                        recommendation="Upgrade peer to support 4-octet ASN (RFC 6793)",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_NO_GRACEFUL_RESTART
# -------------------------------------------------------------------------

class BgpNeighborNoGracefulRestartRule(BaseRule):
    """Flags established BGP neighbors without graceful restart negotiated."""

    rule_id = "BGP_NEIGHBOR_NO_GRACEFUL_RESTART"
    severity = "info"
    title = "BGP Neighbor No Graceful Restart"
    description = "BGP neighbor has not negotiated graceful restart capability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                caps = nbr.get("bgp_negotiated_capabilities", {})
                gr = caps.get("graceful_restart", "")
                if not gr or "received" not in str(gr).lower():
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/no-gr",
                        message=f"BGP neighbor {nbr_addr} has no graceful restart",
                        key_facts={"neighbor": nbr_addr, "vrf": vrf},
                        recommendation="Enable graceful restart for hitless failover during BGP restarts",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_NO_ROUTE_REFRESH
# -------------------------------------------------------------------------

class BgpNeighborNoRouteRefreshRule(BaseRule):
    """Flags established BGP neighbors without route-refresh capability."""

    rule_id = "BGP_NEIGHBOR_NO_ROUTE_REFRESH"
    severity = "info"
    title = "BGP Neighbor No Route Refresh"
    description = "BGP neighbor has not negotiated route-refresh capability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                caps = nbr.get("bgp_negotiated_capabilities", {})
                rr = caps.get("route_refresh", "")
                if not rr or "received" not in str(rr).lower():
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/no-rr",
                        message=f"BGP neighbor {nbr_addr} has no route-refresh capability",
                        key_facts={"neighbor": nbr_addr, "vrf": vrf},
                        recommendation="Route-refresh allows non-disruptive policy changes; verify peer support",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_ROUTE_DAMPENING_ENABLED — Informational
# -------------------------------------------------------------------------

class BgpRouteDampeningEnabledRule(BaseRule):
    """Flags BGP instances with route dampening enabled (advisory)."""

    rule_id = "BGP_ROUTE_DAMPENING_ENABLED"
    severity = "info"
    title = "BGP Route Dampening Enabled"
    description = "Route dampening is enabled — can delay convergence; verify it is intentional"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst_name, inst in bgp.get("instance", {}).items():
                if not isinstance(inst, dict):
                    continue
                for vrf_name, vrf in inst.get("vrf", {}).items():
                    if not isinstance(vrf, dict):
                        continue
                    for af_name, af in vrf.get("address_family", {}).items():
                        if not isinstance(af, dict):
                            continue
                        if af.get("dampening", False):
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="device",
                                element_id=f"{hostname}/bgp/{vrf_name}/{af_name}/dampening",
                                message=f"BGP dampening enabled in {af_name} (VRF {vrf_name})",
                                key_facts={"vrf": vrf_name, "address_family": af_name},
                                recommendation="Verify dampening parameters; modern best practice often avoids dampening",
                            ))

        return findings


# -------------------------------------------------------------------------
# BGP_HOLD_TIME_TOO_SHORT
# -------------------------------------------------------------------------

class BgpHoldTimeTooShortRule(BaseRule):
    """Flags BGP neighbors with hold time below recommended minimum."""

    rule_id = "BGP_HOLD_TIME_TOO_SHORT"
    severity = "low"
    title = "BGP Hold Time Too Short"
    description = "BGP hold time is below recommended minimum — increases flap risk"

    HOLD_MIN = 30  # default; tune per deployment — minimum recommended hold time in seconds

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                timers = nbr.get("bgp_negotiated_keepalive_timers", {})
                hold = timers.get("hold_time", 180)
                if isinstance(hold, (int, float)) and 0 < hold < self.HOLD_MIN:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/hold-time",
                        message=(
                            f"BGP neighbor {nbr_addr} hold time "
                            f"{hold}s (< {self.HOLD_MIN}s)"
                        ),
                        key_facts={"neighbor": nbr_addr, "vrf": vrf, "hold_time": hold},
                        recommendation=f"Increase hold time to at least {self.HOLD_MIN}s to avoid false flaps",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_EBGP_MULTIHOP_EXCESSIVE
# -------------------------------------------------------------------------

class BgpEbgpMultihopExcessiveRule(BaseRule):
    """Flags eBGP neighbors with excessive multihop TTL."""

    rule_id = "BGP_EBGP_MULTIHOP_EXCESSIVE"
    severity = "info"
    title = "BGP eBGP Multihop Excessive"
    description = "eBGP multihop TTL is set excessively high — security and troubleshooting risk"

    MAX_HOPS = 10  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            local_as = None
            for inst_name, inst in bgp.get("instance", {}).items():
                if isinstance(inst, dict):
                    local_as = inst.get("bgp_id")
                    break

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                remote_as = nbr.get("remote_as")
                if local_as and remote_as and str(local_as) == str(remote_as):
                    continue  # iBGP — multihop not relevant
                ebgp_multihop = nbr.get("ebgp_multihop_max_hop", 0)
                if isinstance(ebgp_multihop, (int, float)) and ebgp_multihop > self.MAX_HOPS:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/multihop",
                        message=(
                            f"EBGP neighbor {nbr_addr} multihop "
                            f"TTL {ebgp_multihop} (> {self.MAX_HOPS})"
                        ),
                        key_facts={
                            "neighbor": nbr_addr, "vrf": vrf,
                            "multihop_ttl": ebgp_multihop,
                        },
                        recommendation="Reduce eBGP multihop TTL to the minimum required hop count",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_MESSAGE_QUEUE_BACKED_UP
# -------------------------------------------------------------------------

class BgpMessageQueueBackedUpRule(BaseRule):
    """Flags BGP neighbors with backed-up message queues."""

    rule_id = "BGP_MESSAGE_QUEUE_BACKED_UP"
    severity = "low"
    title = "BGP Message Queue Backed Up"
    description = "BGP neighbor has backed-up message queue indicating congestion"

    QUEUE_THRESHOLD = 50  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                msg_stats = nbr.get("bgp_neighbor_counters", {}).get("messages", {})
                # Check output queue depth
                out_queue = msg_stats.get("out_queue_depth", 0)
                in_queue = msg_stats.get("in_queue_depth", 0)
                max_q = max(int(out_queue or 0), int(in_queue or 0))
                if max_q > self.QUEUE_THRESHOLD:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/msg-queue",
                        message=(
                            f"BGP neighbor {nbr_addr} message queue "
                            f"depth {max_q} (threshold: {self.QUEUE_THRESHOLD})"
                        ),
                        key_facts={
                            "neighbor": nbr_addr, "vrf": vrf,
                            "out_queue": out_queue, "in_queue": in_queue,
                        },
                        recommendation="Investigate BGP processing delays or network congestion",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_FREQUENT_RESET
# -------------------------------------------------------------------------

class BgpNeighborFrequentResetRule(BaseRule):
    """Flags BGP neighbors with frequent session resets."""

    rule_id = "BGP_NEIGHBOR_FREQUENT_RESET"
    severity = "info"
    title = "BGP Neighbor Frequent Reset"
    description = "BGP neighbor session has been reset (cumulative, no timestamp)"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                transport = nbr.get("bgp_session_transport", {}).get("connection", {})
                last_reset = str(transport.get("last_reset", "never")).lower()
                reset_reason = transport.get("reset_reason", "")
                # Flag if last_reset is not "never" and there's a reset reason
                if last_reset != "never" and reset_reason:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/reset",
                        message=(
                            f"BGP neighbor {nbr_addr} was reset "
                            f"(reason: {reset_reason})"
                        ),
                        key_facts={
                            "neighbor": nbr_addr, "vrf": vrf,
                            "last_reset": last_reset, "reset_reason": reset_reason,
                        },
                        recommendation="Investigate BGP session stability and root cause of resets",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_NEIGHBOR_HIGH_NOTIFICATION_RATE
# -------------------------------------------------------------------------

class BgpNeighborHighNotificationRateRule(BaseRule):
    """Flags BGP neighbors with high notification message counts."""

    rule_id = "BGP_NEIGHBOR_HIGH_NOTIFICATION_RATE"
    severity = "info"
    title = "BGP Neighbor High Notification Rate"
    description = "BGP neighbor has sent/received many notification messages indicating errors"

    NOTIFICATION_THRESHOLD = 5  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                msg_stats = nbr.get("bgp_neighbor_counters", {}).get("messages", {})
                sent_notif = msg_stats.get("sent", {}).get("notifications", 0)
                recv_notif = msg_stats.get("received", {}).get("notifications", 0)
                total_notif = int(sent_notif or 0) + int(recv_notif or 0)
                if total_notif > self.NOTIFICATION_THRESHOLD:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/notifications",
                        message=(
                            f"BGP neighbor {nbr_addr} has "
                            f"{total_notif} notification messages "
                            f"(sent: {sent_notif}, recv: {recv_notif})"
                        ),
                        key_facts={
                            "neighbor": nbr_addr, "vrf": vrf,
                            "sent": sent_notif, "received": recv_notif,
                        },
                        recommendation="Review BGP notification reasons — may indicate configuration or protocol errors",
                    ))

        return findings


# -------------------------------------------------------------------------
# BGP_PREFIX_LIMIT_APPROACHING
# -------------------------------------------------------------------------

class BgpPrefixLimitApproachingRule(BaseRule):
    """Flags BGP neighbors approaching their prefix limit."""

    rule_id = "BGP_PREFIX_LIMIT_APPROACHING"
    severity = "high"
    title = "BGP Prefix Limit Approaching"
    description = "BGP neighbor received prefix count is approaching the configured maximum"

    WARN_PERCENT = 80  # tunable default

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                for af_name, af in nbr.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    max_prefixes = af.get("maximum_prefix_max_prefix_no", 0)
                    if not max_prefixes:
                        continue
                    prefixes = af.get("prefixes", {})
                    received = prefixes.get("received", prefixes.get("total_entries", 0))
                    if not received:
                        continue
                    pct = (received / max_prefixes) * 100
                    if pct >= self.WARN_PERCENT:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/{af_name}/prefix-limit",
                            message=(
                                f"BGP neighbor {nbr_addr} ({af_name}) "
                                f"at {pct:.0f}% of prefix limit ({received}/{max_prefixes})"
                            ),
                            key_facts={
                                "neighbor": nbr_addr, "vrf": vrf,
                                "received": received, "max_prefixes": max_prefixes,
                                "percent": round(pct, 1),
                            },
                            recommendation="Increase prefix limit or review advertised routes from peer",
                        ))

        return findings


# -------------------------------------------------------------------------
# BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID
# -------------------------------------------------------------------------

class BgpRouteReflectorNoClusterIdRule(BaseRule):
    """Flags BGP route reflectors without an explicit cluster-id."""

    rule_id = "BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID"
    severity = "info"
    title = "BGP Route Reflector No Cluster ID"
    description = "BGP route reflector client configured but no explicit cluster-id set"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            # route-reflector-client + cluster-id are config-only — genie's
            # operational `show bgp` never exposes them. Read the running-config
            # parse (bgp_config.json), the authoritative source the sibling RR
            # rules also use.
            bgp_cfg = load_device_facts(run_path, hostname, "bgp_config")
            if not bgp_cfg:
                continue

            neighbors = bgp_cfg.get("neighbors", {})
            rr_clients = [
                ip for ip, nbr in neighbors.items()
                if isinstance(nbr, dict) and nbr.get("route_reflector_client")
            ]
            if not rr_clients:
                continue
            # An RR with no explicit `bgp cluster-id` falls back to its router-id;
            # fine for a single RR, but a hazard once a second RR appears.
            if not bgp_cfg.get("cluster_id"):
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/bgp/rr-no-cluster-id",
                    message="BGP route reflector has no explicit cluster-id",
                    key_facts={"has_rr_clients": True, "rr_client_count": len(rr_clients)},
                    recommendation="Set explicit cluster-id for proper RR loop prevention",
                ))

        return findings


# -------------------------------------------------------------------------
# BGP_NO_MAX_PREFIX — eBGP neighbor without maximum-prefix
# -------------------------------------------------------------------------

class BgpNoMaxPrefixRule(BaseRule):
    """Flags established eBGP neighbors without maximum-prefix configured.

    audit: without maximum-prefix, an eBGP peer can
    advertise an unlimited number of prefixes, risking RIB/FIB exhaustion.
    """

    rule_id = "BGP_NO_MAX_PREFIX"
    severity = "high"
    title = "BGP eBGP No Max-Prefix"
    description = "eBGP neighbor has no maximum-prefix limit — risk of RIB exhaustion"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            # Get local AS from instance level
            local_as = None
            for inst_name, inst in bgp.get("instance", {}).items():
                if isinstance(inst, dict):
                    local_as = inst.get("bgp_id")
                    break

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                remote_as = nbr.get("remote_as")
                # Only check eBGP (local_as != remote_as)
                if local_as and remote_as and str(local_as) == str(remote_as):
                    continue  # iBGP — skip
                for af_name, af in nbr.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    max_prefix = af.get("maximum_prefix_max_prefix_no")
                    if not max_prefix:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/{af_name}/no-max-prefix",
                            message=(
                                f"EBGP neighbor {nbr_addr} (AS {remote_as}, "
                                f"{af_name}) has no maximum-prefix limit"
                            ),
                            key_facts={
                                "neighbor": nbr_addr, "vrf": vrf,
                                "remote_as": remote_as, "af": af_name,
                            },
                            recommendation=(
                                "Configure 'neighbor <ip> maximum-prefix <limit>' "
                                "to protect against route leaks"
                            ),
                        ))

        return findings


# -------------------------------------------------------------------------
# BGP_EBGP_NO_PREFIX_FILTER — eBGP with pass-all route policy
# -------------------------------------------------------------------------

def _is_passall_policy(config: str, policy_name: str) -> bool:
    """Check if a route-map/route-policy is a pass-all (no filtering).

    IOS XR: ``route-policy <name>\\n  pass\\nend-policy``
    IOS XE: ``route-map <name> permit 10`` with no match clauses
    """
    # IOS XR: route-policy <name> ... end-policy
    m = re.search(
        rf"route-policy\s+{re.escape(policy_name)}\s*\n(.*?)\nend-policy",
        config, re.DOTALL,
    )
    if m:
        body = m.group(1).strip()
        # A pass-all policy body is just "pass" (possibly with comments)
        lines = [ln.strip() for ln in body.splitlines()
                 if ln.strip() and not ln.strip().startswith("!")]
        return lines == ["pass"]

    # IOS XE: route-map <name> permit ... (check if all clauses lack match)
    rm_blocks = re.findall(
        rf"route-map\s+{re.escape(policy_name)}\s+permit\s+\d+\s*\n((?:[ \t]+.*\n)*)",
        config,
    )
    if rm_blocks:
        for block in rm_blocks:
            if "match " in block:
                return False  # Has at least one match clause
        return True  # All permit clauses have no match = pass-all

    return False


class BgpEbgpNoFilterRule(BaseRule):
    """Flags eBGP neighbors using pass-all route policies (no real filtering).

    audit: a route-map/route-policy that permits
    everything is effectively no filter at all. This is distinct from
    BGP_NEIGHBOR_MISSING_INBOUND_POLICY which catches *missing* policies.
    """

    rule_id = "BGP_EBGP_NO_PREFIX_FILTER"
    severity = "high"
    title = "BGP eBGP Pass-All Filter"
    description = "eBGP neighbor uses a pass-all route policy — no real prefix filtering"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            bgp = _load_bgp(run_path, hostname)
            if bgp is None:
                continue

            config = load_running_config(run_path, hostname) or ""

            # Get local AS
            local_as = None
            for inst_name, inst in bgp.get("instance", {}).items():
                if isinstance(inst, dict):
                    local_as = inst.get("bgp_id")
                    break

            for inst, vrf, nbr_addr, nbr in _iter_bgp_neighbors(bgp):
                state = str(nbr.get("session_state", "")).lower()
                if state != "established":
                    continue
                remote_as = nbr.get("remote_as")
                if local_as and remote_as and str(local_as) == str(remote_as):
                    continue  # iBGP

                for af_name, af in nbr.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    # Check inbound policy
                    in_policy = af.get("route_map_name_in") or af.get("policy_in") or ""
                    if in_policy and config and _is_passall_policy(config, in_policy):
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/bgp/{vrf}/{nbr_addr}/{af_name}/passall-in",
                            message=(
                                f"EBGP neighbor {nbr_addr} ({af_name}) "
                                f"inbound policy '{in_policy}' is pass-all"
                            ),
                            key_facts={
                                "neighbor": nbr_addr, "vrf": vrf,
                                "remote_as": remote_as, "af": af_name,
                                "direction": "inbound",
                                "policy_name": in_policy,
                            },
                            recommendation=(
                                "Replace pass-all policy with proper prefix filtering "
                                "to prevent route leaks"
                            ),
                        ))

        return findings
