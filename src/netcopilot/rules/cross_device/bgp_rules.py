"""
BGP Cross-Device Rules — .

11 rules comparing BGP parameters between peered devices.

Bilateral rules (8): Compare neighbor-level BGP parameters.
Topology rules (3): Domain-wide BGP consistency.

Rule IDs:
    BGP_PEER_AS_MISMATCH, BGP_PEER_ASYMMETRIC, BGP_AUTH_MISMATCH,
    BGP_UPDATE_SOURCE_MISMATCH, BGP_EBGP_MULTIHOP_MISSING,
    BGP_ADDRESS_FAMILY_MISMATCH, BGP_ROUTE_REFLECTOR_CLIENT_ASYMMETRIC,
    BGP_TIMER_MISMATCH, BGP_CLUSTER_ID_DUPLICATE,
    BGP_ROUTER_ID_DUPLICATE, BGP_AS_SINGLE_SPEAKER
"""

from typing import Any

from netcopilot.rules.cross_device.helpers import (
    extract_bgp_router_id,
    find_bgp_neighbor,
    make_bilateral_element_id,
    make_finding,
    safe_get,
)
from netcopilot.rules.finding import Finding

RULE_IDS = [
    "BGP_PEER_AS_MISMATCH",
    "BGP_PEER_ASYMMETRIC",
    "BGP_AUTH_MISMATCH",
    "BGP_UPDATE_SOURCE_MISMATCH",
    "BGP_EBGP_MULTIHOP_MISSING",
    "BGP_ADDRESS_FAMILY_MISMATCH",
    "BGP_ROUTE_REFLECTOR_CLIENT_ASYMMETRIC",
    "BGP_TIMER_MISMATCH",
    "BGP_CLUSTER_ID_DUPLICATE",
    "BGP_ROUTER_ID_DUPLICATE",
    "BGP_AS_SINGLE_SPEAKER",
]


# =========================================================================
# Bilateral rules — compare BGP neighbor parameters
# =========================================================================

def evaluate_bilateral(
    bgp_peers: list[dict],
    links: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Evaluate bilateral BGP rules on all collected BGP adjacencies."""
    findings: list[Finding] = []

    for entry in bgp_peers:
        dev_a = entry["dev_a"]
        dev_b = entry["dev_b"]
        adj = entry["adj"]

        bgp_a = facts[dev_a].get("genie_bgp", {})
        bgp_b = facts[dev_b].get("genie_bgp", {})

        # We need to find how each side sees the other as a neighbor.
        # BGP neighbors are keyed by IP address, not hostname.
        # Try to find dev_b in dev_a's neighbor table and vice versa.
        nbr_a_sees_b = _find_peer_neighbor(bgp_a, bgp_b, dev_b)
        nbr_b_sees_a = _find_peer_neighbor(bgp_b, bgp_a, dev_a)

        if nbr_a_sees_b is None and nbr_b_sees_a is None:
            continue

        eid = make_bilateral_element_id(dev_a, "bgp", dev_b, "bgp")

        # --- Peer AS mismatch ---
        if nbr_a_sees_b and nbr_b_sees_a:
            _check_peer_as(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

            # --- Auth mismatch ---
            _check_auth(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

            # --- Update source mismatch ---
            _check_update_source(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

            # --- eBGP multihop ---
            _check_ebgp_multihop(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

            # --- Address family mismatch ---
            _check_address_family(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

            # --- Route reflector client asymmetric ---
            _check_rr_client(
                findings, adj,
                dev_a, dev_b, eid,
            )

            # --- Timer mismatch ---
            _check_timers(
                findings, nbr_a_sees_b, nbr_b_sees_a,
                dev_a, dev_b, eid,
            )

    return findings


# =========================================================================
# Topology rules — BGP domain-wide consistency
# =========================================================================

def evaluate_domain(
    bgp_domains: dict[str, list[str]],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Evaluate BGP domain-wide consistency rules."""
    findings: list[Finding] = []
    findings.extend(_check_cluster_id_duplicate(facts))
    findings.extend(_check_router_id_duplicate(facts))
    findings.extend(_check_as_single_speaker(bgp_domains, facts))
    return findings


# =========================================================================
# Adjacency rules — BGP adjacency state analysis
# =========================================================================

def evaluate_adjacency(
    adjacencies: list[dict],
) -> list[Finding]:
    """Evaluate BGP adjacency-based rules."""
    findings: list[Finding] = []
    findings.extend(_check_peer_asymmetric(adjacencies))
    return findings


# =========================================================================
# Bilateral check implementations
# =========================================================================

def _check_peer_as(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check if configured remote AS matches the peer's actual local AS."""
    # A's configured remote_as should match B's local AS
    remote_as_a = nbr_a.get("remote_as")
    local_as_b = nbr_b.get("local_as_as_no")

    if remote_as_a is not None and local_as_b is not None:
        if remote_as_a != local_as_b:
            findings.append(make_finding(
                rule_id="BGP_PEER_AS_MISMATCH",
                severity="critical",
                title="BGP Peer AS Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"BGP peer AS mismatch: {dev_a} expects remote AS "
                    f"{remote_as_a} but {dev_b} has local AS {local_as_b}. "
                    f"Session will not establish."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_expects": remote_as_a,
                    "dev_b_actual": local_as_b,
                },
                recommendation=(
                    "Correct the neighbor remote-as configuration."
                ),
            ))


def _check_auth(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check for BGP authentication configuration asymmetry."""
    # Check if one side has password configured and the other doesn't
    auth_a = bool(safe_get(nbr_a, "bgp_session_transport", "connection",
                           "password_configured"))
    auth_b = bool(safe_get(nbr_b, "bgp_session_transport", "connection",
                           "password_configured"))

    if auth_a != auth_b:
        findings.append(make_finding(
            rule_id="BGP_AUTH_MISMATCH",
            severity="critical",
            title="BGP Authentication Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP auth mismatch: {dev_a} has password "
                f"{'configured' if auth_a else 'not configured'}, "
                f"{dev_b} has password "
                f"{'configured' if auth_b else 'not configured'}. "
                f"Session will not establish."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_auth": auth_a,
                "dev_b_auth": auth_b,
            },
            recommendation=(
                "Configure matching BGP authentication on both peers."
            ),
        ))


def _check_update_source(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check for update-source interface mismatch."""
    src_a = safe_get(nbr_a, "bgp_session_transport", "transport",
                     "local_host")
    src_b = safe_get(nbr_b, "bgp_session_transport", "transport",
                     "local_host")

    if not src_a or not src_b:
        return

    # Check if A's local_host matches what B expects to see as foreign_host
    foreign_b = safe_get(nbr_b, "bgp_session_transport", "transport",
                         "foreign_host")
    if foreign_b and src_a != foreign_b:
        findings.append(make_finding(
            rule_id="BGP_UPDATE_SOURCE_MISMATCH",
            severity="critical",
            title="BGP Update Source Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP update-source mismatch: {dev_a} sends from {src_a} "
                f"but {dev_b} expects {foreign_b}."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_source": src_a,
                "dev_b_expects": foreign_b,
            },
            recommendation=(
                "Configure matching 'neighbor update-source' on both peers."
            ),
        ))


def _check_ebgp_multihop(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check if eBGP sessions need multihop but don't have it configured."""
    local_as_a = nbr_a.get("local_as_as_no")
    remote_as_a = nbr_a.get("remote_as")

    if local_as_a is None or remote_as_a is None:
        return
    if local_as_a == remote_as_a:
        return  # iBGP — multihop not needed

    # eBGP session — check if loopback peering (needs multihop)
    src_a = safe_get(nbr_a, "bgp_session_transport", "transport", "local_host")
    if not src_a:
        return

    # If update-source is a loopback IP (not directly connected)
    # then multihop is needed
    multihop_a = nbr_a.get("ebgp_multihop")
    if not multihop_a and nbr_a.get("ebgp_multihop_max_hop", 0) <= 1:
        # Only flag if session is NOT established (misconfigured)
        state = nbr_a.get("session_state", "")
        if state and state != "established":
            findings.append(make_finding(
                rule_id="BGP_EBGP_MULTIHOP_MISSING",
                severity="low",
                title="BGP eBGP Multihop Missing",
                element_type="link",
                element_id=eid,
                message=(
                    f"eBGP session {dev_a}→{dev_b} (AS {local_as_a}→"
                    f"{remote_as_a}) is not established and multihop "
                    f"is not configured."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "local_as": local_as_a,
                    "remote_as": remote_as_a,
                    "state": state,
                },
                recommendation=(
                    "Configure 'neighbor ebgp-multihop' if peering over "
                    "loopback addresses."
                ),
            ))


def _check_address_family(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check for BGP address family mismatch between peers."""
    af_a = set(nbr_a.get("address_family", {}).keys())
    af_b = set(nbr_b.get("address_family", {}).keys())

    if not af_a or not af_b:
        return

    if af_a != af_b:
        only_a = af_a - af_b
        only_b = af_b - af_a
        findings.append(make_finding(
            rule_id="BGP_ADDRESS_FAMILY_MISMATCH",
            severity="critical",
            title="BGP Address Family Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP address family mismatch between {dev_a} and {dev_b}. "
                f"Only on {dev_a}: {sorted(only_a) if only_a else 'none'}. "
                f"Only on {dev_b}: {sorted(only_b) if only_b else 'none'}."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_afs": sorted(af_a),
                "dev_b_afs": sorted(af_b),
            },
            recommendation=(
                "Activate matching address families on both peers."
            ),
        ))


def _check_rr_client(
    findings: list[Finding],
    adj: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check for route-reflector client asymmetry.

    Reads the model adjacency's bilateral ``route_reflector_client_{a,b}``
    flags (sourced from each device's running-config ``bgp_config.json`` fact —
    genie omits ``route-reflector-client`` because it is config-only, never in
    operational ``show bgp`` output).
    """
    # In iBGP, if A marks B as RR client, B doesn't necessarily mark A
    # This is expected. But if BOTH mark each other as RR client, that's wrong.
    rr_a = bool(adj.get("route_reflector_client_a"))
    rr_b = bool(adj.get("route_reflector_client_b"))

    if rr_a and rr_b:
        findings.append(make_finding(
            rule_id="BGP_ROUTE_REFLECTOR_CLIENT_ASYMMETRIC",
            severity="low",
            title="BGP Route Reflector Client — Both Peers",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP peering {dev_a}↔{dev_b}: both sides mark the "
                f"other as route-reflector client. This creates a "
                f"routing loop risk."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_rr_client": True,
                "dev_b_rr_client": True,
            },
            recommendation=(
                "Only one side should be the route-reflector; the other "
                "should be the client."
            ),
        ))


def _check_timers(
    findings: list[Finding],
    nbr_a: dict, nbr_b: dict,
    dev_a: str, dev_b: str, eid: str,
) -> None:
    """Check for BGP keepalive/holdtime timer mismatch."""
    ka_a = nbr_a.get("keepalive_interval")
    ka_b = nbr_b.get("keepalive_interval")
    hold_a = nbr_a.get("holdtime")
    hold_b = nbr_b.get("holdtime")

    mismatches = []
    if ka_a is not None and ka_b is not None and ka_a != ka_b:
        mismatches.append(f"keepalive {ka_a}s vs {ka_b}s")
    if hold_a is not None and hold_b is not None and hold_a != hold_b:
        mismatches.append(f"holdtime {hold_a}s vs {hold_b}s")

    if mismatches:
        findings.append(make_finding(
            rule_id="BGP_TIMER_MISMATCH",
            severity="info",
            title="BGP Timer Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP timer mismatch {dev_a}↔{dev_b}: "
                f"{'; '.join(mismatches)}. BGP will negotiate to the "
                f"higher holdtime, but inconsistency may indicate drift."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_keepalive": ka_a,
                "dev_a_holdtime": hold_a,
                "dev_b_keepalive": ka_b,
                "dev_b_holdtime": hold_b,
            },
            recommendation=(
                "Configure matching BGP timers on both peers for consistency."
            ),
        ))


# =========================================================================
# Topology check implementations
# =========================================================================

def _check_cluster_id_duplicate(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Check for duplicate BGP cluster-IDs across route reflectors.

    A route reflector is a device whose running-config (``bgp_config.json``
    fact) marks at least one neighbor as ``route-reflector-client``. Its
    effective cluster-ID is the explicit ``bgp cluster-id`` if configured,
    otherwise the BGP router-ID (the IOS/IOS-XR default). genie cannot supply
    this — ``route-reflector-client`` and an unset cluster-id are config-only.
    """
    findings: list[Finding] = []

    cid_map: dict[str, list[str]] = {}
    for hostname, device_facts in facts.items():
        bgp_cfg = device_facts.get("bgp_config")
        if not bgp_cfg:
            continue
        neighbors = bgp_cfg.get("neighbors", {})
        is_rr = any(
            nbr.get("route_reflector_client") for nbr in neighbors.values()
        )
        if not is_rr:
            continue
        # Effective cluster-ID: explicit config, else router-ID default.
        cid = bgp_cfg.get("cluster_id") or bgp_cfg.get("router_id")
        if cid:
            cid_map.setdefault(cid, []).append(hostname)

    for cid, hostnames in cid_map.items():
        if len(hostnames) > 1:
            findings.append(make_finding(
                rule_id="BGP_CLUSTER_ID_DUPLICATE",
                severity="critical",
                title="Duplicate BGP Cluster-ID",
                element_type="device",
                element_id=f"bgp::cluster_id_dup::{cid}",
                message=(
                    f"BGP cluster-ID {cid} shared by {len(hostnames)} "
                    f"route reflectors: {', '.join(hostnames)}. "
                    f"Route reflection loops may occur."
                ),
                key_facts={
                    "devices": hostnames,
                    "cluster_id": cid,
                },
                recommendation=(
                    "Assign unique cluster-IDs to each route reflector."
                ),
            ))

    return findings


def _check_router_id_duplicate(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Check for duplicate BGP router-IDs."""
    findings: list[Finding] = []

    rid_map: dict[str, list[str]] = {}
    for hostname, device_facts in facts.items():
        bgp = device_facts.get("genie_bgp")
        if not bgp:
            continue
        rid = extract_bgp_router_id(bgp)
        if rid:
            rid_map.setdefault(rid, []).append(hostname)

    for rid, hostnames in rid_map.items():
        if len(hostnames) > 1:
            findings.append(make_finding(
                rule_id="BGP_ROUTER_ID_DUPLICATE",
                severity="critical",
                title="Duplicate BGP Router-ID",
                element_type="device",
                element_id=f"bgp::rid_dup::{rid}",
                message=(
                    f"BGP router-ID {rid} is used by {len(hostnames)} "
                    f"devices: {', '.join(hostnames)}."
                ),
                key_facts={
                    "devices": hostnames,
                    "router_id": rid,
                },
                recommendation=(
                    "Assign unique BGP router-IDs (typically loopback IPs)."
                ),
            ))

    return findings


def _check_as_single_speaker(
    bgp_domains: dict[str, list[str]],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Flag BGP AS numbers with only a single speaker (no redundancy)."""
    findings: list[Finding] = []

    for asn, members in bgp_domains.items():
        if len(members) == 1:
            hostname = members[0]
            findings.append(make_finding(
                rule_id="BGP_AS_SINGLE_SPEAKER",
                severity="low",
                title="BGP AS Single Speaker",
                element_type="device",
                element_id=f"bgp::as_{asn}::single_speaker",
                message=(
                    f"AS {asn} has only 1 speaker ({hostname}). "
                    f"No redundancy — single point of failure for "
                    f"external routing."
                ),
                key_facts={
                    "devices": [hostname],
                    "asn": asn,
                },
                recommendation=(
                    "Deploy a second BGP speaker in the AS for redundancy."
                ),
            ))

    return findings


# =========================================================================
# Adjacency check implementations
# =========================================================================

def _check_peer_asymmetric(
    adjacencies: list[dict],
) -> list[Finding]:
    """Flag BGP adjacencies that are asymmetric (one side doesn't see peer)."""
    findings: list[Finding] = []

    for adj in adjacencies:
        if adj.get("protocol") != "bgp":
            continue
        if not adj.get("peer_collected", False):
            continue
        if adj.get("bilateral", True):
            continue  # Both sides see each other — OK

        dev_a = adj.get("device_a", "")
        dev_b = adj.get("device_b", "")
        eid = make_bilateral_element_id(dev_a, "bgp", dev_b, "bgp")

        findings.append(make_finding(
            rule_id="BGP_PEER_ASYMMETRIC",
            severity="critical",
            title="BGP Peer Asymmetric",
            element_type="link",
            element_id=eid,
            message=(
                f"BGP peering {dev_a}↔{dev_b} is asymmetric: "
                f"one side does not see the neighbor. "
                f"State: {adj.get('state')}."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "state": adj.get("state"),
                "bilateral": False,
            },
            recommendation=(
                "Check BGP neighbor configuration, IP reachability, "
                "and authentication on both sides."
            ),
        ))

    return findings


# =========================================================================
# Internal helpers
# =========================================================================

def _find_peer_neighbor(
    local_bgp: dict,
    remote_bgp: dict,
    remote_hostname: str,
) -> dict | None:
    """
    Find how the local device sees the remote device as a BGP neighbor.

    BGP neighbors are keyed by IP address. We match by finding a neighbor
    whose address is one of the remote device's known IPs.

    Strategy:
    1. Collect the remote device's known IPs: router-id and transport
       addresses (local_host from its own neighbor entries).
    2. Look for a local neighbor keyed by one of those IPs (exact match).
    3. Fallback: match on remote_as == remote device's local AS.
    """
    # Build set of remote device's known IPs
    remote_ips: set[str] = set()
    remote_local_as = None
    for inst, idata in remote_bgp.get("instance", {}).items():
        for vrf, vdata in idata.get("vrf", {}).items():
            rid = vdata.get("router_id")
            if rid:
                remote_ips.add(rid)
            if remote_local_as is None:
                remote_local_as = vdata.get("as_number") or idata.get("bgp_id")
            # Collect transport IPs from the remote device's own sessions
            for _nbr, ndata in vdata.get("neighbor", {}).items():
                transport = ndata.get("bgp_session_transport", {}).get("transport", {})
                lh = transport.get("local_host")
                if lh:
                    remote_ips.add(lh)

    # Pass 1: exact IP match (neighbor key == remote device's IP)
    for inst, idata in local_bgp.get("instance", {}).items():
        for vrf, vdata in idata.get("vrf", {}).items():
            for nbr_addr, nbr_data in vdata.get("neighbor", {}).items():
                if nbr_addr in remote_ips:
                    return nbr_data

    # Pass 2: match on remote_as == remote device's local AS
    if remote_local_as is not None:
        for inst, idata in local_bgp.get("instance", {}).items():
            for vrf, vdata in idata.get("vrf", {}).items():
                for nbr_addr, nbr_data in vdata.get("neighbor", {}).items():
                    if nbr_data.get("remote_as") == remote_local_as:
                        state = nbr_data.get("session_state", "")
                        if state == "established":
                            return nbr_data

    return None
