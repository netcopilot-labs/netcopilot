"""
OSPF Cross-Device Rules — .

15 rules comparing OSPF parameters between connected devices.

Bilateral rules (10): Compare interface-level OSPF parameters on links.
Topology rules (3): Domain-wide OSPF consistency.
Adjacency rules (2): OSPF adjacency state analysis.

Rule IDs:
    OSPF_HELLO_INTERVAL_MISMATCH, OSPF_DEAD_INTERVAL_MISMATCH,
    OSPF_AREA_ID_MISMATCH, OSPF_NETWORK_TYPE_MISMATCH,
    OSPF_AUTH_TYPE_MISMATCH, OSPF_MTU_MISMATCH_DBD,
    OSPF_STUB_FLAG_MISMATCH, OSPF_PASSIVE_INTERFACE_ASYMMETRIC,
    OSPF_COST_ASYMMETRIC, OSPF_RETRANSMIT_INTERVAL_MISMATCH,
    OSPF_ROUTER_ID_DUPLICATE, OSPF_REFERENCE_BANDWIDTH_INCONSISTENT,
    OSPF_SPF_TIMER_INCONSISTENT, OSPF_ADJACENCY_ASYMMETRIC,
    OSPF_AREA_SINGLE_ABR
"""

from typing import Any

from netcopilot.rules.cross_device.helpers import (
    extract_ospf_spf_timers_by_vrf,
    extract_reference_bandwidth_by_vrf,
    find_ospf_interface,
    find_ospf_interface_with_context,
    is_area_border_router,
    make_bilateral_element_id,
    make_finding,
    normalize_ip_mtu,
)
from netcopilot.rules.finding import Finding

RULE_IDS = [
    "OSPF_HELLO_INTERVAL_MISMATCH",
    "OSPF_DEAD_INTERVAL_MISMATCH",
    "OSPF_AREA_ID_MISMATCH",
    "OSPF_NETWORK_TYPE_MISMATCH",
    "OSPF_AUTH_TYPE_MISMATCH",
    "OSPF_MTU_MISMATCH_DBD",
    "OSPF_STUB_FLAG_MISMATCH",
    "OSPF_PASSIVE_INTERFACE_ASYMMETRIC",
    "OSPF_COST_ASYMMETRIC",
    "OSPF_RETRANSMIT_INTERVAL_MISMATCH",
    "OSPF_ROUTER_ID_DUPLICATE",
    "OSPF_REFERENCE_BANDWIDTH_INCONSISTENT",
    "OSPF_SPF_TIMER_INCONSISTENT",
    "OSPF_ADJACENCY_ASYMMETRIC",
    "OSPF_AREA_SINGLE_ABR",
]


# =========================================================================
# Bilateral rules — compare OSPF interface parameters on connected links
# =========================================================================

def evaluate_bilateral(
    ospf_links: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Evaluate bilateral OSPF rules on all OSPF-enabled links."""
    findings: list[Finding] = []

    for entry in ospf_links:
        dev_a = entry["dev_a"]
        dev_b = entry["dev_b"]
        intf_a = entry["intf_a"]  # already canonicalized
        intf_b = entry["intf_b"]

        ospf_a = facts[dev_a].get("genie_ospf", {})
        ospf_b = facts[dev_b].get("genie_ospf", {})

        # Find OSPF interface data on both sides
        ctx_a = find_ospf_interface_with_context(ospf_a, intf_a)
        ctx_b = find_ospf_interface_with_context(ospf_b, intf_b)

        if ctx_a is None or ctx_b is None:
            continue  # Interface not in OSPF on one side

        ifa, vrf_a, pid_a, area_a = ctx_a
        ifb, vrf_b, pid_b, area_b = ctx_b

        # OSPF runs per-VRF: two interfaces in different VRFs are in separate OSPF
        # domains and cannot form an adjacency, so comparing their OSPF parameters
        # (area / hello / dead / network-type) is meaningless. Without this guard a
        # shared subnet across a VRF boundary — e.g. a reused IP in the global table
        # and a VRF — produces spurious "mismatch" findings on a link that does not
        # exist as an adjacency.
        if vrf_a != vrf_b:
            continue

        # Use raw (non-canonical) names for readable element_id
        link = entry["link"]
        _, raw_a = link.get("local_interface_id", ":").split(":", 1)
        _, raw_b = link.get("remote_interface_id", ":").split(":", 1)
        eid = make_bilateral_element_id(dev_a, raw_a, dev_b, raw_b)

        # --- Area ID mismatch ---
        if area_a != area_b:
            findings.append(make_finding(
                rule_id="OSPF_AREA_ID_MISMATCH",
                severity="critical",
                title="OSPF Area ID Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF area mismatch on link {dev_a}:{raw_a} "
                    f"(area {area_a}) vs {dev_b}:{raw_b} (area {area_b}). "
                    f"Adjacency cannot form."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_area": area_a,
                    "dev_b_area": area_b,
                },
                recommendation=(
                    "Configure matching OSPF area on both endpoints."
                ),
            ))
            continue  # No point checking other params if areas differ

        # --- Hello interval mismatch ---
        _check_param(
            findings, ifa, ifb, "hello_interval",
            "OSPF_HELLO_INTERVAL_MISMATCH", "critical",
            "OSPF Hello Interval Mismatch",
            dev_a, raw_a, dev_b, raw_b, eid,
            "Adjacency cannot form — dead timer will expire.",
            "Configure matching OSPF hello intervals. Standard: 10s.",
        )

        # --- Dead interval mismatch ---
        _check_param(
            findings, ifa, ifb, "dead_interval",
            "OSPF_DEAD_INTERVAL_MISMATCH", "critical",
            "OSPF Dead Interval Mismatch",
            dev_a, raw_a, dev_b, raw_b, eid,
            "Adjacency cannot form — timer disagreement.",
            "Configure matching OSPF dead intervals. Standard: 40s.",
        )

        # --- Network type mismatch ---
        net_a = str(ifa.get("interface_type", "")).lower()
        net_b = str(ifb.get("interface_type", "")).lower()
        if net_a and net_b and net_a != net_b:
            findings.append(make_finding(
                rule_id="OSPF_NETWORK_TYPE_MISMATCH",
                severity="critical",
                title="OSPF Network Type Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF network type mismatch on link {dev_a}:{raw_a} "
                    f"({net_a}) vs {dev_b}:{raw_b} ({net_b}). "
                    f"DR/BDR election and hello timers may conflict."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_type": net_a,
                    "dev_b_type": net_b,
                },
                recommendation=(
                    "Configure matching OSPF network type on both endpoints."
                ),
            ))

        # --- Auth type mismatch ---
        auth_a = ifa.get("authentication", {})
        auth_b = ifb.get("authentication", {})
        if auth_a and auth_b:
            type_a = auth_a.get("auth_trailer_key_chain", {}).get(
                "crypto_algorithm"
            ) or auth_a.get("auth_trailer_key", {}).get("crypto_algorithm", "")
            type_b = auth_b.get("auth_trailer_key_chain", {}).get(
                "crypto_algorithm"
            ) or auth_b.get("auth_trailer_key", {}).get("crypto_algorithm", "")
            if type_a and type_b and type_a != type_b:
                findings.append(make_finding(
                    rule_id="OSPF_AUTH_TYPE_MISMATCH",
                    severity="critical",
                    title="OSPF Authentication Type Mismatch",
                    element_type="link",
                    element_id=eid,
                    message=(
                        f"OSPF auth type mismatch on link {dev_a}:{raw_a} "
                        f"({type_a}) vs {dev_b}:{raw_b} ({type_b}). "
                        f"Adjacency cannot form."
                    ),
                    key_facts={
                        "devices": [dev_a, dev_b],
                        "dev_a_auth": type_a,
                        "dev_b_auth": type_b,
                    },
                    recommendation=(
                        "Configure matching OSPF authentication on both endpoints."
                    ),
                ))
        elif bool(auth_a) != bool(auth_b):
            # One side has auth, other doesn't
            findings.append(make_finding(
                rule_id="OSPF_AUTH_TYPE_MISMATCH",
                severity="critical",
                title="OSPF Authentication Type Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF auth mismatch: {dev_a}:{raw_a} has auth "
                    f"{'enabled' if auth_a else 'disabled'}, "
                    f"{dev_b}:{raw_b} has auth "
                    f"{'enabled' if auth_b else 'disabled'}."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_has_auth": bool(auth_a),
                    "dev_b_has_auth": bool(auth_b),
                },
                recommendation=(
                    "Configure OSPF authentication on both endpoints."
                ),
            ))

        # --- MTU mismatch (DBD exchange) ---
        # Use OSPF interface MTU if present, else interface MTU. Normalize each
        # side to the IP MTU before comparing: OSPF DBD negotiates on the IP
        # MTU, but IOS XR's interface MTU includes the 14-byte L2 Ethernet
        # header (default 1514) while IOS XE reports the IP MTU directly
        # (default 1500). Comparing raw values flags a default XR<->XE link as
        # a mismatch when the IP MTU is identical (1500) — a false positive.
        mtu_a = normalize_ip_mtu(facts[dev_a], ifa.get("mtu") or _get_intf_mtu(facts[dev_a], intf_a))
        mtu_b = normalize_ip_mtu(facts[dev_b], ifb.get("mtu") or _get_intf_mtu(facts[dev_b], intf_b))
        if mtu_a and mtu_b and mtu_a != mtu_b:
            findings.append(make_finding(
                rule_id="OSPF_MTU_MISMATCH_DBD",
                severity="critical",
                title="OSPF MTU Mismatch (DBD Exchange)",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF IP MTU mismatch on link {dev_a}:{raw_a} ({mtu_a}) "
                    f"vs {dev_b}:{raw_b} ({mtu_b}). "
                    f"DBD exchange will fail — adjacency stuck in ExStart."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_mtu": mtu_a,
                    "dev_b_mtu": mtu_b,
                },
                recommendation=(
                    "Configure matching MTU or use 'ip ospf mtu-ignore'."
                ),
            ))

        # --- Stub flag mismatch ---
        stub_a = _get_stub_flag(ospf_a, area_a)
        stub_b = _get_stub_flag(ospf_b, area_b)
        if stub_a is not None and stub_b is not None and stub_a != stub_b:
            findings.append(make_finding(
                rule_id="OSPF_STUB_FLAG_MISMATCH",
                severity="critical",
                title="OSPF Stub Flag Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF stub flag mismatch for area {area_a}: "
                    f"{dev_a} ({'stub' if stub_a else 'normal'}) vs "
                    f"{dev_b} ({'stub' if stub_b else 'normal'}). "
                    f"Adjacency cannot form."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_stub": stub_a,
                    "dev_b_stub": stub_b,
                    "area": area_a,
                },
                recommendation=(
                    "Configure matching stub/NSSA settings for the area."
                ),
            ))

        # --- Passive interface asymmetric ---
        passive_a = ifa.get("passive", False)
        passive_b = ifb.get("passive", False)
        if passive_a and not passive_b:
            findings.append(make_finding(
                rule_id="OSPF_PASSIVE_INTERFACE_ASYMMETRIC",
                severity="critical",
                title="OSPF Passive Interface Asymmetric",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF passive mismatch: {dev_a}:{raw_a} is passive, "
                    f"{dev_b}:{raw_b} is active. "
                    f"Adjacency cannot form from {dev_b}'s perspective."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_passive": True,
                    "dev_b_passive": False,
                },
                recommendation=(
                    "Remove passive-interface if adjacency is intended."
                ),
            ))
        elif passive_b and not passive_a:
            findings.append(make_finding(
                rule_id="OSPF_PASSIVE_INTERFACE_ASYMMETRIC",
                severity="critical",
                title="OSPF Passive Interface Asymmetric",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF passive mismatch: {dev_b}:{raw_b} is passive, "
                    f"{dev_a}:{raw_a} is active. "
                    f"Adjacency cannot form from {dev_a}'s perspective."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_passive": False,
                    "dev_b_passive": True,
                },
                recommendation=(
                    "Remove passive-interface if adjacency is intended."
                ),
            ))

        # --- Cost asymmetric ---
        cost_a = ifa.get("cost")
        cost_b = ifb.get("cost")
        if cost_a is not None and cost_b is not None and cost_a != cost_b:
            findings.append(make_finding(
                rule_id="OSPF_COST_ASYMMETRIC",
                severity="low",
                title="OSPF Cost Asymmetric",
                element_type="link",
                element_id=eid,
                message=(
                    f"OSPF cost asymmetry on link {dev_a}:{raw_a} "
                    f"(cost {cost_a}) vs {dev_b}:{raw_b} (cost {cost_b}). "
                    f"Traffic may prefer different paths in each direction."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "dev_a_cost": cost_a,
                    "dev_b_cost": cost_b,
                },
                recommendation=(
                    "Verify OSPF cost is intentionally asymmetric. "
                    "Ensure auto-cost reference bandwidth is consistent."
                ),
            ))

        # --- Retransmit interval mismatch ---
        _check_param(
            findings, ifa, ifb, "retransmit_interval",
            "OSPF_RETRANSMIT_INTERVAL_MISMATCH", "info",
            "OSPF Retransmit Interval Mismatch",
            dev_a, raw_a, dev_b, raw_b, eid,
            "Different retransmit intervals — minor operational inconsistency.",
            "Configure matching retransmit intervals for operational consistency.",
        )

    return findings


# =========================================================================
# Topology rules — OSPF domain-wide consistency
# =========================================================================

def evaluate_domain(
    ospf_domains: dict[str, list[str]],
    facts: dict[str, dict[str, Any]],
    adjacencies: list[dict],
) -> list[Finding]:
    """Evaluate OSPF domain-wide consistency rules.

    ``ospf_domains`` (area-keyed) is retained for call-site stability but no
    longer drives the consistency checks: reference-bandwidth and SPF-timer
    consistency is now partitioned by OSPF domain = VRF (derived from the model
    adjacencies' resolved ``vrf``), so separate VRFs are never compared and a
    multi-process device contributes the value for the domain's own process.
    """
    findings: list[Finding] = []
    findings.extend(_check_router_id_duplicate(adjacencies))
    findings.extend(_check_reference_bandwidth(adjacencies, facts))
    findings.extend(_check_spf_timer_inconsistent(adjacencies, facts))
    return findings


def _ospf_domains_by_vrf(adjacencies: list[dict]) -> dict[str, list[str]]:
    """VRF -> sorted devices sharing an OSPF adjacency in that VRF.

    Each VRF's OSPF instance is a separate domain; reference-bandwidth / SPF
    timers must be consistent within a domain, not across the whole network.
    """
    domains: dict[str, set[str]] = {}
    for adj in adjacencies:
        if adj.get("protocol") != "ospf":
            continue
        vrf = adj.get("vrf", "default")
        for dev_key in ("device_a", "device_b"):
            dev = adj.get(dev_key)
            if dev:
                domains.setdefault(vrf, set()).add(dev)
    return {vrf: sorted(devs) for vrf, devs in domains.items()}


def _check_router_id_duplicate(
    adjacencies: list[dict],
) -> list[Finding]:
    """Check for duplicate OSPF router-IDs within an OSPF domain (per VRF).

    Reads the model adjacencies' VRF-resolved router-ids (``router_id_a/b`` +
    ``vrf``). A router-ID must be unique within an OSPF domain, but the same id
    legitimately recurs across VRFs (separate domains).

    Do NOT re-derive from genie here: genie stores every process's router-id
    under the ``default`` VRF block regardless of the process's real VRF, so
    genie-derived ``(vrf, rid)`` keys all collapse to ``default`` and would
    false-positive legitimate cross-VRF reuse. The model already resolves the
    real per-VRF router-id (R1 Phase 2 / O1).
    """
    findings: list[Finding] = []

    # {(vrf, router_id): {hostname, ...}}
    rid_map: dict[tuple[str, str], set[str]] = {}
    for adj in adjacencies:
        if adj.get("protocol") != "ospf":
            continue
        vrf = adj.get("vrf", "default")
        for dev_key, rid_key in (("device_a", "router_id_a"), ("device_b", "router_id_b")):
            dev, rid = adj.get(dev_key), adj.get(rid_key)
            if dev and rid:
                rid_map.setdefault((vrf, rid), set()).add(dev)

    for (vrf, rid), hosts in sorted(rid_map.items()):
        if len(hosts) > 1:
            host_list = sorted(hosts)
            vrf_label = "" if vrf == "default" else f" (VRF {vrf})"
            findings.append(make_finding(
                rule_id="OSPF_ROUTER_ID_DUPLICATE",
                severity="critical",
                title="Duplicate OSPF Router-ID",
                element_type="device",
                element_id=f"ospf::rid_dup::{vrf}::{rid}",
                message=(
                    f"OSPF router-ID {rid}{vrf_label} is used by {len(host_list)} "
                    f"devices: {', '.join(host_list)}. LSDB corruption will occur."
                ),
                key_facts={
                    "devices": host_list,
                    "router_id": rid,
                    "vrf": vrf,
                },
                recommendation=(
                    "Assign unique OSPF router-IDs. Use loopback addresses."
                ),
            ))

    return findings


def _check_reference_bandwidth(
    adjacencies: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Inconsistent OSPF reference bandwidth — checked per VRF domain.

    Reference-bandwidth must match within an OSPF domain; different VRFs are
    separate domains and may legitimately differ, so the comparison is scoped
    per VRF (not network-wide). Each device contributes its value for that
    domain's process via the genie-quirk-aware extractor.
    """
    findings: list[Finding] = []

    for vrf, devices in sorted(_ospf_domains_by_vrf(adjacencies).items()):
        by_bw: dict[int, list[str]] = {}
        for hostname in devices:
            ospf = facts.get(hostname, {}).get("genie_ospf")
            if not ospf:
                continue
            bw = extract_reference_bandwidth_by_vrf(ospf).get(vrf)
            if bw is not None:
                by_bw.setdefault(bw, []).append(hostname)

        if len(by_bw) > 1:
            details = ", ".join(
                f"{', '.join(hosts)}={bw}" for bw, hosts in sorted(by_bw.items())
            )
            all_hosts = sorted(h for hosts in by_bw.values() for h in hosts)
            vrf_label = "" if vrf == "default" else f" (VRF {vrf})"
            findings.append(make_finding(
                rule_id="OSPF_REFERENCE_BANDWIDTH_INCONSISTENT",
                severity="low",
                title="OSPF Reference Bandwidth Inconsistent",
                element_type="device",
                element_id=f"ospf::ref_bw_inconsistent::{vrf}",
                message=(
                    f"OSPF auto-cost reference bandwidth differs across devices"
                    f"{vrf_label}: {details}. Metric calculation will be inconsistent."
                ),
                key_facts={
                    "devices": all_hosts,
                    "vrf": vrf,
                    "bandwidth_values": {str(bw): hosts for bw, hosts in by_bw.items()},
                },
                recommendation=(
                    "Configure 'auto-cost reference-bandwidth' consistently "
                    "across all OSPF routers in the domain."
                ),
            ))

    return findings


def _check_spf_timer_inconsistent(
    adjacencies: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Inconsistent SPF throttle timers — checked per VRF domain.

    Same per-VRF-domain scoping rationale as :func:`_check_reference_bandwidth`.
    """
    findings: list[Finding] = []

    for vrf, devices in sorted(_ospf_domains_by_vrf(adjacencies).items()):
        by_config: dict[str, list[str]] = {}
        for hostname in devices:
            ospf = facts.get(hostname, {}).get("genie_ospf")
            if not ospf:
                continue
            timers = extract_ospf_spf_timers_by_vrf(ospf).get(vrf)
            if timers:
                by_config.setdefault(str(timers), []).append(hostname)

        if len(by_config) > 1:
            all_hosts = sorted(h for hosts in by_config.values() for h in hosts)
            vrf_label = "" if vrf == "default" else f" (VRF {vrf})"
            findings.append(make_finding(
                rule_id="OSPF_SPF_TIMER_INCONSISTENT",
                severity="info",
                title="OSPF SPF Timer Inconsistent",
                element_type="device",
                element_id=f"ospf::spf_timer_inconsistent::{vrf}",
                message=(
                    f"OSPF SPF throttle timers differ across "
                    f"{len(all_hosts)} devices{vrf_label}."
                ),
                key_facts={
                    "devices": all_hosts,
                    "vrf": vrf,
                    "timer_groups": by_config,
                },
                recommendation=(
                    "Configure consistent SPF throttle timers across "
                    "all OSPF routers in the domain."
                ),
            ))

    return findings


# =========================================================================
# Adjacency rules — OSPF adjacency state analysis
# =========================================================================

def evaluate_adjacency(
    adjacencies: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Evaluate OSPF adjacency-based rules."""
    findings: list[Finding] = []
    findings.extend(_check_adjacency_asymmetric(adjacencies, facts))
    findings.extend(_check_area_single_abr(adjacencies))
    return findings


def _check_adjacency_asymmetric(
    adjacencies: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """
    Flag OSPF adjacencies where bilateral=False (one side doesn't see
    the adjacency) but peer_collected=True.
    """
    findings: list[Finding] = []

    for adj in adjacencies:
        if adj.get("protocol") != "ospf":
            continue
        if not adj.get("peer_collected", False):
            continue
        if adj.get("bilateral", True):
            continue  # Both sides agree — OK

        dev_a = adj.get("device_a", "")
        dev_b = adj.get("device_b", "")
        intf_a = adj.get("interface_a", "")
        intf_b = adj.get("interface_b", "")

        # The side whose interface is unknown didn't report this adjacency. If we
        # never collected that side's OSPF at all (e.g. a FortiGate — OSPF is not
        # exposed via our REST endpoints), the missing reverse observation is a
        # COLLECTION gap, not an asymmetry. Don't flag a healthy adjacency as a
        # misconfiguration. (A peer that DID expose OSPF but doesn't see us still
        # fires — that is a real asymmetry.)
        missing = dev_b if not intf_b else (dev_a if not intf_a else None)
        if missing and not facts.get(missing, {}).get("genie_ospf"):
            continue

        eid = make_bilateral_element_id(dev_a, intf_a, dev_b, intf_b)

        findings.append(make_finding(
            rule_id="OSPF_ADJACENCY_ASYMMETRIC",
            severity="critical",
            title="OSPF Adjacency Asymmetric",
            element_type="link",
            element_id=eid,
            message=(
                f"OSPF adjacency {dev_a}↔{dev_b} is asymmetric: "
                f"one side does not see the neighbor. State: {adj.get('state')}."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "state": adj.get("state"),
                "bilateral": False,
                "area": adj.get("area"),
            },
            recommendation=(
                "Check hello/dead timers, authentication, and MTU "
                "on both endpoints."
            ),
        ))

    return findings


def _check_area_single_abr(
    adjacencies: list[dict],
) -> list[Finding]:
    """
    Flag OSPF areas that have only a single ABR (no redundancy).

    An ABR is a device that appears in both the non-backbone area
    and area 0.0.0.0 in the adjacency data.
    """
    findings: list[Finding] = []

    # Build: {(vrf, area_id): set of devices}. Areas are per-VRF — a non-backbone
    # area 1 in VRF RED is a different OSPF domain from area 1 in VRF BLUE — so key
    # by VRF to avoid merging separate domains and miscounting ABRs. (R1 O1 — same
    # genie/VRF class as the router-id duplicate fix; reads the model adjacency vrf.)
    area_devices: dict[tuple[str, str], set[str]] = {}
    for adj in adjacencies:
        if adj.get("protocol") != "ospf":
            continue
        area = adj.get("area", "")
        if not area:
            continue
        vrf = adj.get("vrf", "default")
        area_devices.setdefault((vrf, area), set()).add(adj.get("device_a", ""))
        area_devices.setdefault((vrf, area), set()).add(adj.get("device_b", ""))

    # For non-backbone areas, count devices that also appear in area 0 of the SAME VRF.
    for (vrf, area_id), devices in sorted(area_devices.items()):
        if area_id == "0.0.0.0":
            continue

        backbone_devices = area_devices.get((vrf, "0.0.0.0"), set())
        abrs = devices & backbone_devices
        if len(abrs) == 1:
            abr = sorted(abrs)[0]
            vrf_label = "" if vrf == "default" else f" (VRF {vrf})"
            findings.append(make_finding(
                rule_id="OSPF_AREA_SINGLE_ABR",
                severity="low",
                title="OSPF Area — Single ABR",
                element_type="device",
                element_id=f"ospf::area_{vrf}_{area_id}::single_abr",
                message=(
                    f"OSPF area {area_id}{vrf_label} has only 1 ABR ({abr}). "
                    f"If it fails, the area loses backbone connectivity."
                ),
                key_facts={
                    "area": area_id,
                    "vrf": vrf,
                    "abr": abr,
                    "area_devices": sorted(devices),
                },
                recommendation=(
                    "Deploy a second ABR for area redundancy."
                ),
            ))

    return findings


# =========================================================================
# Internal helpers
# =========================================================================

def _check_param(
    findings: list[Finding],
    ifa: dict,
    ifb: dict,
    param_name: str,
    rule_id: str,
    severity: str,
    title: str,
    dev_a: str,
    raw_a: str,
    dev_b: str,
    raw_b: str,
    eid: str,
    impact: str,
    recommendation: str,
) -> None:
    """Compare a single OSPF interface parameter and emit finding if mismatched."""
    val_a = ifa.get(param_name)
    val_b = ifb.get(param_name)
    if val_a is None or val_b is None:
        return
    if val_a != val_b:
        findings.append(make_finding(
            rule_id=rule_id,
            severity=severity,
            title=title,
            element_type="link",
            element_id=eid,
            message=(
                f"{param_name.replace('_', ' ').title()} mismatch on link "
                f"{dev_a}:{raw_a} ({val_a}) vs {dev_b}:{raw_b} ({val_b}). "
                f"{impact}"
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                f"dev_a_{param_name}": val_a,
                f"dev_b_{param_name}": val_b,
            },
            recommendation=recommendation,
        ))


def _get_intf_mtu(device_facts: dict, intf_name: str) -> int | None:
    """Get interface MTU from genie_interface data."""
    intf_data = device_facts.get("genie_interface", {})
    intf = intf_data.get(intf_name, {})
    return intf.get("mtu")


def _get_stub_flag(ospf_data: dict, area_id: str) -> bool | None:
    """Check if an OSPF area is configured as stub/NSSA."""
    for _vrf, vrf_data in ospf_data.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for _pid, pdata in instances.items():
            area = pdata.get("areas", {}).get(area_id)
            if area is None:
                continue
            # Check for stub or nssa configuration
            area_type = area.get("area_type", "normal")
            if area_type in ("stub", "nssa"):
                return True
            return False
    return None
