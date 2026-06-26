"""
Interface Cross-Device Rules — .

9 rules comparing L1/L2 interface parameters between connected devices.

Bilateral rules use topology links to find connected interface pairs.
Topology rules compare VLAN/STP consistency across the domain.

Rule IDs:
    INTF_MTU_MISMATCH, INTF_DUPLEX_MISMATCH, INTF_SPEED_MISMATCH,
    LLDP_TOPOLOGY_MISMATCH, VLAN_NATIVE_MISMATCH, VLAN_ALLOWED_MISMATCH,
    VLAN_CONSISTENCY, LAG_MEMBER_COUNT_MISMATCH, STP_ROOT_BRIDGE_CONFLICT
"""

from typing import Any

from netcopilot.model.interface_normalizer import canonicalize
from netcopilot.rules.cross_device.helpers import (
    find_interface_facts,
    make_bilateral_element_id,
    make_finding,
    normalize_ip_mtu,
    parse_interface_from_id,
    select_best_links_per_pair,
)
from netcopilot.rules.finding import Finding

# All rule IDs exported for evaluator registration
RULE_IDS = [
    "INTF_MTU_MISMATCH",
    "INTF_DUPLEX_MISMATCH",
    "INTF_SPEED_MISMATCH",
    "LLDP_TOPOLOGY_MISMATCH",
    "VLAN_NATIVE_MISMATCH",
    "VLAN_ALLOWED_MISMATCH",
    "VLAN_CONSISTENCY",
    "LAG_MEMBER_COUNT_MISMATCH",
    "STP_ROOT_BRIDGE_CONFLICT",
    "VLAN_FRAGMENTED",
]

# =========================================================================
# Bilateral rules — compare parameters on connected interfaces
# =========================================================================

def evaluate_bilateral(
    links: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Evaluate all bilateral interface rules across topology links."""
    findings: list[Finding] = []
    filtered_links = select_best_links_per_pair(links)

    for link in filtered_links:

        dev_a = link.get("local_device_id", "")
        dev_b = link.get("remote_device_id", "")

        if dev_a not in facts or dev_b not in facts:
            continue

        facts_a = facts[dev_a]
        facts_b = facts[dev_b]

        # Both sides need interface data
        intf_data_a = facts_a.get("genie_interface", {})
        intf_data_b = facts_b.get("genie_interface", {})
        if not intf_data_a or not intf_data_b:
            continue

        # Extract and canonicalize interface names
        _, raw_a = parse_interface_from_id(
            link.get("local_interface_id", "")
        )
        _, raw_b = parse_interface_from_id(
            link.get("remote_interface_id", "")
        )
        intf_a = canonicalize(raw_a) or raw_a
        intf_b = canonicalize(raw_b) or raw_b

        ifa = find_interface_facts(intf_data_a, intf_a)
        ifb = find_interface_facts(intf_data_b, intf_b)

        if ifa is None or ifb is None:
            continue

        eid = make_bilateral_element_id(dev_a, raw_a, dev_b, raw_b)

        # --- MTU mismatch ---
        findings.extend(_check_mtu(dev_a, raw_a, ifa, facts_a, dev_b, raw_b, ifb, facts_b, eid))

        # --- Duplex mismatch ---
        findings.extend(
            _check_duplex(dev_a, raw_a, ifa, dev_b, raw_b, ifb, eid)
        )

        # --- Speed mismatch ---
        findings.extend(
            _check_speed(dev_a, raw_a, ifa, dev_b, raw_b, ifb, eid)
        )

        # --- LLDP topology mismatch ---
        findings.extend(
            _check_lldp(
                dev_a, raw_a, intf_a, facts_a,
                dev_b, raw_b, intf_b, facts_b,
                eid,
            )
        )

        # --- VLAN native mismatch ---
        findings.extend(
            _check_vlan_native(dev_a, raw_a, ifa, dev_b, raw_b, ifb, eid)
        )

        # --- VLAN allowed mismatch ---
        findings.extend(
            _check_vlan_allowed(dev_a, raw_a, ifa, dev_b, raw_b, ifb, eid)
        )

        # --- LAG member count mismatch ---
        findings.extend(
            _check_lag_members(
                dev_a, raw_a, intf_a, facts_a,
                dev_b, raw_b, intf_b, facts_b,
                eid,
            )
        )

    return findings


# =========================================================================
# Topology rules — domain-wide consistency
# =========================================================================

def evaluate_topology(
    shared_services: list[dict],
    links: list[dict],
    facts: dict[str, dict[str, Any]],
    l2_domains: list[dict] | None = None,
) -> list[Finding]:
    """Evaluate topology-level interface rules."""
    findings: list[Finding] = []
    findings.extend(_check_vlan_consistency(facts, l2_domains, shared_services))
    findings.extend(_check_stp_root_conflict(facts, l2_domains))
    findings.extend(_check_vlan_fragmented(l2_domains))
    return findings


# =========================================================================
# Bilateral check implementations
# =========================================================================

def _check_mtu(
    dev_a: str, raw_a: str, ifa: dict, facts_a: dict,
    dev_b: str, raw_b: str, ifb: dict, facts_b: dict,
    eid: str,
) -> list[Finding]:
    # Compare IP MTU, not raw interface MTU: IOS XR reports the L2 MTU (which
    # includes the 14-byte Ethernet header — default 1514) while IOS XE reports
    # the IP MTU (default 1500). Normalize both to IP MTU, then ignore any
    # remaining difference of <= 14 bytes: that is exactly the L2-header
    # convention-ambiguity zone (XR L2 vs XE IP, and the jumbo case where XE
    # may report the L2 MTU too), and is operationally benign. Only a
    # difference larger than the header (e.g. 1500 vs 9000) is an unambiguous,
    # real MTU mismatch worth flagging.
    mtu_a = normalize_ip_mtu(facts_a, ifa.get("mtu"))
    mtu_b = normalize_ip_mtu(facts_b, ifb.get("mtu"))
    if mtu_a is None or mtu_b is None:
        return []
    mtu_diff = abs(int(mtu_a) - int(mtu_b))
    if mtu_diff <= 14:
        return []

    # Determine severity based on operational state.
    both_up = (
        ifa.get("oper_status", "").lower() == "up"
        and ifb.get("oper_status", "").lower() == "up"
    )

    if not both_up:
        severity = "critical"  # may be causing the outage
    else:
        severity = "high"  # working link but risk of packet drops

    return [make_finding(
        rule_id="INTF_MTU_MISMATCH",
        severity=severity,
        title="Interface MTU Mismatch",
        element_type="link",
        element_id=eid,
        message=(
            f"MTU mismatch on link {dev_a}:{raw_a} ({mtu_a}) "
            f"vs {dev_b}:{raw_b} ({mtu_b}). "
            f"May cause packet drops or OSPF/BGP adjacency issues."
        ),
        key_facts={
            "devices": [dev_a, dev_b],
            "dev_a_mtu": mtu_a,
            "dev_b_mtu": mtu_b,
        },
        recommendation=(
            "Configure matching MTU values on both endpoints. "
            "Standard: 1500 for access, 9216 for core/fabric."
        ),
    )]


def _check_duplex(
    dev_a: str, raw_a: str, ifa: dict,
    dev_b: str, raw_b: str, ifb: dict,
    eid: str,
) -> list[Finding]:
    dup_a = ifa.get("duplex_mode")
    dup_b = ifb.get("duplex_mode")
    if not dup_a or not dup_b:
        return []
    if dup_a != dup_b:
        # If both interfaces are operationally up, auto-negotiation handled
        # it — lower severity to informational.
        both_up = (
            ifa.get("oper_status", "").lower() == "up"
            and ifb.get("oper_status", "").lower() == "up"
        )
        severity = "info" if both_up else "critical"
        return [make_finding(
            rule_id="INTF_DUPLEX_MISMATCH",
            severity=severity,
            title="Interface Duplex Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"Duplex mismatch on link {dev_a}:{raw_a} ({dup_a}) "
                f"vs {dev_b}:{raw_b} ({dup_b}). "
                f"Causes late collisions and poor performance."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_duplex": dup_a,
                "dev_b_duplex": dup_b,
            },
            recommendation="Configure matching duplex mode on both endpoints.",
        )]
    return []


def _normalize_speed(speed: str) -> int | None:
    """Normalize speed string to Mbps integer for comparison.

    Handles: "1000mbps", "1000Mb/s", "100gb/s", "10000Mb/s", "10000000" (kbit/s).
    """
    if speed is None:
        return None
    s = str(speed).strip().lower().replace(",", "")
    # "100gb/s" or "100gbps"
    if "gb" in s:
        try:
            num = int("".join(c for c in s.split("gb")[0] if c.isdigit()))
            return num * 1000
        except (ValueError, IndexError):
            pass
    # "1000mb/s" or "1000mbps"
    if "mb" in s:
        try:
            return int("".join(c for c in s.split("mb")[0] if c.isdigit()))
        except (ValueError, IndexError):
            pass
    # Pure numeric — assume kbit/s (Genie bandwidth) if large enough.
    # Genie bandwidth is always kbit/s: 1000000 = 1G, 100000000 = 100G.
    # Genie port_speed is sometimes plain Mbps: 1000 = 1G.
    try:
        val = int(s)
        if val >= 1_000_000:  # kbit/s → Mbps
            return val // 1000
        return val  # already Mbps (e.g., port_speed "1000")
    except ValueError:
        return None


def _check_speed(
    dev_a: str, raw_a: str, ifa: dict,
    dev_b: str, raw_b: str, ifb: dict,
    eid: str,
) -> list[Finding]:
    # Speed may be in port_speed or bandwidth
    speed_a = ifa.get("port_speed") or ifa.get("bandwidth")
    speed_b = ifb.get("port_speed") or ifb.get("bandwidth")
    if speed_a is None or speed_b is None:
        return []
    norm_a = _normalize_speed(speed_a)
    norm_b = _normalize_speed(speed_b)
    # If normalization succeeds, compare numeric; otherwise fall back to string
    if norm_a is not None and norm_b is not None:
        mismatch = norm_a != norm_b
    else:
        mismatch = str(speed_a).lower() != str(speed_b).lower()
    if mismatch:
        # If both interfaces are operationally up, auto-negotiation handled
        # it — lower severity to informational.
        both_up = (
            ifa.get("oper_status", "").lower() == "up"
            and ifb.get("oper_status", "").lower() == "up"
        )
        severity = "info" if both_up else "low"
        return [make_finding(
            rule_id="INTF_SPEED_MISMATCH",
            severity=severity,
            title="Interface Speed Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"Speed mismatch on link {dev_a}:{raw_a} ({speed_a}) "
                f"vs {dev_b}:{raw_b} ({speed_b})."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_speed": speed_a,
                "dev_b_speed": speed_b,
            },
            recommendation="Configure matching speed on both endpoints.",
        )]
    return []


def _check_lldp(
    dev_a: str, raw_a: str, intf_a: str, facts_a: dict,
    dev_b: str, raw_b: str, intf_b: str, facts_b: dict,
    eid: str,
) -> list[Finding]:
    """Check if LLDP neighbor data matches the topology link."""
    lldp_a = facts_a.get("genie_lldp", {}).get("interfaces", {})
    if not lldp_a:
        return []

    lldp_intf = lldp_a.get(intf_a, {})
    if not lldp_intf:
        return []

    # LLDP neighbors for this interface
    neighbors = lldp_intf.get("neighbors", {})
    if not neighbors:
        return []

    # Check if any LLDP neighbor matches the expected peer
    for _nbr_name, nbr_data in neighbors.items():
        # Compare port_id or chassis_id with expected peer
        port_id = nbr_data.get("port_id", "")
        chassis_id = nbr_data.get("chassis_id", "")
        system_name = nbr_data.get("system_name", "")

        # If LLDP system_name matches dev_b and port_id matches intf_b
        if system_name and system_name != dev_b:
            return [make_finding(
                rule_id="LLDP_TOPOLOGY_MISMATCH",
                severity="low",
                title="LLDP Topology Mismatch",
                element_type="link",
                element_id=eid,
                message=(
                    f"LLDP on {dev_a}:{raw_a} sees {system_name} "
                    f"but topology model expects {dev_b}. "
                    f"Possible cabling error or stale LLDP data."
                ),
                key_facts={
                    "devices": [dev_a, dev_b],
                    "lldp_system_name": system_name,
                    "lldp_port_id": port_id,
                    "expected_peer": dev_b,
                },
                recommendation=(
                    "Verify physical cabling matches topology documentation."
                ),
            )]

    return []


def _check_vlan_native(
    dev_a: str, raw_a: str, ifa: dict,
    dev_b: str, raw_b: str, ifb: dict,
    eid: str,
) -> list[Finding]:
    """Check native VLAN mismatch on trunk links."""
    native_a = ifa.get("native_vlan")
    native_b = ifb.get("native_vlan")
    if native_a is None or native_b is None:
        return []
    if native_a != native_b:
        return [make_finding(
            rule_id="VLAN_NATIVE_MISMATCH",
            severity="critical",
            title="Native VLAN Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"Native VLAN mismatch on trunk {dev_a}:{raw_a} "
                f"(VLAN {native_a}) vs {dev_b}:{raw_b} (VLAN {native_b}). "
                f"Untagged traffic will be placed in different VLANs."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_native": native_a,
                "dev_b_native": native_b,
            },
            recommendation="Configure matching native VLAN on both trunk endpoints.",
        )]
    return []


def _check_vlan_allowed(
    dev_a: str, raw_a: str, ifa: dict,
    dev_b: str, raw_b: str, ifb: dict,
    eid: str,
) -> list[Finding]:
    """Check allowed VLAN list mismatch on trunk links."""
    allowed_a = ifa.get("trunk_vlans")
    allowed_b = ifb.get("trunk_vlans")
    if not allowed_a or not allowed_b:
        return []

    # Parse VLAN ranges into sets for comparison
    set_a = _parse_vlan_range(str(allowed_a))
    set_b = _parse_vlan_range(str(allowed_b))

    if set_a and set_b and set_a != set_b:
        only_a = set_a - set_b
        only_b = set_b - set_a
        return [make_finding(
            rule_id="VLAN_ALLOWED_MISMATCH",
            severity="low",
            title="Allowed VLAN List Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"Allowed VLAN mismatch on trunk {dev_a}:{raw_a} "
                f"vs {dev_b}:{raw_b}. "
                f"Only on {dev_a}: {_format_vlans(only_a)}. "
                f"Only on {dev_b}: {_format_vlans(only_b)}."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_vlans": str(allowed_a),
                "dev_b_vlans": str(allowed_b),
            },
            recommendation=(
                "Ensure allowed VLAN lists match on both trunk endpoints "
                "to avoid connectivity gaps."
            ),
        )]
    return []


def _check_lag_members(
    dev_a: str, raw_a: str, intf_a: str, facts_a: dict,
    dev_b: str, raw_b: str, intf_b: str, facts_b: dict,
    eid: str,
) -> list[Finding]:
    """Check if LAG member counts match on connected port-channels."""
    lag_a = facts_a.get("parsed_lag", {}).get("interfaces", {})
    lag_b = facts_b.get("parsed_lag", {}).get("interfaces", {})
    if not lag_a or not lag_b:
        return []

    # Find the port-channel matching our interface
    po_a = _find_lag_for_interface(lag_a, intf_a)
    po_b = _find_lag_for_interface(lag_b, intf_b)

    if po_a is None or po_b is None:
        return []

    members_a = len(po_a.get("members", {}))
    members_b = len(po_b.get("members", {}))

    if members_a != members_b:
        return [make_finding(
            rule_id="LAG_MEMBER_COUNT_MISMATCH",
            severity="low",
            title="LAG Member Count Mismatch",
            element_type="link",
            element_id=eid,
            message=(
                f"LAG member count mismatch on {dev_a}:{raw_a} "
                f"({members_a} members) vs {dev_b}:{raw_b} "
                f"({members_b} members). May indicate failed links."
            ),
            key_facts={
                "devices": [dev_a, dev_b],
                "dev_a_members": members_a,
                "dev_b_members": members_b,
            },
            recommendation=(
                "Investigate member link status. Both sides of a LAG "
                "should have matching member counts."
            ),
        )]
    return []


# =========================================================================
# Topology check implementations
# =========================================================================

def _check_vlan_consistency(
    facts: dict[str, dict[str, Any]],
    l2_domains: list[dict] | None = None,
    shared_services: list[dict] | None = None,
) -> list[Finding]:
    """
    Check VLAN consistency within each L2 broadcast domain.

    Flags switches that participate in a VLAN's broadcast domain (an access or
    trunk port carrying it) but are missing the VLAN from their VLAN database —
    a real black-holing risk. Scoping to ``l2_domains`` (connectivity-based)
    instead of the ID-based ``shared_services`` removes the false positive where
    a router merely shares the VLAN's *subnet* (no L2 port) and so legitimately
    has no VLAN-database entry.

    When ``l2_domains`` is None (caller did not thread it), falls back to the
    legacy ``shared_services`` membership so older callers keep their behaviour.
    """
    findings: list[Finding] = []

    # Membership source: each broadcast domain, or legacy shared-services VLANs.
    if l2_domains is not None:
        groups = [
            (str(d["vlan_id"]), d.get("name") or "", d["id"], d["member_devices"])
            for d in l2_domains
        ]
    else:
        groups = [
            (str(s.get("identifier", "")), s.get("name") or "",
             f"vlan_{s.get('identifier', '')}", s.get("members", []))
            for s in (shared_services or [])
            if s.get("service_type") == "vlan"
        ]

    for vlan_id, vlan_name, scope_id, members in groups:
        if len(members) < 2:
            continue

        # Members that participate in the domain but lack the VLAN in their DB.
        missing_members = []
        for member in members:
            if member not in facts:
                continue
            vlan_data = facts[member].get("genie_vlan", {}).get("vlans", {})
            if not vlan_data:
                continue  # No VLAN data at all — skip
            if vlan_id not in vlan_data:
                missing_members.append(member)

        if missing_members:
            findings.append(make_finding(
                rule_id="VLAN_CONSISTENCY",
                severity="low",
                title="VLAN Consistency Issue",
                element_type="device",
                element_id=f"{scope_id}::missing",
                message=(
                    f"VLAN {vlan_id} ({vlan_name}) is shared across "
                    f"{len(members)} devices but missing from VLAN "
                    f"database on: {', '.join(sorted(missing_members))}."
                ),
                key_facts={
                    "vlan_id": vlan_id,
                    "vlan_name": vlan_name,
                    "expected_members": sorted(members),
                    "missing_from": sorted(missing_members),
                },
                recommendation=(
                    "Ensure VLAN is created on all switches that need it. "
                    "Missing VLANs cause traffic black-holing."
                ),
            ))

    return findings


def _check_vlan_fragmented(
    l2_domains: list[dict] | None = None,
) -> list[Finding]:
    """
    Flag a VLAN that exists as two or more SEPARATE L2 broadcast domains.

    A VLAN id is only a label; two switches' "VLAN N" are the same broadcast
    domain only when an L2 trunk carries N between them. When ``l2_domains``
    (connectivity-based) shows a single VLAN id as 2+ disconnected domains, the
    VLAN has fragmented into islands — hosts in different islands cannot reach
    each other at Layer 2. Usually a missing trunk allow-list entry; sometimes
    intentional VLAN-id reuse, hence ``low`` severity with a verify-intent note.
    """
    findings: list[Finding] = []

    by_vlan: dict[int, list[dict]] = {}
    for dom in l2_domains or []:
        by_vlan.setdefault(dom.get("vlan_id"), []).append(dom)

    for vlan_id, domains in sorted(by_vlan.items(), key=lambda kv: kv[0]):
        if len(domains) < 2:
            continue
        islands = sorted(
            sorted(d.get("member_devices") or []) for d in domains
        )
        island_strs = "; ".join("{" + ", ".join(i) + "}" for i in islands)
        all_devices = sorted({dev for i in islands for dev in i})
        findings.append(make_finding(
            rule_id="VLAN_FRAGMENTED",
            severity="high",
            title="VLAN Fragmented Across Broadcast Domains",
            element_type="device",
            element_id=f"vlan_fragmented::{vlan_id}",
            message=(
                f"VLAN {vlan_id} forms {len(domains)} separate L2 broadcast "
                f"domains: {island_strs}. Hosts in different domains cannot "
                f"communicate at Layer 2 — verify this is intentional "
                f"(VLAN-id reuse) rather than a missing trunk."
            ),
            key_facts={
                "vlan_id": str(vlan_id),
                "domain_count": len(domains),
                "devices": all_devices,   # loader attaches the finding to these
                "domains": islands,
            },
            recommendation=(
                "If the VLAN should be one segment, add it to the trunk(s) "
                "linking the islands. If the reuse is intentional, no action."
            ),
        ))

    return findings


def _check_stp_root_conflict(
    facts: dict[str, dict[str, Any]],
    l2_domains: list[dict] | None = None,
) -> list[Finding]:
    """
    Check for STP root bridge conflicts — multiple devices claiming root
    for the same VLAN with the same priority **within one L2 broadcast
    domain**.

    Root election only contends among switches in the *same* broadcast domain.
    Two switches that both carry a VLAN but are routed (not L2-bridged) between
    each other are separate spanning trees — each legitimately its own root, NOT
    a conflict. ``l2_domains`` (connectivity-based, ``model["l2_domains"]``)
    partitions the claimants so we only flag a genuine same-domain contest.

    When ``l2_domains`` is None (caller did not thread it) the legacy global
    grouping is used, so older callers keep their behaviour.
    """
    findings: list[Finding] = []

    # Collect: {vlan_id: [(hostname, bridge_priority, bridge_address), ...]}
    vlan_roots: dict[str, list[tuple[str, int, str]]] = {}

    for hostname, device_facts in facts.items():
        stp_data = device_facts.get("genie_stp", {})
        # Check rapid_pvst first (most common)
        for mode in ("rapid_pvst", "mstp"):
            mode_data = stp_data.get(mode, {})
            if not isinstance(mode_data, dict):
                continue
            for _scope, scope_data in mode_data.items():
                if not isinstance(scope_data, dict):
                    continue
                for vid, vlan_stp in scope_data.get("vlans", {}).items():
                    priority = vlan_stp.get("bridge_priority")
                    address = vlan_stp.get("bridge_address", "")
                    root_priority = vlan_stp.get("designated_root_priority")
                    root_address = vlan_stp.get("designated_root_address", "")

                    if priority is not None:
                        # A device is root if its bridge matches designated root
                        is_root = (
                            address == root_address
                            and priority is not None
                            and root_priority is not None
                        )
                        if is_root:
                            vlan_roots.setdefault(vid, []).append(
                                (hostname, priority, address)
                            )

    # Index L2 broadcast domains by VLAN id -> list of member-device sets.
    domains_by_vlan: dict[str, list[set[str]]] = {}
    for dom in l2_domains or []:
        domains_by_vlan.setdefault(str(dom.get("vlan_id")), []).append(
            set(dom.get("member_devices") or [])
        )

    # Flag VLANs with multiple roots at same priority, partitioned by domain.
    for vid, roots in vlan_roots.items():
        if len(roots) < 2:
            continue

        # Partition the root claimants into the L2 broadcast domains they
        # actually belong to. With l2_domains available, a claimant outside
        # every domain for this VLAN cannot contend with anyone (its own tree).
        if l2_domains is None:
            claimant_groups = [roots]                       # legacy: one global group
        else:
            claimant_groups = [
                [r for r in roots if r[0] in members]
                for members in domains_by_vlan.get(vid, [])
            ]

        for group in claimant_groups:
            if len(group) < 2:
                continue
            # Check if multiple devices have the same priority
            priorities = {r[1] for r in group}
            if len(priorities) != 1:
                continue
            # Same priority on multiple root bridges in one domain — conflict
            hostnames = sorted(r[0] for r in group)
            priority = group[0][1]
            # VLAN 1 with default priority is low — typically unused
            sev = "info" if vid == "1" and priority == 32768 else "low"
            findings.append(make_finding(
                rule_id="STP_ROOT_BRIDGE_CONFLICT",
                severity=sev,
                title="STP Root Bridge Conflict",
                element_type="device",
                element_id=f"stp_vlan_{vid}::root_conflict",
                message=(
                    f"VLAN {vid}: multiple devices claim STP root with "
                    f"same priority {priority}: {', '.join(hostnames)}. "
                    f"Root election depends on MAC address — may be "
                    f"non-deterministic."
                ),
                key_facts={
                    "vlan_id": vid,
                    "devices": hostnames,
                    "bridge_priority": priority,
                },
                recommendation=(
                    "Configure explicit STP root priority on the intended "
                    "root bridge (lower priority wins)."
                ),
            ))

    return findings


# =========================================================================
# Utility helpers
# =========================================================================

def _parse_vlan_range(vlan_str: str) -> set[int]:
    """Parse a VLAN range string like '1-100,200,300-400' into a set."""
    result: set[int] = set()
    if not vlan_str or vlan_str.lower() in ("all", "none"):
        return result
    for part in vlan_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for v in range(int(start), int(end) + 1):
                    result.add(v)
            except (ValueError, OverflowError):
                continue
        else:
            try:
                result.add(int(part))
            except ValueError:
                continue
    return result


def _format_vlans(vlans: set[int]) -> str:
    """Format a set of VLAN IDs into a compact string."""
    if not vlans:
        return "none"
    sorted_vlans = sorted(vlans)
    if len(sorted_vlans) <= 5:
        return str(sorted_vlans)
    return f"{sorted_vlans[:3]}... ({len(sorted_vlans)} total)"


def _find_lag_for_interface(
    lag_data: dict,
    intf_name: str,
) -> dict | None:
    """Find the LAG (port-channel) containing or matching an interface."""
    canon = canonicalize(intf_name) or intf_name

    for po_name, po_data in lag_data.items():
        po_canon = canonicalize(po_name) or po_name
        if po_canon == canon:
            return po_data

        # Check if interface is a member of this LAG
        for member_name in po_data.get("members", {}):
            m_canon = canonicalize(member_name) or member_name
            if m_canon == canon:
                return po_data

    return None
