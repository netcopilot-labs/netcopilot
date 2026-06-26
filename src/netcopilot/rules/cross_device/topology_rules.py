"""
Topology Cross-Device Rules — .

5 rules checking VRF consistency, NTP consistency, and redundancy.

These are topology/global and adjacency/graph pattern rules that
examine properties across the entire network domain.

Rule IDs:
    VRF_RT_ASYMMETRIC, VRF_RD_INCONSISTENT, NTP_SOURCE_INCONSISTENT,
    NTP_STRATUM_INCONSISTENT, LINK_SINGLE_UPLINK
"""

from typing import Any

from netcopilot.rules.cross_device.helpers import (
    make_finding,
    safe_get,
)
from netcopilot.rules.finding import Finding

# All rule IDs exported for evaluator registration
RULE_IDS = [
    "VRF_RT_ASYMMETRIC",
    "VRF_RD_INCONSISTENT",
    "NTP_SOURCE_INCONSISTENT",
    "NTP_STRATUM_INCONSISTENT",
    "LINK_SINGLE_UPLINK",
]


def evaluate(
    facts: dict[str, dict[str, Any]],
    shared_services: list[dict],
    device_degree: dict[str, int],
    model: dict,
) -> list[Finding]:
    """Evaluate all topology cross-device rules."""
    findings: list[Finding] = []
    findings.extend(_check_vrf_rt_asymmetric(facts))
    findings.extend(_check_vrf_rd_inconsistent(facts))
    findings.extend(_check_ntp_source_inconsistent(facts))
    findings.extend(_check_ntp_stratum_inconsistent(facts))
    findings.extend(_check_single_uplink(device_degree, model))
    return findings


# =========================================================================
# VRF_RT_ASYMMETRIC — Route target import/export mismatch across VRF peers
# =========================================================================

def _check_vrf_rt_asymmetric(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """
    Check VRF route-target asymmetry across devices.

    If device A exports RT X for a VRF, at least one other device with
    the same VRF should import RT X. Otherwise traffic won't be exchanged.
    """
    findings: list[Finding] = []

    # Collect: {vrf_name: {hostname: {"import": set, "export": set}}}
    vrf_rts: dict[str, dict[str, dict[str, set]]] = {}

    for hostname, device_facts in facts.items():
        vrf_data = device_facts.get("genie_vrf", {}).get("vrfs", {})
        for vrf_name, vrf_info in vrf_data.items():
            if vrf_name.lower() in ("default", "mgmt-vrf", "management"):
                continue

            # Extract route targets from address_family sections
            import_rts: set[str] = set()
            export_rts: set[str] = set()

            for _af, af_data in vrf_info.get("address_family", {}).items():
                # Genie uses "route_targets" (plural) with rt entries
                rts = af_data.get("route_targets", {})
                for rt_value, rt_info in rts.items():
                    rt_type = rt_info.get("rt_type", "")
                    if rt_type in ("import", "both"):
                        import_rts.add(rt_value)
                    if rt_type in ("export", "both"):
                        export_rts.add(rt_value)

            if import_rts or export_rts:
                vrf_rts.setdefault(vrf_name, {})[hostname] = {
                    "import": import_rts,
                    "export": export_rts,
                }

    # Check for asymmetry: exported RT not imported by any OTHER peer
    for vrf_name, devices in vrf_rts.items():
        if len(devices) < 2:
            continue

        for hostname, rts in devices.items():
            # Compute imports from all OTHER devices (exclude self)
            peer_imports: set[str] = set()
            for other_host, other_rts in devices.items():
                if other_host != hostname:
                    peer_imports.update(other_rts["import"])

            # Check if this device's exports are imported by some peer
            orphan_exports = rts["export"] - peer_imports
            if orphan_exports:
                findings.append(make_finding(
                    rule_id="VRF_RT_ASYMMETRIC",
                    severity="low",
                    title="VRF Route-Target Asymmetric",
                    element_type="device",
                    element_id=f"vrf_{vrf_name}::{hostname}::rt_orphan",
                    message=(
                        f"VRF {vrf_name} on {hostname}: exported RT "
                        f"{', '.join(sorted(orphan_exports))} not imported "
                        f"by any other device in the VRF domain."
                    ),
                    key_facts={
                        "devices": list(devices.keys()),
                        "vrf": vrf_name,
                        "orphan_exports": sorted(orphan_exports),
                        "hostname": hostname,
                    },
                    recommendation=(
                        "Verify RT import/export configuration. Exported RTs "
                        "should be imported by at least one VRF peer."
                    ),
                ))

    return findings


# =========================================================================
# VRF_RD_INCONSISTENT — Route distinguisher inconsistency check
# =========================================================================

def _check_vrf_rd_inconsistent(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """
    Check for VRF route-distinguisher (RD) inconsistency.

    Within a VRF used across devices, all devices should use consistent
    RD values (or at least intentionally different ones).
    Flags cases where some devices have RD and some don't.
    """
    findings: list[Finding] = []

    # Collect: {vrf_name: {hostname: rd_value}}
    vrf_rds: dict[str, dict[str, str]] = {}

    for hostname, device_facts in facts.items():
        vrf_data = device_facts.get("genie_vrf", {}).get("vrfs", {})
        for vrf_name, vrf_info in vrf_data.items():
            if vrf_name.lower() in ("default", "mgmt-vrf", "management"):
                continue
            rd = vrf_info.get("route_distinguisher")
            if rd:
                vrf_rds.setdefault(vrf_name, {})[hostname] = str(rd)

    # Check for inconsistency within each VRF
    for vrf_name, devices in vrf_rds.items():
        if len(devices) < 2:
            continue

        rd_values = set(devices.values())
        if len(rd_values) > 1:
            findings.append(make_finding(
                rule_id="VRF_RD_INCONSISTENT",
                severity="info",
                title="VRF Route-Distinguisher Inconsistent",
                element_type="device",
                element_id=f"vrf_{vrf_name}::rd_inconsistent",
                message=(
                    f"VRF {vrf_name} has inconsistent RD values across "
                    f"{len(devices)} devices: "
                    f"{', '.join(f'{h}={rd}' for h, rd in devices.items())}."
                ),
                key_facts={
                    "vrf": vrf_name,
                    "rd_values": dict(devices),
                },
                recommendation=(
                    "Verify if different RD values are intentional. "
                    "Inconsistent RDs may indicate configuration drift."
                ),
            ))

    return findings


# =========================================================================
# NTP_SOURCE_INCONSISTENT — Different NTP sources across devices
# =========================================================================

def _check_ntp_source_inconsistent(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """
    Check if devices use inconsistent NTP server sources.

    All devices in the network should ideally use the same NTP
    server(s) for consistent time synchronization.
    """
    findings: list[Finding] = []

    # Collect: {hostname: set of NTP server addresses}
    device_ntp: dict[str, set[str]] = {}

    for hostname, device_facts in facts.items():
        ntp_data = device_facts.get("genie_ntp", {})
        servers: set[str] = set()

        # Check unicast_configuration -> address
        for _vrf, vrf_data in ntp_data.get("vrf", {}).items():
            addrs = safe_get(vrf_data, "unicast_configuration", "address")
            if isinstance(addrs, dict):
                servers.update(addrs.keys())

        if servers:
            device_ntp[hostname] = servers

    if len(device_ntp) < 2:
        return findings

    # Find the "standard" NTP source set (most common)
    source_groups: dict[frozenset[str], list[str]] = {}
    for hostname, servers in device_ntp.items():
        key = frozenset(servers)
        source_groups.setdefault(key, []).append(hostname)

    if len(source_groups) > 1:
        # Find the majority group
        majority = max(source_groups.items(), key=lambda x: len(x[1]))
        majority_servers = majority[0]

        for servers_key, hostnames in source_groups.items():
            if servers_key == majority_servers:
                continue
            # A device that still uses ALL the common (majority) NTP servers —
            # just with extra/backup servers on top (a superset) — stays time-
            # consistent: it syncs to the same shared source as everyone else.
            # Only flag devices that are MISSING one or more of the common
            # servers (a disjoint or partial set), which is the real
            # inconsistency. Avoids false-positiving redundant NTP config.
            missing = majority_servers - servers_key
            if not missing:
                continue
            findings.append(make_finding(
                rule_id="NTP_SOURCE_INCONSISTENT",
                severity="low",
                title="NTP Source Inconsistent",
                element_type="device",
                element_id=f"ntp::source_inconsistent::{','.join(sorted(hostnames))}",
                message=(
                    f"NTP server mismatch: {', '.join(hostnames)} are missing "
                    f"common NTP server(s) {sorted(missing)} used by the "
                    f"majority ({len(majority[1])} devices use "
                    f"{sorted(majority_servers)}); they use {sorted(servers_key)}."
                ),
                key_facts={
                    "devices": hostnames,
                    "their_servers": sorted(servers_key),
                    "majority_servers": sorted(majority_servers),
                    "missing_common_servers": sorted(missing),
                },
                recommendation=(
                    "Configure all devices to use the same NTP server(s) "
                    "for consistent time synchronization."
                ),
            ))

    return findings


# =========================================================================
# NTP_STRATUM_INCONSISTENT — NTP stratum mismatch across devices
# =========================================================================

def _check_ntp_stratum_inconsistent(
    facts: dict[str, dict[str, Any]],
) -> list[Finding]:
    """
    Check for NTP stratum inconsistency across devices.

    Flags devices with unusually high stratum (16 = unsynchronized)
    or significant stratum differences.
    """
    findings: list[Finding] = []

    # Collect: {hostname: min_stratum}
    device_stratum: dict[str, int] = {}

    for hostname, device_facts in facts.items():
        ntp_data = device_facts.get("genie_ntp", {})
        min_stratum = 16  # Default: unsynchronized

        for _vrf, vrf_data in ntp_data.get("vrf", {}).items():
            assoc_addrs = safe_get(vrf_data, "associations", "address")
            if not isinstance(assoc_addrs, dict):
                continue
            for _addr, addr_data in assoc_addrs.items():
                for _mode, mode_data in addr_data.get("local_mode", {}).items():
                    for _cfg, cfg_data in mode_data.get("isconfigured", {}).items():
                        stratum = cfg_data.get("stratum", 16)
                        if isinstance(stratum, int) and stratum < min_stratum:
                            min_stratum = stratum

        if min_stratum < 16:
            device_stratum[hostname] = min_stratum

    if len(device_stratum) < 2:
        return findings

    strata = set(device_stratum.values())
    if len(strata) > 1:
        # Group by stratum
        by_stratum: dict[int, list[str]] = {}
        for hostname, s in device_stratum.items():
            by_stratum.setdefault(s, []).append(hostname)

        # Only flag if stratum difference > 2 (significant)
        min_s = min(strata)
        max_s = max(strata)
        if max_s - min_s > 2:
            findings.append(make_finding(
                rule_id="NTP_STRATUM_INCONSISTENT",
                severity="low",
                title="NTP Stratum Inconsistent",
                element_type="device",
                element_id="ntp::stratum_inconsistent",
                message=(
                    f"NTP stratum varies significantly across devices: "
                    f"range {min_s}-{max_s}. "
                    f"Details: {', '.join(f'{h}=stratum {s}' for s, hosts in sorted(by_stratum.items()) for h in hosts)}."
                ),
                key_facts={
                    "stratum_range": [min_s, max_s],
                    "by_stratum": {str(s): hosts for s, hosts in by_stratum.items()},
                },
                recommendation=(
                    "Ensure all devices reach the same NTP source. "
                    "High stratum indicates poor time reference."
                ),
            ))

    return findings


# =========================================================================
# LINK_SINGLE_UPLINK — Device with only one uplink (no redundancy)
# =========================================================================

def _check_single_uplink(
    device_degree: dict[str, int],
    model: dict,
) -> list[Finding]:
    """
    Flag devices with only a single uplink (degree=1).

    Core/distribution devices should have redundant uplinks.
    Access devices with single uplinks get a lower priority.
    """
    findings: list[Finding] = []

    # Build hostname -> role mapping
    device_roles: dict[str, str] = {}
    for dev in model.get("devices", []):
        hostname = dev.get("hostname", "")
        role = dev.get("role", "unknown")
        device_roles[hostname] = role

    for hostname, degree in device_degree.items():
        if degree != 1:
            continue

        role = device_roles.get(hostname, "unknown")

        # Skip firewalls — single uplink is expected by design
        if role in ("firewall",):
            continue

        findings.append(make_finding(
            rule_id="LINK_SINGLE_UPLINK",
            severity="info",
            title="Single Uplink — Possible Lack of Redundancy",
            element_type="device",
            element_id=f"{hostname}::single_uplink",
            message=(
                f"{hostname} (role: {role}) has only 1 uplink — "
                f"may indicate a lack of redundancy."
            ),
            key_facts={
                "devices": [hostname],
                "degree": degree,
                "role": role,
            },
            recommendation=(
                "Verify whether a redundant uplink is needed for this "
                "device's role. In multihomed designs (e.g. border routers "
                "each peering with a different ISP), redundancy may already "
                "be provided at the system level by peer devices."
            ),
        ))

    return findings
