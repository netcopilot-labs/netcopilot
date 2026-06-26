"""
Cross-Device Helpers — Data loading, navigation, and finding utilities.

Provides helper functions for cross-device rule evaluation:
- Genie JSON navigation (OSPF, BGP, interface)
- Interface key canonicalization at pre-load time
- Finding creation with cross-device element_id format
- Safe nested dict traversal

These helpers are used by all four rule family modules
(ospf_rules, bgp_rules, interface_rules, topology_rules).
"""

import json
import logging
from pathlib import Path
from typing import Any

from netcopilot.model.interface_normalizer import canonicalize
from netcopilot.rules.finding import Finding

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Safe dict traversal
# -------------------------------------------------------------------------

def safe_get(data: dict | None, *keys: str, default: Any = None) -> Any:
    """Traverse nested dicts safely, returning default on any miss."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def normalize_ip_mtu(device_facts: dict, mtu: int | None) -> int | None:
    """Normalize an interface MTU to the comparable IP MTU.

    IOS XR's genie/`show interfaces` MTU is the L2 (interface) MTU, which
    includes the 14-byte Ethernet header (default 1514). IOS XE reports the
    L3 IP MTU directly (default 1500). OSPF DBD and interface MTU checks
    compare the IP MTU, so to compare an XR endpoint against an XE endpoint
    the XR L2 header must be stripped — otherwise a default XR<->XE link
    (1514 vs 1500) reads as a mismatch when the IP MTU is identical. A genuine
    mismatch (e.g. one side configured for jumbo frames) still differs after
    normalization and fires.

    ``device_facts`` is the per-device facts dict (the value at facts[dev]),
    which carries device_facts.os ("ios-xr" / "ios-xe").
    """
    if not mtu:
        return mtu
    os_name = str(device_facts.get("device_facts", {}).get("os", "")).lower().replace("-", "")
    if os_name == "iosxr" and mtu > 14:
        return mtu - 14
    return mtu


# -------------------------------------------------------------------------
# Pre-load device facts
# -------------------------------------------------------------------------

def load_all_device_facts(
    facts_dir: str | Path,
    device_hostnames: list[str],
) -> dict[str, dict[str, Any]]:
    """
    Bulk-load all Genie JSON facts for all devices.

    Returns:
        {"hostname": {"genie_ospf": {...}, "genie_bgp": {...}, ...}, ...}
    """
    facts_path = Path(facts_dir)
    all_facts: dict[str, dict[str, Any]] = {}

    for hostname in device_hostnames:
        device_dir = facts_path / hostname
        if not device_dir.is_dir():
            continue

        device_facts: dict[str, Any] = {}
        for json_file in device_dir.glob("*.json"):
            try:
                with open(json_file, encoding="utf-8") as f:
                    device_facts[json_file.stem] = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load {json_file}: {e}")

        if device_facts:
            all_facts[hostname] = device_facts

    return all_facts


# -------------------------------------------------------------------------
# Interface key canonicalization
# -------------------------------------------------------------------------

def canonicalize_facts_keys(facts: dict[str, dict[str, Any]]) -> None:
    """
    Normalize interface keys in all Genie dicts in-place.

    After this call, all interface-keyed dicts use canonical lowercase
    full names (e.g., "gigabitethernet0/0/0/1") matching canonicalize().
    """
    for _hostname, device_facts in facts.items():
        # genie_interface — keys are interface names
        if "genie_interface" in device_facts:
            orig = device_facts["genie_interface"]
            device_facts["genie_interface"] = {
                canonicalize(k) or k: v for k, v in orig.items()
            }

        # genie_ospf — interface keys nested deep
        if "genie_ospf" in device_facts:
            _canonicalize_ospf_keys(device_facts["genie_ospf"])

        # genie_lldp, genie_cdp — interface keys under "interfaces"
        for source in ("genie_lldp", "genie_cdp"):
            if source in device_facts:
                intf_section = device_facts[source].get("interfaces", {})
                if intf_section:
                    device_facts[source]["interfaces"] = {
                        canonicalize(k) or k: v
                        for k, v in intf_section.items()
                    }


def _canonicalize_ospf_keys(ospf_data: dict) -> None:
    """Walk OSPF tree and canonicalize interface-level keys in-place."""
    for _vrf, vrf_data in ospf_data.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for _pid, pdata in instances.items():
            for _area_id, area_data in pdata.get("areas", {}).items():
                intfs = area_data.get("interfaces", {})
                if intfs:
                    area_data["interfaces"] = {
                        canonicalize(k) or k: v
                        for k, v in intfs.items()
                    }


# -------------------------------------------------------------------------
# OSPF Genie navigation helpers
# -------------------------------------------------------------------------

def find_ospf_interface(
    genie_ospf: dict,
    intf_name: str,
) -> dict | None:
    """
    Find OSPF interface data by canonical interface name.

    Navigates vrf -> address_family -> instance -> areas -> interfaces.
    Returns the interface dict if found, None otherwise.
    """
    canon = canonicalize(intf_name) or intf_name
    for _vrf, vrf_data in genie_ospf.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for _pid, pdata in instances.items():
            for _area_id, area_data in pdata.get("areas", {}).items():
                intfs = area_data.get("interfaces", {})
                if canon in intfs:
                    return intfs[canon]
    return None


def find_ospf_interface_with_context(
    genie_ospf: dict,
    intf_name: str,
) -> tuple[dict, str, str, str] | None:
    """
    Find OSPF interface data with its VRF, process ID, and area.

    Returns (intf_dict, vrf_name, process_id, area_id) or None.
    """
    canon = canonicalize(intf_name) or intf_name
    for vrf, vrf_data in genie_ospf.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for pid, pdata in instances.items():
            for area_id, area_data in pdata.get("areas", {}).items():
                intfs = area_data.get("interfaces", {})
                if canon in intfs:
                    return intfs[canon], vrf, pid, area_id
    return None


def extract_ospf_router_id(genie_ospf: dict) -> str | None:
    """Extract OSPF router-ID from first OSPF instance."""
    for _vrf, vrf_data in genie_ospf.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for _pid, pdata in instances.items():
            rid = pdata.get("router_id")
            if rid:
                return rid
    return None


def _ospf_proc_real_vrf(vrf_dict: dict) -> tuple[set[str], dict[str, str]]:
    """Return (all process ids, process_id -> real VRF).

    Genie copies every OSPF process under the 'default' VRF block regardless of
    real VRF (the same quirk O1/O-mem handle). A process that appears in any
    non-default block belongs to that VRF; one only seen under 'default' is a
    real default-VRF process.
    """
    all_procs: set[str] = set()
    proc_vrf: dict[str, str] = {}
    for vname, vdata in vrf_dict.items():
        instances = vdata.get("address_family", {}).get("ipv4", {}).get("instance", {})
        for pid in instances:
            all_procs.add(pid)
            if vname != "default":
                proc_vrf[pid] = vname
    return all_procs, proc_vrf


def extract_reference_bandwidth_by_vrf(genie_ospf: dict) -> dict[str, int | None]:
    """OSPF auto-cost reference bandwidth keyed by the process's real VRF.

    Returns ``{vrf: ref_bw|None}``. The value is read wherever genie stores it
    (typically the 'default' block, per the quirk) but attributed to the
    process's real VRF so domain-consistency checks compare like with like —
    different VRFs are separate OSPF domains and may legitimately differ.
    Deterministic: processes are visited in sorted order.
    """
    vrf_dict = genie_ospf.get("vrf", {})
    all_procs, proc_vrf = _ospf_proc_real_vrf(vrf_dict)

    proc_bw: dict[str, int] = {}
    for vname in sorted(vrf_dict):
        instances = vrf_dict[vname].get("address_family", {}).get("ipv4", {}).get("instance", {})
        for pid, pdata in instances.items():
            bw = safe_get(pdata, "auto_cost", "reference_bandwidth")
            if bw is not None and pid not in proc_bw:
                proc_bw[pid] = bw

    result: dict[str, int | None] = {}
    for pid in sorted(all_procs):
        vrf = proc_vrf.get(pid, "default")
        bw = proc_bw.get(pid)
        if vrf not in result or (result[vrf] is None and bw is not None):
            result[vrf] = bw
    return result


def is_area_border_router(genie_ospf: dict, area_id: str) -> bool:
    """Check if device is an ABR: in the given area AND area 0, with 2+ areas."""
    areas_seen: set[str] = set()
    for _vrf, vrf_data in genie_ospf.get("vrf", {}).items():
        instances = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("instance", {})
        )
        for _pid, pdata in instances.items():
            areas_seen.update(pdata.get("areas", {}).keys())
    return (
        len(areas_seen) >= 2
        and area_id in areas_seen
        and "0.0.0.0" in areas_seen
    )


def extract_ospf_spf_timers_by_vrf(genie_ospf: dict) -> dict[str, dict | None]:
    """OSPF SPF throttle timers keyed by the process's real VRF.

    Returns ``{vrf: throttle_dict|None}``. Same genie-quirk handling and
    per-domain rationale as :func:`extract_reference_bandwidth_by_vrf`.
    """
    vrf_dict = genie_ospf.get("vrf", {})
    all_procs, proc_vrf = _ospf_proc_real_vrf(vrf_dict)

    proc_spf: dict[str, dict] = {}
    for vname in sorted(vrf_dict):
        instances = vrf_dict[vname].get("address_family", {}).get("ipv4", {}).get("instance", {})
        for pid, pdata in instances.items():
            throttle = safe_get(pdata, "spf_control", "throttle", "spf")
            if throttle and pid not in proc_spf:
                proc_spf[pid] = throttle

    result: dict[str, dict | None] = {}
    for pid in sorted(all_procs):
        vrf = proc_vrf.get(pid, "default")
        spf = proc_spf.get(pid)
        if vrf not in result or (result[vrf] is None and spf):
            result[vrf] = spf
    return result


# -------------------------------------------------------------------------
# BGP Genie navigation helpers
# -------------------------------------------------------------------------

def find_bgp_neighbor(
    genie_bgp: dict,
    peer_address: str,
) -> dict | None:
    """
    Find BGP neighbor data by peer IP address.

    Navigates instance -> vrf -> neighbor -> {address}.
    """
    for _inst, idata in genie_bgp.get("instance", {}).items():
        for _vrf, vdata in idata.get("vrf", {}).items():
            nbr = vdata.get("neighbor", {}).get(peer_address)
            if nbr is not None:
                return nbr
    return None


def find_bgp_neighbor_with_context(
    genie_bgp: dict,
    peer_address: str,
) -> tuple[dict, str, str] | None:
    """
    Find BGP neighbor data with its instance and VRF.

    Returns (neighbor_dict, instance_name, vrf_name) or None.
    """
    for inst, idata in genie_bgp.get("instance", {}).items():
        for vrf, vdata in idata.get("vrf", {}).items():
            nbr = vdata.get("neighbor", {}).get(peer_address)
            if nbr is not None:
                return nbr, inst, vrf
    return None


def extract_bgp_router_id(genie_bgp: dict) -> str | None:
    """Extract BGP router-ID (IP) from first instance/VRF.

    The actual router-ID lives at the VRF level as an IP address
    (e.g. "10.255.255.1"), not at the instance level where bgp_id
    is the AS number.
    """
    for _inst, idata in genie_bgp.get("instance", {}).items():
        for _vrf, vdata in idata.get("vrf", {}).items():
            rid = vdata.get("router_id")
            if rid:
                return str(rid)
    return None


def extract_bgp_cluster_id(genie_bgp: dict) -> str | None:
    """Extract BGP cluster-ID (for route reflectors) from first instance."""
    for _inst, idata in genie_bgp.get("instance", {}).items():
        for _vrf, vdata in idata.get("vrf", {}).items():
            cluster_id = vdata.get("cluster_id")
            if cluster_id:
                return str(cluster_id)
    return None


# -------------------------------------------------------------------------
# Interface Genie navigation helpers
# -------------------------------------------------------------------------

def find_interface_facts(
    genie_interface: dict,
    intf_name: str,
) -> dict | None:
    """Lookup interface facts by canonical name (flat dict)."""
    canon = canonicalize(intf_name) or intf_name
    return genie_interface.get(canon)


# -------------------------------------------------------------------------
# Topology model helpers
# -------------------------------------------------------------------------

def get_device_hostnames(model: dict) -> list[str]:
    """Extract list of device hostnames from topology model."""
    return [d.get("hostname", "") for d in model.get("devices", [])]


def get_device_platform(model: dict, hostname: str) -> str | None:
    """Get os_family for a device from topology model."""
    for device in model.get("devices", []):
        if device.get("hostname") == hostname:
            return device.get("os")
    return None


def get_adjacencies(
    model: dict,
    protocol: str | None = None,
) -> list[dict]:
    """
    Get adjacencies from topology model, optionally filtered by protocol.

    Args:
        model: Topology model dict.
        protocol: Filter by protocol (e.g., "ospf", "bgp"). None = all.
    """
    adjs = model.get("adjacencies", [])
    if protocol is None:
        return adjs
    return [a for a in adjs if a.get("protocol") == protocol]


def get_shared_services(
    model: dict,
    service_type: str | None = None,
) -> list[dict]:
    """
    Get shared services from topology model, optionally filtered by type.

    Args:
        model: Topology model dict.
        service_type: Filter (e.g., "vlan", "ospf_area", "bgp_asn").
    """
    svcs = model.get("shared_services", [])
    if service_type is None:
        return svcs
    return [s for s in svcs if s.get("service_type") == service_type]


def parse_interface_from_id(interface_id: str) -> tuple[str, str]:
    """
    Parse 'hostname:interface' from interface_id.

    Args:
        interface_id: e.g., "core-sw-02:Gi0/0"

    Returns:
        (hostname, interface_name) e.g., ("core-sw-02", "Gi0/0")
    """
    parts = interface_id.split(":", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return interface_id, ""


# -------------------------------------------------------------------------
# Link pre-filtering — shared by all bilateral rule families
# -------------------------------------------------------------------------

# Management interface prefixes — out-of-band management plane,
# not relevant for data-plane bilateral checks.
_MGMT_PREFIXES = ("Mgmt", "Management", "mgmt", "management")


def is_management_interface(interface_id: str) -> bool:
    """Return True if the interface is an OOB management port."""
    _, intf = parse_interface_from_id(interface_id)
    return intf.startswith(_MGMT_PREFIXES) if intf else False


def select_best_links_per_pair(links: list[dict]) -> list[dict]:
    """
    Pre-filter topology links for bilateral checks:
    1. Skip uncollected peers.
    2. Skip links where either endpoint is a management interface.
    3. For each device pair, keep only the best-evidence link
       (lowest discovery_priority) to avoid duplicate findings from
       multiple logical/physical links between the same pair.
    """
    best: dict[tuple[str, str], dict] = {}
    for link in links:
        if not link.get("peer_collected", False):
            continue
        local_id = link.get("local_interface_id", "")
        remote_id = link.get("remote_interface_id", "")
        if is_management_interface(local_id) or is_management_interface(remote_id):
            continue
        dev_a = link.get("local_device_id", "")
        dev_b = link.get("remote_device_id", "")
        pair = tuple(sorted([dev_a, dev_b]))
        pri = link.get("discovery_priority", 99)
        existing = best.get(pair)
        if existing is None or pri < existing.get("discovery_priority", 99):
            best[pair] = link
    return list(best.values())


# -------------------------------------------------------------------------
# Index builders for evaluator
# -------------------------------------------------------------------------

def build_ospf_link_index(
    links: list[dict],
    facts: dict[str, dict],
) -> list[dict]:
    """
    Build index of links where both endpoints have OSPF data.

    Pre-filters: management interfaces excluded, best-evidence link
    per device pair only (avoids duplicate findings from ARP/subnet links).

    Returns list of dicts:
        {"link": <link>, "dev_a": str, "intf_a": str,
         "dev_b": str, "intf_b": str}
    """
    index = []
    for link in select_best_links_per_pair(links):
        dev_a = link.get("local_device_id", "")
        dev_b = link.get("remote_device_id", "")

        if dev_a not in facts or dev_b not in facts:
            continue

        # Both sides need OSPF data
        if "genie_ospf" not in facts[dev_a] or "genie_ospf" not in facts[dev_b]:
            continue

        # Extract and canonicalize interface names from interface_id
        _, raw_intf_a = parse_interface_from_id(
            link.get("local_interface_id", "")
        )
        _, raw_intf_b = parse_interface_from_id(
            link.get("remote_interface_id", "")
        )

        intf_a = canonicalize(raw_intf_a) or raw_intf_a
        intf_b = canonicalize(raw_intf_b) or raw_intf_b

        index.append({
            "link": link,
            "dev_a": dev_a,
            "intf_a": intf_a,
            "dev_b": dev_b,
            "intf_b": intf_b,
        })

    return index


def build_bgp_peer_index(
    adjacencies: list[dict],
    facts: dict[str, dict],
) -> list[dict]:
    """
    Build index of BGP adjacencies where both endpoints are collected.

    Per device pair, keeps only the first adjacency to avoid duplicate
    findings from multiple BGP sessions between the same pair.

    Returns list of dicts:
        {"adj": <adjacency>, "dev_a": str, "dev_b": str,
         "nbr_a_addr": str, "nbr_b_addr": str}
    """
    index = []
    seen_pairs: set[tuple[str, str]] = set()
    for adj in adjacencies:
        if adj.get("protocol") != "bgp":
            continue
        if not adj.get("peer_collected", False):
            continue  # 

        dev_a = adj.get("device_a", "")
        dev_b = adj.get("device_b", "")

        # One finding per device pair
        pair = tuple(sorted([dev_a, dev_b]))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        if dev_a not in facts or dev_b not in facts:
            continue
        if "genie_bgp" not in facts[dev_a] or "genie_bgp" not in facts[dev_b]:
            continue

        nbr_a_addr = adj.get("neighbor_address_a", "")
        nbr_b_addr = adj.get("neighbor_address_b", "")

        index.append({
            "adj": adj,
            "dev_a": dev_a,
            "dev_b": dev_b,
            "nbr_a_addr": nbr_a_addr,
            "nbr_b_addr": nbr_b_addr,
        })

    return index


def build_domain_index(
    shared_services: list[dict],
    service_type: str,
) -> dict[str, list[str]]:
    """
    Build a dict of domain_id -> list[hostname] for a service type.

    Example for service_type="ospf_area":
        {"0.0.0.0": ["core-sw-01", "core-sw-01", "core-sw-01"]}
    """
    domains: dict[str, list[str]] = {}
    for svc in shared_services:
        if svc.get("service_type") != service_type:
            continue
        domain_id = str(svc.get("identifier", ""))
        members = svc.get("members", [])
        domains[domain_id] = list(members)
    return domains


def build_device_degree(links: list[dict]) -> dict[str, int]:
    """
    Count the number of links per device (node degree in topology graph).

    Only counts links where both endpoints are collected devices.
    """
    degree: dict[str, int] = {}
    for link in links:
        if not link.get("peer_collected", False):
            continue
        dev_a = link.get("local_device_id", "")
        dev_b = link.get("remote_device_id", "")
        if dev_a:
            degree[dev_a] = degree.get(dev_a, 0) + 1
        if dev_b:
            degree[dev_b] = degree.get(dev_b, 0) + 1
    return degree


# -------------------------------------------------------------------------
# Cross-device finding creation
# -------------------------------------------------------------------------

def make_bilateral_element_id(
    dev_a: str,
    intf_a: str,
    dev_b: str,
    intf_b: str,
) -> str:
    """
    Create element_id for bilateral findings: devA:intfA--devB:intfB.

    Mirrors the link_id format from topology model.
    """
    return f"{dev_a}:{intf_a}--{dev_b}:{intf_b}"


def make_finding(
    rule_id: str,
    severity: str,
    title: str,
    element_type: str,
    element_id: str,
    message: str,
    key_facts: dict[str, Any],
    recommendation: str,
) -> Finding:
    """
    Create a Finding for cross-device rules.

    Uses Finding.create() to auto-generate finding_id.
    """
    return Finding.create(
        rule_id=rule_id,
        severity=severity,
        title=title,
        element_type=element_type,
        element_id=element_id,
        message=message,
        key_facts=key_facts,
        recommendation=recommendation,
    )
