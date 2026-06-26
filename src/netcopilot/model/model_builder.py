"""
Network Model Builder - Main orchestration module.

This module is the entry point for building a unified network model
from per-device facts. It coordinates loading data, building device
and interface lists, discovering links (5-level hierarchy), extracting
routing adjacencies, discovering shared services, and generating warnings.

Architecture (Sprint 12):
    facts/*.json + manifest.json
            │
            ▼
    load_run_data()              [loader.py]
            │
            ▼
    _build_devices()             [this module]
            │
            ▼
    _build_interfaces()          [this module + interface_classifier.py]
            │
            ▼
    link_builder pipeline:       [link_builder.py]
      ├─ L1: CDP bilateral/unilateral
      ├─ L2: LLDP bilateral/unilateral
      ├─ L6: LACP bilateral/unilateral
      ├─ L7: FDB firewall (ARP→FDB→LACP fingerprint)
      ├─ L3: ARP + subnet
      ├─ L4: MAC + subnet
      ├─ L5: Subnet-only
      ├─ deduplicate_links()
      ├─ enrich_l2/l3_metadata()
      ├─ classify_link_type()
      ├─ L8: Stack mirror (FDB-confirmed)
      ├─ extract_ospf/bgp_adjacencies()
      └─ discover_shared_services()
            │
            ▼
    _detect_warnings()           [this module]
            │
            ▼
    network_model.json

Design Principles:
    - Deterministic: Same input always produces same output
    - Traceable: Every model element traces back to source facts
    - Explicit: Missing data = null, unknown patterns = "unknown"
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Module imports
# -------------------------------------------------------------------------
# We import from our own model package modules
from netcopilot.model.loader import load_run_data
from netcopilot.model.interface_classifier import classify_interface
from netcopilot.model.interface_normalizer import canonicalize, normalize_interface_name
from netcopilot.parse.cisco_native.stack import parse_stack_ports
from netcopilot.model.link_builder import (
    _build_hw_mac_to_device_index,
    _make_pair_key,
    build_subnet_index,
    classify_link_type,
    classify_mgmt_type,
    compute_oob_device_names,
    create_inband_mgmt_links,
    deduplicate_links,
    detect_management_subnets,
    discover_arp_subnet_links,
    discover_cdp_links,
    discover_mac_fingerprint_links,
    discover_fdb_firewall_links,
    discover_lacp_links,
    discover_stack_interconnect_links,
    discover_mgmt_fdb_member_links,
    attribute_fortigate_ha_cables,
    discover_lldp_links,
    discover_mac_subnet_links,
    discover_shared_services,
    discover_subnet_only_links,
    enrich_l2_metadata,
    enrich_l3_metadata,
    extract_bgp_adjacencies,
    extract_ospf_adjacencies,
    extract_ospf_lsdb,
    suppress_cdp_portchannel_when_lacp_bilateral,
    suppress_unilateral_cable_on_bilateral_port,
)
from netcopilot.model.l2_domains import discover_l2_domains


def build_model(run_id: str, runs_base: str = "runs") -> dict[str, Any]:
    """
    Build a unified network model from a collection run.

    This is the main entry point for model building. It:
    1. Loads all facts files and the manifest
    2. Builds the device list (with management IPs from manifest)
    3. Builds the interface list (with type classification)
    4. Builds facts_dirs mapping for link_builder
    5. Runs 5-level link discovery (CDP→LLDP→ARP→MAC→subnet)
    6. Deduplicates and enriches links (L2/L3 metadata)
    7. Extracts routing adjacencies (OSPF + BGP)
    8. Discovers shared services (VLANs, subnets, OSPF areas, BGP ASNs)
    9. Detects topology warnings
    10. Writes the model to JSON

    Args:
        run_id: The run identifier (e.g., "2026-01-15_12-00-00")
        runs_base: Base directory for runs (default: "runs")

    Returns:
        The complete network model as a dictionary

    Raises:
        ValueError: If run doesn't exist or has invalid data
        FileNotFoundError: If required files are missing

    Example:
        >>> model = build_model("2026-01-15_12-00-00")
        >>> print(f"Found {len(model['devices'])} devices")
        Found 5 devices
    """
    run_path = Path(runs_base) / run_id

    # -------------------------------------------------------------------------
    # Step 1: Load all input data
    # -------------------------------------------------------------------------
    # This loads manifest.json and all facts/*.json files
    # The loader validates that files exist and are valid JSON
    run_data = load_run_data(run_path)
    manifest = run_data["manifest"]
    facts_by_hostname = run_data["facts"]

    # -------------------------------------------------------------------------
    # Step 2: Build device list
    # -------------------------------------------------------------------------
    # Combines facts (platform, version, serial) with manifest (management_ip)
    # ADR-219: facts dirs are now named by inventory_name — no remapping needed.
    devices = _build_devices(manifest, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 3: Build interface list with classification
    # -------------------------------------------------------------------------
    # Extracts all interfaces from all devices and classifies their types
    interfaces = _build_interfaces(facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 4: Build facts_dirs mapping for link_builder
    # -------------------------------------------------------------------------
    # link_builder functions need a {hostname: Path} map pointing to each
    # device's facts directory. This lets them load genie_*.json files
    # (CDP, LLDP, ARP, OSPF, BGP, VLAN, interface) directly.
    facts_base = run_path / "facts"
    facts_dirs: dict[str, Path] = {}
    # sorted(): filesystem iteration order is not stable across machines/runs, and
    # facts_dirs insertion order decides downstream collision winners (IP/router-id
    # -> hostname). Sorting makes the whole model a deterministic function of the
    # facts — same input, same graph, anywhere. (R1 determinism core.)
    for device_dir in sorted(facts_base.iterdir()):
        if device_dir.is_dir():
            facts_dirs[device_dir.name] = device_dir

    # -------------------------------------------------------------------------
    # Step 4b: Enrich interfaces with L1 properties (Sprint 17, ADR-131)
    # -------------------------------------------------------------------------
    # Add speed, duplex, mtu, description, media_type from genie_interface.json
    # (Cisco) or fortigate_*_interface.json (FortiGate). Runs once at build time
    # so neither Neo4j loader nor dashboard need to read facts files at query time.
    _enrich_interfaces_l1(interfaces, facts_dirs, facts_by_hostname, run_path)

    # -------------------------------------------------------------------------
    # Step 4c: Enrich interfaces with QoS data (Sprint 18B, ADR-150)
    # -------------------------------------------------------------------------
    # Add qos dict (input/output sub-objects) from genie_policy_map*.json.
    # Same pattern as L1 enrichment — runs once at build time.
    _enrich_interfaces_qos(interfaces, facts_dirs)

    # -------------------------------------------------------------------------
    # Step 4d: Enrich interfaces with switchport data (Sprint 19B, ADR-191)
    # -------------------------------------------------------------------------
    # Parse running_config.txt for switchport mode, access VLAN, trunk VLANs,
    # native VLAN. Same pattern as L1/QoS enrichment — runs once at build time.
    _enrich_interfaces_switchport(interfaces, facts_dirs, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 4d-post: Filter FortiGate interfaces to the data VDOM only
    # -------------------------------------------------------------------------
    # _enrich_fortigate_switchport() tags data-VDOM interfaces with a vdom field.
    # Remove FortiGate interfaces that were not tagged (interfaces on other
    # VDOMs like root). Single-VDOM FortiGates keep all interfaces because the
    # data VDOM falls back to the only VDOM and all interfaces get tagged.
    fg_hostnames = {
        h for h, facts in facts_by_hostname.items()
        if (facts.get("os") or "").lower() == "fortios"
    }
    if fg_hostnames:
        before = len(interfaces)
        interfaces[:] = [
            i for i in interfaces
            if i["device_id"] not in fg_hostnames or i.get("vdom")
        ]
        removed = before - len(interfaces)
        if removed:
            logger.info("Filtered %d non-data-VDOM FortiGate interfaces", removed)

    # -------------------------------------------------------------------------
    # Step 4e: Enrich devices with VLAN database (Sprint 19B, ADR-194)
    # -------------------------------------------------------------------------
    # Parse genie_vlan.json per device → vlans[] list on each device dict.
    # Feeds Vlan nodes in Neo4j for the VLANs tab and dropdown.
    _enrich_devices_vlans(devices, facts_dirs)

    # -------------------------------------------------------------------------
    # Step 5: Multi-level link discovery (Sprint 12, ADR-080/081)
    # -------------------------------------------------------------------------
    # Replaces the old CDP-only _correlate_links() with 6-level discovery:
    #   L1: CDP bilateral/unilateral (very_high/high confidence)
    #   L2: LLDP bilateral/unilateral (very_high/high confidence)
    #   L6: LACP bilateral/unilateral (high/medium confidence) — Sprint 16
    #   L3: ARP + shared subnet (medium confidence)
    #   L4: MAC table + shared subnet (low confidence)
    #   L5: Shared subnet only (very_low confidence)
    # All produce LinkCandidate objects that are deduplicated in Step 6.
    collected_hostnames = set(facts_by_hostname.keys())
    subnet_index = build_subnet_index(facts_dirs, facts_by_hostname)

    all_candidates = []
    all_candidates.extend(discover_cdp_links(facts_by_hostname, collected_hostnames, facts_dirs))
    all_candidates.extend(discover_lldp_links(facts_dirs, collected_hostnames))
    all_candidates.extend(discover_lacp_links(facts_dirs, collected_hostnames))
    all_candidates.extend(discover_fdb_firewall_links(facts_dirs, facts_by_hostname))

    # MAC fingerprint: prove physical cabling from ARP + hardware MACs (no CDP/LLDP).
    # Runs before arp_subnet so its very_high/high candidates win deduplication on
    # the same interface pair (a routed fingerprint and arp_subnet resolve the same
    # two ports, so dedup merges them and the fingerprint upgrades the link to
    # physical). No coarser suppression: distinct connections between the same pair
    # (e.g. a data cable AND an OOB-mgmt link) must each survive.
    hw_mac_index = _build_hw_mac_to_device_index(facts_dirs, facts_by_hostname)
    all_candidates.extend(discover_mac_fingerprint_links(
        facts_dirs, facts_by_hostname, collected_hostnames, subnet_index, hw_mac_index,
    ))
    all_candidates.extend(discover_arp_subnet_links(
        facts_dirs, facts_by_hostname, collected_hostnames, subnet_index,
    ))
    all_candidates.extend(discover_mac_subnet_links(
        facts_dirs, collected_hostnames, subnet_index,
    ))

    # Build existing pair keys for subnet-only to skip already-discovered pairs
    existing_pair_keys = set(_make_pair_key(c) for c in all_candidates)

    all_candidates.extend(discover_subnet_only_links(
        subnet_index, collected_hostnames, existing_pair_keys,
    ))

    # -------------------------------------------------------------------------
    # Step 6: Deduplicate + promote → final link dicts
    # -------------------------------------------------------------------------
    # Same physical connection discovered by multiple methods → one link.
    # Highest confidence wins, evidence accumulated, status calculated.
    links = deduplicate_links(all_candidates, interfaces)

    # ADR-165: Remove CDP bilateral links over port-channel interfaces when
    # LACP bilateral links already exist for the same device pair.  LACP
    # bilateral links carry per-physical-member interface names (Hu1/0/1,
    # Hu2/0/2) enabling correct compound-node edge routing; the CDP link over
    # the virtual aggregate (Po/Be) would create duplicate edges with wrong
    # member attribution.
    links = suppress_cdp_portchannel_when_lacp_bilateral(links)

    # Drop unilateral cable links on a port already confirmed by a bilateral
    # cable (one port = one cable). E.g. a mac_fingerprint_unilateral that
    # resolved only its near port duplicating a cdp_bilateral on that port —
    # different pair-key (empty far end) so dedup can't merge it.
    links = suppress_unilateral_cable_on_bilateral_port(links)

    # -------------------------------------------------------------------------
    # Step 6b: Resolve FortiGate aggregate names for LACP unilateral links
    # -------------------------------------------------------------------------
    # LACP unilateral links to FortiGate have empty remote_interface because
    # Genie doesn't expose LACP partner port numbers for FortiGate.  The
    # FortiGate system_interface.json contains aggregate→member mappings.
    # For each FortiGate with aggregates, set remote_interface to the
    # aggregate name so L1 enrichment and bilateral display work.
    _resolve_fortigate_aggregate_interfaces(links, facts_dirs, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 7: Enrich links with L2/L3 metadata
    # -------------------------------------------------------------------------
    enrich_l2_metadata(links, facts_dirs, interfaces)
    enrich_l3_metadata(links, facts_dirs, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 8: Classify link types (Sprint 17, ADR-128)
    # -------------------------------------------------------------------------
    # After L2/L3 enrichment, classify each link as physical / management /
    # l3_reachability / subnet_association.  Requires device roles (from
    # devices list) and management subnet detection (from device mgmt IPs).
    role_by_device = {d["device_id"]: d.get("role", "unknown") for d in devices}
    mgmt_subnets, mgmt_interface_ids, mgmt_vlans = detect_management_subnets(
        devices, interfaces, links,
    )
    logger.info("Management VLANs detected: %s", sorted(mgmt_vlans) if mgmt_vlans else "(none)")
    # ADR-167: compute which devices are OOB (mgmt_ip in mgmt-switch subnet)
    oob_device_names = compute_oob_device_names(devices, mgmt_subnets)
    logger.info(
        "OOB management devices (%d): %s",
        len(oob_device_names), sorted(oob_device_names),
    )

    # ADR-192: Both interfaces and links now use normalized short names,
    # so mgmt_interface_ids from detect_management_subnets() already matches.

    # Build interface index for infrastructure classification (Sprint 19B)
    # Index by both full interface_id and abbreviated form (link_builder uses
    # abbreviated names like "Gi1/1/1" while interfaces use "GigabitEthernet1/1/1").
    # ADR-192: interface_ids already use short names, direct lookup suffices.
    intf_by_id: dict[str, dict] = {}
    for iface in interfaces:
        intf_by_id[iface["interface_id"]] = iface

    # Warn about visibility: devices with only l3/subnet links will be invisible
    # in both Physical and MGMT views.
    _view_visible = {"physical", "management"}
    _device_view_types: dict[str, set[str]] = {}

    for link in links:
        lt = classify_link_type(
            link, role_by_device, mgmt_subnets, mgmt_interface_ids,
            mgmt_vlans, intf_by_id,
        )
        link["link_type"] = lt
        # Classify management links as OOB or inband
        mt = classify_mgmt_type(link, role_by_device, oob_device_names)
        if mt:
            link["mgmt_type"] = mt
        for dev in (link["local_device_id"], link["remote_device_id"]):
            _device_view_types.setdefault(dev, set()).add(lt)

    # Log classification summary
    import collections as _collections
    _lt_counts = _collections.Counter(l["link_type"] for l in links)
    logger.info(
        "Link type classification: %s",
        ", ".join(f"{t}={c}" for t, c in sorted(_lt_counts.items())),
    )

    # Warn about devices only reachable via l3/subnet links
    for dev_id in facts_by_hostname:
        view_types = _device_view_types.get(dev_id, set())
        if view_types and not (view_types & _view_visible):
            logger.warning(
                "Device '%s' has only %s links — invisible in Physical and MGMT views",
                dev_id, "/".join(sorted(view_types)),
            )

    # -------------------------------------------------------------------------
    # Step 8a: Synthetic inband MGMT_LINKs (ADR-167)
    # -------------------------------------------------------------------------
    # Devices whose management_ip is NOT in any mgmt-switch subnet have no
    # management links at all (venue switches, inband-managed devices).  For
    # each such device, read genie_routing.json to find the default-route
    # next-hop in the management VRF and create one MGMT_LINK pointing to
    # that gateway device.
    existing_mgmt_sources = {
        l["local_device_id"] for l in links
        if l.get("link_type") == "management"
        and (l.get("discovery_priority") or 99) <= 6
    }
    # Build ip → device_id map from model interfaces (post-remap)
    all_iface_ips: dict[str, str] = {}
    for iface in interfaces:
        ip_cidr = iface.get("ip_address", "") or ""
        if not ip_cidr:
            continue
        ip_only = ip_cidr.split("/")[0] if "/" in ip_cidr else ip_cidr
        iface_id = iface.get("interface_id", "")
        dev_name = iface_id.split(":", 1)[0] if ":" in iface_id else ""
        if ip_only and dev_name:
            all_iface_ips[ip_only] = dev_name
    # ADR-219: facts_dirs keyed by inventory_name — no inversion needed
    inband_links = create_inband_mgmt_links(
        devices,
        oob_device_names,
        existing_mgmt_sources,
        facts_dirs,
        all_iface_ips,
        links,
        interfaces,
    )
    links.extend(inband_links)
    if inband_links:
        logger.info(
            "Inband MGMT_LINKs created: %d (%s)",
            len(inband_links),
            ", ".join(l["local_device_id"] for l in inband_links),
        )

    # -------------------------------------------------------------------------
    # Step 8b: Stack interconnect links (Sprint 18, S18-5)
    # -------------------------------------------------------------------------
    # Create links between stack members from stack_ports data (C9300 cables,
    # C9500 SVL/DAD). These links have link_type="stack_interconnect" pre-set
    # and do not need classification.
    stack_interconnect = discover_stack_interconnect_links(devices, facts_dirs)
    links.extend(stack_interconnect)

    # -------------------------------------------------------------------------
    # Step 8d: FortiGate HA cable-to-member attribution (Sprint 18, S18-6)
    # -------------------------------------------------------------------------
    # For FortiGate HA pairs, attribute each cable to active or passive
    # member using ARP heartbeat MAC + LACP partner correlation.
    # Mutates links in place — adds ha_member field.
    attribute_fortigate_ha_cables(links, facts_dirs, devices, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 8e: Assign member IDs to link endpoints (Sprint 18, S18-7)
    # -------------------------------------------------------------------------
    # For stacked devices, parse interface name to determine which stack member
    # the cable connects to. Virtual interfaces (Vlan, Loopback, etc.) get null.
    # FortiGate links use ha_member field instead of interface parsing.
    _assign_member_ids(links, devices)

    # ADR-165: For CDP bilateral links over port-channel interfaces on stacked
    # devices, cross-reference LAG partner MACs to determine which physical
    # member port connects to the remote device and set source_member_id correctly.
    _resolve_portchannel_member_ids(links, devices, facts_dirs)

    # -------------------------------------------------------------------------
    # Step 8f: FDB-based management link discovery for SVL standby members
    # -------------------------------------------------------------------------
    # SVL standby members have a unique Gi0/0 MAC that management switches
    # learn via FDB (the port is physically up but silent). Cross-reference
    # genie_switch.json (per-member MACs) with mgmt_switch genie_fdb.json.
    # Gracefully skips if genie_switch.json is absent (old runs, non-SVL).
    fdb_mgmt_links = discover_mgmt_fdb_member_links(
        devices, links, facts_dirs, mgmt_vlans, role_by_device,
    )
    links.extend(fdb_mgmt_links)

    # -------------------------------------------------------------------------
    # Step 8g: Link interface_ids already match Interface nodes
    # -------------------------------------------------------------------------
    # Interface names are normalized to short form in _build_interfaces(),
    # matching link interface_ids from CDP/LACP/FDB — no rewrite needed.

    # -------------------------------------------------------------------------
    # Step 9: Extract routing protocol adjacencies
    # -------------------------------------------------------------------------
    adjacencies = []
    adjacencies.extend(extract_ospf_adjacencies(facts_dirs))
    adjacencies.extend(extract_bgp_adjacencies(facts_dirs, facts_by_hostname))

    # Step 9a: Route-reflector role. A device that reflects to a client
    # (rr_reflector on any iBGP adjacency) is an RR; its cluster-id is the
    # configured one, or its BGP router-id by default. genie's operational BGP
    # exposes neither route-reflector-client nor (without config) cluster-id, so
    # we read them from the parsed running-config fact (bgp_config.json).
    _rr_hosts = {a["rr_reflector"] for a in adjacencies if a.get("rr_reflector")}
    for dev in devices:
        host = dev["hostname"]
        dev["is_route_reflector"] = host in _rr_hosts
        dev["rr_cluster_id"] = None
        if host in _rr_hosts:
            bgp_cfg = {}
            try:
                p = facts_dirs.get(host)
                if p is not None and (p / "bgp_config.json").exists():
                    bgp_cfg = json.loads((p / "bgp_config.json").read_text())
            except (OSError, ValueError):
                bgp_cfg = {}
            dev["rr_cluster_id"] = bgp_cfg.get("cluster_id") or bgp_cfg.get("router_id")

    # -------------------------------------------------------------------------
    # Step 9b: Extract OSPF LSDB entries (ADR-220)
    # -------------------------------------------------------------------------
    ospf_lsdb = extract_ospf_lsdb(facts_dirs)

    # -------------------------------------------------------------------------
    # Step 10: Discover shared network services
    # -------------------------------------------------------------------------
    shared_services = discover_shared_services(facts_dirs, facts_by_hostname)

    # Enrich VLAN shared services with numeric vlan_id (S19B-1, ADR-186)
    for svc in shared_services:
        if svc.get("service_type") == "vlan":
            try:
                svc["vlan_id"] = int(svc["identifier"])
            except (ValueError, TypeError):
                pass

    # -------------------------------------------------------------------------
    # Step 11: Detect topology warnings
    # -------------------------------------------------------------------------
    # Identifies issues like unidirectional links, devices with no neighbors
    warnings = _detect_warnings(devices, interfaces, links, facts_by_hostname)

    # -------------------------------------------------------------------------
    # Step 11b: Strip internal _genie_name from interfaces (ADR-192)
    # -------------------------------------------------------------------------
    # _genie_name was needed for genie_interface.json lookups during
    # enrichment but is not part of the public model.
    for intf in interfaces:
        intf.pop("_genie_name", None)

    # -------------------------------------------------------------------------
    # Step 11c: Discover L2 broadcast domains (connectivity-based)
    # -------------------------------------------------------------------------
    # Connected components of switches per VLAN over L2 bridging links — the
    # true broadcast domain, vs the ID-based ``shared_services`` VLAN grouping.
    # Pure function of (interfaces, links); consumed by cross-device VLAN/STP
    # rules in a later step.
    l2_domains = discover_l2_domains(interfaces, links)

    # -------------------------------------------------------------------------
    # Step 12: Assemble the model
    # -------------------------------------------------------------------------
    model = {
        "model_metadata": {
            "run_id": run_id,
            "model_version": "0.3.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "collection_timestamp": manifest.get("timestamp_utc"),
        },
        "devices": devices,
        "interfaces": interfaces,
        "links": links,
        "adjacencies": adjacencies,
        "shared_services": shared_services,
        "l2_domains": l2_domains,
        "ospf_lsdb": ospf_lsdb,
        "topology_warnings": warnings,
    }

    # -------------------------------------------------------------------------
    # Step 13: Write model to file
    # -------------------------------------------------------------------------
    _write_model(model, run_path)

    return model


def _build_devices(
    manifest: dict[str, Any],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Build the unified device list from manifest and facts.

    Each device combines:
    - From facts: hostname, platform, version, serial, os_family
    - From manifest: management_ip (the 'target' field)

    ADR-219: facts dirs are named by inventory_name, so facts_by_hostname
    keys are inventory names. Manifest lookups use inventory_name to match.

    Args:
        manifest: The run manifest with device connection info
        facts_by_hostname: Facts keyed by inventory_name (dir name)

    Returns:
        List of device dictionaries, sorted by hostname for determinism
    """
    # -------------------------------------------------------------------------
    # Step 1: Build lookups from manifest keyed by inventory_name (ADR-219)
    # -------------------------------------------------------------------------
    # ADR-219: Use inventory_name as the canonical key for all manifest lookups.
    # Fall back to hostname for backward compat with pre-ADR-219 runs.
    def _manifest_key(device: dict) -> str:
        return device.get("inventory_name") or device["hostname"]

    management_ip_by_name: dict[str, str] = {
        _manifest_key(device): device["target"]
        for device in manifest.get("devices", [])
    }

    # Sprint 10: Extract cluster_declared_size from inventory cluster.size
    cluster_declared_size_by_name: dict[str, int | None] = {}
    for device in manifest.get("devices", []):
        cluster = device.get("cluster")
        key = _manifest_key(device)
        if cluster and isinstance(cluster, dict):
            cluster_declared_size_by_name[key] = cluster.get("size")
        else:
            cluster_declared_size_by_name[key] = None

    # Sprint 11C: Extract role and site from manifest (ADR-074/075)
    role_by_name: dict[str, str] = {
        _manifest_key(device): device.get("role", "unknown")
        for device in manifest.get("devices", [])
    }
    site_by_name: dict[str, str] = {
        _manifest_key(device): device.get("site", "unassigned")
        for device in manifest.get("devices", [])
    }

    # ADR-219: Build real_hostname lookup for metadata
    real_hostname_by_name: dict[str, str] = {
        _manifest_key(device): device.get("hostname", "")
        for device in manifest.get("devices", [])
    }

    # -------------------------------------------------------------------------
    # Step 2: Build device list from facts
    # -------------------------------------------------------------------------
    # ADR-219: facts_by_hostname keys are inventory_name (= directory name)
    devices: list[dict[str, Any]] = []

    for hostname, facts in facts_by_hostname.items():
        # Get device_info from facts (may be None if parsing failed)
        device_info = facts.get("device_info") or {}

        # Build the device dict
        device = {
            "device_id": hostname,
            "hostname": hostname,
            "real_hostname": real_hostname_by_name.get(hostname, hostname),
            "management_ip": management_ip_by_name.get(hostname),
            "platform": device_info.get("platform"),
            "version": device_info.get("version"),
            "serial": device_info.get("serial"),
            # Canonical os_family: hyphen-stripped lowercase (iosxe/iosxr/fortios).
            # The inventory 'os' convention is inconsistent ('ios-xe' vs 'iosxe');
            # model-layer consumers (chunker, interface_classifier, the CIS/STP/VLAN
            # rules) all key on the stripped form, so normalize once here.
            "os_family": (facts.get("os") or "").lower().replace("-", ""),
            "os_raw": facts.get("os"),  # original 'os' value, preserved for reference
            # Sprint 11C: Role and site from inventory (ADR-074/075)
            "role": role_by_name.get(hostname, "unknown"),
            "site": site_by_name.get(hostname, "unassigned"),
            # Sprint 10: Cluster/HA per-member data (ADR-046, ADR-047)
            "cluster_members": facts.get("cluster_members", []),
            "redundancy_group": facts.get("redundancy_group"),
            # Declared cluster size from inventory — compared against observed
            # member count by the CLUSTER_SIZE_MISMATCH rule
            "cluster_declared_size": cluster_declared_size_by_name.get(hostname),
            # Sprint 18: Normalized stack port data from Genie parsers
            # (C9300 cable or C9500 SVL/DAD). Empty for non-stack devices.
            "stack_ports": parse_stack_ports(facts),
        }

        devices.append(device)

    # -------------------------------------------------------------------------
    # Step 3: Sort for determinism
    # -------------------------------------------------------------------------
    # Same input should always produce same output
    # Sorting by hostname ensures consistent ordering
    devices.sort(key=lambda d: d["device_id"])

    return devices


# -------------------------------------------------------------------------
# FortiGate aggregate resolution for LACP unilateral links
# -------------------------------------------------------------------------

def _resolve_fortigate_aggregate_interfaces(
    links: list[dict],
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict],
) -> None:
    """Resolve empty remote_interface on LACP unilateral links to FortiGate.

    FortiGate doesn't expose LACP partner port numbers, so lacp_unilateral
    links from Cisco to FortiGate have remote_interface=''.  This function
    reads fortigate_system_interface.json to build aggregate→member mappings,
    then sets remote_interface to the aggregate name (e.g., 'PO35').

    For each FortiGate device, builds {aggregate_name: [member_names]} from
    interfaces with type='aggregate'.  Then for each LACP unilateral link
    pointing to that FortiGate with empty remote_interface, assigns the
    aggregate name.  When only one data aggregate exists (excluding mgmt
    aggregates like PO_Mgmt), all links get that aggregate.  When multiple
    exist, uses lag_group matching or falls back to the first match.
    """
    import json as _json

    # Find FortiGate devices
    fg_hostnames = {
        h for h, facts in facts_by_hostname.items()
        if (facts.get("os") or "").lower() == "fortios"
    }
    if not fg_hostnames:
        return

    # Build aggregate mappings per FortiGate
    fg_aggregates: dict[str, dict[str, list[str]]] = {}  # hostname → {agg_name: [members]}
    for hostname in fg_hostnames:
        facts_dir = facts_dirs.get(hostname)
        if not facts_dir:
            continue
        sys_path = facts_dir / "fortigate_system_interface.json"
        if not sys_path.is_file():
            continue
        try:
            data = _json.loads(sys_path.read_text())
            results = data.get("results", [])
            if isinstance(results, dict):
                results = list(results.values())
            # Index members by aggregate
            member_to_agg: dict[str, str] = {}
            agg_names: set[str] = set()
            for intf in results:
                if intf.get("type") == "aggregate":
                    agg_names.add(intf["name"])
                agg = intf.get("aggregate", "")
                if agg:
                    member_to_agg[intf["name"]] = agg
            # Build aggregate → members
            aggs: dict[str, list[str]] = {}
            for member, agg in member_to_agg.items():
                aggs.setdefault(agg, []).append(member)
            if aggs:
                fg_aggregates[hostname] = aggs
        except (_json.JSONDecodeError, OSError, KeyError):
            continue

    if not fg_aggregates:
        return

    # Resolve links
    resolved = 0
    for link in links:
        if link.get("discovery_method") != "lacp_unilateral":
            continue
        # Check both directions
        for local_key, remote_key, intf_key in (
            ("local_device_id", "remote_device_id", "remote_interface_id"),
            ("remote_device_id", "local_device_id", "local_interface_id"),
        ):
            remote_dev = link.get(remote_key, "")
            if remote_dev not in fg_aggregates:
                continue
            current_intf = link.get(intf_key, "")
            # Interface ID format is "hostname:intf_name" — check if intf part is empty
            intf_part = current_intf.split(":", 1)[1] if ":" in current_intf else current_intf
            if intf_part:
                continue  # already resolved

            aggs = fg_aggregates[remote_dev]
            # Filter out management aggregates (PO_Mgmt, mgmt-agg, etc.)
            data_aggs = {
                name: members for name, members in aggs.items()
                if "mgmt" not in name.lower()
            }
            if not data_aggs:
                data_aggs = aggs  # fallback to all

            if len(data_aggs) == 1:
                agg_name = next(iter(data_aggs))
                link[intf_key] = f"{remote_dev}:{agg_name}"
                resolved += 1
            # Multiple aggregates: could match by lag_group, but for now
            # use the first non-mgmt aggregate (rare edge case)
            elif data_aggs:
                agg_name = sorted(data_aggs.keys())[0]
                link[intf_key] = f"{remote_dev}:{agg_name}"
                resolved += 1

    if resolved:
        logger.info(
            "FortiGate aggregate resolution: %d LACP links resolved", resolved,
        )


def _build_interfaces(
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Build the unified interface list with type classification.

    Each interface includes:
    - interface_id: "hostname:interface_name" (unique key)
    - device_id: Reference to parent device
    - name: Original interface name
    - type: Classified type (physical, logical, etc.)
    - ip_address, admin_status, oper_status

    Interface ID Format:
        We use "hostname:interface_name" as the unique identifier.
        This is important because interface names like "Gi0/1" are
        not globally unique - many devices have the same port names.

        Example: "core-rtr-01:GigabitEthernet1/0/1"

    Status Normalization:
        Parser outputs have different status strings:
        - IOS XE: "up", "down", "administratively down"
        - IOS XR: "Up", "Down", "Shutdown"

        We normalize these to consistent values:
        - admin_status: "up" or "down" (is it administratively enabled?)
        - oper_status: "up" or "down" (is it operationally working?)

    Args:
        facts_by_hostname: Facts keyed by hostname

    Returns:
        List of interface dictionaries, sorted by interface_id
    """
    interfaces: list[dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Process each device's interfaces
    # -------------------------------------------------------------------------
    for hostname, facts in facts_by_hostname.items():
        # Get the OS type for interface classification
        # Default to empty string if not present (will use generic classifier)
        os_family = facts.get("os", "").replace("-", "")

        # Get interface list from facts
        # May be empty list if parsing failed or no interfaces found
        raw_interfaces = facts.get("interfaces", [])

        # -----------------------------------------------------------------
        # Build reverse LAG lookup from genie_lag.json data
        # Covers IOS XR (no port_channel field in genie_interface.json)
        # and fills any gaps for IOS XE as well.
        # -----------------------------------------------------------------
        genie_lag = facts.get("genie", {}).get("lag", {})
        lag_reverse: dict[str, str] = {}  # member_name → po_name
        for po_name, po_info in genie_lag.get("interfaces", {}).items():
            for member_name in po_info.get("members", {}):
                lag_reverse[member_name] = po_name
                # Also index by normalized short name (e.g. TenGigabitEthernet1/1/1 → Te1/1/1)
                # so venue switches whose facts use short names can match.
                short = normalize_interface_name(member_name)
                if short and short != member_name:
                    lag_reverse[short] = po_name

        # -------------------------------------------------------------------------
        # Process each interface
        # -------------------------------------------------------------------------
        for iface in raw_interfaces:
            # Get interface name - skip if missing
            raw_name = iface.get("name")
            if not raw_name:
                continue

            # -----------------------------------------------------------------
            # Normalize interface name to canonical short form (ADR-192)
            # -----------------------------------------------------------------
            # Genie/config files use vendor-specific long names
            # ("GigabitEthernet1/0/1", "TwentyFiveGigE1/0/10"). Normalize
            # to short form ("Gi1/0/1", "Tw1/0/10") so interfaces and links
            # (which use CDP/LACP abbreviated names) share one format.
            # Keep raw_name for genie_interface.json lookups during enrichment.
            name = normalize_interface_name(raw_name) or raw_name

            # -----------------------------------------------------------------
            # Build unique interface ID
            # -----------------------------------------------------------------
            # Format: "hostname:interface_name"
            # This is globally unique across all devices
            interface_id = f"{hostname}:{name}"

            # -----------------------------------------------------------------
            # Classify interface type
            # -----------------------------------------------------------------
            # FortiGate parsers provide pre-classified "type" field
            # (physical, vlan, tunnel, etc.). Cisco parsers don't, so
            # we classify from name patterns. Use facts type if present.
            interface_type = iface.get("type") or classify_interface(name, os_family)

            # -----------------------------------------------------------------
            # Normalize status values
            # -----------------------------------------------------------------
            # FortiGate parsers provide pre-normalized admin_status/oper_status.
            # Cisco parsers provide raw "status"/"protocol" fields that need
            # normalization. Use pre-normalized values if present.
            if iface.get("admin_status") or iface.get("oper_status"):
                admin_status = iface.get("admin_status", "unknown")
                oper_status = iface.get("oper_status", "unknown")
            else:
                admin_status, oper_status = _normalize_status(
                    status=iface.get("status", ""),
                    protocol=iface.get("protocol", ""),
                )

            # -----------------------------------------------------------------
            # Build interface record
            # -----------------------------------------------------------------
            # Extract prefix_length from Genie interface ipv4 data
            genie_intfs_ip = facts.get("genie", {}).get("interface", {})
            genie_ip_data = genie_intfs_ip.get(raw_name, {}).get("ipv4", {})
            prefix_len = None
            for _cidr, ip_info in genie_ip_data.items():
                if not ip_info.get("secondary", False):
                    prefix_len = ip_info.get("prefix_length")
                    if prefix_len is not None:
                        try:
                            prefix_len = int(prefix_len)
                        except (ValueError, TypeError):
                            prefix_len = None
                    break

            interface = {
                "interface_id": interface_id,
                "device_id": hostname,
                "name": name,
                "_genie_name": raw_name,  # original full name for genie lookups
                "type": interface_type,
                "ip_address": iface.get("ip_address"),
                "prefix_length": prefix_len,
                "admin_status": admin_status,
                "oper_status": oper_status,
            }

            # -----------------------------------------------------------------
            # Port-channel membership (stored as flat fields for Neo4j)
            # -----------------------------------------------------------------
            # IOS XE: genie_interface.json has port_channel.port_channel_int
            genie_intfs = facts.get("genie", {}).get("interface", {})
            genie_data = genie_intfs.get(raw_name, {})
            pc_info = genie_data.get("port_channel")
            if pc_info and pc_info.get("port_channel_member") and pc_info.get("port_channel_int"):
                interface["port_channel_int"] = normalize_interface_name(
                    pc_info["port_channel_int"]
                ) or pc_info["port_channel_int"]
            elif raw_name in lag_reverse:
                # IOS XR (and IOS XE gaps): reverse lookup from genie_lag
                interface["port_channel_int"] = normalize_interface_name(
                    lag_reverse[raw_name]
                ) or lag_reverse[raw_name]
            elif name in lag_reverse:
                # Fallback: lag_reverse may have short names from normalize
                interface["port_channel_int"] = normalize_interface_name(
                    lag_reverse[name]
                ) or lag_reverse[name]
            elif iface.get("port_channel_int"):
                # FortiGate: parser provides port_channel_int from aggregate membership
                interface["port_channel_int"] = iface["port_channel_int"]

            # Members list for Port-channel/Bundle-Ether interfaces
            lag_intf_info = genie_lag.get("interfaces", {}).get(raw_name)
            if lag_intf_info:
                members = sorted(
                    normalize_interface_name(m) or m
                    for m in lag_intf_info.get("members", {}).keys()
                )
                if members:
                    interface["port_channel_members"] = members

            interfaces.append(interface)

    # -------------------------------------------------------------------------
    # Sort for determinism
    # -------------------------------------------------------------------------
    # Same input should always produce same output order
    interfaces.sort(key=lambda i: i["interface_id"])

    return interfaces


def _normalize_status(status: str, protocol: str) -> tuple[str, str]:
    """
    Normalize interface status values to consistent format.

    Different OSes report status differently:
        IOS XE:
            status: "up", "down", "administratively down"
            protocol: "up", "down"
        IOS XR:
            status: "Up", "Down", "Shutdown"
            protocol: "Up", "Down"

    We normalize to:
        admin_status: "up" or "down" (administratively enabled?)
        oper_status: "up" or "down" (operationally working?)

    Logic:
        - If status contains "admin" or "shutdown", admin_status = "down"
        - Otherwise admin_status is based on status field
        - oper_status comes from protocol field

    Args:
        status: Raw status string from parser
        protocol: Raw protocol string from parser

    Returns:
        Tuple of (admin_status, oper_status)

    Examples:
        >>> _normalize_status("up", "up")
        ('up', 'up')
        >>> _normalize_status("administratively down", "down")
        ('down', 'down')
        >>> _normalize_status("Shutdown", "Down")
        ('down', 'down')
    """
    # Convert to lowercase for consistent comparison
    status_lower = status.lower() if status else ""
    protocol_lower = protocol.lower() if protocol else ""

    # -------------------------------------------------------------------------
    # Determine admin_status
    # -------------------------------------------------------------------------
    # Check for administratively down indicators
    if "admin" in status_lower or "shutdown" in status_lower:
        admin_status = "down"
    elif "up" in status_lower:
        admin_status = "up"
    elif "down" in status_lower:
        # Down but not administratively down - interface is enabled but not working
        admin_status = "up"
    else:
        # Unknown status - default to unknown indicator
        admin_status = "unknown"

    # -------------------------------------------------------------------------
    # Determine oper_status
    # -------------------------------------------------------------------------
    # Operational status comes from protocol field
    if "up" in protocol_lower:
        oper_status = "up"
    elif "down" in protocol_lower:
        oper_status = "down"
    else:
        oper_status = "unknown"

    return admin_status, oper_status


# =========================================================================
# L1 Interface Enrichment (Sprint 17, ADR-131)
# =========================================================================

def _enrich_interfaces_l1(
    interfaces: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
    run_path: Path,
) -> None:
    """Enrich interface records with L1 properties: speed, duplex, mtu, description, media_type.

    Reads genie_interface.json (Cisco) or fortigate_*_interface.json (FortiGate)
    from the facts directory. Also parses show_inventory.txt for transceiver/media_type.

    Modifies interfaces in place — no return value.

    Args:
        interfaces: The built interface list (mutated in place).
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        facts_by_hostname: Facts keyed by hostname (for os_family).
        run_path: Path to the run directory (for raw/ files).
    """
    import json as _json

    # Build per-device L1 data caches
    genie_intf_cache: dict[str, dict] = {}   # hostname → genie_interface.json data
    fg_sys_cache: dict[str, dict] = {}       # hostname → {name: sys_intf_entry}
    fg_mon_cache: dict[str, dict] = {}       # hostname → {name: monitor_entry}
    fg_xcvr_cache: dict[str, dict] = {}     # hostname → {port_name: transceiver_entry}
    inventory_cache: dict[str, dict] = {}    # hostname → {name: transceiver_info}

    for hostname, facts_dir in facts_dirs.items():
        os_family = (facts_by_hostname.get(hostname, {}).get("os", "") or "").lower().replace("-", "")

        if os_family in ("iosxe", "iosxr"):
            # Load genie_interface.json
            gi_path = facts_dir / "genie_interface.json"
            if gi_path.is_file():
                try:
                    genie_intf_cache[hostname] = _json.loads(gi_path.read_text())
                except (_json.JSONDecodeError, OSError):
                    pass

            # Load show_inventory.txt for transceiver info
            raw_dir = run_path / "raw" / hostname
            inv_path = raw_dir / "show_inventory.txt"
            if inv_path.is_file():
                try:
                    inventory_cache[hostname] = _parse_inventory_transceivers(
                        inv_path.read_text()
                    )
                except OSError:
                    pass

        elif os_family == "fortios":
            # Load fortigate_system_interface.json (config: alias, mtu)
            sys_path = facts_dir / "fortigate_system_interface.json"
            if sys_path.is_file():
                try:
                    data = _json.loads(sys_path.read_text())
                    fg_sys_cache[hostname] = {
                        entry["name"]: entry
                        for entry in data.get("results", [])
                        if "name" in entry
                    }
                except (_json.JSONDecodeError, OSError):
                    pass

            # Load fortigate_monitor_interface.json (runtime: speed, duplex)
            # Results can be a dict {port_name: entry} or list [{name: ...}]
            mon_path = facts_dir / "fortigate_monitor_interface.json"
            if mon_path.is_file():
                try:
                    data = _json.loads(mon_path.read_text())
                    raw = data.get("results", {})
                    if isinstance(raw, dict):
                        fg_mon_cache[hostname] = {
                            k: v for k, v in raw.items()
                            if isinstance(v, dict)
                        }
                    else:
                        fg_mon_cache[hostname] = {
                            entry["name"]: entry
                            for entry in raw
                            if isinstance(entry, dict) and "name" in entry
                        }
                except (_json.JSONDecodeError, OSError):
                    pass

            # Load fortigate_interface_transceivers.json (SFP PID, vendor, serial)
            xcvr_path = facts_dir / "fortigate_interface_transceivers.json"
            if xcvr_path.is_file():
                try:
                    data = _json.loads(xcvr_path.read_text())
                    fg_xcvr_cache[hostname] = {
                        entry["interface"]: entry
                        for entry in data.get("results", [])
                        if "interface" in entry
                    }
                except (_json.JSONDecodeError, OSError):
                    pass

    # Enrich each interface
    enriched_count = 0
    for intf in interfaces:
        hostname = intf["device_id"]
        name = intf["name"]
        genie_name = intf.get("_genie_name", name)  # original full name for genie lookups
        os_family = (facts_by_hostname.get(hostname, {}).get("os", "") or "").lower().replace("-", "")

        if os_family in ("iosxe", "iosxr"):
            gi = genie_intf_cache.get(hostname, {}).get(genie_name, {})
            inv = inventory_cache.get(hostname, {}).get(canonicalize(genie_name) or genie_name, {})

            intf["speed"] = gi.get("port_speed") or None
            intf["duplex"] = gi.get("duplex_mode") or None
            intf["mtu"] = gi.get("mtu") or None
            intf["description"] = gi.get("description") or None

            # Media type: from transceiver PID if available.
            # Default to "copper" only for GigabitEthernet/FastEthernet (commonly
            # copper). TenGig+ ports without a transceiver PID means no SFP
            # inserted — leave as None. Bandwidth is unreliable (down 100G port
            # reports 100Mbps), so use interface name prefix instead.
            media = inv.get("media_type")
            if not media:
                _COPPER_PREFIXES = ("GigabitEthernet", "FastEthernet", "Ethernet", "Gi", "Fa", "Et",
                                    "MgmtEth", "Mgmt")
                if genie_name.startswith(_COPPER_PREFIXES) and intf.get("type") in ("physical", "management", "unknown"):
                    media = "copper"
                # else: TenGig/TwentyFiveGig/HundredGig/FortyGig — fiber, no SFP
            intf["media_type"] = media or None
            intf["sfp_pid"] = inv.get("pid")

            # Speed override: copper SFP modules in high-speed slots (TenGig+)
            # report slot capability (10G/25G) as port_speed instead of the
            # actual negotiated link speed. Copper SFPs are 1G modules —
            # GLC-T, GLC-TE, SFP-GE-T are 1GBASE-T; SFP-10G-T-X is 10GBASE-T
            # but auto-negotiates to 1G with GigE peers. Override to 1G when
            # media_type is copper-sfp and reported speed exceeds 1G.
            if media == "copper-sfp" and intf.get("speed"):
                spd = (intf["speed"] or "").lower()
                if any(x in spd for x in ("10gb", "25gb", "100gb", "10000", "25000")):
                    intf["speed"] = "1000mb/s"

        elif os_family == "fortios":
            sys_entry = fg_sys_cache.get(hostname, {}).get(name, {})
            mon_entry = fg_mon_cache.get(hostname, {}).get(name, {})

            # Speed from monitor (Mbps) → formatted string
            mon_speed = mon_entry.get("speed", 0)
            if mon_speed and mon_speed > 0:
                speed_mb = int(mon_speed)
                intf["speed"] = f"{speed_mb // 1000}gb/s" if speed_mb >= 1000 else f"{speed_mb}mb/s"
            else:
                intf["speed"] = None

            # Duplex from monitor (1=full, 0=half/unknown)
            mon_duplex = mon_entry.get("duplex")
            if mon_duplex == 1:
                intf["duplex"] = "full"
            elif mon_duplex and mon_duplex > 0:
                intf["duplex"] = "half"
            else:
                intf["duplex"] = None

            # MTU from system config
            intf["mtu"] = sys_entry.get("mtu") or None

            # Description from alias
            alias = sys_entry.get("alias", "")
            intf["description"] = alias if alias else None

            # Media type + SFP PID from transceiver API + system config
            xcvr = fg_xcvr_cache.get(hostname, {}).get(name, {})
            if xcvr:
                intf["sfp_pid"] = xcvr.get("vendor_part_number")
                # Use mediatype from system config for fiber sub-type
                # (sr, lr, sr4, lr4, gmii, etc.)
                raw_mt = (sys_entry.get("mediatype") or "").lower()
                if raw_mt in ("sr", "sr4"):
                    intf["media_type"] = "fiber-sr"
                elif raw_mt in ("lr", "lr4"):
                    intf["media_type"] = "fiber-lr"
                elif raw_mt in ("gmii", "serdes-sfp"):
                    intf["media_type"] = "fiber"
                elif raw_mt and raw_mt != "none":
                    intf["media_type"] = f"fiber-{raw_mt}"
                else:
                    intf["media_type"] = "fiber"
            elif intf.get("type") == "physical":
                intf["sfp_pid"] = None
                intf["media_type"] = "copper"
            else:
                intf["sfp_pid"] = None
                intf["media_type"] = None

        else:
            # Unknown OS — set all L1 fields to None
            intf["speed"] = None
            intf["duplex"] = None
            intf["mtu"] = None
            intf["description"] = None
            intf["media_type"] = None
            intf["sfp_pid"] = None

        if intf.get("speed") or intf.get("duplex") or intf.get("mtu"):
            enriched_count += 1

    # Second pass: port-channel interfaces inherit media_type and sfp_pid
    # from their first member interface (Po64 gets Hu1/0/5's transceiver data).
    intf_by_key: dict[tuple[str, str], dict] = {
        (i["device_id"], i["name"]): i for i in interfaces
    }
    for intf in interfaces:
        members = intf.get("port_channel_members")
        if not members:
            continue
        hostname = intf["device_id"]
        for member_name in members:
            member = intf_by_key.get((hostname, member_name))
            if not member:
                continue
            if not intf.get("media_type") and member.get("media_type"):
                intf["media_type"] = member["media_type"]
            if not intf.get("sfp_pid") and member.get("sfp_pid"):
                intf["sfp_pid"] = member["sfp_pid"]
            if not intf.get("speed") and member.get("speed"):
                intf["speed"] = member["speed"]
            if not intf.get("duplex") and member.get("duplex"):
                intf["duplex"] = member["duplex"]
            if intf.get("media_type") and intf.get("sfp_pid"):
                break  # got everything we need

    logger.info(
        "L1 enrichment: %d of %d interfaces have L1 data",
        enriched_count, len(interfaces),
    )


import re as _re

_INVENTORY_BLOCK_RE = _re.compile(
    r'NAME:\s*"([^"]+)".*?'
    r'DESCR:\s*"([^"]*)".*?'
    r'PID:\s*(\S+)',
    _re.DOTALL,
)


def _parse_inventory_transceivers(inventory_text: str) -> dict[str, dict[str, Any]]:
    """Parse show inventory output for transceiver information.

    Extracts PID, description, serial, and infers media_type from PID keywords.

    Args:
        inventory_text: Raw output of 'show inventory' command.

    Returns:
        Dict mapping interface name → {"pid", "description", "serial", "media_type"}.
    """
    result: dict[str, dict[str, Any]] = {}

    # Split into NAME blocks (each starts with "NAME:")
    blocks = inventory_text.split("NAME:")
    for block in blocks[1:]:  # Skip the empty first split
        block_text = "NAME:" + block

        # Try to extract NAME, DESCR, PID
        match = _INVENTORY_BLOCK_RE.search(block_text)
        if not match:
            continue

        name = match.group(1).strip()
        descr = match.group(2).strip()
        pid = match.group(3).strip()

        # Only care about interface transceiver entries
        # Skip chassis, power supply, fan, etc.
        # Interface names contain digits with slashes (Gi1/0/1, Te1/1/1, etc.)
        if "/" not in name and not name.startswith(("Gi", "Te", "Fo", "Tw", "Hu", "Fa")):
            continue

        # Extract serial number if present
        serial_match = _re.search(r'SN:\s*(\S+)', block_text)
        serial = serial_match.group(1) if serial_match else None

        # Infer media type from PID
        pid_upper = pid.upper()
        if "AOC" in pid_upper:
            media_type = "fiber-aoc"
        elif "SR" in pid_upper or "CSR" in pid_upper:
            media_type = "fiber-sr"
        elif "LR" in pid_upper:
            media_type = "fiber-lr"
        elif "ER" in pid_upper:
            media_type = "fiber-er"
        elif "ZR" in pid_upper:
            media_type = "fiber-zr"
        elif "SX" in pid_upper:
            media_type = "fiber-mm"
        elif (
            "CU" in pid_upper
            or "GLC-TE" in pid_upper
            or "GLC-T" in pid_upper
            or "10G-T" in pid_upper   # SFP-10G-T, SFP-10G-T-X (10GBASE-T copper)
            or "GE-T" in pid_upper    # SFP-GE-T (1G copper SFP)
            or "CR" in pid_upper      # SFP-25G-CR, QSFP-40G-CR4 (copper DAC)
        ):
            media_type = "copper-sfp"
        elif pid_upper and pid_upper != "N/A":
            # Before defaulting to fiber, check DESCR for copper indicators.
            # Third-party SFPs (e.g., VENDOR-SFP-1G-T) have unrecognized PIDs but
            # DESCR reveals the actual type (e.g., "GE T" = 1G copper).
            descr_upper = descr.upper()
            if any(kw in descr_upper for kw in (
                "GE T", "1000BASE-T", "10GBASE-T", "COPPER", "BASE-T",
            )):
                media_type = "copper-sfp"
            else:
                media_type = "fiber"
        else:
            media_type = None

        # Store by canonical key so abbreviated names (Twe1/0/1) match
        # long-form names (TwentyFiveGigE1/0/1) at lookup time.
        key = canonicalize(name) or name
        result[key] = {
            "pid": pid if pid != "N/A" else None,
            "description": descr if descr else None,
            "serial": serial,
            "media_type": media_type,
        }

    return result


# -------------------------------------------------------------------------
# QoS enrichment (Sprint 18B, S18B-2)
# -------------------------------------------------------------------------

def _enrich_interfaces_qos(
    interfaces: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
) -> None:
    """
    Enrich interface records with QoS policy data.

    Reads genie_policy_map.json and genie_policy_map_interface.json from
    each device's facts directory. Correlates policy definitions with
    per-interface counters and adds a `qos` dict to each interface.

    Same pattern as _enrich_interfaces_l1() — modifies interfaces in place.

    Interfaces with no service-policy get qos=null. Devices with no QoS
    data files are skipped (no enrichment, no error).

    Args:
        interfaces: The built interface list (mutated in place).
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
    """
    import json as _json
    from netcopilot.parse.cisco_native.qos import parse_qos_for_interfaces

    # -------------------------------------------------------------------------
    # Group interfaces by device for efficient per-device processing
    # -------------------------------------------------------------------------
    interfaces_by_device: dict[str, list[dict[str, Any]]] = {}
    for intf in interfaces:
        dev_id = intf.get("device_id", "")
        interfaces_by_device.setdefault(dev_id, []).append(intf)

    # -------------------------------------------------------------------------
    # Process each device that has QoS facts
    # -------------------------------------------------------------------------
    devices_with_qos = 0
    interfaces_with_qos = 0

    for hostname, device_intfs in interfaces_by_device.items():
        facts_dir = facts_dirs.get(hostname)
        if not facts_dir:
            # No facts directory — set qos=null on all interfaces
            for intf in device_intfs:
                intf["qos"] = None
            continue

        # Load QoS files — both are needed for full correlation
        pm_path = facts_dir / "genie_policy_map.json"
        pmi_path = facts_dir / "genie_policy_map_interface.json"

        if not pmi_path.exists():
            # No per-interface QoS data — set qos=null on all interfaces
            for intf in device_intfs:
                intf["qos"] = None
            continue

        try:
            pm_data = {}
            if pm_path.exists():
                pm_data = _json.loads(pm_path.read_text(encoding="utf-8"))
            pmi_data = _json.loads(pmi_path.read_text(encoding="utf-8"))
        except (_json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "QoS enrichment: failed to read QoS files for %s: %s",
                hostname, exc,
            )
            for intf in device_intfs:
                intf["qos"] = None
            continue

        # Parse QoS data into per-interface dicts
        qos_by_intf = parse_qos_for_interfaces(pm_data, pmi_data)

        if qos_by_intf:
            devices_with_qos += 1

        # Apply QoS data to interfaces
        for intf in device_intfs:
            genie_name = intf.get("_genie_name", intf.get("name", ""))
            qos_data = qos_by_intf.get(genie_name)
            if qos_data:
                intf["qos"] = qos_data
                interfaces_with_qos += 1
            else:
                intf["qos"] = None

    logger.info(
        "QoS enrichment: %d devices with QoS, %d interfaces enriched",
        devices_with_qos, interfaces_with_qos,
    )


# -------------------------------------------------------------------------
# Switchport enrichment (Sprint 19B, ADR-191)
# -------------------------------------------------------------------------

_INTF_LINE_RE = re.compile(r"^interface\s+(\S+)")
_VRF_FWD_RE = re.compile(r"^\s+(?:ip\s+)?vrf\s+(?:forwarding\s+)?(\S+)")
_SW_MODE_RE = re.compile(r"^\s+switchport\s+mode\s+(\S+)")
_SW_ACCESS_VLAN_RE = re.compile(r"^\s+switchport\s+access\s+vlan\s+(\d+)")
_SW_TRUNK_ALLOWED_RE = re.compile(r"^\s+switchport\s+trunk\s+allowed\s+vlan\s+(.+)")
_SW_TRUNK_NATIVE_RE = re.compile(r"^\s+switchport\s+trunk\s+native\s+vlan\s+(\d+)")


def _expand_vlan_range(vlan_spec: str) -> list[int]:
    """Expand a Cisco VLAN list string into a sorted list of ints.

    Handles comma-separated values and dash ranges:
        "100,200-203,300" → [100, 200, 201, 202, 203, 300]
        "1800,1801,1890"  → [1800, 1801, 1890]
        "all"             → [] (empty — 'all' cannot be enumerated)
    """
    result: list[int] = []
    for part in vlan_spec.split(","):
        part = part.strip()
        if not part or part.lower() in ("all", "none"):
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                for v in range(int(lo), int(hi) + 1):
                    result.append(v)
            except (ValueError, TypeError):
                continue
        else:
            try:
                result.append(int(part))
            except (ValueError, TypeError):
                continue
    return sorted(set(result))


def _parse_switchport_from_config(
    config_text: str,
) -> dict[str, dict[str, Any]]:
    """Parse running-config for per-interface switchport properties.

    Returns:
        Dict mapping interface full name → {
            "switchport_mode": "access"|"trunk",
            "access_vlan": int|None,
            "trunk_vlans": list[int]|None,
            "native_vlan": int|None,
        }
    """
    result: dict[str, dict[str, Any]] = {}
    current_intf: str | None = None
    current_data: dict[str, Any] = {}

    for line in config_text.splitlines():
        # New interface block
        m = _INTF_LINE_RE.match(line)
        if m:
            # Save previous interface if it had switchport data
            if current_intf and current_data.get("switchport_mode"):
                result[current_intf] = current_data
            current_intf = m.group(1)
            current_data = {}
            continue

        if current_intf is None:
            continue

        # End of interface block (line not indented)
        if line and not line[0].isspace() and line[0] != "!":
            if current_data.get("switchport_mode"):
                result[current_intf] = current_data
            current_intf = None
            current_data = {}
            continue

        m = _SW_MODE_RE.match(line)
        if m:
            current_data["switchport_mode"] = m.group(1)
            continue

        m = _SW_ACCESS_VLAN_RE.match(line)
        if m:
            current_data["access_vlan"] = int(m.group(1))
            continue

        m = _SW_TRUNK_ALLOWED_RE.match(line)
        if m:
            vlan_spec = m.group(1)
            # Strip "add" keyword from continuation lines
            if vlan_spec.startswith("add "):
                vlan_spec = vlan_spec[4:]
            new_vlans = _expand_vlan_range(vlan_spec)
            prev = current_data.get("trunk_vlans", [])
            current_data["trunk_vlans"] = sorted(set(prev + new_vlans))
            continue

        m = _SW_TRUNK_NATIVE_RE.match(line)
        if m:
            current_data["native_vlan"] = int(m.group(1))
            continue

    # Flush last interface
    if current_intf and current_data.get("switchport_mode"):
        result[current_intf] = current_data

    return result


def _parse_vrf_from_config(config_text: str) -> dict[str, str]:
    """Parse running-config for per-interface VRF assignments.

    Handles both IOS XE (``ip vrf forwarding <name>`` /
    ``vrf forwarding <name>``) and IOS XR (``vrf <name>``).

    Returns:
        Dict mapping interface full name → VRF name.
    """
    result: dict[str, str] = {}
    current_intf: str | None = None

    for line in config_text.splitlines():
        m = _INTF_LINE_RE.match(line)
        if m:
            current_intf = m.group(1)
            continue

        if current_intf is None:
            continue

        # End of interface block
        if line and not line[0].isspace() and line[0] != "!":
            current_intf = None
            continue

        m = _VRF_FWD_RE.match(line)
        if m:
            result[current_intf] = m.group(1)
            continue

    return result


def _enrich_fortigate_switchport(
    device_intfs: list[dict[str, Any]],
    facts_dir: Path,
) -> int:
    """Enrich FortiGate interfaces with VLAN assignments.

    Parses fortigate_system_interface.json to extract:
    - type=vlan entries → switchport_mode='access', access_vlan=vlanid
    - type=aggregate entries → switchport_mode='trunk', trunk_vlans from child VLANs

    Returns the number of interfaces enriched.
    """
    import json as _json

    sys_path = facts_dir / "fortigate_system_interface.json"
    if not sys_path.is_file():
        return 0
    try:
        data = _json.loads(sys_path.read_text(encoding="utf-8"))
    except (_json.JSONDecodeError, OSError):
        return 0

    results = data.get("results", data) if isinstance(data, dict) else data
    if not isinstance(results, list):
        return 0

    # Determine the data VDOM — same heuristic as discover_fdb_firewall_links():
    # the VDOM with the most aggregate interfaces.
    agg_vdom_count: dict[str, int] = {}
    for entry in results:
        if entry.get("type") == "aggregate" and entry.get("member"):
            vdom = entry.get("vdom", "root")
            agg_vdom_count[vdom] = agg_vdom_count.get(vdom, 0) + 1
    data_vdom = max(agg_vdom_count, key=lambda v: agg_vdom_count[v]) if agg_vdom_count else None

    # Build VLAN→parent mapping, aggregate→VLANs mapping, and hierarchy lookups.
    # Only process entries from the data VDOM (filter out other VDOMs).
    vlan_by_name: dict[str, int] = {}
    agg_vlans: dict[str, list[int]] = {}
    vdom_by_name: dict[str, str] = {}
    parent_by_name: dict[str, str] = {}
    members_by_agg: dict[str, list[str]] = {}

    for entry in results:
        # Skip non-data-VDOM entries
        entry_vdom = entry.get("vdom", "")
        if data_vdom and entry_vdom != data_vdom:
            continue
        etype = entry.get("type", "")
        ename = entry.get("name", "")

        # Track VDOM for all data-VDOM entries
        if ename:
            vdom_by_name[ename] = entry_vdom

        if etype == "vlan":
            vid = entry.get("vlanid")
            if vid is not None:
                vlan_by_name[ename] = int(vid)
                parent = entry.get("interface", "")
                if parent:
                    agg_vlans.setdefault(parent, []).append(int(vid))
                    parent_by_name[ename] = parent
        elif etype == "aggregate":
            members = entry.get("member", [])
            members_by_agg[ename] = sorted(
                m.get("interface-name", "") for m in members if m.get("interface-name")
            )

    # Build interface name → enrichment data
    switchport_data: dict[str, dict[str, Any]] = {}
    for name, vid in vlan_by_name.items():
        switchport_data[name] = {"switchport_mode": "access", "access_vlan": vid}
    for agg_name, vlans in agg_vlans.items():
        switchport_data[agg_name] = {
            "switchport_mode": "trunk",
            "trunk_vlans": sorted(set(vlans)),
        }

    # Apply to model interfaces
    count = 0
    for intf in device_intfs:
        name = intf.get("name", "")

        # Set hierarchy fields for all data-VDOM interfaces
        if name in vdom_by_name:
            intf["vdom"] = vdom_by_name[name]
        if name in vlan_by_name:
            intf["vlanid"] = vlan_by_name[name]
        if name in parent_by_name:
            intf["parent_interface"] = parent_by_name[name]
        if name in members_by_agg:
            intf["aggregate_members"] = members_by_agg[name]

        # Set switchport data
        sw = switchport_data.get(name)
        if not sw:
            continue
        intf["switchport_mode"] = sw["switchport_mode"]
        if sw["switchport_mode"] == "access":
            intf["access_vlan"] = sw.get("access_vlan")
        elif sw["switchport_mode"] == "trunk":
            intf["trunk_vlans"] = sw.get("trunk_vlans")
        count += 1

    return count


def _enrich_interfaces_switchport(
    interfaces: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> None:
    """Enrich interfaces with switchport mode and VLAN assignments.

    Parses running_config.txt for each Cisco device and sets:
    - switchport_mode: "access" | "trunk"
    - access_vlan: int (access ports)
    - trunk_vlans: list[int] (trunk ports)
    - native_vlan: int (trunk ports, optional)

    FortiGate and unknown OS devices are skipped (no running_config.txt).
    Modifies interfaces in place.
    """
    # Group interfaces by device
    interfaces_by_device: dict[str, list[dict[str, Any]]] = {}
    for intf in interfaces:
        dev_id = intf.get("device_id", "")
        interfaces_by_device.setdefault(dev_id, []).append(intf)

    enriched_count = 0

    for hostname, device_intfs in interfaces_by_device.items():
        os_family = (facts_by_hostname.get(hostname, {}).get("os", "") or "").lower().replace("-", "")

        # --- FortiGate: parse VLAN interfaces from fortigate_system_interface.json ---
        if os_family == "fortios":
            facts_dir = facts_dirs.get(hostname)
            if not facts_dir:
                continue
            enriched_count += _enrich_fortigate_switchport(
                device_intfs, facts_dir,
            )
            continue

        # --- Cisco (IOS XE / IOS XR): parse running_config.txt ---
        if os_family not in ("iosxe", "iosxr"):
            continue

        facts_dir = facts_dirs.get(hostname)
        if not facts_dir:
            continue

        config_path = facts_dir / "running_config.txt"
        if not config_path.is_file():
            continue

        try:
            config_text = config_path.read_text(encoding="utf-8")
        except OSError:
            continue

        switchport_data = _parse_switchport_from_config(config_text)
        vrf_data = _parse_vrf_from_config(config_text)

        for intf in device_intfs:
            genie_name = intf.get("_genie_name", intf.get("name", ""))

            # VRF assignment
            vrf_name = vrf_data.get(genie_name)
            if vrf_name:
                intf["vrf"] = vrf_name

            # Switchport data
            sw = switchport_data.get(genie_name)
            if not sw:
                continue

            mode = sw.get("switchport_mode")
            intf["switchport_mode"] = mode

            if mode == "access":
                intf["access_vlan"] = sw.get("access_vlan")
            elif mode == "trunk":
                intf["trunk_vlans"] = sw.get("trunk_vlans")
                intf["native_vlan"] = sw.get("native_vlan")

            enriched_count += 1

    logger.info(
        "Switchport enrichment: %d interfaces enriched with VLAN/VRF data",
        enriched_count,
    )


# -------------------------------------------------------------------------
# Device VLAN enrichment (Sprint 19B, Step 4e)
# -------------------------------------------------------------------------

# Default VLANs to exclude — present on every switch by default
_DEFAULT_VLAN_IDS = {"1", "1002", "1003", "1004", "1005"}


def _enrich_devices_vlans(
    devices: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
) -> None:
    """Enrich device dicts with VLAN database from genie_vlan.json.

    Populates ``device["vlans"]`` with a sorted list of VLAN entries.
    Devices without genie_vlan.json get an empty list.

    ADR-219: facts_dirs keyed by inventory_name, matching device["hostname"].
    """
    device_by_hostname: dict[str, dict[str, Any]] = {
        d["hostname"]: d for d in devices
    }

    enriched = 0
    total_vlans = 0

    for hostname, facts_dir in facts_dirs.items():
        device = device_by_hostname.get(hostname)
        if device is None:
            continue

        vlan_path = facts_dir / "genie_vlan.json"
        if not vlan_path.exists():
            device["vlans"] = []
            continue

        try:
            raw = json.loads(vlan_path.read_text())
        except (json.JSONDecodeError, OSError):
            device["vlans"] = []
            continue

        vlans_dict = raw.get("vlans", raw)
        vlan_entries: list[dict[str, Any]] = []

        # Build SVI VLAN ID set from genie_interface.json (Vlan<N> interfaces).
        # Used to include L3-only VLANs (no access ports, but routed via SVI).
        svi_vlan_ids: set[int] = set()
        intf_path = facts_dir / "genie_interface.json"
        if intf_path.exists():
            try:
                intf_raw = json.loads(intf_path.read_text())
                for intf_name in intf_raw:
                    if intf_name.startswith("Vlan"):
                        try:
                            svi_vlan_ids.add(int(intf_name[4:]))
                        except ValueError:
                            pass
            except (json.JSONDecodeError, OSError):
                pass

        for vlan_id_str, block in vlans_dict.items():
            if vlan_id_str in _DEFAULT_VLAN_IDS:
                continue
            if block.get("state") == "unsupport":
                continue

            try:
                vlan_id = int(vlan_id_str)
            except (ValueError, TypeError):
                continue

            # Normalize interface names (ADR-192)
            raw_intfs = block.get("interfaces", [])
            norm_intfs = []
            for intf_name in raw_intfs:
                norm = normalize_interface_name(intf_name)
                norm_intfs.append(norm if norm else intf_name)

            # Skip VLANs with no active presence on this device.
            # VTP clients inherit the full network VLAN database (700+ entries)
            # but only a fraction are locally active. Include a VLAN only if it
            # has active switch ports (norm_intfs) or an SVI (Vlan<N> interface).
            if not norm_intfs and vlan_id not in svi_vlan_ids:
                continue

            vlan_entries.append({
                "vlan_id": vlan_id,
                "name": block.get("name"),
                "state": block.get("state", "active"),
                "shutdown": bool(block.get("shutdown", False)),
                "interfaces": sorted(norm_intfs),
            })

        device["vlans"] = sorted(vlan_entries, key=lambda v: v["vlan_id"])
        if vlan_entries:
            enriched += 1
            total_vlans += len(vlan_entries)

    # Ensure devices not in facts_dirs also get empty vlans
    for device in devices:
        if "vlans" not in device:
            device["vlans"] = []

    logger.info(
        "VLAN enrichment: %d devices enriched, %d total VLANs",
        enriched, total_vlans,
    )


# -------------------------------------------------------------------------
# Member ID assignment (Sprint 18, S18-7)
# -------------------------------------------------------------------------

# Regex to extract member ID from interface name — first digit after the
# type prefix. Matches patterns like Gi1/0/23 → member 1, Hu2/0/1 → member 2,
# Tw1/0/24 → member 1, Te2/0/10 → member 2.
_MEMBER_INTF_RE = re.compile(r"^[A-Za-z]+(\d+)/")

# Virtual interface prefixes — these don't belong to a specific stack member.
_VIRTUAL_PREFIXES = ("Vl", "Vlan", "Lo", "Loopback", "Po", "Port-channel",
                     "Tu", "Tunnel", "BVI", "Bluetooth", "Gi0/", "mgmt",
                     "Mgmt", "AppGigabitEthernet")


def _extract_member_from_interface(interface_id: str | None) -> int | None:
    """
    Extract stack member ID from a compound interface ID.

    Parses "DEVICE:Gi1/0/23" → 1, "DEVICE:Hu2/0/1" → 2.
    Returns None for virtual interfaces or unparseable names.
    """
    if not interface_id:
        return None

    # Extract interface name from "DEVICE:INTERFACE"
    parts = interface_id.split(":", 1)
    intf_name = parts[1] if len(parts) == 2 else parts[0]

    if not intf_name:
        return None

    # Virtual interfaces don't belong to a specific member
    for prefix in _VIRTUAL_PREFIXES:
        if intf_name.startswith(prefix):
            return None

    # FortiGate interface names (port1, x1, 99) don't encode member
    if intf_name[0].isdigit() or intf_name.startswith("port") or intf_name.startswith("x"):
        return None

    # Extract first digit after type prefix
    m = _MEMBER_INTF_RE.match(intf_name)
    if m:
        return int(m.group(1))

    return None


def _assign_member_ids(
    links: list[dict[str, Any]],
    devices: list[dict[str, Any]],
) -> None:
    """
    Assign source_member_id and target_member_id to link endpoints.

    For stacked devices (cluster_declared_size >= 2), parses the interface
    name to determine which stack member the cable connects to. Only assigns
    member IDs for devices that are actually stacked.

    FortiGate links use the ha_member field instead of interface parsing.

    Mutates links in place.

    Args:
        links: List of link dicts (mutated in place).
        devices: List of device dicts from the model.
    """
    # Build set of stacked device names for O(1) lookup
    stacked_devices = {
        d["hostname"]
        for d in devices
        if (d.get("cluster_declared_size") or 0) >= 2
    }

    if not stacked_devices:
        return

    # Build set of FortiGate HA device names (use ha_member for member IDs
    # instead of interface parsing, since FG port names don't encode member)
    fortios_devices = {
        d["hostname"]
        for d in devices
        if d.get("os_family") == "fortios"
        and (d.get("cluster_declared_size") or 0) >= 2
    }

    # Build active member ID lookup for Cisco stacks.
    # Virtual interfaces (Gi0/0, Loopback, etc.) belong to the active member.
    active_member_id: dict[str, int] = {}
    for d in devices:
        hn = d.get("hostname", "")
        if hn not in stacked_devices or hn in fortios_devices:
            continue
        for cm in d.get("cluster_members", []):
            if (cm.get("role") or "").lower() == "active":
                active_member_id[hn] = cm.get("member_id")
                break

    for link in links:
        # Non-cable management links (ARP/subnet, dp≥7) are logical —
        # skip member attribution.  Cable-based mgmt links (CDP/FDB, dp≤6)
        # still need member IDs for compound node edge routing.
        if link.get("link_type") == "management" and (link.get("discovery_priority") or 99) >= 7:
            continue

        local_dev = link.get("local_device_id", "")
        remote_dev = link.get("remote_device_id", "")
        src_member = None
        tgt_member = None

        # Source member (local device side)
        if local_dev in stacked_devices:
            if local_dev in fortios_devices and link.get("ha_member") is not None:
                ha_member = link["ha_member"]
                src_member = 0 if ha_member == "active" else 1
            else:
                src_member = _extract_member_from_interface(
                    link.get("local_interface_id")
                )

        # Target member (remote device side)
        if remote_dev in stacked_devices:
            if remote_dev in fortios_devices and link.get("ha_member") is not None:
                ha_member = link["ha_member"]
                tgt_member = 0 if ha_member == "active" else 1
            else:
                tgt_member = _extract_member_from_interface(
                    link.get("remote_interface_id")
                )

        # Fallback for virtual interfaces (Gi0/0, Bluetooth, etc.):
        # 1. If peer's member is known, use it (cable follows the physical member)
        # 2. Otherwise, use the active member
        if local_dev in stacked_devices and src_member is None:
            if tgt_member is not None and local_dev not in fortios_devices:
                src_member = tgt_member
            elif local_dev in active_member_id:
                src_member = active_member_id[local_dev]

        if remote_dev in stacked_devices and tgt_member is None:
            if src_member is not None and remote_dev not in fortios_devices:
                tgt_member = src_member
            elif remote_dev in active_member_id:
                tgt_member = active_member_id[remote_dev]

        if src_member is not None:
            link["source_member_id"] = src_member
        if tgt_member is not None:
            link["target_member_id"] = tgt_member

        # Stack interconnect links already have member IDs
        if link.get("link_type") == "stack_interconnect":
            link["source_member_id"] = link.get("local_member_id")
            link["target_member_id"] = link.get("remote_member_id")


def _resolve_portchannel_member_ids(
    links: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    facts_dirs: dict[str, Any],
) -> None:
    """Correct source_member_id for CDP bilateral links with port-channel interfaces.

    When a CDP bilateral link terminates on a port-channel (Po/Be) of a stacked
    device, _assign_member_ids() cannot extract the member from the interface name
    and falls back to the active member (always member 1 for Cisco SVL stacks).
    This leaves all CDP venue uplinks attributed to member 1, even when some
    physically connect to member 2.

    This function reads genie_lag.json partner MACs for the local device and
    resolves each member's partner_id to a hostname. When a partner resolves to
    the link's remote device, the member's interface name gives the correct
    source_member_id (e.g. Hu2/0/3 → member 2).

    Mutates links in place. Called after _assign_member_ids().

    Args:
        links: Link dicts (mutated in place).
        devices: Device dicts from the model.
        facts_dirs: Map of hostname → facts directory Path.
    """
    from netcopilot.model.link_builder import (
        _build_mac_lookup,
        _strip_lacp_priority_prefix,
        _load_json_file,
    )

    stacked = {
        d["hostname"]
        for d in devices
        if (d.get("cluster_declared_size") or 0) >= 2
    }
    if not stacked:
        return

    mac_table = _build_mac_lookup(facts_dirs)

    _PO_LONG = ("port-channel", "bundle-ether")
    _PO_SHORT = ("po", "be")

    for link in links:
        if link.get("discovery_method") != "cdp_bilateral":
            continue

        local_dev = link.get("local_device_id", "")
        if local_dev not in stacked:
            continue

        local_intf_id = link.get("local_interface_id", "")
        local_intf = local_intf_id.split(":", 1)[-1] if ":" in local_intf_id else local_intf_id
        intf_lower = local_intf.lower()

        if not (
            any(intf_lower.startswith(p) for p in _PO_LONG)
            or any(
                intf_lower.startswith(p) and len(intf_lower) > len(p) and intf_lower[len(p)].isdigit()
                for p in _PO_SHORT
            )
        ):
            continue

        facts_dir = facts_dirs.get(local_dev)
        if not facts_dir:
            continue

        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if not lag_data:
            continue

        remote_dev = link.get("remote_device_id", "")

        # Scan all port-channel members — find the one whose partner MAC
        # resolves to remote_dev, then set source_member_id from its interface name.
        found = False
        for po_info in lag_data.get("interfaces", {}).values():
            for member_name, member_info in po_info.get("members", {}).items():
                partner_id = member_info.get("partner_id")
                if not partner_id:
                    continue
                partner_mac = _strip_lacp_priority_prefix(partner_id)
                if mac_table.get(partner_mac) == remote_dev:
                    member_id = _extract_member_from_interface(f"{local_dev}:{member_name}")
                    if member_id is not None:
                        link["source_member_id"] = member_id
                        found = True
                        break
            if found:
                break


def _detect_warnings(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    links: list[dict[str, Any]],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Detect topology warnings and issues.

    Warning Types (Sprint 12 — multi-method discovery):
        - isolated_device: Device has no links from any discovery method
        - unidirectional_link: Only one side reports the connection
        - link_down: Link has status "down" (connectivity problem)
        - link_admin_down: Link is administratively disabled
        - low_confidence_only: Device links discovered only via low-confidence
          methods (ARP, MAC, subnet) — no CDP/LLDP confirmation
        - external_peers: Link endpoints outside the collection inventory
        - role_missing: Device has no role assigned in inventory (Sprint 11C)
        - site_missing: Device has no site assigned in inventory (Sprint 11C)

    Warning Structure:
        Each warning is a dict with:
        - warning_id: Unique identifier for this warning
        - type: Warning type (from list above)
        - severity: "error" | "warning" | "info"
        - message: Human-readable description
        - affected_elements: List of device/interface/link IDs affected
        - details: Additional context (optional)

    Args:
        devices: The built device list
        interfaces: The built interface list
        links: The built link list
        facts_by_hostname: Original facts for reference

    Returns:
        List of warning dictionaries, sorted by warning_id
    """
    warnings: list[dict[str, Any]] = []
    warning_counter = 0

    # -------------------------------------------------------------------------
    # Pre-compute: devices that appear in any link
    # -------------------------------------------------------------------------
    # Used by isolated_device and low_confidence_only warnings.
    # Build a set of all hostnames that appear as either end of any link.
    devices_with_links: set[str] = set()
    for link in links:
        devices_with_links.add(link["local_device_id"])
        devices_with_links.add(link["remote_device_id"])

    # -------------------------------------------------------------------------
    # Warning Type 1: Isolated Devices (no links from any discovery method)
    # -------------------------------------------------------------------------
    # A device with no links at all might indicate:
    # - Legitimate: standalone device, access layer switch
    # - Problem: discovery protocols disabled, physically disconnected
    #
    # We check against all 5 discovery levels (CDP, LLDP, ARP, MAC, subnet),
    # not just CDP. Severity is "info" since it's not necessarily an error.
    for hostname in facts_by_hostname:
        if hostname not in devices_with_links:
            warning_counter += 1
            warnings.append({
                "warning_id": f"W{warning_counter:04d}",
                "type": "isolated_device",
                "severity": "info",
                "message": f"Device '{hostname}' has no discovered links",
                "affected_elements": [hostname],
                "details": {
                    "possible_causes": [
                        "CDP/LLDP disabled on all interfaces",
                        "Device is standalone (not connected to other managed devices)",
                        "All connected neighbors are outside collection scope",
                        "Device is physically disconnected",
                        "No shared subnets with other collected devices",
                    ]
                },
            })

    # -------------------------------------------------------------------------
    # Warning Type 2: Unidirectional Links (CDP/LLDP only)
    # -------------------------------------------------------------------------
    # A unidirectional CDP/LLDP link means one side reports the neighbor but
    # the other side does not. This is genuinely concerning — possible causes
    # include CDP/LLDP disabled on one side, interface name mismatch, or
    # collection scope gaps.
    #
    # ARP/MAC/subnet links are ALWAYS unidirectional by nature (one-sided
    # evidence), so generating a warning for each one is noise. These are
    # already flagged via "low_confidence_only" warning (Type 5) if no
    # CDP/LLDP confirmation exists.
    for link in links:
        if link["direction"] != "unidirectional":
            continue
        discovery = link.get("discovery_method", "unknown")
        # Only warn for CDP/LLDP — ARP/MAC/subnet are inherently unidirectional
        if not (discovery.startswith("cdp") or discovery.startswith("lldp")):
            continue
        warning_counter += 1
        warnings.append({
            "warning_id": f"W{warning_counter:04d}",
            "type": "unidirectional_link",
            "severity": "warning",
            "message": (
                f"Unidirectional link between {link['local_device_id']} "
                f"and {link['remote_device_id']}"
            ),
            "affected_elements": [
                link["link_id"],
                link["local_device_id"],
                link["remote_device_id"],
            ],
            "details": {
                "link_id": link["link_id"],
                "reporting_device": link["local_device_id"],
                "discovery_method": discovery,
                "possible_causes": [
                    "Discovery protocol disabled on remote device",
                    "Remote device not in collection scope",
                    "Interface name mismatch in discovery data",
                ],
            },
        })

    # -------------------------------------------------------------------------
    # Warning Type 3: Links with Down Status
    # -------------------------------------------------------------------------
    # Links that are operationally down indicate connectivity problems.
    # Severity is "error" because this typically means loss of connectivity.
    for link in links:
        if link["status"] == "down":
            warning_counter += 1
            warnings.append({
                "warning_id": f"W{warning_counter:04d}",
                "type": "link_down",
                "severity": "error",
                "message": (
                    f"Link down between {link['local_device_id']} "
                    f"and {link['remote_device_id']}"
                ),
                "affected_elements": [
                    link["link_id"],
                    link["local_interface_id"],
                    link["remote_interface_id"],
                ],
                "details": {
                    "link_id": link["link_id"],
                    "local_interface": link["local_interface_id"],
                    "remote_interface": link["remote_interface_id"],
                    "possible_causes": [
                        "Cable disconnected or damaged",
                        "Port error (CRC, input errors)",
                        "Speed/duplex mismatch",
                        "Remote device powered off",
                    ],
                },
            })

    # -------------------------------------------------------------------------
    # Warning Type 4: Links Administratively Down
    # -------------------------------------------------------------------------
    # Links that are admin down are intentionally disabled.
    # Severity is "info" because this is usually deliberate.
    for link in links:
        if link["status"] == "admin_down":
            warning_counter += 1
            warnings.append({
                "warning_id": f"W{warning_counter:04d}",
                "type": "link_admin_down",
                "severity": "info",
                "message": (
                    f"Link administratively down between {link['local_device_id']} "
                    f"and {link['remote_device_id']}"
                ),
                "affected_elements": [
                    link["link_id"],
                    link["local_interface_id"],
                    link["remote_interface_id"],
                ],
                "details": {
                    "link_id": link["link_id"],
                    "local_interface": link["local_interface_id"],
                    "remote_interface": link["remote_interface_id"],
                    "note": "One or both interfaces are administratively shutdown",
                },
            })

    # -------------------------------------------------------------------------
    # Warning Type 5: Low-Confidence-Only Links (Sprint 12)
    # -------------------------------------------------------------------------
    # If ALL links for a device are low-confidence (ARP, MAC, subnet-only)
    # with no CDP/LLDP confirmation, flag it. This typically means CDP/LLDP
    # is disabled or the device is only reachable via L3 inference.
    #
    # Confidence hierarchy: very_high > high > medium > low > very_low
    # "Low-confidence-only" means no link has confidence "very_high" or "high".
    _HIGH_CONFIDENCE = {"very_high", "high"}

    # Build per-device best confidence
    best_confidence_by_device: dict[str, str] = {}
    for link in links:
        for dev_id in (link["local_device_id"], link["remote_device_id"]):
            conf = link.get("confidence", "unknown")
            if conf in _HIGH_CONFIDENCE:
                best_confidence_by_device[dev_id] = "high"  # shortcut
            elif dev_id not in best_confidence_by_device:
                best_confidence_by_device[dev_id] = conf

    for hostname in facts_by_hostname:
        # Only flag devices that have links but none are high-confidence
        if hostname in devices_with_links:
            best = best_confidence_by_device.get(hostname, "unknown")
            if best not in _HIGH_CONFIDENCE:
                # Count how many links this device has
                device_links = [
                    l for l in links
                    if l["local_device_id"] == hostname
                    or l["remote_device_id"] == hostname
                ]
                methods = sorted(set(
                    l.get("discovery_method", "unknown") for l in device_links
                ))
                warning_counter += 1
                warnings.append({
                    "warning_id": f"W{warning_counter:04d}",
                    "type": "low_confidence_only",
                    "severity": "info",
                    "message": (
                        f"Device '{hostname}' has {len(device_links)} link(s) "
                        f"but none confirmed by CDP/LLDP"
                    ),
                    "affected_elements": [hostname],
                    "details": {
                        "link_count": len(device_links),
                        "discovery_methods": methods,
                        "possible_causes": [
                            "CDP/LLDP disabled on device or neighbors",
                            "Device connected only to non-managed peers",
                            "Links inferred from ARP/MAC/subnet data",
                        ],
                    },
                })

    # -------------------------------------------------------------------------
    # Warning Type 6: External BGP Peers (Sprint 12)
    # -------------------------------------------------------------------------
    # BGP adjacencies where the peer device is NOT in the collected inventory.
    # This is informational — it highlights the network boundary.
    # External peers are identified by device names starting with "EXTERNAL:"
    # (set by extract_bgp_adjacencies when peer IP can't be resolved).
    #
    # Note: We pass adjacencies through the function signature indirectly —
    # external peer info is in the links/adjacencies produced by link_builder.
    # For now, we detect external peers from any link with a device not in
    # facts_by_hostname.
    external_peers: set[str] = set()
    for link in links:
        if link["remote_device_id"] not in facts_by_hostname:
            external_peers.add(link["remote_device_id"])
        if link["local_device_id"] not in facts_by_hostname:
            external_peers.add(link["local_device_id"])

    if external_peers:
        warning_counter += 1
        warnings.append({
            "warning_id": f"W{warning_counter:04d}",
            "type": "external_peers",
            "severity": "info",
            "message": (
                f"{len(external_peers)} external peer(s) referenced in links "
                f"but not in collection inventory"
            ),
            "affected_elements": sorted(external_peers),
            "details": {
                "external_peers": sorted(external_peers),
                "note": (
                    "These devices appear as link neighbors but were not collected. "
                    "They may be ISP routers, peer networks, or devices outside scope."
                ),
            },
        })

    # -------------------------------------------------------------------------
    # Warning Type 7: Missing Role (Sprint 11C, ADR-074)
    # -------------------------------------------------------------------------
    # A device with role "unknown" has no role in the inventory.
    # This means diagrams cannot label it and role-aware rules cannot filter it.
    # Severity is "warning" because roles should be declared for all devices.
    for device in devices:
        if device.get("role") == "unknown":
            warning_counter += 1
            warnings.append({
                "warning_id": f"W{warning_counter:04d}",
                "type": "role_missing",
                "severity": "warning",
                "message": (
                    f"Device '{device['hostname']}' has no role assigned in inventory"
                ),
                "affected_elements": [device["hostname"]],
                "details": {
                    "remediation": (
                        f"Add 'role: <role_name>' to the device entry for "
                        f"'{device['hostname']}' in the inventory YAML"
                    ),
                },
            })

    # -------------------------------------------------------------------------
    # Warning Type 8: Missing Site (Sprint 11C, ADR-075)
    # -------------------------------------------------------------------------
    # A device with site "unassigned" has no site in the inventory.
    # This means diagrams cannot group it into a site cluster.
    # Severity is "warning" because sites should be declared for all devices.
    for device in devices:
        if device.get("site") == "unassigned":
            warning_counter += 1
            warnings.append({
                "warning_id": f"W{warning_counter:04d}",
                "type": "site_missing",
                "severity": "warning",
                "message": (
                    f"Device '{device['hostname']}' has no site assigned in inventory"
                ),
                "affected_elements": [device["hostname"]],
                "details": {
                    "remediation": (
                        f"Add 'site: <site_name>' to the device entry for "
                        f"'{device['hostname']}' in the inventory YAML"
                    ),
                },
            })

    # -------------------------------------------------------------------------
    # Sort warnings by ID for determinism
    # -------------------------------------------------------------------------
    warnings.sort(key=lambda w: w["warning_id"])

    return warnings


def _write_model(model: dict[str, Any], run_path: Path) -> None:
    """
    Write the model to JSON file.

    Output Location:
        runs/<run-id>/model/network_model.json

    File Format:
        - Pretty-printed JSON (indent=2) for human readability
        - UTF-8 encoding for international character support
        - Consistent key ordering (sort_keys not needed with Python 3.7+)

    Why Pretty Print?
        - Enables git diff comparison between model versions
        - Allows manual inspection during debugging
        - Negligible size increase for our scale

    Directory Creation:
        We create the model/ subdirectory if it doesn't exist.
        This follows the same pattern as facts/ in Sprint 2.

    Args:
        model: The complete model dictionary
        run_path: Path to the run directory
    """
    # -------------------------------------------------------------------------
    # Import json here (could be at top, but keeping with local import pattern)
    # -------------------------------------------------------------------------
    import json

    # -------------------------------------------------------------------------
    # Create output directory
    # -------------------------------------------------------------------------
    # mkdir(exist_ok=True) creates the directory if needed, no error if exists
    # This is idempotent - safe to call multiple times
    model_dir = run_path / "model"
    model_dir.mkdir(exist_ok=True)

    # -------------------------------------------------------------------------
    # Write model to JSON file
    # -------------------------------------------------------------------------
    # Path.write_text() is cleaner than open() + write() for simple cases
    # encoding="utf-8" ensures consistent behavior across platforms
    model_file = model_dir / "network_model.json"
    model_file.write_text(
        json.dumps(model, indent=2),
        encoding="utf-8",
    )
