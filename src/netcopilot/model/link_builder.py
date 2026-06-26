"""
Link builder — discover typed links between devices from per-device facts.

Each discovery method (CDP, LLDP, LACP, FDB, ARP, MAC table, shared subnet)
produces ``LinkCandidate`` objects. ``deduplicate_links()`` then merges all
candidates for the same physical connection into one final link dict, with the
highest-confidence discovery method winning and all evidence accumulated.

This module is built up slice by slice. This first slice covers the CDP path:
``discover_cdp_links()`` (consumes the canonical ``facts["cdp_neighbors"]``) and
the ``deduplicate_links()`` merge step that turns candidates into link dicts.
Later slices add LLDP/LACP/FDB/ARP/MAC discovery (which read Genie ``*.json``
evidence) plus L2/L3 enrichment and routing-adjacency extraction.

Design Principles:
    - Deterministic: Same input always produces same output (sorted results)
    - Traceable: Every link carries evidence strings back to its source
    - Explicit: Missing data = skip, never guess
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcopilot.model.interface_normalizer import canonicalize, normalize_interface_name
from netcopilot.model.interface_taxonomy import is_virtual_interface as _is_virtual_interface
from netcopilot.model.link_status import calculate_link_status
from netcopilot.parse.cisco_native.ospf_config import parse_ospf_process_configs

logger = logging.getLogger(__name__)


# =========================================================================
# LinkCandidate — Intermediate discovery result before deduplication
# =========================================================================

@dataclass
class LinkCandidate:
    """
    Intermediate link discovery result before deduplication.

    Each discovery method (CDP, LLDP, ARP, MAC, subnet) produces one or
    more LinkCandidate objects. These are later deduplicated: multiple
    candidates for the same physical connection are merged into a single
    link, with the highest-confidence candidate winning as the primary
    discovery method.

    Fields:
        local_device:       Hostname of the local device (sanitized).
        local_interface:    Local interface name in ORIGINAL form (for display).
                            May be None for subnet-only discovery.
        local_interface_canonical:
                            Local interface in canonical lowercase form
                            (from canonicalize()). Used for dedup matching.
        remote_device:      Hostname of the remote device (sanitized).
        remote_interface:   Remote interface name in ORIGINAL form (for display).
                            May be None for subnet-only or unresolved links.
        remote_interface_canonical:
                            Remote interface in canonical lowercase form.
                            Used for dedup matching.
        discovery_method:   How this link was discovered. One of:
                            cdp_bilateral, cdp_unilateral,
                            lldp_bilateral, lldp_unilateral,
                            arp_subnet, mac_subnet, subnet_only
        confidence:         Confidence level: very_high, high, medium, low,
                            very_low. Determines winner during dedup.
        evidence:           List of evidence strings for traceability.
                            E.g., ["cdp:core-rtr-01→dist-sw-01",
                                   "cdp:dist-sw-01→core-rtr-01"]
        peer_collected:     True if the remote device has facts/ data
                            (was successfully collected). False for unmanaged
                            devices that appear in CDP/LLDP but have no facts.
    """

    local_device: str
    local_interface: str | None
    local_interface_canonical: str | None
    remote_device: str
    remote_interface: str | None
    remote_interface_canonical: str | None
    discovery_method: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    peer_collected: bool = True


# =========================================================================
# Confidence ranking for deduplication
# =========================================================================
# Higher number = higher confidence. Used to determine which discovery
# method wins when the same physical connection is found by multiple methods.
CONFIDENCE_RANK = {
    "very_high": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "very_low": 1,
}

# =========================================================================
# Discovery method → protocol name mapping
# =========================================================================
# The diagram/render layer reads "discovery_protocol" for edge labels.
# This maps discovery_method names to the protocol string.
DISCOVERY_PROTOCOL_MAP = {
    "cdp_bilateral": "CDP",
    "cdp_unilateral": "CDP",
    "lldp_bilateral": "LLDP",
    "lldp_unilateral": "LLDP",
    "lacp_bilateral": "LACP",
    "lacp_unilateral": "LACP",
    "fdb_firewall": "FDB",
    "stack_interconnect": "Stack",
    "mac_fingerprint_bilateral": "MAC-FP",
    "mac_fingerprint_unilateral": "MAC-FP",
    "arp_subnet": "ARP",
    "mac_subnet": "MAC",
    "subnet_only": "Subnet",
}


# =========================================================================
# Discovery Priority (consumed by the render layer for styling)
# =========================================================================
# Lower number = higher priority / stronger evidence.
DISCOVERY_PRIORITY = {
    "cdp_bilateral": 1,
    "lldp_bilateral": 2,
    "cdp_unilateral": 3,
    "stack_interconnect": 2,
    "mac_fingerprint_bilateral": 2,
    "lldp_unilateral": 4,
    "mac_fingerprint_unilateral": 4,
    "lacp_bilateral": 5,
    "fdb_firewall": 5,
    "lacp_unilateral": 6,
    "arp_subnet": 7,
    "mac_subnet": 9,
    "subnet_only": 11,
}


def sanitize_cdp_hostname(raw_hostname: str) -> str:
    """
    Extract the real hostname from potentially corrupted CDP output.

    Some platforms produce CDP output where the parsed neighbor_hostname field
    contains the entire CDP detail line instead of just the hostname. For
    example:

        "core-rtr-01   Gig 1/0/8   168   R S I  Switch Gig 1/0/3"

    The actual hostname is the first whitespace-delimited token: "core-rtr-01".

    This is a parsing artifact where the text parser captures more text than
    expected from the raw CDP output table on platforms whose CDP output format
    differs slightly from the common IOS XE layout.

    Algorithm:
        1. Strip leading/trailing whitespace
        2. Split on whitespace
        3. Take the first token as the hostname
        4. Validate: hostnames should not contain spaces (RFC 952/1123)

    Args:
        raw_hostname: The neighbor_hostname value from device_facts.json.
                      May be clean ("dist-sw-01") or corrupted
                      ("core-rtr-01   Gig 1/0/8  168  ...").

    Returns:
        The sanitized hostname string (first token).
        Returns empty string if input is empty.

    Examples:
        >>> sanitize_cdp_hostname("dist-sw-01")
        'dist-sw-01'
        >>> sanitize_cdp_hostname("core-rtr-01   Gig 1/0/8   168")
        'core-rtr-01'
        >>> sanitize_cdp_hostname("")
        ''
    """
    # -------------------------------------------------------------------------
    # Step 1: Handle empty input
    # -------------------------------------------------------------------------
    if not raw_hostname:
        return ""

    # -------------------------------------------------------------------------
    # Step 2: Strip and split on whitespace
    # -------------------------------------------------------------------------
    # str.split() without arguments splits on any whitespace and removes
    # empty strings from the result. This handles multiple spaces between
    # the hostname and the trailing CDP data.
    tokens = raw_hostname.strip().split()

    if not tokens:
        return ""

    # -------------------------------------------------------------------------
    # Step 3: Return the first token (the real hostname)
    # -------------------------------------------------------------------------
    # Hostnames follow RFC 952/1123: alphanumeric + hyphens, no spaces.
    # The first whitespace-delimited token is always the hostname because
    # CDP detail lines start with the device ID followed by spaces.
    hostname = tokens[0]

    # Log a warning if we detected and fixed corruption — this helps
    # track which devices have the parsing artifact.
    if len(tokens) > 1:
        logger.debug(
            "Sanitized corrupted CDP hostname: '%s' → '%s'",
            raw_hostname[:80],
            hostname,
        )

    return hostname


# =========================================================================
# CDP Link Discovery (Level 1)
# =========================================================================

def discover_cdp_links(
    facts_by_hostname: dict[str, dict[str, Any]],
    collected_hostnames: set[str],
    facts_dirs: dict[str, Any] | None = None,
) -> list[LinkCandidate]:
    """
    Discover physical links from CDP neighbor data.

    CDP (Cisco Discovery Protocol) is the highest-confidence source for
    physical link discovery. When both endpoints report each other, we
    have definitive proof of a direct physical connection.

    Algorithm:
        1. Build a CDP lookup table from all devices:
           Key: (local_hostname, canonical_local_intf, remote_hostname)
           Value: (original_remote_intf, canonical_remote_intf)

        2. For each CDP neighbor entry:
           a. Sanitize the neighbor hostname (fix corrupted data)
           b. Canonicalize both interface names for cross-platform matching
           c. Check if reverse entry exists (B→A matching A→B)
           d. If bilateral: confidence = very_high, method = cdp_bilateral
           e. If unilateral: confidence = high, method = cdp_unilateral

        3. Avoid duplicates: track seen pairs by sorted canonical key.
           When A→B and B→A both exist, only produce one candidate.

    CDP Format Variants Handled:
        - IOS XE CDP:  "Gig 1/0/3" (with space after abbreviation)
        - IOS XR CDP:  "Hu0/0/1/0" (no space)
        - Full form:   "GigabitEthernet1/0/3"

        All are canonicalized to "gigabitethernet1/0/3" for matching.

    Unmanaged Devices:
        If a CDP neighbor hostname is not in collected_hostnames, it means
        we have no facts for that device (it wasn't in our inventory, or
        collection failed). These links get peer_collected=False.

    Args:
        facts_by_hostname: Dict mapping hostname → device_facts dict.
                           Each facts dict has a "cdp_neighbors" list.
        collected_hostnames: Set of hostnames that have facts/ data.
                             Used to determine peer_collected status.
        facts_dirs: Optional dict mapping hostname → Path to facts/ dir.
                    When present, running_config.txt is read to map a
                    device's configured hostname (what CDP neighbors report)
                    back to its inventory name.

    Returns:
        List of LinkCandidate objects for CDP-discovered links.
        Each candidate has discovery_method "cdp_bilateral" or "cdp_unilateral".

    Example:
        >>> candidates = discover_cdp_links(facts, {"core-rtr-01", "dist-sw-01"})
        >>> for c in candidates:
        ...     print(f"{c.local_device}:{c.local_interface} → "
        ...           f"{c.remote_device}:{c.remote_interface} "
        ...           f"({c.discovery_method})")
        core-rtr-01:Gig 0/0 → dist-sw-01:Gig 1/0/3 (cdp_bilateral)
    """
    # -------------------------------------------------------------------------
    # Step 0: Build configured hostname → inventory name mapping
    # -------------------------------------------------------------------------
    # Devices may have a configured hostname (in running_config) that differs
    # from the inventory name used in facts_by_hostname. CDP neighbors report
    # the configured hostname, so we need to map it back to the inventory name.
    # Example: inventory "dist-sw-01" has running config "hostname dist-sw-01a".
    # When another device sees it via CDP, it reports "dist-sw-01a".
    configured_to_inventory: dict[str, str] = {}
    if facts_dirs:
        for inv_name, facts_path in facts_dirs.items():
            rc_file = Path(facts_path) / "running_config.txt"
            if rc_file.exists():
                try:
                    with open(rc_file) as f:
                        for line in f:
                            stripped = line.strip()
                            if stripped.startswith("hostname "):
                                configured = stripped.split(None, 1)[1].strip()
                                if configured and configured != inv_name:
                                    configured_to_inventory[configured] = inv_name
                                    logger.debug(
                                        "CDP hostname map: %s → %s",
                                        configured, inv_name,
                                    )
                                break
                except OSError:
                    pass

    if configured_to_inventory:
        logger.info(
            "CDP hostname mapping: %d configured names → inventory names",
            len(configured_to_inventory),
        )

    # -------------------------------------------------------------------------
    # Step 1: Build CDP lookup table with canonical interface names
    # -------------------------------------------------------------------------
    # Key: (local_hostname, canonical_local_interface, sanitized_neighbor_hostname)
    # Value: (original_neighbor_interface, canonical_neighbor_interface)
    #
    # We store both original and canonical forms because:
    # - Canonical: for matching (reverse lookup)
    # - Original: for display in the final link (human-readable interface names)
    cdp_lookup: dict[tuple[str, str, str], tuple[str, str]] = {}

    for hostname, facts in facts_by_hostname.items():
        for neighbor in facts.get("cdp_neighbors", []):
            # Extract raw fields from the CDP neighbor entry
            local_intf = neighbor.get("local_interface", "")
            raw_neighbor_hostname = neighbor.get("neighbor_hostname", "")
            neighbor_intf = neighbor.get("neighbor_interface", "")

            # Skip incomplete entries — all three fields are required
            # for a valid CDP relationship
            if not local_intf or not raw_neighbor_hostname or not neighbor_intf:
                continue

            # Sanitize the neighbor hostname to handle corrupted CDP output
            neighbor_hostname = sanitize_cdp_hostname(raw_neighbor_hostname)
            if not neighbor_hostname:
                continue

            # Map configured hostname to inventory name
            neighbor_hostname = configured_to_inventory.get(
                neighbor_hostname, neighbor_hostname
            )

            # Canonicalize interface names for cross-platform matching
            # canonicalize() returns None for MAC addresses and empty strings
            canonical_local = canonicalize(local_intf)
            canonical_neighbor = canonicalize(neighbor_intf)

            # Skip if canonicalization failed (shouldn't happen for valid
            # interface names, but defensive coding)
            if not canonical_local or not canonical_neighbor:
                logger.warning(
                    "CDP canonicalization failed for %s: local='%s' → %s, "
                    "neighbor='%s' → %s",
                    hostname, local_intf, canonical_local,
                    neighbor_intf, canonical_neighbor,
                )
                continue

            # Build the lookup key and store both original and canonical forms
            key = (hostname, canonical_local, neighbor_hostname)
            cdp_lookup[key] = (neighbor_intf, canonical_neighbor)

    # -------------------------------------------------------------------------
    # Step 2: Iterate CDP entries and produce link candidates
    # -------------------------------------------------------------------------
    # Track seen canonical pairs to avoid producing duplicate candidates
    # for the same physical connection (A→B and B→A should produce one link)
    seen_pairs: set[str] = set()
    candidates: list[LinkCandidate] = []

    for hostname, facts in facts_by_hostname.items():
        for neighbor in facts.get("cdp_neighbors", []):
            # Extract raw fields (same extraction as Step 1)
            local_intf = neighbor.get("local_interface", "")
            raw_neighbor_hostname = neighbor.get("neighbor_hostname", "")
            neighbor_intf = neighbor.get("neighbor_interface", "")

            # Skip incomplete entries
            if not local_intf or not raw_neighbor_hostname or not neighbor_intf:
                continue

            # Sanitize hostname and canonicalize interfaces
            neighbor_hostname = sanitize_cdp_hostname(raw_neighbor_hostname)
            if not neighbor_hostname:
                continue

            # Map configured hostname to inventory name
            neighbor_hostname = configured_to_inventory.get(
                neighbor_hostname, neighbor_hostname
            )

            canonical_local = canonicalize(local_intf)
            canonical_neighbor = canonicalize(neighbor_intf)

            if not canonical_local or not canonical_neighbor:
                continue

            # -----------------------------------------------------------------
            # Build canonical pair key for dedup
            # -----------------------------------------------------------------
            # Sort endpoints alphabetically so A→B and B→A produce the
            # same key. This prevents duplicate candidates.
            endpoint_a = f"{hostname}:{canonical_local}"
            endpoint_b = f"{neighbor_hostname}:{canonical_neighbor}"

            if endpoint_a > endpoint_b:
                endpoint_a, endpoint_b = endpoint_b, endpoint_a

            pair_key = f"{endpoint_a}--{endpoint_b}"

            # Skip if we've already processed this pair
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # -----------------------------------------------------------------
            # Check for bilateral CDP: does the reverse entry exist?
            # -----------------------------------------------------------------
            # If neighbor B also reports seeing hostname A on matching
            # interfaces, we have bilateral CDP proof.
            reverse_key = (neighbor_hostname, canonical_neighbor, hostname)
            is_bilateral = reverse_key in cdp_lookup

            # -----------------------------------------------------------------
            # Determine discovery method and confidence
            # -----------------------------------------------------------------
            if is_bilateral:
                method = "cdp_bilateral"
                confidence = "very_high"
                # Bilateral evidence: both directions
                evidence = [
                    f"cdp:{hostname}→{neighbor_hostname}",
                    f"cdp:{neighbor_hostname}→{hostname}",
                ]
            else:
                method = "cdp_unilateral"
                confidence = "high"
                # Unilateral evidence: only one direction
                evidence = [
                    f"cdp:{hostname}→{neighbor_hostname}",
                ]

            # -----------------------------------------------------------------
            # Determine peer_collected status
            # -----------------------------------------------------------------
            # A device is "collected" if we have its facts/ data.
            # Unmanaged devices (not in inventory) appear in CDP but
            # have no facts — they get peer_collected=False.
            peer_collected = neighbor_hostname in collected_hostnames

            # -----------------------------------------------------------------
            # Create the link candidate
            # -----------------------------------------------------------------
            candidate = LinkCandidate(
                local_device=hostname,
                local_interface=local_intf,
                local_interface_canonical=canonical_local,
                remote_device=neighbor_hostname,
                remote_interface=neighbor_intf,
                remote_interface_canonical=canonical_neighbor,
                discovery_method=method,
                confidence=confidence,
                evidence=evidence,
                peer_collected=peer_collected,
            )

            candidates.append(candidate)

    # -------------------------------------------------------------------------
    # Step 3: Sort candidates for determinism
    # -------------------------------------------------------------------------
    # Sort by (local_device, remote_device, local_interface_canonical) so
    # the output is reproducible regardless of dict iteration order.
    candidates.sort(key=lambda c: (
        c.local_device,
        c.remote_device,
        c.local_interface_canonical or "",
    ))

    logger.info(
        "CDP discovery: %d candidates (%d bilateral, %d unilateral)",
        len(candidates),
        sum(1 for c in candidates if c.discovery_method == "cdp_bilateral"),
        sum(1 for c in candidates if c.discovery_method == "cdp_unilateral"),
    )

    return candidates


# =========================================================================
# Shared genie evidence loader
# =========================================================================

def _load_json_file(file_path: Path) -> dict[str, Any] | None:
    """
    Safely load a JSON file, returning None on any error.

    This is a utility for loading protocol-specific Genie JSON evidence
    (genie_lldp.json, genie_arp.json, etc.) from a device's facts directory.
    Missing files and empty/invalid JSON are handled gracefully — the caller
    can simply skip that device for the current discovery method.

    Args:
        file_path: Absolute path to the JSON file.

    Returns:
        Parsed JSON as a dict, or None if the file doesn't exist,
        is empty, or contains invalid JSON.
    """
    if not file_path.is_file():
        return None

    try:
        text = file_path.read_text(encoding="utf-8")
        if not text.strip():
            return None
        data = json.loads(text)
        # Return None for empty dicts/lists (treat as "no data")
        if not data:
            return None
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load %s: %s", file_path, exc)
        return None


# =========================================================================
# LLDP Link Discovery (Level 2)
# =========================================================================

def discover_lldp_links(
    facts_dirs: dict[str, Path],
    collected_hostnames: set[str],
) -> list[LinkCandidate]:
    """
    Discover physical links from LLDP neighbor data.

    LLDP (Link Layer Discovery Protocol, IEEE 802.1AB) is a vendor-neutral
    alternative to CDP. When both endpoints report each other via LLDP,
    we have definitive proof of a direct physical connection (same
    confidence as CDP bilateral).

    Genie LLDP JSON Schema:
        The Genie Ops LLDP model produces JSON with this structure::

            {
              "interfaces": {
                "GigabitEthernet1/0/1": {
                  "port_id": {
                    "GigabitEthernet1/0/1": {
                      "neighbors": {
                        "neighbor-host": {
                          "neighbor_id": "neighbor-host",
                          "system_name": "neighbor-host",
                          "port_id": "GigabitEthernet0/0/0/1",
                          "port_description": "...",
                          "chassis_id": "aabb.ccdd.eeff"
                        }
                      }
                    }
                  }
                }
              }
            }

        When every LLDP file is empty ({}) this function returns an empty
        list — the code is ready for when LLDP becomes available.

    Algorithm:
        1. For each device: load facts/<hostname>/genie_lldp.json
        2. Navigate: interfaces → <intf_name> → port_id → <port> → neighbors
        3. For each LLDP neighbor:
           a. Extract system_name (remote hostname) and port_id (remote intf)
           b. Canonicalize both interfaces
           c. Add to LLDP lookup table
        4. Check bilateral matches (same as CDP)
        5. Produce link candidates

    Args:
        facts_dirs: Dict mapping hostname → Path to that device's facts/
                    directory.
        collected_hostnames: Set of hostnames that have facts/ data.

    Returns:
        List of LinkCandidate objects for LLDP-discovered links.
        Returns empty list if no LLDP data is available.
    """
    # -------------------------------------------------------------------------
    # Step 1: Load LLDP data from all devices and build lookup table
    # -------------------------------------------------------------------------
    # Key: (local_hostname, canonical_local_interface, remote_hostname)
    # Value: (original_remote_interface, canonical_remote_interface)
    lldp_lookup: dict[tuple[str, str, str], tuple[str, str]] = {}

    # Also store all raw LLDP entries for iteration in Step 2
    # Each entry: (local_hostname, local_intf_original, canonical_local,
    #              remote_hostname, remote_intf_original, canonical_remote)
    lldp_entries: list[tuple[str, str, str, str, str, str]] = []

    for hostname, facts_dir in facts_dirs.items():
        # Load genie_lldp.json from this device's facts directory
        lldp_path = facts_dir / "genie_lldp.json"
        lldp_data = _load_json_file(lldp_path)

        if not lldp_data:
            # No LLDP data for this device — skip silently.
            # This is expected for devices that don't support LLDP or
            # where LLDP was not collected.
            continue

        # Navigate the Genie LLDP Ops schema
        interfaces = lldp_data.get("interfaces", {})

        for local_intf_name, intf_data in interfaces.items():
            # The port_id level contains the actual neighbor data
            port_id_data = intf_data.get("port_id", {})

            for _port_key, port_info in port_id_data.items():
                # Each port can have multiple neighbors (rare but possible)
                neighbors = port_info.get("neighbors", {})

                for _neighbor_key, neighbor_info in neighbors.items():
                    # Extract the remote device hostname and interface
                    # system_name is the preferred field (LLDP system name TLV)
                    # neighbor_id is a fallback (may be chassis ID)
                    remote_hostname = (
                        neighbor_info.get("system_name")
                        or neighbor_info.get("neighbor_id", "")
                    )
                    remote_intf = neighbor_info.get("port_id", "")

                    # Skip incomplete entries
                    if not remote_hostname or not remote_intf:
                        continue

                    # Canonicalize interface names for matching
                    canonical_local = canonicalize(local_intf_name)
                    canonical_remote = canonicalize(remote_intf)

                    # canonicalize() returns None for MAC addresses.
                    # LLDP port_id can be a MAC address — in that case
                    # we can't match by interface name, so we skip.
                    if not canonical_local or not canonical_remote:
                        logger.debug(
                            "LLDP skipping entry with non-matchable interface: "
                            "%s:%s → %s:%s (canonical: %s, %s)",
                            hostname, local_intf_name,
                            remote_hostname, remote_intf,
                            canonical_local, canonical_remote,
                        )
                        continue

                    # Add to lookup table and entries list
                    key = (hostname, canonical_local, remote_hostname)
                    lldp_lookup[key] = (remote_intf, canonical_remote)

                    lldp_entries.append((
                        hostname, local_intf_name, canonical_local,
                        remote_hostname, remote_intf, canonical_remote,
                    ))

    # -------------------------------------------------------------------------
    # Step 2: Produce link candidates from LLDP entries
    # -------------------------------------------------------------------------
    seen_pairs: set[str] = set()
    candidates: list[LinkCandidate] = []

    for (hostname, local_intf, canonical_local,
         remote_hostname, remote_intf, canonical_remote) in lldp_entries:

        # Build canonical pair key for dedup (sorted endpoints)
        endpoint_a = f"{hostname}:{canonical_local}"
        endpoint_b = f"{remote_hostname}:{canonical_remote}"

        if endpoint_a > endpoint_b:
            endpoint_a, endpoint_b = endpoint_b, endpoint_a

        pair_key = f"{endpoint_a}--{endpoint_b}"

        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        # Check for bilateral LLDP (reverse entry exists)
        reverse_key = (remote_hostname, canonical_remote, hostname)
        is_bilateral = reverse_key in lldp_lookup

        # Determine method and confidence
        if is_bilateral:
            method = "lldp_bilateral"
            confidence = "very_high"
            evidence = [
                f"lldp:{hostname}→{remote_hostname}",
                f"lldp:{remote_hostname}→{hostname}",
            ]
        else:
            method = "lldp_unilateral"
            confidence = "high"
            evidence = [
                f"lldp:{hostname}→{remote_hostname}",
            ]

        # Determine peer_collected status
        peer_collected = remote_hostname in collected_hostnames

        candidate = LinkCandidate(
            local_device=hostname,
            local_interface=local_intf,
            local_interface_canonical=canonical_local,
            remote_device=remote_hostname,
            remote_interface=remote_intf,
            remote_interface_canonical=canonical_remote,
            discovery_method=method,
            confidence=confidence,
            evidence=evidence,
            peer_collected=peer_collected,
        )

        candidates.append(candidate)

    # -------------------------------------------------------------------------
    # Step 3: Sort candidates for determinism
    # -------------------------------------------------------------------------
    candidates.sort(key=lambda c: (
        c.local_device,
        c.remote_device,
        c.local_interface_canonical or "",
    ))

    logger.info(
        "LLDP discovery: %d candidates (%d bilateral, %d unilateral)",
        len(candidates),
        sum(1 for c in candidates if c.discovery_method == "lldp_bilateral"),
        sum(1 for c in candidates if c.discovery_method == "lldp_unilateral"),
    )

    return candidates


# =========================================================================
# LACP Link Discovery — partner-MAC resolution (genie_lag.json)
# =========================================================================

def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase hex without separators.

    Handles Cisco dotted format (1234.5678.9abc), colon format
    (12:34:56:78:9a:bc), and dash format (12-34-56-78-9a-bc).
    Returns 12-char lowercase hex string (e.g., "123456789abc").
    """
    return re.sub(r"[.:\-]", "", mac).lower()


def _strip_lacp_priority_prefix(partner_id: str) -> str:
    """Strip the IOS XR LACP system-priority prefix from a partner_id.

    IOS XR formats the partner system ID as '8000.aabb.ccdd.eeff' where the
    first 4 hex chars are the LACP priority (e.g., '8000'). A standard MAC is
    12 hex chars. If the normalized form is >12 chars, strip the priority prefix.
    """
    normalized = _normalize_mac(partner_id)
    if len(normalized) > 12:
        # Priority prefix is the leading chars beyond 12
        normalized = normalized[-12:]
    return normalized


def _build_mac_lookup(
    facts_dirs: dict[str, Path],
) -> dict[str, str]:
    """Build a MAC → hostname lookup table from genie_interface.json.

    Indexes every phys_address (physical interfaces) and mac_address
    (Bundle-Ether chassis pool MACs) per device. Also indexes LACP
    system_id MACs from genie_lag.json and FortiGate macaddr fields from
    fortigate_system_interface.json.

    Returns:
        {normalized_mac: hostname}
    """
    # NOTE (R2-LAG-2): MAC→hostname is last-writer-wins. This is order-coupled but
    # LOAD-BEARING on real hardware — an LACP partner system_id MAC can collide in
    # this table, and last-wins currently resolves it to the true owner; a naive
    # setdefault (first-wins) regressed 14 hw links (lost LACP corroboration on CDP
    # cables, golden-master-caught). A proper fix is source-aware resolution (prefer
    # the device whose system_id this MAC is) — deferred; see LEDGER R2-LAG-2.
    table: dict[str, str] = {}

    for hostname, facts_dir in facts_dirs.items():
        # Cisco Genie interfaces
        intf_data = _load_json_file(facts_dir / "genie_interface.json")
        if intf_data:
            for intf_name, intf_info in intf_data.items():
                for mac_field in ("phys_address", "mac_address"):
                    mac = intf_info.get(mac_field)
                    if mac and len(mac) >= 11:  # skip empty/placeholder
                        table[_normalize_mac(mac)] = hostname

        # LACP system_id MACs — the MAC advertised in LACP PDUs (may differ
        # from interface phys_address by ±1 on IOS XR). Remote devices record
        # this as partner_id, so it must be in the lookup table.
        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if lag_data:
            for po_info in lag_data.get("interfaces", {}).values():
                for mac_field in ("system_id_mac", "system_id"):
                    mac = po_info.get(mac_field)
                    if mac and len(mac) >= 11:
                        table[_normalize_mac(mac)] = hostname
                # Also index per-member system_id (IOS XR reports per-member)
                for member_info in po_info.get("members", {}).values():
                    mac = member_info.get("system_id")
                    if mac and len(mac) >= 11:
                        table[_normalize_mac(mac)] = hostname

        # FortiGate interfaces
        fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if fg_data:
            ifaces = fg_data if isinstance(fg_data, list) else fg_data.get("results", [])
            for intf in ifaces:
                mac = intf.get("macaddr")
                if mac and len(mac) >= 11:
                    table[_normalize_mac(mac)] = hostname

    initial_count = len(table)

    # ── LACP cross-reference enrichment ──
    # Problem: IOS XE Genie sometimes omits phys_address from genie_interface.json
    # on virtual platforms, leaving device MACs out of the lookup table.
    # Fix: use LACP symmetry. If A's partner_id resolves to B, then B must
    # have a port-channel whose partner_id is A's system MAC.  We identify
    # which of B's port-channels connects to A using a 1:1 matching constraint.
    all_lag: dict[str, dict] = {}
    for hostname, facts_dir in facts_dirs.items():
        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if lag_data:
            all_lag[hostname] = lag_data

    # Extract unique partner_id per port-channel per device.
    # {hostname: {pc_name: normalized_partner_mac}}
    pc_partners: dict[str, dict[str, str]] = {}
    for hostname, lag_data in all_lag.items():
        pcs: dict[str, str] = {}
        for pc_name, pc_info in lag_data.get("interfaces", {}).items():
            partner_macs = set()
            for member_info in pc_info.get("members", {}).values():
                pid = member_info.get("partner_id")
                if pid:
                    partner_macs.add(_strip_lacp_priority_prefix(pid))
            if len(partner_macs) == 1:
                pcs[pc_name] = partner_macs.pop()
        if pcs:
            pc_partners[hostname] = pcs

    # R2-LAG-5: a reused system_id MAC (advertised by >1 device — the IOL hazard)
    # makes the flat last-writer-wins `table` route it to an arbitrary twin. The
    # symmetry inference below trusts `table.get(a_mac) == device_b`, so a reused
    # bridge MAC can drive it to fabricate a wrong partner from an unrelated
    # (e.g. uncollected) neighbour. Exclude reused system_ids from that evidence.
    # Legitimate fills bridge on a device's UNIQUE identity MAC, so they are
    # untouched; goldens have no reused system_id, so this is a no-op there.
    _sysid_owners, _, _ = _build_lacp_identity_indices(all_lag)
    reused_system_ids = {m for m, owners in _sysid_owners.items() if len(owners) > 1}

    # Iteratively resolve: each round may enable new resolutions.
    enriched = True
    while enriched:
        enriched = False
        for device_b, b_pcs in pc_partners.items():
            # B's partner_ids that are NOT yet in the table
            b_unresolved = {
                pc: mac for pc, mac in b_pcs.items()
                if mac not in table
            }
            if not b_unresolved:
                continue

            # Devices that resolved TO B (A→B via LACP partner_id)
            resolved_to_b: set[str] = set()
            for device_a, a_pcs in pc_partners.items():
                if device_a == device_b:
                    continue
                for a_mac in a_pcs.values():
                    # R2-LAG-5: ignore a reused system_id as resolution evidence —
                    # last-writer-wins may have routed it to the wrong twin.
                    if a_mac in reused_system_ids:
                        continue
                    if table.get(a_mac) == device_b:
                        resolved_to_b.add(device_a)

            if not resolved_to_b:
                continue

            # Among those, which ones does B NOT already resolve back to?
            unmatched_sources: set[str] = set()
            for device_a in resolved_to_b:
                b_resolves_to_a = any(
                    table.get(mac) == device_a for mac in b_pcs.values()
                )
                if not b_resolves_to_a:
                    unmatched_sources.add(device_a)

            if not unmatched_sources:
                continue

            # Safe 1:1 case: exactly one unmatched source ↔ one unresolved MAC
            if len(unmatched_sources) == 1 and len(b_unresolved) == 1:
                mac = next(iter(b_unresolved.values()))
                device_a = next(iter(unmatched_sources))
                table[mac] = device_a
                enriched = True
                logger.debug(
                    "LACP cross-ref: %s partner_id %s → %s (inferred from %s↔%s pair)",
                    device_b, mac, device_a, device_a, device_b,
                )
                continue

            # Multi-match: try member-count heuristic for disambiguation.
            # Each of B's unresolved port-channels has N members; match with
            # the port-channel member count on A's side connecting to B.
            if len(unmatched_sources) == len(b_unresolved):
                a_member_counts: dict[str, int] = {}
                for device_a in unmatched_sources:
                    for a_pc, a_mac in pc_partners.get(device_a, {}).items():
                        if table.get(a_mac) == device_b:
                            a_lag = all_lag.get(device_a, {})
                            a_pc_info = a_lag.get("interfaces", {}).get(a_pc, {})
                            a_member_counts[device_a] = len(
                                a_pc_info.get("members", {})
                            )
                            break

                b_unresolved_counts: dict[str, int] = {}
                for b_pc, b_mac in b_unresolved.items():
                    b_pc_info = all_lag.get(device_b, {}).get(
                        "interfaces", {}
                    ).get(b_pc, {})
                    b_unresolved_counts[b_mac] = len(
                        b_pc_info.get("members", {})
                    )

                # Group by member count for matching
                by_count_a: dict[int, list[str]] = {}
                for dev, cnt in a_member_counts.items():
                    by_count_a.setdefault(cnt, []).append(dev)
                by_count_b: dict[int, list[str]] = {}
                for mac, cnt in b_unresolved_counts.items():
                    by_count_b.setdefault(cnt, []).append(mac)

                for cnt in by_count_a:
                    if cnt in by_count_b:
                        if len(by_count_a[cnt]) == 1 and len(by_count_b[cnt]) == 1:
                            device_a = by_count_a[cnt][0]
                            mac = by_count_b[cnt][0]
                            table[mac] = device_a
                            enriched = True
                            logger.debug(
                                "LACP cross-ref (member-count): %s partner_id %s → %s",
                                device_b, mac, device_a,
                            )

    if len(table) > initial_count:
        logger.info(
            "MAC lookup table enriched: %d → %d entries (LACP cross-reference)",
            initial_count, len(table),
        )

    # FortiGate LACP system MAC indexing via heartbeat ARP prefix.
    # FortiGate REST returns 00:00:00:00:00:00 for all interface MACs, so direct
    # indexing is impossible. However, standard-HA FortiGates expose the passive
    # member's hardware MAC via 169.254.x.x ARP heartbeat entries. The first 4
    # bytes of this MAC identify the device's MAC family; all LACP partner_ids
    # advertised by this firewall share the same 4-byte prefix. Firewalls with no
    # 169.254.x.x ARP entries → fg_prefix_to_host stays empty → behavior unchanged.
    fg_prefix_to_host: dict[str, str] = {}
    for hostname, facts_dir in facts_dirs.items():
        fg_arp = _load_json_file(facts_dir / "fortigate_arp.json")
        if not fg_arp:
            continue
        for entry in fg_arp.get("results", []):
            ip = entry.get("ip", "")
            mac = entry.get("mac", "")
            if not ip.startswith("169.254.") or not mac:
                continue
            hex_clean = mac.replace(":", "").replace(".", "").lower()
            if len(hex_clean) == 12 and int(hex_clean, 16) != 0:
                fg_prefix_to_host[hex_clean[:8]] = hostname  # 4-byte prefix → firewall hostname

    if fg_prefix_to_host:
        fg_hostnames = set(fg_prefix_to_host.values())
        for hostname, facts_dir in facts_dirs.items():
            if hostname in fg_hostnames:
                continue  # skip firewall devices themselves
            lag = _load_json_file(facts_dir / "genie_lag.json") or _load_json_file(
                facts_dir / "parsed_lag.json"
            )
            if not lag:
                continue
            for po_info in lag.get("interfaces", {}).values():
                for member_info in po_info.get("members", {}).values():
                    if member_info.get("lacp_port_priority") != 255:
                        continue
                    partner_id = member_info.get("partner_id", "")
                    if not partner_id:
                        continue
                    norm = _strip_lacp_priority_prefix(partner_id)
                    if len(norm) != 12 or norm in table:
                        continue  # already resolved or invalid length
                    prefix = norm[:8]
                    fw_host = fg_prefix_to_host.get(prefix)
                    if fw_host:
                        table[norm] = fw_host
                        logger.debug(
                            "FG LACP MAC indexed: %s → %s (via heartbeat prefix %s)",
                            norm, fw_host, prefix,
                        )

    logger.info("MAC lookup table: %d entries from %d devices", len(table), len(facts_dirs))
    return table


def _build_lacp_identity_indices(
    all_lag_data: dict[str, dict],
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    """Indices for source-aware LACP partner resolution (R2-LAG-2).

    A system_id MAC can be reused across devices (the IOL hazard), so the flat
    last-writer-wins MAC→hostname table (_build_mac_lookup) resolves an ambiguous
    partner to whichever twin was indexed last — order-coupled and wrong. These
    indices let discover_lacp_links disambiguate by LACP symmetry instead.

    All MACs are normalised to 12 lowercase hex (same key space as mac_table).

    Returns:
        mac_owners:          {system_id_mac: {hostnames advertising it}}
        device_system_ids:   {hostname: {its own system_id MACs}}
        device_partner_macs: {hostname: {partner_id MACs it advertises}}
    """
    mac_owners: dict[str, set[str]] = {}
    device_system_ids: dict[str, set[str]] = {}
    device_partner_macs: dict[str, set[str]] = {}

    for hostname, lag_data in all_lag_data.items():
        sys_ids: set[str] = set()
        partners: set[str] = set()
        for po_info in lag_data.get("interfaces", {}).values():
            for mac_field in ("system_id_mac", "system_id"):
                mac = po_info.get(mac_field)
                if mac and len(mac) >= 11:
                    sys_ids.add(_normalize_mac(mac))
            for member_info in po_info.get("members", {}).values():
                mac = member_info.get("system_id")
                if mac and len(mac) >= 11:
                    sys_ids.add(_normalize_mac(mac))
                pid = member_info.get("partner_id")
                if pid:
                    partners.add(_strip_lacp_priority_prefix(pid))
        if sys_ids:
            device_system_ids[hostname] = sys_ids
            for mac in sys_ids:
                mac_owners.setdefault(mac, set()).add(hostname)
        if partners:
            device_partner_macs[hostname] = partners

    return mac_owners, device_system_ids, device_partner_macs


def _resolve_lacp_partner(
    partner_mac: str,
    local_hostname: str,
    mac_table: dict[str, str],
    mac_owners: dict[str, set[str]],
    device_system_ids: dict[str, set[str]],
    device_partner_macs: dict[str, set[str]],
) -> str | None:
    """Resolve a partner system_id MAC to its owning device (R2-LAG-2).

    Flat last-writer-wins (``mac_table``) is correct unless the MAC is a system_id
    reused across >1 device. In that ambiguous case, disambiguate by LACP symmetry:
    the true partner is the owner that points back at ``local_hostname`` (has a
    bundle whose partner_id is one of the local device's own system_ids). Falls
    back to the flat table when symmetry is inconclusive (0 or >1 candidates) —
    never worse than today, and order-independent because every input is a set.
    """
    owners = mac_owners.get(partner_mac)
    if owners and len(owners) > 1:
        local_ids = device_system_ids.get(local_hostname, set())
        if local_ids:
            back = [
                o for o in owners
                if o != local_hostname
                and device_partner_macs.get(o, set()) & local_ids
            ]
            if len(back) == 1:
                return back[0]
    return mac_table.get(partner_mac)


def discover_lacp_links(
    facts_dirs: dict[str, Path],
    collected_hostnames: set[str],
) -> list[LinkCandidate]:
    """Discover physical links from LACP partner data (genie_lag.json).

    For each device with LAG data, extracts partner_id (MAC) from each
    bundle member interface, resolves it to a hostname via MAC lookup,
    and creates a LinkCandidate. Bilateral promotion merges A→B + B→A.

    Args:
        facts_dirs: {hostname: Path} to per-device facts directories.
        collected_hostnames: Set of hostnames we collected data from.

    Returns:
        List of LACP LinkCandidates (unilateral and bilateral).
    """
    mac_table = _build_mac_lookup(facts_dirs)
    unilateral: list[LinkCandidate] = []

    # Pre-load all LACP data and build port_num → interface_name index per device.
    # This lets us resolve partner_port_num to a real interface name.
    all_lag_data: dict[str, dict] = {}
    # port_num_index: {hostname: {port_num: member_interface_name}}
    port_num_index: dict[str, dict[int, str]] = {}
    for hostname, facts_dir in facts_dirs.items():
        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if lag_data is None:
            # Fallback: device.parse("show etherchannel") output, written
            # alongside the learn("lag") output for devices where learn fails.
            lag_data = _load_json_file(facts_dir / "parsed_lag.json")
        if not lag_data:
            continue
        all_lag_data[hostname] = lag_data
        pn_map: dict[int, str] = {}
        for _po_name, po_info in lag_data.get("interfaces", {}).items():
            for member_name, member_info in po_info.get("members", {}).items():
                pn = member_info.get("port_num")
                if pn is not None:
                    pn_map[int(pn)] = member_name
        if pn_map:
            port_num_index[hostname] = pn_map

    # Source-aware partner resolution indices (R2-LAG-2): used only to break a
    # reused-system_id tie; the flat mac_table stays authoritative otherwise.
    mac_owners, device_system_ids, device_partner_macs = (
        _build_lacp_identity_indices(all_lag_data)
    )

    for hostname, lag_data in all_lag_data.items():
        interfaces = lag_data.get("interfaces", {})
        for po_name, po_info in interfaces.items():
            members = po_info.get("members", {})
            for member_name, member_info in members.items():
                partner_id = member_info.get("partner_id")
                if not partner_id:
                    continue

                # Resolve partner MAC to hostname (source-aware — R2-LAG-2).
                partner_mac = _strip_lacp_priority_prefix(partner_id)
                remote_hostname = _resolve_lacp_partner(
                    partner_mac, hostname, mac_table,
                    mac_owners, device_system_ids, device_partner_macs,
                )
                if not remote_hostname or remote_hostname == hostname:
                    continue

                # Resolve remote interface via partner_port_num
                remote_intf = None
                partner_port_num = member_info.get("partner_port_num")
                if partner_port_num is not None and remote_hostname in port_num_index:
                    remote_intf = port_num_index[remote_hostname].get(
                        int(partner_port_num)
                    )

                local_canonical = canonicalize(member_name)

                # port_priority=255 is the FortiGate LACP fingerprint (Cisco
                # default: 32768). When the remote resolved via this fingerprint
                # the evidence is as strong as FDB-based discovery → upgrade to
                # high confidence so the link passes the physical-view filter.
                partner_prio = member_info.get("lacp_port_priority")
                link_confidence = "high" if partner_prio == 255 else "medium"

                unilateral.append(LinkCandidate(
                    local_device=hostname,
                    local_interface=member_name,
                    local_interface_canonical=local_canonical,
                    remote_device=remote_hostname,
                    remote_interface=remote_intf,
                    remote_interface_canonical=canonicalize(remote_intf) if remote_intf else None,
                    discovery_method="lacp_unilateral",
                    confidence=link_confidence,
                    evidence=[f"lacp:{hostname}({member_name})→{remote_hostname}({remote_intf or '?'}) partner_id={partner_id}"],
                    peer_collected=remote_hostname in collected_hostnames,
                ))

    # Bilateral promotion: if A→B and B→A exist for matching member interfaces.
    bilateral: list[LinkCandidate] = []
    promoted: set[int] = set()  # indices of candidates promoted to bilateral

    for i, c in enumerate(unilateral):
        if i in promoted:
            continue

        # Look for the reverse: B→A where B's local device is A's remote device.
        # Since LACP member interfaces carry the same cable, the presence of a
        # reverse partner is enough to confirm both sides.
        reverse_matches = [
            (j, rev)
            for (j, rev) in enumerate(unilateral)
            if j != i
            and j not in promoted
            and rev.local_device == c.remote_device
            and rev.remote_device == c.local_device
        ]

        if reverse_matches:
            # R2-LAG-1: with >=2 port-channels between ONE device pair, every reverse
            # candidate matches by device-pair, so a blind reverse_matches[0] can fuse
            # member c with the WRONG far member (crossing two separate cables). `c`
            # already resolved its true far port (c.remote_interface_canonical, via
            # partner_port_num); prefer the reverse candidate sitting on exactly that
            # port — that pins the cable. This is order-INDEPENDENT and a no-op on
            # single-bundle pairs (one reverse match), so the goldens stay byte-stable.
            # Falls back to [0] only when c's far port is unresolved (e.g. no
            # partner_port_num). (Earlier naive *sorting* of this pick re-paired hw
            # members and dropped LACP corroboration on CDP cables — golden-caught;
            # this targeted match avoids that.)
            chosen = None
            if c.remote_interface_canonical is not None:
                for cand in reverse_matches:
                    if cand[1].local_interface_canonical == c.remote_interface_canonical:
                        chosen = cand
                        break
            if chosen is None:
                chosen = reverse_matches[0]
            j, rev = chosen
            promoted.add(i)
            promoted.add(j)

            # Merge evidence
            merged_evidence = list(c.evidence) + list(rev.evidence)

            bilateral.append(LinkCandidate(
                local_device=c.local_device,
                local_interface=c.local_interface,
                local_interface_canonical=c.local_interface_canonical,
                remote_device=rev.local_device,
                remote_interface=rev.local_interface,
                remote_interface_canonical=rev.local_interface_canonical,
                discovery_method="lacp_bilateral",
                confidence="high",
                evidence=merged_evidence,
                peer_collected=c.peer_collected or rev.peer_collected,
            ))

    # Collect remaining unilateral (not promoted)
    remaining = [c for i, c in enumerate(unilateral) if i not in promoted]

    # NOTE (R2-LAG-3): candidate order is NOT sorted here on purpose — the dedup
    # tie-break is order-sensitive, and re-ordering dropped LACP corroboration on hw
    # CDP cables (golden-caught). A deterministic LACP ordering needs the dedup
    # tie-break fixed in tandem — deferred; see LEDGER R2-LAG-3.
    all_candidates = bilateral + remaining

    logger.info(
        "LACP discovery: %d bilateral + %d unilateral = %d candidates",
        len(bilateral),
        len(remaining),
        len(all_candidates),
    )

    return all_candidates


# =========================================================================
# Subnet Membership Index — shared by ARP, MAC-table, and subnet-only discovery
# =========================================================================

def _parse_fortigate_ip(ip_field: str) -> tuple[str, str] | None:
    """
    Parse a FortiGate "ip" field into (ip_address, prefix_length).

    FortiGate stores IP and mask together in the "ip" field, e.g.
    "192.0.2.1 255.255.255.0". We convert the subnet mask to a prefix length
    for ipaddress-module compatibility.

    Args:
        ip_field: FortiGate ip field string, e.g., "192.0.2.1 255.255.255.0".

    Returns:
        Tuple of (ip_address, prefix_length) as strings, or None if the field
        is empty, "0.0.0.0 0.0.0.0", or unparseable.

    Examples:
        >>> _parse_fortigate_ip("192.0.2.1 255.255.255.0")
        ('192.0.2.1', '24')
        >>> _parse_fortigate_ip("198.51.100.1 255.255.255.252")
        ('198.51.100.1', '30')
        >>> _parse_fortigate_ip("0.0.0.0 0.0.0.0")
        None
    """
    if not ip_field or ip_field.startswith("0.0.0.0"):
        return None

    # Split "IP MASK" format
    parts = ip_field.strip().split()
    if len(parts) != 2:
        return None

    ip_addr, mask_str = parts

    # Convert subnet mask to prefix length using the ipaddress module
    # "255.255.255.0" → 24, "255.255.255.252" → 30
    try:
        from ipaddress import IPv4Network
        # Create a network with host bits masked to compute prefix
        net = IPv4Network(f"0.0.0.0/{mask_str}")
        prefix_length = str(net.prefixlen)
        return (ip_addr, prefix_length)
    except (ValueError, TypeError):
        return None


def build_subnet_index(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> dict[str, list[tuple[str, str, str]]]:
    """
    Build a subnet membership index from all device interface IPs.

    Scans all devices' interface data (Genie genie_interface.json for Cisco,
    fortigate_system_interface.json for FortiGate) and groups interfaces by
    their subnet. This index is shared by ARP discovery, subnet-only
    discovery, and shared-services enumeration.

    IP Data Sources:
        - Cisco IOS XE/XR: genie_interface.json → interface → ipv4 →
          {ip_with_prefix: {ip, prefix_length}}
        - FortiGate: fortigate_system_interface.json → results[] →
          {name, ip: "IP MASK"}

    Subnet Computation:
        Uses Python's ipaddress.ip_interface() to compute the network address
        from IP + prefix, e.g. 192.0.2.100/24 → network 192.0.2.0/24.

    Excluded:
        - Loopback / host routes (/32): point-to-point, not shared
        - DHCP-negotiated IPs: no static subnet membership
        - Interfaces with 0.0.0.0 or unassigned IPs

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        facts_by_hostname: Dict mapping hostname → device_facts dict. Used to
                           detect FortiGate devices via the facts "os" field.

    Returns:
        Dict mapping subnet string (e.g., "192.0.2.0/24") to a list of
        (hostname, interface_name, ip_address) tuples. Only subnets with 2+
        members are useful for link discovery, but all are returned.

    Example:
        >>> idx = build_subnet_index(facts_dirs, facts_by_hostname)
        >>> idx["192.0.2.0/24"]
        [("core-rtr-01", "GigabitEthernet0/0", "192.0.2.1"),
         ("dist-sw-01", "Vlan99", "192.0.2.100"),
         ("edge-fw-01", "port1", "192.0.2.254")]
    """
    from ipaddress import ip_interface, AddressValueError

    # subnet_string → [(hostname, interface_name, ip_address)]
    subnet_index: dict[str, list[tuple[str, str, str]]] = {}

    for hostname, facts_dir in facts_dirs.items():
        facts = facts_by_hostname.get(hostname, {})
        # The canonical facts carry the OS at top level ("fortios"/"ios-xe"/
        # "ios-xr"); FortiGate IPs come from the REST interface file.
        os_family = facts.get("os", "")

        # -----------------------------------------------------------------
        # Source 1: FortiGate system interface (for FortiGate devices)
        # -----------------------------------------------------------------
        if os_family == "fortios":
            fg_path = facts_dir / "fortigate_system_interface.json"
            fg_data = _load_json_file(fg_path)

            if fg_data:
                for iface in fg_data.get("results", []):
                    name = iface.get("name", "")
                    ip_field = iface.get("ip", "")

                    parsed = _parse_fortigate_ip(ip_field)
                    if not parsed:
                        continue

                    ip_addr, prefix_length = parsed

                    # Skip loopbacks and host routes (/32)
                    if prefix_length == "32":
                        continue

                    try:
                        net = ip_interface(
                            f"{ip_addr}/{prefix_length}"
                        ).network
                        subnet_key = str(net)
                        subnet_index.setdefault(subnet_key, []).append(
                            (hostname, name, ip_addr)
                        )
                    except (ValueError, AddressValueError):
                        continue

            # FortiGate done — skip Genie interface parsing
            continue

        # -----------------------------------------------------------------
        # Source 2: Genie interface JSON (for Cisco IOS XE/XR)
        # -----------------------------------------------------------------
        intf_path = facts_dir / "genie_interface.json"
        intf_data = _load_json_file(intf_path)

        if not intf_data:
            continue

        for intf_name, intf_info in intf_data.items():
            ipv4_block = intf_info.get("ipv4", {})

            for addr_key, addr_info in ipv4_block.items():
                ip_addr = addr_info.get("ip", "")
                prefix_length = addr_info.get("prefix_length", "")

                # Skip DHCP-negotiated, empty, or unassigned IPs
                if not ip_addr or ip_addr == "dhcp_negotiated":
                    continue
                if not prefix_length:
                    continue

                # Skip loopback host routes (/32)
                if str(prefix_length) == "32":
                    continue

                try:
                    net = ip_interface(
                        f"{ip_addr}/{prefix_length}"
                    ).network
                    subnet_key = str(net)
                    subnet_index.setdefault(subnet_key, []).append(
                        (hostname, intf_name, ip_addr)
                    )
                except (ValueError, AddressValueError):
                    continue

    # Sort members within each subnet for determinism
    for subnet_key in subnet_index:
        subnet_index[subnet_key].sort()

    # Log summary
    shared_subnets = {k: v for k, v in subnet_index.items() if len(v) >= 2}
    logger.info(
        "Subnet index: %d total subnets, %d shared (2+ devices)",
        len(subnet_index),
        len(shared_subnets),
    )

    return subnet_index


def _build_ip_to_device_index(
    subnet_index: dict[str, list[tuple[str, str, str]]],
) -> dict[str, tuple[str, str]]:
    """
    Build a reverse lookup from IP address to (hostname, interface).

    Used by ARP discovery to resolve "I see IP X in my ARP table" to
    "IP X belongs to device Y on interface Z".

    Args:
        subnet_index: The subnet membership index from build_subnet_index().

    Returns:
        Dict mapping IP address string → (hostname, interface_name). If the
        same IP appears on multiple devices (misconfiguration), the last one
        wins (rare edge case).

    Example:
        >>> ip_to_dev = _build_ip_to_device_index(subnet_index)
        >>> ip_to_dev["192.0.2.100"]
        ("dist-sw-01", "Vlan99")
    """
    ip_to_device: dict[str, tuple[str, str]] = {}

    for _subnet, members in subnet_index.items():
        for hostname, intf_name, ip_addr in members:
            ip_to_device[ip_addr] = (hostname, intf_name)

    return ip_to_device


# =========================================================================
# MAC-Fingerprint Link Discovery (protocol-free physical cabling)
# =========================================================================
# Detects PHYSICAL cabling with no discovery protocol (CDP/LLDP) by cross-
# referencing ARP (IP→MAC) against a global index of every interface's burned-in
# hardware MAC. If device A's ARP for a peer IP returns a MAC that is the
# hardware address of device B's interface, A's port is physically wired to B.
# This turns links that would otherwise be arp_subnet/medium/l3_reachability
# (hidden from the Physical view) into proven physical/very_high cables.

def _build_hw_mac_to_device_index(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]] | None = None,
) -> dict[str, set[tuple[str, str]]]:
    """Build ``normalized_mac → {(hostname, interface), ...}`` from per-interface
    burned-in hardware MACs across all device types.

    Unlike :func:`_build_mac_to_device_index` (which collapses to one shortest
    interface per MAC and keys on dot-format), this keeps ALL interfaces a MAC
    maps to and keys on the format-agnostic :func:`_normalize_mac` form, so Cisco
    dot-format and FortiGate colon-format MACs unify. The full ``(host, intf)``
    set lets the fingerprint resolver detect intra-device MAC reuse (some virtual
    platforms put the same burned-in MAC on several of their own ports) — the
    remote *device* is then still unambiguous even when the remote *port* is not.

    Sources:
        Cisco (IOS-XE/XR): ``genie_interface.json[intf].phys_address`` (fallback
            ``mac_address``).
        FortiGate: ``fortigate_monitor_interface.json results[port].mac`` (the
            cmdb ``system_interface`` ``macaddr`` is usually empty; the real
            hardware MACs live in the monitor endpoint).
    """
    index: dict[str, set[tuple[str, str]]] = {}

    def _add(mac: str, host: str, intf: str) -> None:
        norm = _normalize_mac(mac)
        if len(norm) != 12 or norm == "000000000000":
            return
        index.setdefault(norm, set()).add((host, intf))

    for hostname, facts_dir in facts_dirs.items():
        # --- Cisco interfaces (IOS-XE / IOS-XR) ---
        intf_data = _load_json_file(facts_dir / "genie_interface.json")
        if intf_data:
            for intf_name, intf_info in intf_data.items():
                if not isinstance(intf_info, dict):
                    continue
                intf_lower = intf_name.lower()
                if intf_lower.startswith(("bluetooth", "appgigabitethernet")):
                    continue
                mac = intf_info.get("phys_address") or intf_info.get("mac_address") or ""
                if mac:
                    _add(mac, hostname, intf_name)

        # --- FortiGate runtime interface MACs (REST monitor endpoint) ---
        fg_mon = _load_json_file(facts_dir / "fortigate_monitor_interface.json")
        if fg_mon:
            results = fg_mon.get("results", fg_mon)
            if isinstance(results, dict):
                items = results.items()
            elif isinstance(results, list):
                items = ((r.get("name") or r.get("id"), r) for r in results
                         if isinstance(r, dict))
            else:
                items = ()
            for port_name, port_info in items:
                if not isinstance(port_info, dict):
                    continue
                mac = port_info.get("mac") or ""
                name = port_info.get("name") or port_info.get("id") or port_name
                if mac and name:
                    _add(mac, hostname, name)

    return index


def _iter_arp_entries(facts_dirs: dict[str, Path]):
    """Yield ``(hostname, local_interface, peer_ip, peer_mac)`` from every device's
    ARP table — Cisco ``genie_arp.json`` and FortiGate ``fortigate_arp.json``."""
    for hostname, facts_dir in facts_dirs.items():
        cisco = _load_json_file(facts_dir / "genie_arp.json")
        if cisco:
            for intf_name, intf_info in cisco.get("interfaces", {}).items():
                neighbors = intf_info.get("ipv4", {}).get("neighbors", {})
                for ip_addr, entry in neighbors.items():
                    mac = (entry or {}).get("link_layer_address") or ""
                    if mac:
                        yield hostname, intf_name, ip_addr, mac

        fg = _load_json_file(facts_dir / "fortigate_arp.json")
        if fg:
            results = fg.get("results", []) if isinstance(fg, dict) else fg
            for entry in (results or []):
                if not isinstance(entry, dict):
                    continue
                intf_name = entry.get("interface")
                ip_addr = entry.get("ip")
                mac = entry.get("mac") or ""
                if intf_name and ip_addr and mac:
                    yield hostname, intf_name, ip_addr, mac


def _fdb_physical_port_for_mac(facts_dir: Path, norm_mac: str) -> str | None:
    """Return the physical port a MAC is learned on in this device's FDB
    (``genie_fdb.json``), skipping SVIs and Port-channel aggregates. None if
    absent (no FDB, or learned only on an SVI/Po). IOS-XE switches only."""
    fdb = _load_json_file(facts_dir / "genie_fdb.json")
    if not fdb:
        return None
    for _vlan_id, vlan_data in fdb.get("mac_table", {}).get("vlans", {}).items():
        for mac_addr, mac_info in vlan_data.get("mac_addresses", {}).items():
            if _normalize_mac(mac_addr) != norm_mac:
                continue
            for fdb_intf_name in mac_info.get("interfaces", {}):
                low = fdb_intf_name.lower()
                if low.startswith(("vlan", "port-channel", "bluetooth",
                                   "appgigabitethernet")):
                    continue
                return fdb_intf_name
    return None


def _is_aggregate_interface(name: str | None) -> bool:
    """True for LAG aggregate interfaces (Port-channel / Bundle-Ether and short
    forms Po<n>/BE<n>). These are NOT single physical cables — LACP discovery owns
    their member links — so the MAC fingerprint must skip them to avoid phantom
    aggregate-to-aggregate cables."""
    if not name:
        return False
    low = name.lower()
    if low.startswith(("port-channel", "portchannel", "bundle-ether")):
        return True
    for p in ("po", "be"):
        if low.startswith(p) and len(low) > len(p) and low[len(p)].isdigit():
            return True
    return False


def discover_mac_fingerprint_links(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
    collected_hostnames: set[str],
    subnet_index: dict[str, list[tuple[str, str, str]]],
    hw_mac_index: dict[str, set[tuple[str, str]]] | None = None,
) -> list[LinkCandidate]:
    """Discover physical cables by MAC fingerprinting — no CDP/LLDP required.

    Phase 1 (L3 routed): A's ARP entry for a peer IP returns the peer's physical
    interface burned-in MAC; the hardware-MAC index resolves it to the remote
    DEVICE. The local port is A's own ARP interface (authoritative). When B's ARP
    independently resolves back to A, it's bilateral (very_high) and the remote
    port is taken from B's own ARP interface toward A — never the index, which can
    be ambiguous when a device reuses one MAC across ports. Unilateral (A only,
    e.g. B uncollected) yields high with the remote port from the index if unique.

    Phase 2 (L2 switchport): when A's ARP interface is a virtual SVI, A's physical
    port is recovered from A's FDB (peer MAC → learned physical port), and the
    remote port from B's FDB (A's local-port MAC → B's physical port). Requires
    FDB on both ends (IOS-XE switches only); no-op gracefully otherwise.

    Guardrails: a MAC must resolve to exactly one remote device (drops HSRP/VRRP/HA
    virtual MACs and cross-device collisions); a local interface that resolves more
    than one distinct remote device is a shared/multi-access segment and is skipped
    entirely (left to arp_subnet as l3_reachability).
    """
    if hw_mac_index is None:
        hw_mac_index = _build_hw_mac_to_device_index(facts_dirs, facts_by_hostname)

    # normalized_mac → set of owning hostnames (device-level projection)
    mac_owners: dict[str, set[str]] = {
        mac: {h for h, _ in pairs} for mac, pairs in hw_mac_index.items()
    }

    # --- Pass 1: collect ARP claims that resolve to exactly one remote device ---
    # claim = (host, local_intf, peer_ip, peer_mac, remote_host)
    claims: list[tuple[str, str, str, str, str]] = []
    intf_remote_devs: dict[tuple[str, str], set[str]] = {}

    for host, local_intf, peer_ip, peer_mac in _iter_arp_entries(facts_dirs):
        owners = mac_owners.get(_normalize_mac(peer_mac), set()) - {host}
        if len(owners) != 1:
            continue  # unresolved / self-only / cross-device-ambiguous → skip
        remote_host = next(iter(owners))
        intf_remote_devs.setdefault((host, local_intf), set()).add(remote_host)
        claims.append((host, local_intf, peer_ip, peer_mac, remote_host))

    def _multiaccess(host: str, local_intf: str) -> bool:
        return len(intf_remote_devs.get((host, local_intf), set())) > 1

    # --- Split into L3 routed claims (directed map) and L2 SVI claims ---
    # directed[(A, B)] = {A_local_intf: peer_mac_A_saw}
    directed: dict[tuple[str, str], dict[str, str]] = {}
    l2_claims: list[tuple[str, str, str, str, str]] = []

    for host, local_intf, peer_ip, peer_mac, remote_host in claims:
        if _multiaccess(host, local_intf):
            continue
        if _is_aggregate_interface(local_intf):
            continue  # LAG aggregate — LACP owns its member cables
        if _is_virtual_interface(local_intf):
            l2_claims.append((host, local_intf, peer_ip, peer_mac, remote_host))
        else:
            directed.setdefault((host, remote_host), {})[local_intf] = peer_mac

    candidates: list[LinkCandidate] = []
    seen_pairs: set[str] = set()

    def _emit(a: str, ai: str | None, b: str, bi: str | None,
              method: str, confidence: str, evidence: list[str]) -> None:
        can_a = canonicalize(ai) if ai else None
        can_b = canonicalize(bi) if bi else None
        ea = f"{a}:{can_a or ai or '?'}"
        eb = f"{b}:{can_b or bi or '?'}"
        lo, hi = sorted([ea, eb])
        key = f"{lo}--{hi}"
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        candidates.append(LinkCandidate(
            local_device=a, local_interface=ai, local_interface_canonical=can_a,
            remote_device=b, remote_interface=bi, remote_interface_canonical=can_b,
            discovery_method=method, confidence=confidence,
            evidence=evidence, peer_collected=b in collected_hostnames,
        ))

    # --- Pass 2a: Phase 1 — L3 routed-port links ---
    for (a, b), a_intf_macs in directed.items():
        b_intf_macs = directed.get((b, a), {})
        if b_intf_macs:
            # Bilateral: each side's own ARP interface is authoritative.
            for ai in sorted(a_intf_macs):
                for bi in sorted(b_intf_macs):
                    _emit(a, ai, b, bi, "mac_fingerprint_bilateral", "very_high",
                          [f"macfp:{a}({ai})↔{b}({bi}) via hw-mac"])
        else:
            # Unilateral: remote port from the index if a single interface matches.
            for ai, peer_mac in sorted(a_intf_macs.items()):
                owners_full = hw_mac_index.get(_normalize_mac(peer_mac), set())
                b_ifaces = sorted({i for h, i in owners_full if h == b})
                bi = b_ifaces[0] if len(b_ifaces) == 1 else None
                _emit(a, ai, b, bi, "mac_fingerprint_unilateral", "high",
                      [f"macfp:{a}({ai})→{peer_mac}→{b} (one-sided)"])

    # --- Pass 2b: Phase 2 — L2 switchport (FDB) links ---
    for host, svi_intf, peer_ip, peer_mac, remote_host in l2_claims:
        local_port = _fdb_physical_port_for_mac(facts_dirs[host], _normalize_mac(peer_mac))
        if not local_port:
            continue  # peer MAC not learned on a physical port here → no L2 cable
        # Remote physical port: find this local port's hardware MAC in remote's FDB.
        local_port_macs = {
            m for m, pairs in hw_mac_index.items()
            if (host, local_port) in pairs
        }
        remote_port = None
        if remote_host in facts_dirs:
            for m in sorted(local_port_macs):  # R2-FDB-2: deterministic MAC pick
                remote_port = _fdb_physical_port_for_mac(facts_dirs[remote_host], m)
                if remote_port:
                    break
        if remote_port:
            _emit(host, local_port, remote_host, remote_port,
                  "mac_fingerprint_bilateral", "very_high",
                  [f"macfp-fdb:{host}({local_port})↔{remote_host}({remote_port})"])
        else:
            _emit(host, local_port, remote_host, None,
                  "mac_fingerprint_unilateral", "high",
                  [f"macfp-fdb:{host}({local_port})→{remote_host} (one-sided)"])

    logger.info(
        "MAC-fingerprint discovery: %d link candidate(s) (%d L2/FDB inputs)",
        len(candidates), len(l2_claims),
    )
    return candidates


# =========================================================================
# ARP + Subnet Link Discovery (Level 3)
# =========================================================================

def discover_arp_subnet_links(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
    collected_hostnames: set[str],
    subnet_index: dict[str, list[tuple[str, str, str]]],
) -> list[LinkCandidate]:
    """
    Discover physical links from ARP tables correlated with shared subnets.

    This is the primary discovery method for devices that don't support
    CDP/LLDP (e.g., FortiGate firewalls). When a Cisco switch has a
    FortiGate's IP in its ARP table on a specific interface, and both devices
    share a subnet, that's strong evidence of a physical connection.

    Algorithm:
        1. Build an IP→(device, interface) ownership index from the subnet
           membership data (to resolve ARP IP → device identity).
        2. For each device with ARP data (genie_arp.json):
           a. For each ARP entry: (learned_on_interface, neighbor_ip, mac)
           b. Resolve neighbor_ip → (remote_device, remote_interface)
           c. Skip self-references
           d. Record the link local_device:arp_interface ↔ remote_device:ip_interface
        3. Check for mutual ARP (does the remote device also have the local
           device's IP?) → two evidence strings vs one.
        4. Deduplicate: A→B and B→A produce one candidate.

    ARP Interface Semantics:
        The ARP table records which INTERFACE learned a neighbor's IP. On an
        L3 switch this is the SVI (e.g., Vlan99), not the physical port — the
        physical port is discoverable via the MAC table, but the SVI gives the
        L3 connectivity.

    FortiGate Handling:
        FortiGate devices have no genie_arp.json (Genie is Cisco-only), but
        Cisco devices in the same subnet have the FortiGate's IP in THEIR ARP
        tables. This one-sided ARP is sufficient evidence for a link.

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        facts_by_hostname: Dict mapping hostname → device_facts dict.
        collected_hostnames: Set of hostnames with facts/ data.
        subnet_index: Pre-built subnet membership index from
                      build_subnet_index().

    Returns:
        List of LinkCandidate objects with discovery_method "arp_subnet"
        and confidence "medium".
    """
    # -------------------------------------------------------------------------
    # Step 1: Build IP → (device, interface) ownership index
    # -------------------------------------------------------------------------
    ip_to_device = _build_ip_to_device_index(subnet_index)

    # -------------------------------------------------------------------------
    # Step 2: Build per-device ARP lookup
    # -------------------------------------------------------------------------
    # Structure: {hostname: {ip_seen: arp_interface}}
    arp_by_device: dict[str, dict[str, str]] = {}

    for hostname, facts_dir in facts_dirs.items():
        arp_path = facts_dir / "genie_arp.json"
        arp_data = _load_json_file(arp_path)

        if not arp_data:
            continue

        device_arp: dict[str, str] = {}

        # Navigate Genie ARP Ops schema:
        # interfaces → <intf_name> → ipv4 → neighbors → <ip> → {ip, mac, origin}
        for intf_name, intf_info in arp_data.get("interfaces", {}).items():
            ipv4_block = intf_info.get("ipv4", {})
            neighbors = ipv4_block.get("neighbors", {})

            for ip_addr, _entry_info in neighbors.items():
                # Record which interface this IP was learned on
                # (if the same IP appears on multiple interfaces, last wins)
                device_arp[ip_addr] = intf_name

        if device_arp:
            arp_by_device[hostname] = device_arp

    logger.info(
        "ARP data loaded: %d devices with ARP tables, %d total entries",
        len(arp_by_device),
        sum(len(v) for v in arp_by_device.values()),
    )

    # -------------------------------------------------------------------------
    # Step 3: Discover links from ARP + subnet correlation
    # -------------------------------------------------------------------------
    seen_pairs: set[str] = set()
    candidates: list[LinkCandidate] = []

    for hostname, device_arp in arp_by_device.items():
        for ip_seen, arp_interface in device_arp.items():
            # Skip if we don't know who owns this IP
            if ip_seen not in ip_to_device:
                continue

            remote_hostname, remote_interface = ip_to_device[ip_seen]

            # Skip self-references (device seeing its own IP in ARP)
            if remote_hostname == hostname:
                continue

            # -----------------------------------------------------------------
            # Build canonical pair key for dedup
            # -----------------------------------------------------------------
            canonical_local = canonicalize(arp_interface)
            canonical_remote = canonicalize(remote_interface)

            endpoint_a = f"{hostname}:{canonical_local or arp_interface}"
            endpoint_b = f"{remote_hostname}:{canonical_remote or remote_interface}"

            if endpoint_a > endpoint_b:
                endpoint_a, endpoint_b = endpoint_b, endpoint_a

            pair_key = f"{endpoint_a}--{endpoint_b}"

            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # -----------------------------------------------------------------
            # Check for mutual ARP (both sides see each other)
            # -----------------------------------------------------------------
            remote_arp = arp_by_device.get(remote_hostname, {})

            # Find what IP 'hostname' has on 'arp_interface' for the reverse check
            local_ip_on_interface = None
            for _subnet, members in subnet_index.items():
                for member_host, member_intf, member_ip in members:
                    if member_host == hostname and member_intf == arp_interface:
                        local_ip_on_interface = member_ip
                        break
                if local_ip_on_interface:
                    break

            is_mutual = False
            if local_ip_on_interface and local_ip_on_interface in remote_arp:
                is_mutual = True

            # -----------------------------------------------------------------
            # Build evidence and candidate
            # -----------------------------------------------------------------
            evidence_parts = [
                f"arp:{hostname}({arp_interface})→{ip_seen}→{remote_hostname}",
            ]
            if is_mutual:
                evidence_parts.append(
                    f"arp:{remote_hostname}→{local_ip_on_interface}→{hostname}",
                )

            peer_collected = remote_hostname in collected_hostnames

            candidate = LinkCandidate(
                local_device=hostname,
                local_interface=arp_interface,
                local_interface_canonical=canonical_local,
                remote_device=remote_hostname,
                remote_interface=remote_interface,
                remote_interface_canonical=canonical_remote,
                discovery_method="arp_subnet",
                confidence="medium",
                evidence=evidence_parts,
                peer_collected=peer_collected,
            )

            candidates.append(candidate)

    # -------------------------------------------------------------------------
    # Step 4: Sort for determinism
    # -------------------------------------------------------------------------
    candidates.sort(key=lambda c: (
        c.local_device,
        c.remote_device,
        c.local_interface_canonical or "",
    ))

    logger.info(
        "ARP+subnet discovery: %d candidates (%d mutual, %d one-way)",
        len(candidates),
        sum(1 for c in candidates if len(c.evidence) > 1),
        sum(1 for c in candidates if len(c.evidence) == 1),
    )

    return candidates


# =========================================================================
# MAC Table + Subnet Link Discovery (Level 4)
# =========================================================================

def _build_mac_to_device_index(
    facts_dirs: dict[str, Path],
) -> dict[str, tuple[str, str]]:
    """
    Build a MAC address → (device, interface) lookup from Genie interface data.

    Scans genie_interface.json for each device and extracts the MAC address of
    each interface. This index resolves a MAC learned in a switch's FDB to the
    device and interface that owns it.

    MAC Format:
        Genie interface data uses Cisco dot-quad format ("1234.5678.9abc").
        We normalize to lowercase for consistent lookup.

    Multiple Interfaces per MAC:
        Sub-interfaces share their parent's MAC (e.g., Gi0/2, Gi0/2.1000,
        Gi0/2.1101 all have the same MAC). We prefer the SHORTEST interface
        name (the physical parent) to avoid sub-interface noise.

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.

    Returns:
        Dict mapping lowercase MAC string → (hostname, interface_name). Only
        interfaces with a mac_address field are included.

    Example:
        >>> mac_idx = _build_mac_to_device_index(facts_dirs)
        >>> mac_idx["1234.5678.9abc"]
        ("core-rtr-01", "GigabitEthernet0/0")
    """
    mac_to_device: dict[str, tuple[str, str]] = {}

    for hostname, facts_dir in facts_dirs.items():
        intf_path = facts_dir / "genie_interface.json"
        intf_data = _load_json_file(intf_path)

        if not intf_data:
            continue

        # Track MAC→(hostname, interface) per MAC, preferring shorter
        # interface names (physical parent over sub-interface)
        local_mac_map: dict[str, tuple[str, int]] = {}

        for intf_name, intf_info in intf_data.items():
            mac = intf_info.get("mac_address", "")
            if not mac:
                continue

            # Skip non-network interfaces whose MACs pollute the FDB:
            # - Bluetooth0/4: Catalyst BLE management radio
            # - AppGigabitEthernet: internal backplane to the app-hosting container
            intf_lower = intf_name.lower()
            if intf_lower.startswith(("bluetooth", "appgigabitethernet")):
                continue

            mac_lower = mac.lower()
            name_len = len(intf_name)

            # Keep the shortest interface name for this MAC
            # (physical interface over sub-interface)
            if mac_lower not in local_mac_map or name_len < local_mac_map[mac_lower][1]:
                local_mac_map[mac_lower] = (intf_name, name_len)

        # Merge into global index
        for mac_lower, (intf_name, _) in local_mac_map.items():
            mac_to_device[mac_lower] = (hostname, intf_name)

    return mac_to_device


def discover_mac_subnet_links(
    facts_dirs: dict[str, Path],
    collected_hostnames: set[str],
    subnet_index: dict[str, list[tuple[str, str, str]]],
) -> list[LinkCandidate]:
    """
    Discover links from switch MAC address tables (FDB) + subnet correlation.

    When a switch learns a device's MAC address on a specific physical port,
    and both devices share a subnet, that gives the PHYSICAL PORT level
    connection that ARP-based discovery (which uses SVIs) cannot provide.

    This is especially valuable for L2 switches where:
    - ARP says: "dist-sw-01:Vlan99 sees edge-fw-01 at 192.0.2.254"
    - FDB says: "dist-sw-01:Gi1/0/6 learned MAC 1234.5678.9abc"
    - MAC index says: "1234.5678.9abc = edge-fw-01:port1"
    - → Physical link: dist-sw-01:Gi1/0/6 ↔ edge-fw-01:port1

    Genie FDB JSON Schema::

        {
          "mac_table": {
            "vlans": {
              "99": {
                "vlan": 99,
                "mac_addresses": {
                  "1234.5678.9abc": {
                    "mac_address": "1234.5678.9abc",
                    "interfaces": {
                      "GigabitEthernet1/0/6": {
                        "interface": "GigabitEthernet1/0/6",
                        "entry_type": "dynamic"
                      }
                    }
                  }
                }
              }
            }
          }
        }

    Algorithm:
        1. Build MAC→(device, interface) index from genie_interface.json
        2. For each switch with genie_fdb.json:
           a. For each dynamic MAC entry on a physical port (not SVI):
              - Look up the MAC to find the owner device/interface
              - Verify they share a subnet (using subnet_index)
              - Create link: switch:physical_port ↔ owner:interface
        3. Only use dynamic entries (static = self-referencing SVI MACs)
        4. Skip entries learned on an SVI (Vlan*) or Port-channel aggregate

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        collected_hostnames: Set of hostnames with facts/ data.
        subnet_index: Pre-built subnet membership index (for subnet check).

    Returns:
        List of LinkCandidate objects with discovery_method "mac_subnet"
        and confidence "low".
    """
    # -------------------------------------------------------------------------
    # Step 1: Build MAC → (device, interface) index
    # -------------------------------------------------------------------------
    mac_to_device = _build_mac_to_device_index(facts_dirs)

    logger.info(
        "MAC-to-device index: %d unique MACs from genie_interface.json",
        len(mac_to_device),
    )

    # -------------------------------------------------------------------------
    # Step 2: Build subnet membership sets for verification
    # -------------------------------------------------------------------------
    device_subnets: dict[str, set[str]] = {}
    for subnet_key, members in subnet_index.items():
        for hostname, _intf, _ip in members:
            device_subnets.setdefault(hostname, set()).add(subnet_key)

    # -------------------------------------------------------------------------
    # Step 3: Scan FDB tables and cross-reference
    # -------------------------------------------------------------------------
    seen_pairs: set[str] = set()
    candidates: list[LinkCandidate] = []

    for hostname, facts_dir in facts_dirs.items():
        fdb_path = facts_dir / "genie_fdb.json"
        fdb_data = _load_json_file(fdb_path)

        if not fdb_data:
            continue

        # Navigate Genie FDB Ops schema:
        # mac_table → vlans → <vlan_id> → mac_addresses → <mac> →
        #   interfaces → <intf> → {interface, entry_type}
        vlans = fdb_data.get("mac_table", {}).get("vlans", {})

        for vlan_id, vlan_data in vlans.items():
            mac_addresses = vlan_data.get("mac_addresses", {})

            for mac_addr, mac_info in mac_addresses.items():
                interfaces = mac_info.get("interfaces", {})

                for fdb_intf_name, fdb_intf_info in interfaces.items():
                    entry_type = fdb_intf_info.get("entry_type", "")

                    # Skip static entries (self-referencing SVI MACs)
                    if entry_type != "dynamic":
                        continue

                    # Skip SVIs (we want physical port mappings only)
                    if fdb_intf_name.lower().startswith("vlan"):
                        continue

                    # Skip Port-channel aggregates (member ports are more useful)
                    if fdb_intf_name.lower().startswith("port-channel"):
                        continue

                    # Skip non-network interfaces (Bluetooth, AppGigabitEthernet)
                    fdb_lower = fdb_intf_name.lower()
                    if fdb_lower.startswith(("bluetooth", "appgigabitethernet")):
                        continue

                    # Look up the MAC in our device index
                    mac_lower = mac_addr.lower()
                    if mac_lower not in mac_to_device:
                        continue

                    remote_hostname, remote_interface = mac_to_device[mac_lower]

                    # Skip self-references (switch seeing its own MAC)
                    if remote_hostname == hostname:
                        continue

                    # Verify both devices share at least one subnet
                    local_subnets = device_subnets.get(hostname, set())
                    remote_subnets = device_subnets.get(remote_hostname, set())
                    shared = local_subnets & remote_subnets

                    if not shared:
                        # No shared subnet — could be a transitive MAC learned
                        # via another switch. Skip to avoid false positive links.
                        continue

                    # Build canonical pair key for dedup
                    canonical_local = canonicalize(fdb_intf_name)
                    canonical_remote = canonicalize(remote_interface)

                    endpoint_a = f"{hostname}:{canonical_local or fdb_intf_name}"
                    endpoint_b = f"{remote_hostname}:{canonical_remote or remote_interface}"

                    if endpoint_a > endpoint_b:
                        endpoint_a, endpoint_b = endpoint_b, endpoint_a

                    pair_key = f"{endpoint_a}--{endpoint_b}"

                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    evidence = [
                        f"fdb:{hostname}({fdb_intf_name})←MAC:{mac_addr}→"
                        f"{remote_hostname}({remote_interface}) "
                        f"vlan={vlan_id}",
                    ]

                    peer_collected = remote_hostname in collected_hostnames

                    candidate = LinkCandidate(
                        local_device=hostname,
                        local_interface=fdb_intf_name,
                        local_interface_canonical=canonical_local,
                        remote_device=remote_hostname,
                        remote_interface=remote_interface,
                        remote_interface_canonical=canonical_remote,
                        discovery_method="mac_subnet",
                        confidence="low",
                        evidence=evidence,
                        peer_collected=peer_collected,
                    )

                    candidates.append(candidate)

    candidates.sort(key=lambda c: (
        c.local_device,
        c.remote_device,
        c.local_interface_canonical or "",
    ))

    logger.info("MAC+subnet discovery: %d candidates", len(candidates))

    return candidates


# =========================================================================
# Subnet-Only Link Discovery (Level 5) — lowest-confidence fallback
# =========================================================================

# Minimum prefix length (= maximum network size) for subnet-only discovery.
# The filter skips subnets where prefix_len < this value:
#   /30, /29, /24 (>= 24) → INCLUDED (point-to-point + typical LAN)
#   /23, /16    (< 24)    → EXCLUDED (too many hosts → high false-positive risk)
# Subnet co-location on a large broadcast domain does not reliably imply a
# direct physical connection.
_MAX_SUBNET_ONLY_PREFIX = 24

# Maximum number of devices on a single subnet for L5 discovery. A subnet with
# more than this many devices is likely a shared broadcast domain (e.g., a
# management VLAN) where co-location does NOT imply direct connection — a /24
# management subnet with 6 devices would produce C(6,2)=15 meaningless links.
# Point-to-point segments (/30, /31) have 2 devices; small transit subnets
# (/29) up to 3-4.
_MAX_SUBNET_ONLY_MEMBERS = 3


def discover_subnet_only_links(
    subnet_index: dict[str, list[tuple[str, str, str]]],
    collected_hostnames: set[str],
    existing_pair_keys: set[str],
) -> list[LinkCandidate]:
    """
    Create low-confidence link candidates for device pairs sharing a subnet.

    This is the fallback discovery method (Level 5) — used when no ARP, MAC,
    CDP, or LLDP evidence exists for a device pair that shares a subnet. These
    candidates represent "these two devices COULD be connected because they're
    on the same subnet, but we have no protocol-level proof."

    When to Expect L5 Links:
        In a well-connected network where CDP/ARP/MAC cover all relationships,
        this produces 0 candidates. L5 links only appear when a device's ARP
        table was not collected, the device supports no neighbor protocol, the
        ARP cache expired, or a new device hasn't generated ARP traffic yet.

    Subnet Size Limit:
        Only subnets with prefix length >= 24 are considered. Larger subnets
        (/16, /8) would produce a combinatorial explosion of false positives.

    Member Count Limit:
        Only subnets with <= 3 unique devices are considered.

    Args:
        subnet_index: Pre-built subnet membership index.
        collected_hostnames: Set of hostnames with facts/ data.
        existing_pair_keys: Canonical pair keys already discovered by L1-L4
                            methods ("devA:intf--devB:intf"). Pairs already
                            present here are skipped. Pass an empty set if no
                            prior discovery was done.

    Returns:
        List of LinkCandidate objects with discovery_method "subnet_only"
        and confidence "very_low".
    """
    seen_pairs: set[str] = set()
    candidates: list[LinkCandidate] = []

    for subnet_key, members in subnet_index.items():
        # Filter: only shared subnets (2+ members)
        if len(members) < 2:
            continue

        # Filter: only small subnets (/24 or smaller).
        # Extract prefix length from subnet string "192.0.2.0/24" → 24
        try:
            prefix_len = int(subnet_key.split("/")[1])
        except (IndexError, ValueError):
            continue

        if prefix_len < _MAX_SUBNET_ONLY_PREFIX:
            # Subnet too large (e.g., /16) — skip to avoid combinatorial
            # false positives
            continue

        # Filter: skip subnets with too many members (shared broadcast domain).
        # Deduplicate by hostname (one device may have several interfaces here).
        unique_hosts = set(m[0] for m in members)
        if len(unique_hosts) > _MAX_SUBNET_ONLY_MEMBERS:
            logger.debug(
                "Subnet-only: skipping %s — %d devices (limit %d)",
                subnet_key, len(unique_hosts), _MAX_SUBNET_ONLY_MEMBERS,
            )
            continue

        # Generate all pairs within this subnet
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                host_a, intf_a, ip_a = members[i]
                host_b, intf_b, ip_b = members[j]

                canonical_a = canonicalize(intf_a)
                canonical_b = canonicalize(intf_b)

                endpoint_a = f"{host_a}:{canonical_a or intf_a}"
                endpoint_b = f"{host_b}:{canonical_b or intf_b}"

                if endpoint_a > endpoint_b:
                    endpoint_a, endpoint_b = endpoint_b, endpoint_a

                pair_key = f"{endpoint_a}--{endpoint_b}"

                # Skip if already seen within L5
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # Skip if already discovered at a higher confidence level (L1-L4)
                if pair_key in existing_pair_keys:
                    continue

                evidence = [
                    f"subnet:{subnet_key} "
                    f"({host_a}:{intf_a}={ip_a}, "
                    f"{host_b}:{intf_b}={ip_b})",
                ]

                peer_collected = host_b in collected_hostnames

                candidate = LinkCandidate(
                    local_device=host_a,
                    local_interface=intf_a,
                    local_interface_canonical=canonical_a,
                    remote_device=host_b,
                    remote_interface=intf_b,
                    remote_interface_canonical=canonical_b,
                    discovery_method="subnet_only",
                    confidence="very_low",
                    evidence=evidence,
                    peer_collected=peer_collected,
                )

                candidates.append(candidate)

    candidates.sort(key=lambda c: (
        c.local_device,
        c.remote_device,
        c.local_interface_canonical or "",
    ))

    logger.info("Subnet-only discovery: %d candidates (L5 fallback)", len(candidates))

    return candidates


# =========================================================================
# FDB-based Firewall Link Discovery (Level 7)
# =========================================================================
# FortiGate firewalls have no CDP/LLDP, and their REST API returns
# 00:00:00:00:00:00 for all MAC fields, so standard LACP resolution fails.
# This function uses ARP → FDB → LACP fingerprinting to discover the physical
# member-pair links between switches and firewalls.


def _mac_prefix_bytes(mac: str, num_bytes: int = 5) -> str:
    """Extract the first N bytes of a MAC address as a normalized prefix.

    Handles both colon (12:34:56:78:9a:bc) and Cisco dot (1234.5678.9abc)
    formats. Default 5 bytes (10 hex chars) — enough to distinguish FortiGate
    HA members that share an OUI + batch byte but differ at byte 5.

    Examples (5 bytes):
        "12:34:56:78:9a:bc" → "123456789a"
        "12:34:56:78:aa:d4" → "12345678aa"
    """
    # Strip all separators and lowercase
    clean = mac.lower().replace(":", "").replace(".", "").replace("-", "")
    chars = num_bytes * 2
    return clean[:chars] if len(clean) >= chars else clean


def discover_fdb_firewall_links(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict],
) -> list[LinkCandidate]:
    """Discover physical links between switches and FortiGate firewalls.

    Algorithm:
      1. Identify firewall devices (os == "fortios")
      2. Build FortiGate aggregate → physical member map from
         fortigate_system_interface.json (restricted to the data VDOM)
      3. Collect firewall IPs from fortigate_system_interface.json
      4. Search ARP tables across all switches for those IPs → firewall MACs
      5. Search FDB tables for those MACs on Port-channel interfaces
      6. Filter via LACP port_priority=255 fingerprint (FortiGate default)
      7. Scan remaining switches for LACP Po's with the same fingerprint
      8. Expand each switch Po into physical member pairs

    Returns:
        List of LinkCandidates for each physical cable (switch member ↔ FW member).
    """
    # Step 1: Identify firewall devices
    firewall_ids: set[str] = set()
    for hostname, facts in facts_by_hostname.items():
        os_val = facts.get("os", "")
        if os_val == "fortios":
            firewall_ids.add(hostname)
    if not firewall_ids:
        return []

    # Step 2: Build FortiGate aggregate → physical member map.
    # A FortiGate may have aggregates in multiple VDOMs; we restrict discovery
    # to the data VDOM (the VDOM with the most aggregate interfaces) so that
    # connections on other VDOMs are not discovered as physical cables.
    # {fw_id: {agg_name_lower: [member1, member2, ...]}}
    fw_agg_members: dict[str, dict[str, list[str]]] = {}
    fw_data_vdom: dict[str, str] = {}  # fw_id → data VDOM name (for Step 2.5)
    for fw_id in firewall_ids:
        facts_dir = facts_dirs.get(fw_id)
        if not facts_dir:
            continue
        fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if not fg_data:
            continue
        intfs = fg_data.get("results", fg_data) if isinstance(fg_data, dict) else fg_data
        if not isinstance(intfs, list):
            continue
        # Two-pass: collect per-VDOM aggregate maps, then select the data VDOM
        agg_by_vdom: dict[str, dict[str, list[str]]] = {}
        agg_vdom_count: dict[str, int] = {}
        for intf in intfs:
            if intf.get("type") == "aggregate":
                members = [m.get("interface-name", "") for m in intf.get("member", [])]
                members = [m for m in members if m]
                if members:
                    vdom = intf.get("vdom", "")
                    agg_vdom_count[vdom] = agg_vdom_count.get(vdom, 0) + 1
                    agg_by_vdom.setdefault(vdom, {})[intf["name"].lower()] = members
        if not agg_vdom_count:
            continue
        # Data VDOM = the VDOM with the most aggregate interfaces
        data_vdom = max(agg_vdom_count, key=lambda v: agg_vdom_count[v])
        agg_map = agg_by_vdom.get(data_vdom, {})
        if agg_map:
            fw_agg_members[fw_id] = agg_map
            fw_data_vdom[fw_id] = data_vdom

    # Step 2.5: Load actual hardware port MACs from fortigate_monitor_interface.json.
    # The CMDB endpoint (fortigate_system_interface) returns zero MACs for physical
    # ports; the monitor endpoint returns real hardware MACs. The monitor is called
    # from the data-VDOM context so it returns only that VDOM's physical ports.
    # fw_data_mac_to_port stays empty for FortiGates whose monitor returns zero MACs
    # (e.g. a FortiGate VM) — those fall back to the legacy sequential formula in 8d.
    fw_data_mac_to_port: dict[int, str] = {}  # active-unit MAC last-2-bytes → port name

    for fw_id in firewall_ids:
        facts_dir = facts_dirs.get(fw_id)
        if not facts_dir:
            continue
        mon_data = _load_json_file(facts_dir / "fortigate_monitor_interface.json")
        if not mon_data:
            continue
        mon_results = mon_data.get("results", {})
        if not isinstance(mon_results, dict):
            continue
        data_vdom = fw_data_vdom.get(fw_id, "")
        fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
        intfs_mon = fg_data.get("results", fg_data) if isinstance(fg_data, dict) else fg_data
        port_vdom_mon: dict[str, str] = {}
        if isinstance(intfs_mon, list):
            for intf in intfs_mon:
                if intf.get("type") == "physical":
                    port_vdom_mon[intf.get("name", "")] = intf.get("vdom", "")
        for port_name, port_info in mon_results.items():
            if data_vdom and port_vdom_mon.get(port_name) != data_vdom:
                continue  # Skip ports on other VDOMs
            mac_str = port_info.get("mac", "")
            if not mac_str:
                continue
            hex_clean = mac_str.replace(":", "").replace(".", "").lower()
            if len(hex_clean) != 12 or int(hex_clean, 16) == 0:
                continue  # Skip zero MACs (FortiGate VM / placeholder)
            mac_last2 = int(hex_clean[-4:], 16)
            fw_data_mac_to_port[mac_last2] = port_name

    logger.debug(
        "FDB firewall discovery: fw_data_mac_to_port has %d entries%s",
        len(fw_data_mac_to_port),
        "" if fw_data_mac_to_port else " (legacy formula fallback active)",
    )

    # Step 3: Collect firewall IPs from fortigate_system_interface.json,
    # restricted to the VDOM containing the physical aggregates (data VDOM only)
    # so IPs from other VDOMs don't cause false-positive FDB discovery.
    fw_ips: set[str] = set()
    for fw_id in firewall_ids:
        facts_dir = facts_dirs.get(fw_id)
        if not facts_dir:
            continue
        fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if not fg_data:
            continue
        intfs = fg_data.get("results", fg_data) if isinstance(fg_data, dict) else fg_data
        if not isinstance(intfs, list):
            continue
        # Determine data VDOM from aggregate interfaces (resolved in Step 2)
        agg_names = set(fw_agg_members.get(fw_id, {}).keys())
        data_vdom: str | None = None
        for intf in intfs:
            if intf.get("name", "").lower() in agg_names and intf.get("vdom"):
                data_vdom = intf["vdom"]
                break
        for intf in intfs:
            if data_vdom and intf.get("vdom") != data_vdom:
                continue
            ip_str = intf.get("ip", "")
            if isinstance(ip_str, str) and " " in ip_str:
                ip = ip_str.split()[0]
                if ip and ip != "0.0.0.0":
                    fw_ips.add(ip)

    if not fw_ips:
        logger.debug("FDB firewall discovery: no firewall IPs found")
        return []

    # Step 4: Search ALL devices' ARP tables for firewall MACs.
    # Also build per-switch sets so Step 5 can filter to data-VDOM-only
    # connections. A switch directly connected to the data VDOM will have the
    # same FW MAC in both its ARP table and its FDB on the Port-channel. A
    # switch connected to a non-collected VDOM will have a *different* FW MAC in
    # FDB (learned transitively) — that mismatch is the filter.
    fw_macs: set[str] = set()
    fw_macs_per_switch: dict[str, set[str]] = {}   # switch_id → FW MACs from its own ARP
    for hostname, facts_dir in facts_dirs.items():
        if hostname in firewall_ids:
            continue
        arp_data = _load_json_file(facts_dir / "genie_arp.json")
        if not arp_data:
            continue
        for intf_data in arp_data.get("interfaces", {}).values():
            for nbr_ip, nbr in intf_data.get("ipv4", {}).get("neighbors", {}).items():
                if nbr_ip in fw_ips:
                    mac = nbr.get("link_layer_address", "")
                    if mac and mac != "0000.0000.0000":
                        fw_macs.add(mac)
                        fw_macs_per_switch.setdefault(hostname, set()).add(mac)

    if not fw_macs:
        logger.debug("FDB firewall discovery: no firewall MACs found in ARP tables")
        return []
    logger.debug("FDB firewall discovery: found %d firewall MACs: %s", len(fw_macs), fw_macs)

    # Step 5: Search ALL switches' FDB for those MACs on Port-channel interfaces.
    # Only accept a Port-channel match when the FDB MAC is the *same* MAC this
    # switch found in its own ARP table. This restricts discovery to interfaces
    # with a direct L3 adjacency to the collected FW VDOM, filtering out physical
    # cables that belong to a different (uncollected) VDOM on the same FortiGate.
    fdb_candidates: dict[str, set[str]] = {}  # switch_id → {Po names}
    for hostname, facts_dir in facts_dirs.items():
        if hostname in firewall_ids:
            continue
        sw_fw_macs = fw_macs_per_switch.get(hostname, set())
        if not sw_fw_macs:
            continue
        fdb_data = _load_json_file(facts_dir / "genie_fdb.json")
        if not fdb_data:
            continue
        for vlan_data in fdb_data.get("mac_table", {}).get("vlans", {}).values():
            for mac_addr, mac_entry in vlan_data.get("mac_addresses", {}).items():
                if mac_addr in sw_fw_macs:
                    for intf_name in mac_entry.get("interfaces", {}):
                        if intf_name.startswith("Port-channel"):
                            fdb_candidates.setdefault(hostname, set()).add(intf_name)

    if not fdb_candidates:
        logger.debug("FDB firewall discovery: no FDB matches on Port-channels")
        return []

    # Step 6: Filter via LACP fingerprint — FortiGate uses port_priority=255
    active_pos: dict[str, set[str]] = {}
    for switch_id, po_names in fdb_candidates.items():
        lag_data = _load_json_file(facts_dirs[switch_id] / "genie_lag.json")
        if not lag_data:
            continue
        for po_name in po_names:
            po_info = lag_data.get("interfaces", {}).get(po_name, {})
            members = po_info.get("members", {})
            if not members:
                continue
            first_member = next(iter(members.values()), {})
            partner_pri = first_member.get("lacp_port_priority")
            # Cisco default is 32768; FortiGate default is 255.
            # Skip Port-channels whose LACP partner is a Cisco device (indirect path).
            if partner_pri == 32768:
                continue
            active_pos.setdefault(switch_id, set()).add(po_name)

    if not active_pos:
        logger.debug("FDB firewall discovery: all FDB matches filtered (indirect paths)")
        return []

    # Determine HA size from FortiGate HA peer data
    ha_size = 1
    for fw_id in firewall_ids:
        facts_dir = facts_dirs.get(fw_id)
        if not facts_dir:
            continue
        ha_data = _load_json_file(facts_dir / "fortigate_ha_peer.json")
        if ha_data:
            peers = ha_data.get("results", [])
            if len(peers) > 1:
                ha_size = len(peers)
            break

    # Collect active FW Port-channels and find HA partner Po's
    fdb_pos: list[tuple[str, str, list[str]]] = []
    ref_prefix = ""       # First 8 hex chars of partner MAC (4 bytes)
    ref_member_count: int | None = None

    for switch_id, po_names in active_pos.items():
        lag_data = _load_json_file(facts_dirs[switch_id] / "genie_lag.json")
        if not lag_data:
            continue

        for po_name in po_names:
            po_info = lag_data.get("interfaces", {}).get(po_name, {})
            members = po_info.get("members", {})
            if not members:
                continue
            first_member = next(iter(members.values()), {})
            partner_mac = first_member.get("partner_id", "")
            if partner_mac and partner_mac != "0000.0000.0000" and not ref_prefix:
                ref_prefix = partner_mac.replace(".", "")[:8]
            if ref_member_count is None:
                ref_member_count = len(members)
            fdb_pos.append((switch_id, po_name, sorted(members.keys())))

        # If HA > 1, find partner Po's by LACP partner MAC prefix
        if ha_size > 1 and ref_prefix and ref_member_count is not None:
            found = len([r for r in fdb_pos if r[0] == switch_id])
            for po_name, po_info in lag_data.get("interfaces", {}).items():
                if po_name in po_names or found >= ha_size:
                    break
                members = po_info.get("members", {})
                if not members or len(members) != ref_member_count:
                    continue
                first_member = next(iter(members.values()), {})
                partner_mac = first_member.get("partner_id", "")
                if not partner_mac:
                    continue
                candidate_prefix = partner_mac.replace(".", "")[:8]
                if candidate_prefix == ref_prefix:
                    fdb_pos.append((switch_id, po_name, sorted(members.keys())))
                    found += 1

    # Step 7: Scan remaining switches for LACP Po's with the FortiGate fingerprint
    if ref_prefix:
        checked_switches = set(active_pos.keys())
        for hostname, facts_dir in facts_dirs.items():
            if hostname in checked_switches or hostname in firewall_ids:
                continue
            lag_data = _load_json_file(facts_dir / "genie_lag.json")
            if not lag_data:
                continue
            sw_found = 0
            for po_name, po_info in lag_data.get("interfaces", {}).items():
                if sw_found >= ha_size:
                    break
                members = po_info.get("members", {})
                if not members:
                    continue
                if ref_member_count and len(members) != ref_member_count:
                    continue
                first_member = next(iter(members.values()), {})
                partner_pri = first_member.get("lacp_port_priority")
                if partner_pri == 32768:
                    continue
                partner_mac = first_member.get("partner_id", "")
                if not partner_mac:
                    continue
                candidate_prefix = partner_mac.replace(".", "")[:8]
                if candidate_prefix != ref_prefix:
                    continue
                # Accept a Po if any of these conditions hold:
                # (a) no ARP-resolved FW MACs: pure L2 switch, trust LACP fingerprint
                # (b) FDB on this Po has a MAC whose 4-byte prefix matches any ARP FW MAC
                #     (FortiGate virtual MACs share a 4-byte prefix but differ at the last
                #     byte, so use prefix comparison instead of exact match)
                # (c) FDB on this Po has no entries at all: FW MAC not yet learned; the LACP
                #     fingerprint (partner_priority=255 + physical MAC prefix) is sufficient
                # Reject only if FDB has entries on this Po that all mismatch — that
                # indicates transit-learned MACs from a different (uncollected) VDOM.
                sw_fw_macs = fw_macs_per_switch.get(hostname, set())
                fdb_data_sw = _load_json_file(facts_dir / "genie_fdb.json")
                fw_mac4s = {_mac_prefix_bytes(m, 4) for m in sw_fw_macs}
                fdb_macs_on_po = [
                    mac
                    for vd in (fdb_data_sw or {}).get("mac_table", {}).get("vlans", {}).values()
                    for mac, me in vd.get("mac_addresses", {}).items()
                    if po_name in me.get("interfaces", {})
                ]
                po_confirmed = (
                    (not sw_fw_macs and not fdb_macs_on_po)   # (a) true pure L2: no ARP + no FDB
                    or not fdb_macs_on_po                      # (c) no FDB entries on Po
                    or any(_mac_prefix_bytes(m, 4) in fw_mac4s for m in fdb_macs_on_po)  # (b)
                )
                if not po_confirmed:
                    continue
                fdb_pos.append((hostname, po_name, sorted(members.keys())))
                sw_found += 1

    if not fdb_pos:
        return []

    # Step 8: Map partner MACs to FW physical aggregates via normalized MAC.
    # The LACP partner_id IS the actual physical MAC of the FortiGate port — no
    # inference needed. FortiGate assigns sequential MACs to ports; active and
    # passive HA units differ by a fixed ha_offset.

    # 8a: Compute HA MAC offset from same-switch same-oper_key entries with 2
    # distinct MACs (e.g., one switch's two Po's to the active/passive units).
    ha_offset = 0
    sw_ok_macs: dict[tuple[str, int], list[int]] = {}
    for sw_id, po_name, _ in fdb_pos:
        lag = _load_json_file(facts_dirs[sw_id] / "genie_lag.json")
        if not lag:
            continue
        po_info = lag.get("interfaces", {}).get(po_name, {})
        first = next(iter(po_info.get("members", {}).values()), {})
        ok = first.get("oper_key", 0)
        pm = first.get("partner_id", "")
        if pm and pm != "0000.0000.0000":
            last2 = int(pm.replace(".", "")[-4:], 16)
            sw_ok_macs.setdefault((sw_id, ok), []).append(last2)
    for macs in sw_ok_macs.values():
        if len(macs) >= 2:
            ha_offset = abs(max(macs) - min(macs))
            if ha_offset > 0:
                break

    # 8b: Collect fw_aggs sorted by min port number ascending (deterministic order)
    def _agg_min_port(agg: list[str]) -> int:
        ports = [int(m[4:]) for m in agg if m.startswith("port") and m[4:].isdigit()]
        return min(ports) if ports else 9999

    fw_aggs: list[list[str]] = []
    seen_agg: set[str] = set()
    for fw_id in firewall_ids:
        for _agg_name, members in fw_agg_members.get(fw_id, {}).items():
            key = ",".join(members)
            if key not in seen_agg:
                fw_aggs.append(members)
                seen_agg.add(key)
    fw_aggs.sort(key=_agg_min_port)

    # Build port-number → agg reverse lookup
    port_to_agg: dict[int, list[str]] = {}
    for agg in fw_aggs:
        for m in agg:
            if m.startswith("port") and m[4:].isdigit():
                port_to_agg[int(m[4:])] = agg

    # 8c: Group fdb_pos by normalized partner MAC.
    # Active-unit MACs have last-2-bytes >= 0x6000; passive are below — normalize
    # to active. (Empirical FortiGate-HA heuristic, not a published spec — the
    # threshold may need tuning for FortiGate models outside the observed range.)
    ACTIVE_THRESHOLD = 0x6000

    def _norm_mac(partner_id: str) -> int:
        if not partner_id or partner_id == "0000.0000.0000":
            return 0x7FFFFFFF  # Unknown → sort last / fallback
        last2 = int(partner_id.replace(".", "")[-4:], 16)
        if ha_offset > 0 and last2 < ACTIVE_THRESHOLD:
            last2 += ha_offset
        return last2

    norm_mac_groups: dict[int, list[tuple[str, str, list[str]]]] = {}
    for entry in fdb_pos:
        sw_id, po_name, _ = entry
        lag = _load_json_file(facts_dirs[sw_id] / "genie_lag.json")
        nm = 0x7FFFFFFF
        if lag:
            po_info = lag.get("interfaces", {}).get(po_name, {})
            first = next(iter(po_info.get("members", {}).values()), {})
            nm = _norm_mac(first.get("partner_id", ""))
        norm_mac_groups.setdefault(nm, []).append(entry)

    # 8d: Assign FW aggregate to each normalized MAC group.
    #
    # PRIMARY path (fw_data_mac_to_port non-empty, FortiGate with hardware MACs):
    #   Normalized partner MAC → direct lookup in fw_data_mac_to_port → port name
    #   → port_to_agg. No sequential formula, no fallback: a MAC absent from the
    #   data-VDOM monitor set belongs to a different VDOM and must be excluded.
    #
    # LEGACY path (fw_data_mac_to_port empty, e.g. FortiGate VM with zero MACs):
    #   Sequential formula (port = base_port + (nm - base_mac)) for standard portN
    #   names, plus a first-available fallback for non-portN aggregate names.
    non_zero_nms = [nm for nm in norm_mac_groups if nm < 0x7FFFFFFF]
    norm_mac_agg: dict[int, list[str]] = {}
    used_agg_keys: set[str] = set()

    if non_zero_nms:
        base_mac = min(non_zero_nms)
        base_mc = len(norm_mac_groups[base_mac][0][2])
        base_port_aggs = [a for a in fw_aggs if len(a) == base_mc]
        base_port = _agg_min_port(base_port_aggs[0]) if base_port_aggs else 1

        for nm in sorted(non_zero_nms):
            entries = norm_mac_groups[nm]
            mc = len(entries[0][2])

            if fw_data_mac_to_port:
                # PRIMARY: direct hardware MAC lookup.
                # nm is already normalized (passive → active via _norm_mac in 8c).
                # If the MAC is absent it connects to a non-data VDOM → exclude.
                port_name = fw_data_mac_to_port.get(nm)
                if not port_name:
                    continue
                if not (port_name.startswith("port") and port_name[4:].isdigit()):
                    continue  # Non-portN name has no entry in port_to_agg
                port_num = int(port_name[4:])
                agg = port_to_agg.get(port_num)
                agg_key = ",".join(agg) if agg else ""
                if agg and len(agg) == mc and agg_key not in used_agg_keys:
                    norm_mac_agg[nm] = agg
                    used_agg_keys.add(agg_key)
                # else: unexpected member-count mismatch — skip rather than guess

            else:
                # LEGACY: sequential formula for FortiGates without hardware MACs.
                port = base_port + (nm - base_mac)
                agg = port_to_agg.get(port)
                agg_key = ",".join(agg) if agg else ""
                if agg and len(agg) == mc and agg_key not in used_agg_keys:
                    norm_mac_agg[nm] = agg
                    used_agg_keys.add(agg_key)
                else:
                    # First-available fallback for non-portN aggregate names.
                    for fa in fw_aggs:
                        fk = ",".join(fa)
                        if fk not in used_agg_keys and len(fa) == mc:
                            norm_mac_agg[nm] = fa
                            used_agg_keys.add(fk)
                            break

    # R2-FDB-1: deterministic firewall pick (was arbitrary set iteration). NOTE:
    # all switch<->FW cables are still attributed to this one firewall; per-cable
    # multi-firewall attribution is a deeper item (needs >=2 FWs) — see LEDGER.
    fw_id = sorted(firewall_ids)[0]
    candidates: list[LinkCandidate] = []

    for sw_id, po_name, po_members in fdb_pos:
        lag = _load_json_file(facts_dirs[sw_id] / "genie_lag.json")
        nm = 0x7FFFFFFF
        if lag:
            po_info = lag.get("interfaces", {}).get(po_name, {})
            first = next(iter(po_info.get("members", {}).values()), {})
            nm = _norm_mac(first.get("partner_id", ""))
        fw_members = norm_mac_agg.get(nm, [])
        if len(po_members) != len(fw_members):
            continue
        for sw_member, fw_member in zip(po_members, fw_members):
            candidates.append(LinkCandidate(
                local_device=sw_id,
                local_interface=sw_member,
                local_interface_canonical=canonicalize(sw_member),
                remote_device=fw_id,
                remote_interface=fw_member,
                remote_interface_canonical=canonicalize(fw_member),
                discovery_method="fdb_firewall",
                confidence="high",
                evidence=[
                    f"fdb_fw:{sw_id}({sw_member})→{fw_id}({fw_member}) "
                    f"via {po_name} lacp_port_priority=255"
                ],
                peer_collected=True,
            ))

    logger.info(
        "FDB firewall discovery: %d physical member links from %d Port-channels "
        "across %d switches for %d firewall(s)",
        len(candidates), len(fdb_pos),
        len({e[0] for e in fdb_pos}), len(firewall_ids),
    )

    return candidates


# =========================================================================
# Stack Interconnect Discovery (Cisco C9300 cable / C9500 SVL+DAD)
# =========================================================================
# Stack interconnect links are self-referential — both endpoints are the same
# hostname, distinguished by member_id. These are produced as final link dicts
# (not LinkCandidates) and appended after dedup.


def _parse_svl_ports_from_config(config_path: Path) -> list[dict]:
    """Parse SVL/DAD port assignments from running_config.txt.

    Scans for interface stanzas containing 'stackwise-virtual link N' or
    'stackwise-virtual dual-active-detection'. Returns one entry per member-1
    interface paired with its matching member-2 counterpart.

    Returns list of dicts: {local_intf, remote_intf, member_from, member_to, subtype}
    """
    if not config_path.exists():
        return []

    # Match interface name with member prefix: e.g. HundredGigE1/0/1
    intf_re = re.compile(
        r"^interface\s+"
        r"([A-Za-z]+)"          # prefix (HundredGigE, TwentyFiveGigE, etc.)
        r"(\d+)"               # member number
        r"(/\d+/\d+)$"        # /slot/port
    )

    # Collect {(prefix, slot_port) → {member → (full_name, subtype)}}
    svl_ports: dict[tuple[str, str], dict[int, tuple[str, str]]] = {}
    current_intf = None  # (prefix, member, slot_port, full_name)

    try:
        text = config_path.read_text(errors="replace")
    except OSError:
        return []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface "):
            m = intf_re.match(stripped)
            if m:
                prefix, member_str, slot_port = m.group(1), m.group(2), m.group(3)
                full_name = f"{prefix}{member_str}{slot_port}"
                current_intf = (prefix, int(member_str), slot_port, full_name)
            else:
                current_intf = None
        elif current_intf and "stackwise-virtual" in stripped:
            prefix, member, slot_port, full_name = current_intf
            key = (prefix, slot_port)
            if "dual-active-detection" in stripped:
                subtype = "dad"
            elif "link" in stripped:
                subtype = "svl"
            else:
                continue
            if key not in svl_ports:
                svl_ports[key] = {}
            svl_ports[key][member] = (full_name, subtype)
        elif stripped.startswith("!") or stripped == "":
            current_intf = None

    # Build pairs: member-1 ↔ member-2 for each port group
    results = []
    for (_prefix, _slot_port), members in svl_ports.items():
        sorted_ids = sorted(members.keys())
        if len(sorted_ids) < 2:
            continue
        m1, m2 = sorted_ids[0], sorted_ids[1]
        local_name, subtype = members[m1]
        remote_name, _ = members[m2]
        results.append({
            "local_intf": local_name,
            "remote_intf": remote_name,
            "member_from": m1,
            "member_to": m2,
            "subtype": subtype,
        })

    return results


def _svl_mirror_interface(intf: str, from_member: int, to_member: int) -> str:
    """Replace the member number in an SVL interface name.

    E.g. "HundredGigE1/0/1" with from=1, to=2 → "HundredGigE2/0/1"
    """
    m = re.match(r"^([A-Za-z]+)(\d+)(/.*)$", intf)
    if m and int(m.group(2)) == from_member:
        return f"{m.group(1)}{to_member}{m.group(3)}"
    return intf


def discover_stack_interconnect_links(
    devices: list[dict[str, Any]],
    facts_dirs: dict[str, Path] | None = None,
) -> list[dict[str, Any]]:
    """Create links between stack members from stack_ports data.

    For C9300 traditional stacks: one link per physical cable (deduplicated so
    member1→member2 and member2→member1 produce one link).

    For C9500 SVL: one link per SVL interface on the lower-numbered member (the
    matching interface on the higher member is the remote end). When stack_ports
    is not collected, parses running_config.txt for SVL port assignments to
    create individual fiber links.

    Stack interconnect links are self-referential — both endpoints are the same
    hostname, distinguished by member_id.

    Args:
        devices: Model device list (each has 'stack_ports' and 'hostname').
        facts_dirs: Mapping of hostname → facts directory path.

    Returns:
        List of link dicts with link_type="stack_interconnect".
    """
    new_links: list[dict[str, Any]] = []
    if facts_dirs is None:
        facts_dirs = {}

    for dev in devices:
        hostname = dev.get("hostname", "")
        stack_ports = dev.get("stack_ports", [])

        if not stack_ports:
            # Fallback: create an inferred interconnect from cluster_members
            # when stack port data wasn't collected (e.g., partial collection)
            cluster_members = dev.get("cluster_members", [])
            if len(cluster_members) < 2:
                continue

            os_family = (dev.get("os_family") or "").lower()
            is_c9500 = "C9500" in (dev.get("platform") or "")
            is_fortios = os_family == "fortios"

            # C9500 SVL: try to parse individual fiber ports from running config
            if is_c9500 and hostname in facts_dirs:
                config_path = facts_dirs[hostname] / "running_config.txt"
                svl_ports = _parse_svl_ports_from_config(config_path)
                if svl_ports:
                    for sp in svl_ports:
                        local_abbrev = normalize_interface_name(sp["local_intf"])
                        remote_abbrev = normalize_interface_name(sp["remote_intf"])
                        link = {
                            "link_id": (
                                f"{hostname}::svl_{local_abbrev}_{remote_abbrev}"
                            ),
                            "local_device_id": hostname,
                            "local_interface_id": f"{hostname}:{local_abbrev}",
                            "remote_device_id": hostname,
                            "remote_interface_id": f"{hostname}:{remote_abbrev}",
                            "status": "up",
                            "direction": "bidirectional",
                            "discovery_method": "config_svl",
                            "confidence": "high",
                            "evidence": [
                                f"running_config: {sp['local_intf']} "
                                f"stackwise-virtual "
                                f"{'dual-active-detection' if sp['subtype'] == 'dad' else 'link 1'}"
                            ],
                            "peer_collected": True,
                            "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                                "stack_interconnect", "Stack"
                            ),
                            "discovery_priority": DISCOVERY_PRIORITY.get(
                                "stack_interconnect", 2
                            ),
                            "link_type": "stack_interconnect",
                            "stack_subtype": sp["subtype"],
                            "local_member_id": sp["member_from"],
                            "remote_member_id": sp["member_to"],
                            "l2": None,
                            "l3": None,
                        }
                        new_links.append(link)
                    logger.info(
                        "Stack interconnect: %d SVL/DAD fiber(s) for %s from running_config",
                        len(svl_ports), hostname,
                    )
                    continue

            # Generic fallback: single inferred link
            subtype = "ha" if is_fortios else ("svl" if is_c9500 else "cable")
            sorted_members = sorted(
                cluster_members, key=lambda m: m.get("member_id", 0)
            )
            for i in range(len(sorted_members) - 1):
                m_from = sorted_members[i].get("member_id", i)
                m_to = sorted_members[i + 1].get("member_id", i + 1)
                link = {
                    "link_id": f"{hostname}::stack_inferred_{m_from}_{m_to}",
                    "local_device_id": hostname,
                    "local_interface_id": f"{hostname}:stack_{m_from}",
                    "remote_device_id": hostname,
                    "remote_interface_id": f"{hostname}:stack_{m_to}",
                    "status": "up",
                    "direction": "bidirectional",
                    "discovery_method": "stack_inferred",
                    "confidence": "medium",
                    "evidence": [
                        f"inferred from cluster_members: {hostname} "
                        f"has {len(cluster_members)} members"
                    ],
                    "peer_collected": True,
                    "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                        "stack_interconnect", "Stack"
                    ),
                    "discovery_priority": DISCOVERY_PRIORITY.get(
                        "stack_interconnect", 2
                    ),
                    "link_type": "stack_interconnect",
                    "stack_subtype": subtype,
                    "local_member_id": m_from,
                    "remote_member_id": m_to,
                    "l2": None,
                    "l3": None,
                }
                new_links.append(link)
            logger.info(
                "Stack interconnect: inferred %d link(s) for %s from cluster_members",
                len(sorted_members) - 1, hostname,
            )
            continue

        # Check port_type from the first entry to determine stack technology
        first_type = stack_ports[0].get("port_type", "")

        if first_type == "cable":
            # C9300: one link per cable, dedup by only processing entries
            # where member_id < neighbor_member
            for sp in stack_ports:
                member = sp.get("member_id", 0)
                neighbor = sp.get("neighbor_member", 0)
                if neighbor == 0 or member >= neighbor:
                    continue  # skip DOWN ports and reverse direction

                port_id = sp.get("port_id", 0)
                status = "up" if sp.get("link_active") else "down"

                link = {
                    "link_id": f"{hostname}::stack_cable_{member}_{neighbor}_p{port_id}",
                    "local_device_id": hostname,
                    "local_interface_id": f"{hostname}:stack_{member}/{port_id}",
                    "remote_device_id": hostname,
                    "remote_interface_id": f"{hostname}:stack_{neighbor}/{port_id}",
                    "status": status,
                    "direction": "bidirectional",
                    "discovery_method": "stack_interconnect",
                    "confidence": "very_high",
                    "evidence": [
                        f"stack_ports:{hostname} M{member}/P{port_id}→M{neighbor} "
                        f"status={sp.get('status', '?')} "
                        f"cable={sp.get('cable_length', '?')}"
                    ],
                    "peer_collected": True,
                    "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                        "stack_interconnect", "Stack"
                    ),
                    "discovery_priority": DISCOVERY_PRIORITY.get(
                        "stack_interconnect", 2
                    ),
                    "link_type": "stack_interconnect",
                    "stack_subtype": "cable",
                    "local_member_id": member,
                    "remote_member_id": neighbor,
                    "l2": None,
                    "l3": None,
                }
                new_links.append(link)

        elif first_type in ("svl", "dad"):
            # C9500 SVL/DAD: process lower-numbered members only.
            # SVL interface naming carries the member number (HundredGigE1/0/X
            # on member 1, HundredGigE2/0/X on member 2).
            for sp in stack_ports:
                member = sp.get("member_id", 0)
                declared_size = dev.get("cluster_declared_size") or 2
                if member > (declared_size // 2):
                    continue

                intf = sp.get("interface", "")
                port_type = sp.get("port_type", "svl")
                link_status = sp.get("link_status", "Unknown")
                status = "up" if link_status == "Up" else "down"

                # Build remote interface by replacing the member number in the name
                remote_member = member + 1
                remote_intf = _svl_mirror_interface(intf, member, remote_member)

                link = {
                    "link_id": f"{hostname}::{port_type}_{intf}",
                    "local_device_id": hostname,
                    "local_interface_id": f"{hostname}:{intf}",
                    "remote_device_id": hostname,
                    "remote_interface_id": f"{hostname}:{remote_intf}",
                    "status": status,
                    "direction": "bidirectional",
                    "discovery_method": "stack_interconnect",
                    "confidence": "very_high",
                    "evidence": [
                        f"{port_type}:{hostname} {intf}↔{remote_intf} "
                        f"link={link_status} "
                        f"proto={sp.get('protocol_status', '?')}"
                    ],
                    "peer_collected": True,
                    "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                        "stack_interconnect", "Stack"
                    ),
                    "discovery_priority": DISCOVERY_PRIORITY.get(
                        "stack_interconnect", 2
                    ),
                    "link_type": "stack_interconnect",
                    "stack_subtype": port_type,
                    "local_member_id": member,
                    "remote_member_id": remote_member,
                    "l2": None,
                    "l3": None,
                }
                if port_type == "svl" and sp.get("svl_id"):
                    link["svl_id"] = sp["svl_id"]
                new_links.append(link)

            # R2-SVL-DAD: stack_ports ("show stackwise-virtual link") carries only
            # the SVL data-plane fibers — the DAD link lives in config. Recover any
            # SVL/DAD port present in running_config but ABSENT from stack_ports, so
            # the DAD cable isn't silently dropped whenever stack_ports is collected.
            if hostname in facts_dirs:
                covered = {
                    normalize_interface_name(sp.get("interface", ""))
                    for sp in stack_ports
                }
                for cp in _parse_svl_ports_from_config(
                    facts_dirs[hostname] / "running_config.txt"
                ):
                    local_abbrev = normalize_interface_name(cp["local_intf"])
                    if local_abbrev in covered:
                        continue  # already emitted from stack_ports
                    remote_abbrev = normalize_interface_name(cp["remote_intf"])
                    new_links.append({
                        "link_id": f"{hostname}::svl_{local_abbrev}_{remote_abbrev}",
                        "local_device_id": hostname,
                        "local_interface_id": f"{hostname}:{local_abbrev}",
                        "remote_device_id": hostname,
                        "remote_interface_id": f"{hostname}:{remote_abbrev}",
                        "status": "up",
                        "direction": "bidirectional",
                        "discovery_method": "config_svl",
                        "confidence": "high",
                        "evidence": [
                            f"running_config: {cp['local_intf']} stackwise-virtual "
                            f"{'dual-active-detection' if cp['subtype'] == 'dad' else 'link 1'}"
                        ],
                        "peer_collected": True,
                        "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                            "stack_interconnect", "Stack"
                        ),
                        "discovery_priority": DISCOVERY_PRIORITY.get(
                            "stack_interconnect", 2
                        ),
                        "link_type": "stack_interconnect",
                        "stack_subtype": cp["subtype"],
                        "local_member_id": cp["member_from"],
                        "remote_member_id": cp["member_to"],
                        "l2": None,
                        "l3": None,
                    })

    if new_links:
        logger.info(
            "Stack interconnect discovery: %d links on %d device(s)",
            len(new_links),
            len({l["local_device_id"] for l in new_links}),
        )

    return new_links


# =========================================================================
# FortiGate HA Cable-to-Member Attribution
# =========================================================================
# For FortiGate HA pairs, attribute each discovered cable to the active or
# passive member. Mutates links in place, adding an 'ha_member' field.


def _find_heartbeat_mac(arp_data: dict[str, Any]) -> str | None:
    """Extract the passive member's heartbeat MAC from a FortiGate ARP table.

    FortiGate HA heartbeat uses 169.254.0.x IPs. The passive member's heartbeat
    entry reveals its hardware MAC address.

    Returns:
        MAC address string (dotted or colon format), or None if not found.
    """
    results = arp_data.get("results", [])
    if not isinstance(results, list):
        return None

    for entry in results:
        ip = entry.get("ip", "")
        if ip.startswith("169.254.0."):
            mac = entry.get("mac", "")
            if mac and mac != "00:00:00:00:00:00":
                return mac
    return None


def _attribute_standard_ha_cables(
    fw_id: str,
    fw_facts_dir: Path,
    facts_dirs: dict[str, Path],
    devices: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> int:
    """Standard HA attribution via ARP heartbeat MAC cross-reference.

    Identifies the passive member's MAC from 169.254.0.x ARP entries, then
    matches against LACP partner system-IDs on upstream switches.

    Returns:
        Number of cables attributed.
    """
    # Load ARP data — if missing, can't attribute
    arp_data = _load_json_file(fw_facts_dir / "fortigate_arp.json")
    if not arp_data:
        logger.debug("FortiGate HA attribution: no ARP data for %s", fw_id)
        return 0

    # Find heartbeat MAC (169.254.0.x entries = passive member)
    passive_mac = _find_heartbeat_mac(arp_data)
    if not passive_mac:
        logger.debug(
            "FortiGate HA attribution: no heartbeat entry found for %s", fw_id
        )
        return 0

    passive_prefix = _mac_prefix_bytes(passive_mac, 5)
    logger.info(
        "FortiGate HA attribution: passive member MAC prefix=%s (from ARP heartbeat)",
        passive_prefix,
    )

    # Build switch_intf_canonical → LACP partner_id mapping
    # from all upstream switches (any device with genie_lag.json)
    intf_to_partner: dict[str, str] = {}
    for hostname, facts_dir in facts_dirs.items():
        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if not lag_data:
            continue
        for po_name, po_data in lag_data.get("interfaces", {}).items():
            for member_name, member_data in po_data.get("members", {}).items():
                partner_id = member_data.get("partner_id", "")
                if partner_id:
                    canonical = canonicalize(member_name)
                    if canonical:
                        intf_to_partner[canonical] = partner_id

    if not intf_to_partner:
        return 0

    # Attribute each firewall link
    attributed = 0
    for link in links:
        local_dev = link.get("local_device_id", "")
        remote_dev = link.get("remote_device_id", "")

        if fw_id not in (local_dev, remote_dev):
            continue

        # Only attribute cable-based links (fdb_firewall, lacp_unilateral)
        if link.get("discovery_method") not in ("fdb_firewall", "lacp_unilateral"):
            link["ha_member"] = None
            continue

        # Get the switch-side interface_id
        if local_dev == fw_id:
            switch_intf_id = link.get("remote_interface_id", "")
        else:
            switch_intf_id = link.get("local_interface_id", "")

        # Extract interface name and canonicalize
        intf_name = switch_intf_id.split(":", 1)[-1] if ":" in switch_intf_id else ""
        canonical_intf = canonicalize(intf_name)

        partner_mac = intf_to_partner.get(canonical_intf) if canonical_intf else None
        if not partner_mac:
            link["ha_member"] = None
            continue

        partner_prefix = _mac_prefix_bytes(partner_mac, 5)
        if partner_prefix == passive_prefix:
            link["ha_member"] = "passive"
        else:
            link["ha_member"] = "active"
        attributed += 1

    return attributed


def _attribute_vcluster_ha_cables(
    fw_id: str,
    fw_facts_dir: Path,
    cluster_members: list[dict[str, Any]],
    links: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
) -> int:
    """Virtual Cluster HA attribution via port → vdom → vcluster → master chain.

    For fdb_firewall links: uses the switch-side LACP partner MAC to identify
    which *physical unit* the cable connects to. Partner MAC last-2-bytes
    < 0x6000 means the passive unit; >= 0x6000 means the active unit. This is
    the same threshold used by _norm_mac() in discover_fdb_firewall_links().

    For lacp_unilateral and other links: follows the vcluster chain:
      1. Identify the FW-side port from the interface ID.
      2. Look up port → vdom (fortigate_system_interface.json).
      3. Look up vdom → vcluster-id (fortigate_system_ha.json vcluster[]).
      4. Look up vcluster-id → master serial (fortigate_ha_peer.json, master=true).
      5. Map master serial → member_id (cluster_members).
      6. member_id==0 → "active", member_id==1 → "passive".

    Returns:
        Number of cables attributed.
    """
    # Build port → vdom from fortigate_system_interface.json
    sys_intf = _load_json_file(fw_facts_dir / "fortigate_system_interface.json")
    if not sys_intf:
        logger.debug("FortiGate vcluster attribution: no system interface data for %s", fw_id)
        return 0
    intfs = sys_intf.get("results", [])
    if not isinstance(intfs, list):
        return 0
    port_to_vdom: dict[str, str] = {
        r.get("name", ""): r.get("vdom", "")
        for r in intfs
        if r.get("name") and r.get("vdom")
    }

    # Build vdom → vcluster-id from fortigate_system_ha.json
    ha_cfg = _load_json_file(fw_facts_dir / "fortigate_system_ha.json")
    if not ha_cfg:
        logger.debug("FortiGate vcluster attribution: no system HA data for %s", fw_id)
        return 0
    vdom_to_vcluster: dict[str, int] = {}
    for vc in (ha_cfg.get("results") or {}).get("vcluster", []):
        vc_id = vc.get("vcluster-id")
        if vc_id is None:
            continue
        for vdom_entry in vc.get("vdom", []):
            vdom_name = vdom_entry.get("name", "")
            if vdom_name:
                vdom_to_vcluster[vdom_name] = vc_id

    # Build vcluster-id → master serial from fortigate_ha_peer.json
    ha_peer = _load_json_file(fw_facts_dir / "fortigate_ha_peer.json")
    if not ha_peer:
        logger.debug("FortiGate vcluster attribution: no HA peer data for %s", fw_id)
        return 0
    vcluster_to_master: dict[int, str] = {}
    for peer in ha_peer.get("results", []):
        if peer.get("master") or peer.get("primary"):
            vc_id = peer.get("vcluster_id")
            serial = peer.get("serial_no", "")
            if vc_id is not None and serial:
                vcluster_to_master[vc_id] = serial

    # Build serial → member_id from cluster_members
    serial_to_member_id: dict[str, int] = {}
    for cm in cluster_members:
        serial = cm.get("serial_number", "")
        mid = cm.get("member_id")
        if serial and mid is not None:
            serial_to_member_id[serial] = mid

    if not vcluster_to_master or not serial_to_member_id:
        logger.debug(
            "FortiGate vcluster attribution: incomplete data for %s "
            "(vcluster_masters=%d serial_map=%d)",
            fw_id, len(vcluster_to_master), len(serial_to_member_id),
        )
        return 0

    # Build (device_id, canonical_intf) → partner MAC last-2-bytes for fdb_firewall
    # attribution. fdb_firewall links use the LACP partner MAC threshold
    # (< 0x6000 = passive unit) to determine which *physical unit* the cable
    # connects to, rather than which vcluster vdom is "active". Keyed by
    # (hostname, canonical) to avoid collisions when multiple devices share the
    # same interface name (e.g. two switches both have Gi1/1/1).
    _FDB_ACTIVE_THRESHOLD = 0x6000
    intf_to_partner_last2: dict[tuple[str, str], int] = {}
    for hostname, facts_dir in facts_dirs.items():
        lag_data = _load_json_file(facts_dir / "genie_lag.json")
        if not lag_data:
            continue
        for po_data in lag_data.get("interfaces", {}).values():
            for member_name, member_data in po_data.get("members", {}).items():
                partner_id = member_data.get("partner_id", "")
                if partner_id and partner_id != "0000.0000.0000":
                    canonical = canonicalize(member_name)
                    if canonical:
                        last2 = int(partner_id.replace(".", "")[-4:], 16)
                        intf_to_partner_last2[(hostname, canonical)] = last2

    # Attribute each firewall link
    attributed = 0
    for link in links:
        local_dev = link.get("local_device_id", "")
        remote_dev = link.get("remote_device_id", "")

        if fw_id not in (local_dev, remote_dev):
            continue

        # Preserved from source: in vcluster mode only fdb_firewall links are
        # attributed; non-fdb links get ha_member=None here. The port→vdom→
        # vcluster→master chain below is retained verbatim for parity but is
        # currently unreachable for non-fdb links via this early return.
        if link.get("discovery_method") != "fdb_firewall":
            link["ha_member"] = None
            continue

        # fdb_firewall: attribute by switch-side LACP partner MAC.
        # The partner MAC's last-2-bytes encode which physical unit the cable
        # reaches: < 0x6000 → passive unit, >= 0x6000 → active unit.
        if link.get("discovery_method") == "fdb_firewall":
            if local_dev == fw_id:
                sw_dev = remote_dev
                sw_intf_id = link.get("remote_interface_id", "")
            else:
                sw_dev = local_dev
                sw_intf_id = link.get("local_interface_id", "")
            intf_name = sw_intf_id.split(":", 1)[-1] if ":" in sw_intf_id else sw_intf_id
            canonical_intf = canonicalize(intf_name)
            partner_last2 = intf_to_partner_last2.get((sw_dev, canonical_intf)) if canonical_intf else None
            if partner_last2 is not None:
                link["ha_member"] = "passive" if partner_last2 < _FDB_ACTIVE_THRESHOLD else "active"
                attributed += 1
            else:
                link["ha_member"] = None
            continue

        # Other links: follow the vcluster chain.
        # Get the FW-side interface ID (remote when switch is local, local when FW is local)
        if local_dev == fw_id:
            fw_intf_id = link.get("local_interface_id", "")
        else:
            fw_intf_id = link.get("remote_interface_id", "")

        fw_port = fw_intf_id.split(":", 1)[-1] if ":" in fw_intf_id else fw_intf_id

        # Follow the chain: port → vdom → vcluster-id → master serial → member_id
        vdom = port_to_vdom.get(fw_port)
        if not vdom:
            link["ha_member"] = None
            continue

        vc_id = vdom_to_vcluster.get(vdom)
        if vc_id is None:
            link["ha_member"] = None
            continue

        master_serial = vcluster_to_master.get(vc_id)
        if not master_serial:
            link["ha_member"] = None
            continue

        master_member_id = serial_to_member_id.get(master_serial)
        if master_member_id is None:
            link["ha_member"] = None
            continue

        link["ha_member"] = "active" if master_member_id == 0 else "passive"
        attributed += 1

    return attributed


def attribute_fortigate_ha_cables(
    links: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    devices: list[dict[str, Any]],
    facts_by_hostname: dict[str, dict],
) -> None:
    """Attribute FortiGate cables to the active/passive HA member.

    Routes between two attribution strategies based on HA mode:

    Standard HA (vcluster-status=disable):
        Uses FortiGate ARP heartbeat entries (169.254.0.x) to identify the
        passive member's MAC prefix, then cross-references with switch LACP
        partner system-IDs to determine which cables connect to which member.

    Virtual Cluster HA (vcluster-status=enable):
        Follows the chain: FW port → vdom (fortigate_system_interface.json) →
        vcluster-id (fortigate_system_ha.json) → master serial
        (fortigate_ha_peer.json) → member_id (cluster_members).

    Mutates links in place — adds an 'ha_member' field ("active"/"passive"/None).

    Args:
        links: All model links (mutated in place).
        facts_dirs: {hostname: Path} mapping.
        devices: Model device list with os_family, cluster_declared_size.
        facts_by_hostname: Device facts keyed by hostname (for os_family lookup).
    """
    # Step 1: Find FortiGate devices with HA
    fw_devices = [
        d for d in devices
        if d.get("os_family") == "fortios"
        and (d.get("cluster_declared_size") or 0) >= 2
    ]
    if not fw_devices:
        return

    for fw_dev in fw_devices:
        fw_id = fw_dev["hostname"]

        # Find facts dir for this FW
        fw_facts_dir = facts_dirs.get(fw_id)
        if not fw_facts_dir:
            # Try all dirs for a fortigate_arp.json match
            for dirname, dirpath in facts_dirs.items():
                if (dirpath / "fortigate_arp.json").exists():
                    fw_facts_dir = dirpath
                    break
        if not fw_facts_dir:
            continue

        # Detect HA mode: standard vs Virtual Cluster
        ha_cfg = _load_json_file(fw_facts_dir / "fortigate_system_ha.json")
        vcluster_status = (ha_cfg or {}).get("results", {}).get("vcluster-status", "disable")

        if vcluster_status == "enable":
            # Virtual Cluster HA: port → vdom → vcluster → master serial → member_id
            attributed = _attribute_vcluster_ha_cables(
                fw_id,
                fw_facts_dir,
                fw_dev.get("cluster_members", []),
                links,
                facts_dirs,
            )
        else:
            # Standard HA: heartbeat ARP MAC cross-reference with LACP partner IDs
            attributed = _attribute_standard_ha_cables(
                fw_id, fw_facts_dir, facts_dirs, devices, links
            )

        if attributed:
            logger.info(
                "FortiGate HA attribution: %d cables attributed for %s (mode=%s)",
                attributed,
                fw_id,
                vcluster_status,
            )


# =========================================================================
# FDB-based Management Link Discovery (SVL standby members)
# =========================================================================
# SVL standby members keep a unique BIA MAC on their Gi0/0 port (physically up
# but silent). The management switch FDB learns this MAC even though the standby
# never responds to management traffic — giving us a management cable the
# protocol-based methods miss.


def _member_id_from_port(port_name: str) -> int | None:
    """Extract the stack member ID from an interface name like Gi1/0/5 → 1.

    Returns None if the name doesn't encode a member number.
    """
    m = re.match(r"^[A-Za-z]+(\d+)/", port_name)
    if m:
        return int(m.group(1))
    return None


def discover_mgmt_fdb_member_links(
    devices: list[dict[str, Any]],
    links: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    mgmt_vlans: set[int],
    role_by_device: dict[str, str],
) -> list[dict[str, Any]]:
    """Discover management links for SVL standby members using FDB evidence.

    SVL standby members have a unique BIA MAC on their Gi0/0 port which stays
    physically up. The management switch FDB learns this MAC even though the
    standby never responds to management traffic (no CDP).

    Per-member MACs come from cluster_members[].mac_address, populated from the
    "Base Ethernet MAC Address" lines in show_version.txt (collected during
    parsing — no extra network call).

    Cross-references:
      - cluster_members[].mac_address: per-member MACs from show_version
      - genie_fdb.json from mgmt_switch devices: FDB for the management VLANs

    Returns new management link dicts (already classified, priority 2, high
    confidence). Gracefully returns [] when MAC data is absent.
    """
    if not mgmt_vlans:
        return []

    # -----------------------------------------------------------------
    # Step 1: Build MAC lookup: normalized_mac → (device_id, member_id)
    # -----------------------------------------------------------------
    member_mac_lookup: dict[str, tuple[str, int]] = {}

    for device in devices:
        cluster_members = device.get("cluster_members")
        if not cluster_members:
            continue

        device_id = device["device_id"]
        for member in cluster_members:
            mac = member.get("mac_address") or ""
            member_id = member.get("member_id")
            if not mac or member_id is None:
                continue
            norm_mac = _normalize_mac(mac)
            if norm_mac:
                member_mac_lookup[norm_mac] = (device_id, member_id)

    if not member_mac_lookup:
        return []

    # -----------------------------------------------------------------
    # Step 2: Record members that already have a management link
    # -----------------------------------------------------------------
    has_mgmt: set[tuple[str, int]] = set()
    for link in links:
        if link.get("link_type") != "management":
            continue
        src_mid = link.get("source_member_id")
        tgt_mid = link.get("target_member_id")
        if src_mid is not None:
            has_mgmt.add((link.get("local_device_id", ""), src_mid))
        if tgt_mid is not None:
            has_mgmt.add((link.get("remote_device_id", ""), tgt_mid))

    # -----------------------------------------------------------------
    # Step 3: Scan each mgmt_switch FDB for member MACs
    # -----------------------------------------------------------------
    new_links: list[dict[str, Any]] = []

    for mgmt_hostname, mgmt_facts_dir in facts_dirs.items():
        if role_by_device.get(mgmt_hostname) != "mgmt_switch":
            continue

        fdb_file = mgmt_facts_dir / "genie_fdb.json"
        if not fdb_file.exists():
            continue

        try:
            fdb_data = json.loads(fdb_file.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "genie_fdb.json parse error for %s: %s", mgmt_hostname, exc
            )
            continue

        vlans_data = fdb_data.get("mac_table", {}).get("vlans", {})

        for vlan_id in mgmt_vlans:
            vlan_entry = vlans_data.get(str(vlan_id), {})
            for fdb_mac, fdb_info in vlan_entry.get("mac_addresses", {}).items():
                norm_fdb_mac = _normalize_mac(fdb_mac)
                if norm_fdb_mac not in member_mac_lookup:
                    continue

                device_id, member_id = member_mac_lookup[norm_fdb_mac]

                # Skip members that already have a management link
                if (device_id, member_id) in has_mgmt:
                    continue

                # Get the port on the mgmt_switch
                interfaces = fdb_info.get("interfaces", {})
                port = next(iter(interfaces), None)
                if port is None:
                    continue

                # Skip ISL/trunk port-channels (not a direct OOB cable)
                if re.search(r"port.channel|^po\d", port, re.IGNORECASE):
                    continue

                norm_port = normalize_interface_name(port) or port
                # Derive the mgmt_switch member_id from the port name
                # (Gi1/0/5 → member 1, Gi2/0/4 → member 2, etc.)
                mgmt_member_id = _member_id_from_port(norm_port)

                new_link: dict[str, Any] = {
                    "link_id": f"fdb_mgmt_{device_id}_m{member_id}",
                    "link_type": "management",
                    "local_device_id": device_id,
                    "local_interface_id": f"{device_id}:Gi0/0",
                    "remote_device_id": mgmt_hostname,
                    "remote_interface_id": f"{mgmt_hostname}:{norm_port}",
                    "direction": "unidirectional",
                    "status": "up",
                    "discovery_method": "fdb_mgmt",
                    "discovery_priority": 2,
                    "confidence": "high",
                    "mgmt_type": "oob",
                    "source_member_id": member_id,
                    "target_member_id": mgmt_member_id,
                    "peer_collected": True,
                }
                new_links.append(new_link)
                # Prevent duplicates if the MAC appears in multiple mgmt-switch FDB tables
                has_mgmt.add((device_id, member_id))
                logger.debug(
                    "FDB mgmt: %s member %d → %s:%s (VLAN %d)",
                    device_id, member_id, mgmt_hostname, port, vlan_id,
                )

    if new_links:
        logger.info(
            "FDB mgmt member links: +%d standby management cable(s) discovered",
            len(new_links),
        )

    return new_links


# =========================================================================
# Deduplication — merge candidates into final link dicts
# =========================================================================

def _make_pair_key(candidate: LinkCandidate) -> str:
    """
    Build a canonical pair key for deduplication grouping.

    The pair key uniquely identifies a physical connection between two
    device:interface endpoints. Two candidates with the same pair key
    represent the SAME physical connection discovered by different methods.

    Key Format:
        "devA:canonical_intf--devB:canonical_intf"

        Where endpoints are sorted alphabetically so A→B and B→A produce
        the same key. The canonical interface name is used (lowercase full
        form) for cross-platform matching.

    Examples:
        CDP candidate: core-rtr-01:Gi0/0 → dist-sw-01:Gi1/0/3
        → "core-rtr-01:gigabitethernet0/0--dist-sw-01:gigabitethernet1/0/3"

        ARP candidate: core-rtr-01:GigabitEthernet0/0 → dist-sw-01:Vlan99
        → "core-rtr-01:gigabitethernet0/0--dist-sw-01:vlan99"
        (DIFFERENT key — different interface pair = different link)

    Args:
        candidate: A LinkCandidate from any discovery level.

    Returns:
        Canonical pair key string.
    """
    # Use canonical interface names for matching, fall back to originals
    local_intf = candidate.local_interface_canonical or candidate.local_interface or ""
    remote_intf = candidate.remote_interface_canonical or candidate.remote_interface or ""

    endpoint_a = f"{candidate.local_device}:{local_intf}"
    endpoint_b = f"{candidate.remote_device}:{remote_intf}"

    # Sort alphabetically for canonical ordering (A→B == B→A)
    if endpoint_a > endpoint_b:
        endpoint_a, endpoint_b = endpoint_b, endpoint_a

    return f"{endpoint_a}--{endpoint_b}"


def deduplicate_links(
    all_candidates: list[LinkCandidate],
    interfaces: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge all link candidates into deduplicated final link dicts.

    This is the critical merge step (Single Link Per Physical Connection).
    Multiple discoveries of the same device:interface pair are collapsed
    into one link object where:
    - The highest-confidence candidate's method/confidence wins
    - ALL evidence strings from all candidates are accumulated
    - The best interface names are preserved (original form for display)
    - peer_collected is True if ANY candidate reports it as True

    Dedup Logic:
        1. Build a canonical pair key for each candidate using _make_pair_key().
        2. Group candidates by pair key.
        3. For each group:
           a. Sort by confidence rank (highest first)
           b. Winner = first candidate (highest confidence)
           c. Merge evidence from all candidates (deduplicated, ordered)
           d. Set peer_collected = True if any candidate says True
        4. Produce final link dicts.

    Important — Different Interface Pairs = Different Links:
        If CDP discovers core-rtr-01:Gi0/0↔dist-sw-01:Gi1/0/3 (physical link)
        and ARP discovers core-rtr-01:Gi0/0↔dist-sw-01:Vlan99 (L3 adjacency),
        these produce DIFFERENT pair keys and become SEPARATE links.

        Merging only happens when the SAME interface pair is discovered
        by multiple methods (e.g., CDP and MAC both see Gi0/0↔Gi1/0/3).

    Direction Logic:
        The "direction" field is derived from the discovery method:
        - bilateral methods → "bidirectional"
        - all other methods → "unidirectional" (we can't prove both sides
          see each other)

    Status Calculation:
        Link status ("up", "down", "admin_down", "unknown") is computed from
        the interface states of both endpoints via calculate_link_status().
        This requires an interface lookup built from the interfaces list.

    Output Format:
        {
            "link_id": "devA:intf--devB:intf",      # sorted canonical
            "local_device_id": "hostname",            # from winner
            "local_interface_id": "hostname:intf",    # normalized form
            "remote_device_id": "hostname",           # from winner
            "remote_interface_id": "hostname:intf",   # normalized form
            "status": "up|down|admin_down|unknown",
            "direction": "bidirectional|unidirectional",
            "discovery_method": "cdp_bilateral|...",  # best method
            "confidence": "very_high|high|...",       # best confidence
            "evidence": ["cdp:A→B", "arp:A→B", ...],  # all evidence
            "peer_collected": true|false,             # any candidate
            "discovery_protocol": "CDP|LLDP|ARP|...", # for diagram label
            "discovery_priority": 1,                  # for render styling
        }

    Args:
        all_candidates: Concatenated list of LinkCandidate objects from all
                        discovery levels.
        interfaces: The built interfaces list. Used for link status
                    calculation. Each interface has "interface_id",
                    "device_id", "name", "admin_status", "oper_status".

    Returns:
        List of deduplicated link dicts, sorted by link_id.
    """
    # -------------------------------------------------------------------------
    # Step 1: Build interface lookups for status calculation
    # -------------------------------------------------------------------------
    # Interfaces and links both use normalized short names, so interface_by_id
    # matches directly. Canonical fallback kept for edge cases (e.g., CDP
    # spaces: "Gi 0/0" vs "Gi0/0").
    interface_by_id: dict[str, dict[str, Any]] = {
        iface["interface_id"]: iface for iface in interfaces
    }

    interface_by_canonical_id: dict[str, dict[str, Any]] = {}
    for iface in interfaces:
        hostname = iface["device_id"]
        canonical_name = canonicalize(iface["name"])
        if canonical_name:
            canonical_id = f"{hostname}:{canonical_name}"
            interface_by_canonical_id[canonical_id] = iface

    # -------------------------------------------------------------------------
    # Step 2: Group candidates by canonical pair key
    # -------------------------------------------------------------------------
    # Dict mapping pair_key → list of candidates for that connection
    groups: dict[str, list[LinkCandidate]] = {}

    for candidate in all_candidates:
        key = _make_pair_key(candidate)
        groups.setdefault(key, []).append(candidate)

    # Post-group merge: candidates with empty remote_interface (e.g., LACP
    # that resolved the device but not the port) should merge into an existing
    # group that has the same local endpoint and remote device.  Build an index
    # of (local_dev:local_canonical, remote_dev) → pair_key for groups that
    # DO have a remote interface, then re-home orphan candidates.
    _partial_index: dict[tuple[str, str, str], str] = {}  # (local_dev, local_can, remote_dev) → key
    _orphan_keys: list[str] = []
    for key, group in groups.items():
        for c in group:
            local_can = c.local_interface_canonical or ""
            remote_can = c.remote_interface_canonical or ""
            if local_can and remote_can:
                _partial_index[(c.local_device, local_can, c.remote_device)] = key
                _partial_index[(c.remote_device, remote_can, c.local_device)] = key

    for key, group in list(groups.items()):
        sample = group[0]
        has_empty_remote = not (sample.remote_interface_canonical or sample.remote_interface)
        if not has_empty_remote:
            continue
        local_can = sample.local_interface_canonical or ""
        match_key = _partial_index.get((sample.local_device, local_can, sample.remote_device))
        if match_key and match_key != key:
            # Merge this group's candidates into the existing full group
            groups[match_key].extend(group)
            _orphan_keys.append(key)
            logger.debug("Dedup merge: %s → %s (LACP empty remote absorbed)", key, match_key)

    for k in _orphan_keys:
        del groups[k]

    logger.info(
        "Dedup: %d raw candidates → %d unique pair keys",
        len(all_candidates),
        len(groups),
    )

    # -------------------------------------------------------------------------
    # Step 3: For each group, produce one final link dict
    # -------------------------------------------------------------------------
    # Discovery methods that indicate bilateral (both sides confirmed)
    _BILATERAL_METHODS = {
        "cdp_bilateral", "lldp_bilateral", "lacp_bilateral",
        "mac_fingerprint_bilateral",
    }

    links: list[dict[str, Any]] = []

    for pair_key, group in groups.items():
        # -----------------------------------------------------------------
        # Step 3a: Sort group by confidence rank (highest first)
        # -----------------------------------------------------------------
        # The highest-confidence candidate becomes the "winner" whose
        # method, confidence, and interface names are used for the link.
        group.sort(
            key=lambda c: CONFIDENCE_RANK.get(c.confidence, 0),
            reverse=True,
        )

        winner = group[0]

        # -----------------------------------------------------------------
        # Step 3b: Accumulate all evidence from all candidates
        # -----------------------------------------------------------------
        # Preserve order but deduplicate (some evidence strings may
        # appear in multiple candidates if the same ARP was found
        # from both sides).
        all_evidence: list[str] = []
        seen_evidence: set[str] = set()
        for candidate in group:
            for ev in candidate.evidence:
                if ev not in seen_evidence:
                    all_evidence.append(ev)
                    seen_evidence.add(ev)

        # -----------------------------------------------------------------
        # Step 3c: Determine peer_collected — True if ANY candidate says so
        # -----------------------------------------------------------------
        peer_collected = any(c.peer_collected for c in group)

        # -----------------------------------------------------------------
        # Step 3d: Determine direction
        # -----------------------------------------------------------------
        # "bidirectional" if ANY candidate in the group used a bilateral
        # method. Otherwise "unidirectional".
        has_bilateral = any(
            c.discovery_method in _BILATERAL_METHODS for c in group
        )
        direction = "bidirectional" if has_bilateral else "unidirectional"

        # -----------------------------------------------------------------
        # Step 3e: Build interface IDs using normalized names
        # -----------------------------------------------------------------
        # The interface_id format is "hostname:normalized_interface_name".
        # We use normalize_interface_name() (not canonicalize()) because
        # interface_id must match what the interface builder produces.
        #
        # The winner's interface names are used since they come from the
        # highest-confidence source (CDP gives the most reliable names).
        # -----------------------------------------------------------------
        # Step 3e/3f: orient local/remote CANONICALLY + build link_id
        # -----------------------------------------------------------------
        # R2-CDP-1: the lexicographically-smaller (device, normalized-interface)
        # endpoint is "local", matching the already-sorted link_id. This makes the
        # A/B sides stable and independent of which candidate happened to win dedup
        # (previously local==winner.local, an arbitrary-but-deterministic side).
        # Dedup already merged the group, so this only LABELS the merged link — it
        # cannot change which candidates merged. Downstream l2/l3 enrichment keys off
        # local_device_id, so it inherits this orientation automatically.
        norm_l = normalize_interface_name(winner.local_interface or "")
        norm_r = normalize_interface_name(winner.remote_interface or "")
        side_a = (winner.local_device, norm_l, winner.local_interface_canonical)
        side_b = (winner.remote_device, norm_r, winner.remote_interface_canonical)
        if (side_a[0], side_a[1]) > (side_b[0], side_b[1]):
            side_a, side_b = side_b, side_a

        local_device, normalized_local, local_canonical = side_a
        remote_device, normalized_remote, remote_canonical = side_b

        local_interface_id = f"{local_device}:{normalized_local}"
        remote_interface_id = f"{remote_device}:{normalized_remote}"
        link_id = f"{local_device}:{normalized_local}--{remote_device}:{normalized_remote}"

        # -----------------------------------------------------------------
        # Step 3g: Calculate link status from interface states
        # -----------------------------------------------------------------
        # Status is a property of the LINK, not of which end we label "local".
        # Compute it from the winner's ORIGINAL endpoints so the canonical relabel
        # above never perturbs status. (calculate_link_status is not symmetric on
        # mixed up/down ends — making it orientation-independent is a separate
        # latent item; here we just keep status byte-stable.)
        w_norm_l = normalize_interface_name(winner.local_interface or "")
        w_norm_r = normalize_interface_name(winner.remote_interface or "")
        local_iface = (
            interface_by_id.get(f"{winner.local_device}:{w_norm_l}")
            or interface_by_canonical_id.get(
                f"{winner.local_device}:{winner.local_interface_canonical}"
            )
        )
        remote_iface = (
            interface_by_id.get(f"{winner.remote_device}:{w_norm_r}")
            or interface_by_canonical_id.get(
                f"{winner.remote_device}:{winner.remote_interface_canonical}"
            )
        )

        status = calculate_link_status(local_iface, remote_iface)

        # -----------------------------------------------------------------
        # Step 3h: Build the final link dict
        # -----------------------------------------------------------------
        link = {
            "link_id": link_id,
            "local_device_id": local_device,
            "local_interface_id": local_interface_id,
            "remote_device_id": remote_device,
            "remote_interface_id": remote_interface_id,
            "status": status,
            "direction": direction,
            "discovery_method": winner.discovery_method,
            "confidence": winner.confidence,
            "evidence": all_evidence,
            "peer_collected": peer_collected,
            "discovery_protocol": DISCOVERY_PROTOCOL_MAP.get(
                winner.discovery_method, "Unknown"
            ),
            "discovery_priority": DISCOVERY_PRIORITY.get(
                winner.discovery_method, 7
            ),
        }

        links.append(link)

    # -------------------------------------------------------------------------
    # Step 4: Sort for determinism
    # -------------------------------------------------------------------------
    links.sort(key=lambda l: l["link_id"])

    # Log summary
    method_counts: dict[str, int] = {}
    for link in links:
        method = link["discovery_method"]
        method_counts[method] = method_counts.get(method, 0) + 1

    logger.info(
        "Dedup result: %d unique links. Methods: %s",
        len(links),
        ", ".join(f"{m}={c}" for m, c in sorted(method_counts.items())),
    )

    return links


# =========================================================================
# Port-channel suppression — CDP bilateral supersedes LACP bilateral
# =========================================================================

def _is_portchannel_intf(intf_id: str | None) -> bool:
    """Return True if the interface_id refers to a port-channel or bundle-ether.

    Handles both short abbreviations (Po1, Be1) and full names
    (Port-channel1, port-channel10, bundle-ether10), case-insensitively.

    Args:
        intf_id: Interface ID in "hostname:interface" or plain "interface" form.

    Returns:
        True if the interface is a port-channel or bundle-ether aggregate.
    """
    if not intf_id:
        return False
    intf = intf_id.split(":", 1)[-1].lower()
    _LONG = ("port-channel", "bundle-ether")
    _SHORT = ("po", "be")
    return (
        any(intf.startswith(p) for p in _LONG)
        or any(
            intf.startswith(p) and len(intf) > len(p) and intf[len(p)].isdigit()
            for p in _SHORT
        )
    )


def suppress_cdp_portchannel_when_lacp_bilateral(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove LACP bilateral links when CDP bilateral links exist for the same
    device pair.

    CDP bilateral is the highest-confidence discovery method (very_high) because
    both switches directly report each other as neighbors. LACP bilateral
    (confidence=high) discovers links via MAC-based partner resolution, which can
    produce ambiguous results on StackWise Virtual (SVL) switches that share a
    system_id_mac across members, causing wrong interface-pair attribution.

    When both CDP bilateral and LACP bilateral links exist between the same two
    devices, the LACP bilateral links are likely duplicates with wrong interface
    attribution, so they are suppressed in favour of the authoritative CDP
    bilateral links.

    FortiGate devices are NOT affected: they don't send CDP PDUs, so there are
    never CDP bilateral links involving FortiGate. LACP bilateral links to/from
    FortiGate are preserved.

    Called from the model builder after deduplicate_links().
    Returns a new list (does not mutate in place).
    """
    # Build set of device pairs that have at least one cdp_bilateral link
    cdp_pairs: set[frozenset[str]] = set()
    for link in links:
        if link.get("discovery_method") == "cdp_bilateral":
            cdp_pairs.add(frozenset([link["local_device_id"], link["remote_device_id"]]))

    if not cdp_pairs:
        return links

    to_remove: set[int] = set()
    for link in links:
        if link.get("discovery_method") != "lacp_bilateral":
            continue
        pair = frozenset([link["local_device_id"], link["remote_device_id"]])
        if pair in cdp_pairs:
            to_remove.add(id(link))

    if not to_remove:
        return links

    logger.debug(
        "suppress_cdp_portchannel_when_lacp_bilateral: removed %d LACP bilateral link(s) "
        "superseded by CDP bilateral (higher confidence, authoritative interface attribution)",
        len(to_remove),
    )
    return [lnk for lnk in links if id(lnk) not in to_remove]


def _port_id_canonical(intf_id: str | None) -> str | None:
    """Return "device:canonical_intf" for a link endpoint, or None if no
    interface is resolved (e.g. a unilateral link's unresolved far end)."""
    if not intf_id or ":" not in intf_id:
        return None
    host, intf = intf_id.split(":", 1)
    if not intf:
        return None
    return f"{host}:{canonicalize(intf) or intf.lower()}"


def suppress_unilateral_cable_on_bilateral_port(
    links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Drop a unilateral cable link whose port is already confirmed by a
    bilateral cable.

    A physical port terminates exactly one cable. When a bilateral method
    (CDP/LLDP/LACP/MAC-fingerprint, both ends agree) has confirmed the cable on
    a port, a *unilateral* link touching that same port is the same cable seen
    one-sidedly — e.g. a ``mac_fingerprint_unilateral`` that resolved only its
    near port (empty far interface) duplicating a ``cdp_bilateral`` on that port.
    Its pair-key differs (empty far end), so dedup can't merge it; it would paint
    a second, phantom edge. The bilateral link is authoritative; the unilateral
    is suppressed.

    Keyed on the specific (device:canonical_interface) port, NOT the device pair,
    so a genuinely distinct cable on another port of the same devices survives.

    Called from the model builder after deduplicate_links(). Returns a new list.
    """
    bilateral = {
        "cdp_bilateral", "lldp_bilateral", "lacp_bilateral",
        "mac_fingerprint_bilateral",
    }
    unilateral = {
        "cdp_unilateral", "lldp_unilateral", "lacp_unilateral",
        "mac_fingerprint_unilateral",
    }

    bilateral_ports: set[str] = set()
    for link in links:
        if link.get("discovery_method") in bilateral:
            for pid in (link.get("local_interface_id"), link.get("remote_interface_id")):
                port = _port_id_canonical(pid)
                if port:
                    bilateral_ports.add(port)

    if not bilateral_ports:
        return links

    to_remove: set[int] = set()
    for link in links:
        if link.get("discovery_method") not in unilateral:
            continue
        ports = (
            _port_id_canonical(link.get("local_interface_id")),
            _port_id_canonical(link.get("remote_interface_id")),
        )
        if any(p and p in bilateral_ports for p in ports):
            to_remove.add(id(link))

    if not to_remove:
        return links

    logger.debug(
        "suppress_unilateral_cable_on_bilateral_port: removed %d unilateral cable "
        "link(s) on a port already confirmed by a bilateral cable",
        len(to_remove),
    )
    return [lnk for lnk in links if id(lnk) not in to_remove]


# =========================================================================
# Link classification — link_type + management (OOB/inband)
# =========================================================================

def _get_link_access_vlan(link: dict[str, Any]) -> int | None:
    """Return the access VLAN ID of the local side of a link, or None.

    Only returns a value when the local interface is in access mode with a
    known VLAN ID. Trunk ports, routed ports, and missing L2 data → None.
    """
    l2 = link.get("l2") or {}
    local = l2.get("local") or {}
    if local.get("mode") == "access":
        vlan = local.get("vlan") or {}
        vid = vlan.get("id")
        if vid is not None:
            try:
                return int(vid)
            except (TypeError, ValueError):
                pass
    return None


def _is_mgmt_port_name(intf_id: str) -> bool:
    """Return True if the interface name indicates a management port (Gi0/0, MgmtEth)."""
    # Extract interface name after the "device:" prefix
    name = intf_id.split(":", 1)[-1] if ":" in intf_id else intf_id
    name_lower = name.lower()
    return (
        name_lower.startswith("gigabitethernet0/0")
        or name_lower.startswith("gi0/0")
        or name_lower.startswith("mgmteth")
        or name_lower.startswith("management")
    )


def _intf_carries_mgmt_vlan(
    intf_id: str,
    intf_by_id: dict[str, dict],
    mgmt_vlans: set[int],
) -> bool:
    """Return True if the interface carries any management VLAN."""
    intf = intf_by_id.get(intf_id)
    if not intf:
        return False
    # Trunk: check trunk_vlans list
    trunk_vlans = intf.get("trunk_vlans")
    if trunk_vlans:
        if mgmt_vlans.intersection(trunk_vlans):
            return True
    # Access: check access_vlan
    av = intf.get("access_vlan")
    if av is not None and av in mgmt_vlans:
        return True
    return False


def classify_link_type(
    link: dict[str, Any],
    role_by_device: dict[str, str],
    mgmt_subnets: set[str],
    mgmt_interface_ids: set[str],
    mgmt_vlans: set[int] | None = None,
    intf_by_id: dict[str, dict] | None = None,
) -> str:
    """Classify a link into one of the link types.

    Classification rules are applied in priority order (first match wins):

    | Priority | Condition                                                  | link_type          |
    |----------|------------------------------------------------------------|--------------------|
    | 0        | L2 access VLAN present and NOT in mgmt_vlans              | physical           |
    | 1a       | mgmt_switch + dp >= 7 (L3/ARP)                            | management         |
    | 1b       | mgmt_switch + dp < 7 + mgmt port (Gi0/0 etc)             | management         |
    | 1c       | mgmt_switch + dp < 7 + carries mgmt VLANs                | infrastructure     |
    | 1d       | mgmt_switch + dp < 7 + no mgmt VLANs                     | physical           |
    | 2        | Either endpoint interface IP is on a mgmt subnet          | management         |
    | 3        | discovery_method == "subnet_only"                         | subnet_association |
    | 4        | Either endpoint interface is virtual (Loopback,           | l3_reachability    |
    |          | VLAN SVI, BVI, Tunnel, NVE, FortiGate numeric)            |                    |
    | 5        | Everything else (confirmed cable)                         | physical           |

    Args:
        link: The link dict (post-dedup, post-enrichment).
        role_by_device: Dict mapping device hostname → role string.
        mgmt_subnets: Set of management subnet strings (e.g., {"192.0.2.0/24"}).
        mgmt_interface_ids: Set of interface_id strings that have mgmt IPs.
        mgmt_vlans: Set of management VLAN IDs derived from mgmt-subnet SVIs.
            When provided, links on non-management access VLANs are classified as
            physical even if an endpoint is a mgmt_switch (e.g. a NetFlow VLAN).
        intf_by_id: Optional dict mapping interface_id → interface dict (with
            switchport_mode, trunk_vlans, access_vlan). Used to determine if
            mgmt_switch physical cables carry management VLANs (→ infrastructure).

    Returns:
        One of: "physical", "management", "infrastructure",
        "l3_reachability", "subnet_association".
    """
    local_dev = link.get("local_device_id", "")
    remote_dev = link.get("remote_device_id", "")

    # Priority 0: L2 access port on a known non-management VLAN → physical.
    # This catches NetFlow/monitoring cables to a mgmt_switch on dedicated VLANs.
    # Only applies to confirmed cable methods — inferred links (mac_subnet,
    # arp_subnet) on non-mgmt VLANs are still not cables.
    _CABLE_METHODS = {
        "cdp_bilateral", "cdp_unilateral",
        "lldp_bilateral", "lldp_unilateral",
        "lacp_bilateral", "lacp_unilateral",
        "fdb_firewall", "fdb_mgmt",
        "mac_fingerprint_bilateral", "mac_fingerprint_unilateral",
    }
    is_confirmed_cable = link.get("discovery_method", "") in _CABLE_METHODS
    if mgmt_vlans and is_confirmed_cable:
        link_vlan = _get_link_access_vlan(link)
        if link_vlan is not None and link_vlan not in mgmt_vlans:
            return "physical"

    # Priority 1: mgmt_switch links
    if role_by_device.get(local_dev) == "mgmt_switch" or \
       role_by_device.get(remote_dev) == "mgmt_switch":
        dp = link.get("discovery_priority", 99)
        local_intf_id = link.get("local_interface_id", "")
        remote_intf_id = link.get("remote_interface_id", "")
        has_mgmt_port = (
            local_intf_id in mgmt_interface_ids
            or remote_intf_id in mgmt_interface_ids
            or _is_mgmt_port_name(local_intf_id)
            or _is_mgmt_port_name(remote_intf_id)
        )
        # 1a: L3/ARP/subnet discovery (dp >= 7)
        if dp >= 7:
            # Determine which side is the mgmt_switch
            is_local_mgmt_sw = role_by_device.get(local_dev) == "mgmt_switch"
            is_remote_mgmt_sw = role_by_device.get(remote_dev) == "mgmt_switch"
            # The non-mgmt_switch side's interface
            non_sw_intf = remote_intf_id if is_local_mgmt_sw else local_intf_id
            non_sw_intf_name = non_sw_intf.split(":", 1)[1] if ":" in non_sw_intf else ""
            non_sw_has_mgmt_port = _is_mgmt_port_name(non_sw_intf)

            if non_sw_has_mgmt_port and (is_local_mgmt_sw or is_remote_mgmt_sw):
                # Mgmt port ↔ mgmt_switch via ARP — inferred OOB cable.
                # Needed for IOS XR devices where mgmt ports don't run CDP.
                return "management"
            elif _is_virtual_interface(non_sw_intf_name):
                # Virtual interface to mgmt_switch → l3_reachability
                return "l3_reachability"
            elif is_local_mgmt_sw or is_remote_mgmt_sw:
                # Non-mgmt-port, non-virtual to mgmt_switch → management (inband)
                return "management"
            else:
                # Neither side is mgmt_switch but dp >= 7 — shouldn't happen
                # in this branch (Priority 1 requires mgmt_switch)
                return "management"
        # 1b: connected to a mgmt port (Gi0/0, MgmtEth) with cable-level discovery
        if has_mgmt_port:
            return "management"
        # 1c/1d: physical cable — check if it carries mgmt VLANs
        if mgmt_vlans and intf_by_id:
            if _intf_carries_mgmt_vlan(local_intf_id, intf_by_id, mgmt_vlans) or \
               _intf_carries_mgmt_vlan(remote_intf_id, intf_by_id, mgmt_vlans):
                return "infrastructure"
        # 1d: confirmed cable to mgmt_switch → physical; inferred → management
        if is_confirmed_cable:
            return "physical"
        return "management"

    # Priority 2: Either endpoint interface is a management interface
    local_intf_id = link.get("local_interface_id", "")
    remote_intf_id = link.get("remote_interface_id", "")

    if local_intf_id in mgmt_interface_ids or remote_intf_id in mgmt_interface_ids:
        # Confirmed cable on mgmt port → management
        # Unconfirmed (ARP/MAC) on mgmt port without mgmt_switch → l3_reachability
        # (these are L3 paths between devices sharing the mgmt subnet, not cables)
        if is_confirmed_cable:
            return "management"
        return "l3_reachability"

    # Also check if the link's L3 subnet is a management subnet
    l3 = link.get("l3") or {}
    link_subnet = l3.get("subnet", "")
    if link_subnet and link_subnet in mgmt_subnets:
        return "management"

    # Priority 3: subnet_only discovery method
    if link.get("discovery_method") == "subnet_only":
        return "subnet_association"

    # Priority 4: Either endpoint interface is virtual
    # Extract interface name from interface_id format "hostname:IntfName"
    local_intf_name = local_intf_id.split(":", 1)[1] if ":" in local_intf_id else ""
    remote_intf_name = remote_intf_id.split(":", 1)[1] if ":" in remote_intf_id else ""

    if _is_virtual_interface(local_intf_name) or _is_virtual_interface(remote_intf_name):
        return "l3_reachability"

    # Priority 5: Only confirmed discovery methods produce "physical" (real cable).
    # Confirmed: CDP, LLDP, LACP, FDB — protocols that prove a direct L1/L2
    # connection between two specific ports. Unconfirmed: ARP/MAC/subnet
    # inference — proves L3/L2 reachability, not a direct cable.
    method = link.get("discovery_method", "")
    if method in _CABLE_METHODS:
        return "physical"

    # Priority 6: Unconfirmed methods → l3_reachability (not a cable)
    return "l3_reachability"


def classify_mgmt_type(
    link: dict[str, Any],
    role_by_device: dict[str, str],
    oob_device_names: set[str] | None = None,
) -> str | None:
    """Classify a management link as OOB or inband.

    Only meaningful for links with link_type == "management".
    Returns None for non-management links.

    OOB (out-of-band): one endpoint is the management switch, the device's
    management_ip is in the mgmt-switch subnet (oob_device_names), or an
    endpoint interface is a dedicated management port (Mgmt0, Gi0/0).
    Inband: everything else (management traffic flows through the data plane).
    """
    if link.get("link_type") != "management":
        return None

    local_dev = link.get("local_device_id", "")
    remote_dev = link.get("remote_device_id", "")

    # If one endpoint is the mgmt_switch → always OOB
    if role_by_device.get(local_dev) == "mgmt_switch" or \
       role_by_device.get(remote_dev) == "mgmt_switch":
        return "oob"

    # Subnet-based: classify by both endpoints' OOB status.
    # A firewall is an infrastructure device (gateway for both OOB and inband);
    # the link's mgmt_type is determined by the *other* endpoint.
    if oob_device_names:
        local_oob = local_dev in oob_device_names
        remote_oob = remote_dev in oob_device_names
        if local_oob and remote_oob:
            return "oob"
        if local_oob or remote_oob:
            return "inband"

    # Fall back to interface-name heuristic (dedicated management ports)
    _OOB_PREFIXES = ("Mgmt", "mgmt", "MgmtEth", "Management")
    _OOB_EXACT = ("Gi0/0", "GigabitEthernet0/0")

    for intf_id in (link.get("local_interface_id", ""),
                    link.get("remote_interface_id", "")):
        # Extract interface name from "hostname:IntfName"
        intf_name = intf_id.split(":", 1)[1] if ":" in intf_id else intf_id
        if not intf_name:
            continue
        if any(intf_name.startswith(p) for p in _OOB_PREFIXES):
            return "oob"
        if intf_name in _OOB_EXACT:
            return "oob"

    return "inband"


# =========================================================================
# Management-subnet detection + inband-management synthesis
# =========================================================================

def detect_management_subnets(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> tuple[set[str], set[str], set[int]]:
    """Detect management subnets, interface IDs, and VLANs from model data.

    Operates on model data directly (no filesystem reads, no YAML loading).

    Algorithm:
    1. Collect management_ip from each device in the model.
    2. Find model interfaces whose ip_address matches a management_ip.
    3. Extract the /N subnet from those interfaces.
    4. Fallback: scan link L3 subnets for those containing management IPs.
    5. Extract management VLAN IDs from SVI interface names (e.g. "Vlan99" → 99).

    Args:
        devices: The built device list (with management_ip field).
        interfaces: The built interface list (with ip_address field).
        links: The built link list (with l3.subnet field).

    Returns:
        Tuple of (mgmt_subnets, mgmt_interface_ids, mgmt_vlans) where:
        - mgmt_subnets: set of subnet strings (e.g., {"192.0.2.0/24"})
        - mgmt_interface_ids: set of interface_id strings
        - mgmt_vlans: set of VLAN IDs (int) derived from SVI interface names
    """
    import ipaddress as _ipaddress
    import re as _re

    mgmt_subnets: set[str] = set()
    mgmt_interface_ids: set[str] = set()
    mgmt_vlans: set[int] = set()

    # Step 1: Collect management IPs from devices
    mgmt_ips: set[str] = set()
    for device in devices:
        mgmt_ip = device.get("management_ip")
        if mgmt_ip:
            mgmt_ips.add(str(mgmt_ip))

    if not mgmt_ips:
        return mgmt_subnets, mgmt_interface_ids, mgmt_vlans

    # Step 2: Build IP → interface mapping
    ip_to_intf: dict[str, dict[str, Any]] = {}
    for intf in interfaces:
        ip_addr = intf.get("ip_address", "")
        if not ip_addr:
            continue
        ip_only = ip_addr.split("/")[0]
        ip_to_intf[ip_only] = intf

    # Step 3: Find management interfaces and extract subnets
    for mgmt_ip in mgmt_ips:
        intf = ip_to_intf.get(mgmt_ip)
        if not intf:
            continue

        mgmt_interface_ids.add(intf["interface_id"])

        ip_addr = intf.get("ip_address", "")
        if "/" in ip_addr:
            try:
                network = _ipaddress.ip_interface(ip_addr).network
                mgmt_subnets.add(str(network))
            except ValueError:
                pass

    # Step 4: Fallback — derive subnets from links touching mgmt interfaces
    if mgmt_interface_ids and not mgmt_subnets:
        for link in links:
            local_intf = link.get("local_interface_id", "")
            remote_intf = link.get("remote_interface_id", "")
            if local_intf in mgmt_interface_ids or remote_intf in mgmt_interface_ids:
                l3 = link.get("l3") or {}
                subnet = l3.get("subnet")
                if subnet:
                    mgmt_subnets.add(subnet)

    # Step 5: Last resort — scan link subnets for any containing mgmt IPs
    if not mgmt_subnets:
        for link in links:
            l3 = link.get("l3") or {}
            subnet_str = l3.get("subnet")
            if not subnet_str:
                continue
            try:
                network = _ipaddress.ip_network(subnet_str, strict=False)
                for mgmt_ip in mgmt_ips:
                    try:
                        if _ipaddress.ip_address(mgmt_ip) in network:
                            mgmt_subnets.add(subnet_str)
                            break
                    except ValueError:
                        continue
            except ValueError:
                continue

    # Step 6: Derive management VLAN IDs from SVI names on management interfaces
    # e.g., "Vlan99", "VLAN 99", "vl99" → 99
    for iface_id in mgmt_interface_ids:
        intf = next((i for i in interfaces if i.get("interface_id") == iface_id), None)
        if not intf:
            continue
        name = intf.get("name", "")
        if name.lower().startswith(("vlan", "vl")):
            m = _re.search(r"\d+", name)
            if m:
                mgmt_vlans.add(int(m.group()))

    return mgmt_subnets, mgmt_interface_ids, mgmt_vlans


def compute_oob_device_names(
    devices: list[dict[str, Any]],
    mgmt_subnets: set[str],
) -> set[str]:
    """Return device_ids whose management_ip is in a management (OOB) subnet.

    Uses the mgmt_subnets set already computed by detect_management_subnets().
    Devices whose management_ip falls in one of these subnets are OOB-managed;
    the remainder are inband candidates.
    """
    import ipaddress as _ipaddress

    if not mgmt_subnets:
        return set()

    oob_networks: list[Any] = []
    for subnet_str in mgmt_subnets:
        try:
            oob_networks.append(_ipaddress.ip_network(subnet_str, strict=False))
        except ValueError:
            continue

    oob_names: set[str] = set()
    for device in devices:
        mgmt_ip_str = device.get("management_ip") or ""
        if not mgmt_ip_str:
            continue
        try:
            mgmt_ip = _ipaddress.ip_address(mgmt_ip_str)
        except ValueError:
            continue
        if any(mgmt_ip in net for net in oob_networks):
            oob_names.add(device["device_id"])

    return oob_names


def create_inband_mgmt_links(
    devices: list[dict[str, Any]],
    oob_device_names: set[str],
    existing_mgmt_link_sources: set[str],
    facts_dirs: dict[str, Path],
    all_interface_ips: dict[str, str],
    links: list[dict[str, Any]] | None = None,
    interfaces: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return hop-by-hop management links along the L2 VLAN path.

    Instead of a single synthetic link from each leaf switch to the gateway,
    traces the actual L2 path through the physical topology:
    leaf → hub → distribution/core → gateway (firewall).

    Each hop is annotated with the management VLAN ID and VRF name.

    Args:
        devices: Built device list (device_id = inventory name).
        oob_device_names: Set of OOB device_ids (skip these).
        existing_mgmt_link_sources: device_ids that already have a mgmt link.
        facts_dirs: inventory_name → Path to that device's facts directory.
        all_interface_ips: ip_str → device_id map built from model interfaces.
        links: Existing physical links for adjacency lookup.
        interfaces: Model interfaces (unused, reserved for future).
    """
    import json as _json
    from collections import defaultdict

    # ------------------------------------------------------------------
    # Phase A: Collect inband device context
    # ------------------------------------------------------------------
    # For each non-OOB device without an existing mgmt link, extract the
    # gateway IP, VRF name, and VLAN ID from routing data.
    inband_context: dict[str, tuple[str, str, str, int | None]] = {}
    #   dev_id → (gw_ip, gw_device, vrf_name, vlan_id)

    for device in devices:
        dev_id = device["device_id"]
        if dev_id in oob_device_names:
            continue
        if dev_id in existing_mgmt_link_sources:
            continue
        if device.get("device_type") == "external":
            continue
        mgmt_ip_str = device.get("management_ip") or ""
        if not mgmt_ip_str:
            continue

        # Locate facts directory (dirs are named by inventory_name)
        facts_path = facts_dirs.get(dev_id)
        if not facts_path:
            logger.debug("inband mgmt: no facts dir for %s", dev_id)
            continue
        routing_path = facts_path / "genie_routing.json"
        if not routing_path.exists():
            logger.debug("inband mgmt: no genie_routing.json for %s", dev_id)
            continue

        try:
            routing = _json.loads(routing_path.read_text())
        except (OSError, _json.JSONDecodeError) as exc:
            logger.warning("inband mgmt: cannot read routing for %s: %s", dev_id, exc)
            continue

        ctx = _find_mgmt_vrf_context(routing, mgmt_ip_str)
        if not ctx:
            logger.debug("inband mgmt: no gateway found for %s (mgmt_ip=%s)", dev_id, mgmt_ip_str)
            continue
        gw_ip, vrf_name, vlan_id = ctx

        gw_device = all_interface_ips.get(gw_ip)
        if not gw_device or gw_device == dev_id:
            logger.debug("inband mgmt: gateway IP %s not in interface map for %s", gw_ip, dev_id)
            continue

        inband_context[dev_id] = (gw_ip, gw_device, vrf_name, vlan_id)

    if not inband_context:
        return []

    # ------------------------------------------------------------------
    # Phase B: Build physical adjacency index
    # ------------------------------------------------------------------
    phys_neighbors: dict[str, set[str]] = defaultdict(set)
    for link in (links or []):
        if link.get("link_type") != "physical":
            continue
        a = link["local_device_id"]
        b = link["remote_device_id"]
        phys_neighbors[a].add(b)
        phys_neighbors[b].add(a)

    # ------------------------------------------------------------------
    # Phase C: Group by L2 domain and generate hop-by-hop links
    # ------------------------------------------------------------------
    # Group inband devices by (gateway_ip, vlan_id) — same L2 domain
    l2_domain_groups: dict[tuple[str, int | None], list[str]] = defaultdict(list)
    for dev_id, (gw_ip, gw_device, vrf_name, vlan_id) in inband_context.items():
        l2_domain_groups[(gw_ip, vlan_id)].append(dev_id)

    result: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()

    def _emit_link(src: str, dst: str, gw_ip: str, vrf: str, vlan: int | None) -> None:
        pair = tuple(sorted((src, dst)))
        if pair in seen_pairs:
            return
        seen_pairs.add(pair)
        vlan_str = f"Vlan{vlan}" if vlan else ""
        result.append({
            "link_id": f"inband-mgmt-{src}--{dst}",
            "local_device_id": src,
            "remote_device_id": dst,
            "local_interface_id": f"{src}:{vlan_str or 'mgmt-vrf-gw'}",
            "remote_interface_id": f"{dst}:{vlan_str or 'mgmt-vrf-gw'}",
            "link_type": "management",
            "mgmt_type": "inband",
            "discovery_method": "inband_vlan_path",
            "discovery_protocol": "routing",
            "discovery_priority": 1,
            "confidence": "medium",
            "direction": "unidirectional",
            "status": "up",
            "peer_collected": False,
            "evidence": [
                f"gateway:{gw_ip}",
                *([] if not vlan else [f"vlan:{vlan}"]),
                f"vrf:{vrf}",
            ],
            "l2": {},
            "l3": {},
            "ha_member": None,
            "source_member_id": None,
            "mgmt_vlan": vlan,
            "mgmt_vrf": vrf,
        })
        logger.info("inband mgmt hop: %s → %s (Vlan%s, %s)", src, dst, vlan or "?", vrf)

    # Build set of known infrastructure device IDs (non-external) for hub detection
    infra_device_ids = {
        d["device_id"] for d in devices
        if d.get("device_type") != "external"
    }

    for (gw_ip, vlan_id), members in l2_domain_groups.items():
        # All members share the same gateway and VRF
        sample_ctx = inband_context[members[0]]
        gw_device = sample_ctx[1]
        vrf_name = sample_ctx[2]
        member_set = set(members)

        # Find hub: a member with a physical neighbor outside the group that is
        # an infrastructure device (not external WAN peers). Prefer
        # distribution/core switches as the upstream.
        hub = None
        upstream = None
        for dev_id in members:
            for neighbor in phys_neighbors.get(dev_id, set()):
                if (
                    neighbor not in member_set
                    and neighbor != gw_device
                    and neighbor in infra_device_ids
                ):
                    hub = dev_id
                    upstream = neighbor
                    break
            if hub:
                break

        if hub and upstream:
            # Leaf → Hub links
            for dev_id in members:
                if dev_id != hub:
                    # Only if leaf has a physical connection to the hub
                    if hub in phys_neighbors.get(dev_id, set()):
                        _emit_link(dev_id, hub, gw_ip, vrf_name, vlan_id)
                    else:
                        # Leaf not physically connected to hub — direct to hub anyway
                        # (L2 reachability via the shared VLAN)
                        _emit_link(dev_id, hub, gw_ip, vrf_name, vlan_id)
            # Hub → Upstream
            _emit_link(hub, upstream, gw_ip, vrf_name, vlan_id)
            # Upstream → Gateway (deduplicated across groups)
            _emit_link(upstream, gw_device, gw_ip, vrf_name, None)
        else:
            # No hub found (single device or no physical path outside group).
            # Fall back: each member directly to the gateway via any known upstream.
            for dev_id in members:
                # Try to find an infrastructure upstream via physical neighbors
                dev_upstream = None
                for neighbor in phys_neighbors.get(dev_id, set()):
                    if neighbor not in member_set and neighbor in infra_device_ids:
                        dev_upstream = neighbor
                        break
                if dev_upstream:
                    _emit_link(dev_id, dev_upstream, gw_ip, vrf_name, vlan_id)
                    _emit_link(dev_upstream, gw_device, gw_ip, vrf_name, None)
                else:
                    # No physical path — fall back to a direct gateway link
                    _emit_link(dev_id, gw_device, gw_ip, vrf_name, vlan_id)

    return result


def _find_mgmt_vrf_context(
    routing: dict[str, Any], mgmt_ip_str: str,
) -> tuple[str, str, int | None] | None:
    """Return (gateway_ip, vrf_name, vlan_id) for the management VRF.

    Identifies the management VRF by finding a connected/local route that
    contains the device's management IP, extracts the VRF name and VLAN ID
    from the outgoing interface (e.g. Vlan1201 → 1201), then returns the
    default-route next-hop along with that context.
    """
    import ipaddress as _ipaddress
    import re as _re

    try:
        target = _ipaddress.ip_address(mgmt_ip_str)
    except ValueError:
        return None

    for vrf_name, vrf_data in routing.get("vrf", {}).items():
        routes = (
            vrf_data
            .get("address_family", {})
            .get("ipv4", {})
            .get("routes", {})
        )
        # Find the VRF where mgmt_ip is a connected/local address
        vlan_id: int | None = None
        in_vrf = False
        for pfx, info in routes.items():
            net = _safe_ip_network(pfx)
            if (
                net is not None
                and target in net
                and info.get("source_protocol") in ("connected", "local")
            ):
                in_vrf = True
                # Extract VLAN ID from the outgoing interface (e.g. Vlan1201 → 1201)
                if vlan_id is None:
                    for intf in info.get("next_hop", {}).get("outgoing_interface", {}):
                        m = _re.match(r"[Vv]lan(\d+)", intf)
                        if m:
                            vlan_id = int(m.group(1))
                            break
        if not in_vrf:
            continue
        # Return first next-hop of the default route in this VRF
        for hop in (
            routes.get("0.0.0.0/0", {})
            .get("next_hop", {})
            .get("next_hop_list", {})
            .values()
        ):
            nh = hop.get("next_hop")
            if nh:
                return (nh, vrf_name, vlan_id)
    return None


def _safe_ip_network(prefix: str) -> Any:
    import ipaddress as _ipaddress
    try:
        return _ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


# =========================================================================
# L2 Metadata Enrichment (VLAN / switchport mode)
# =========================================================================

# Sub-interface suffix pattern: "GigabitEthernet0/2.1000" → tag "1000"
_SUBINTF_TAG_RE = re.compile(r"\.(\d+)$")

# SVI pattern: "Vlan99", "Vlan1101" → VLAN ID "99", "1101"
_SVI_VLAN_RE = re.compile(r"^[Vv]lan(\d+)$")


def _build_vlan_port_index(
    facts_dirs: dict[str, Path],
) -> dict[str, dict[str, dict[str, Any]]]:
    """
    Build a per-device index of access port VLAN assignments from genie_vlan.json.

    Genie VLAN Schema::

        {
          "vlans": {
            "99": {
              "vlan_id": "99",
              "name": "MGMT",
              "state": "active",
              "shutdown": false,
              "interfaces": ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", ...]
            }
          }
        }

    The "interfaces" list in each VLAN contains access ports assigned to that
    VLAN. Trunk ports do NOT appear in this list (Genie behavior).

    Entries are keyed by CANONICAL name (lowercase full form) so that lookups
    using normalized short forms (Gi1/0/3) match Genie's full forms
    (GigabitEthernet1/0/3) via canonicalize().

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.

    Returns:
        Nested dict: hostname → canonical_interface → {"vlan_id", "vlan_name"}.

    Example:
        >>> idx = _build_vlan_port_index(facts_dirs)
        >>> idx["dist-sw-01"]["gigabitethernet1/0/3"]
        {"vlan_id": "99", "vlan_name": "MGMT"}
    """
    # hostname → canonical_interface → {vlan_id, vlan_name}
    vlan_port_index: dict[str, dict[str, dict[str, Any]]] = {}

    for hostname, facts_dir in facts_dirs.items():
        vlan_path = facts_dir / "genie_vlan.json"
        vlan_data = _load_json_file(vlan_path)

        if not vlan_data:
            continue

        port_map: dict[str, dict[str, Any]] = {}

        for vlan_id, vlan_info in vlan_data.get("vlans", {}).items():
            vlan_name = vlan_info.get("name", "")
            vlan_state = vlan_info.get("state", "")

            # Skip inactive VLANs
            if vlan_state in ("unsupport", "suspend"):
                continue

            # Map each interface in this VLAN to its VLAN info, keyed by
            # CANONICAL name for cross-format matching.
            vlan_entry = {
                "vlan_id": str(vlan_id),
                "vlan_name": vlan_name,
            }

            for intf_name in vlan_info.get("interfaces", []):
                canonical = canonicalize(intf_name)
                if canonical:
                    port_map[canonical] = vlan_entry
                # Also store by original name as a fallback
                port_map[intf_name] = vlan_entry

        if port_map:
            vlan_port_index[hostname] = port_map

    return vlan_port_index


def _build_vlan_name_index(
    facts_dirs: dict[str, Path],
) -> dict[str, dict[str, str]]:
    """
    Build a per-device VLAN ID → name lookup from genie_vlan.json.

    Used to resolve VLAN names for SVIs (Vlan99 → "MGMT") and sub-interface
    tags (Gi0/2.1000 → VLAN 1000 → "DATA-TRANSIT").

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.

    Returns:
        Nested dict: hostname → vlan_id_string → vlan_name (active VLANs only).

    Example:
        >>> names = _build_vlan_name_index(facts_dirs)
        >>> names["dist-sw-01"]["1000"]
        "DATA-TRANSIT"
    """
    vlan_name_index: dict[str, dict[str, str]] = {}

    for hostname, facts_dir in facts_dirs.items():
        vlan_path = facts_dir / "genie_vlan.json"
        vlan_data = _load_json_file(vlan_path)

        if not vlan_data:
            continue

        name_map: dict[str, str] = {}
        for vlan_id, vlan_info in vlan_data.get("vlans", {}).items():
            vlan_state = vlan_info.get("state", "")
            if vlan_state in ("unsupport", "suspend"):
                continue
            name_map[str(vlan_id)] = vlan_info.get("name", "")

        if name_map:
            vlan_name_index[hostname] = name_map

    return vlan_name_index


def _resolve_l2_for_interface(
    hostname: str,
    intf_name: str,
    vlan_port_index: dict[str, dict[str, dict[str, Any]]],
    vlan_name_index: dict[str, dict[str, str]],
) -> dict[str, Any] | None:
    """
    Resolve L2 metadata for a single interface on a device.

    Three resolution strategies are tried in order:

    1. Access Port: interface appears in genie_vlan.json's interfaces list.
       → mode="access", vlan={id, name}
    2. SVI: interface name matches "Vlan<id>".
       → mode="svi", vlan={id, name}
    3. Sub-Interface: interface name has a dot tag (e.g., "Gi0/2.1000").
       → mode="subinterface", vlan={id, name}

    If none match (routed port or no VLAN data) → returns None.

    Trunk mode is NOT detected here — Genie learn('vlans') doesn't list trunk
    ports; trunk data comes from running-config parsing (handled in
    enrich_l2_metadata's second pass).

    Args:
        hostname: Device hostname for index lookups.
        intf_name: Interface name (original form from the link dict).
        vlan_port_index: Access port → VLAN index from _build_vlan_port_index().
        vlan_name_index: VLAN ID → name index from _build_vlan_name_index().

    Returns:
        Dict with L2 metadata, or None if no VLAN data available.
    """
    device_ports = vlan_port_index.get(hostname, {})
    device_vlans = vlan_name_index.get(hostname, {})

    # Strategy 1: Access port — interface in a VLAN's interfaces list.
    # Try both original and canonical form for cross-format matching.
    canonical_intf = canonicalize(intf_name)
    lookup_names = [intf_name]
    if canonical_intf:
        lookup_names.append(canonical_intf)

    for name in lookup_names:
        if name in device_ports:
            vlan_info = device_ports[name]
            return {
                "mode": "access",
                "vlan": {
                    "id": vlan_info["vlan_id"],
                    "name": vlan_info["vlan_name"],
                },
            }

    # Strategy 2: SVI — "Vlan99", "Vl99" → VLAN 99
    svi_match = _SVI_VLAN_RE.match(intf_name)
    if not svi_match and canonical_intf:
        svi_match = _SVI_VLAN_RE.match(canonical_intf)
    if svi_match:
        vlan_id = svi_match.group(1)
        vlan_name = device_vlans.get(vlan_id, "")
        return {
            "mode": "svi",
            "vlan": {
                "id": vlan_id,
                "name": vlan_name,
            },
        }

    # Strategy 3: Sub-interface — "Gi0/2.1000" → VLAN 1000.
    # Sub-interface tags typically correspond to the 802.1Q VLAN ID (a common
    # convention, not guaranteed).
    subintf_match = _SUBINTF_TAG_RE.search(intf_name)
    if subintf_match:
        vlan_id = subintf_match.group(1)
        vlan_name = device_vlans.get(vlan_id, "")
        return {
            "mode": "subinterface",
            "vlan": {
                "id": vlan_id,
                "name": vlan_name,
            },
        }

    # No VLAN data found — routed port or unknown
    return None


def enrich_l2_metadata(
    links: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    interfaces: list[dict[str, Any]] | None = None,
) -> None:
    """
    Add L2 metadata (VLAN/mode) to each link in-place.

    For each link, resolves L2 information for both endpoints and adds an "l2"
    key. The l2 block captures what VLAN(s) the endpoints belong to and whether
    they are access ports, SVIs, or sub-interfaces.

    If NEITHER endpoint has L2 data → l2 = null (routed link). If at least one
    endpoint has data → the l2 block is populated.

    Output Schema::

        link["l2"] = {
            "local":  {"mode": "access|svi|subinterface", "vlan": {...}} | null,
            "remote": {"mode": "access|svi|subinterface", "vlan": {...}} | null,
        } | null

    Trunk Ports:
        Trunk data comes from running_config.txt parsing, stored on Interface
        dicts as switchport_mode/trunk_vlans/native_vlan. If the `interfaces`
        parameter is provided, a second pass enriches links where at least one
        endpoint is a trunk port with l2.trunk data (port-channel members
        inherit their parent's trunk config).

    Mutates each link dict in-place. No return value.

    Args:
        links: List of deduplicated link dicts. Each has "local_device_id",
               "remote_device_id", and interface IDs in "hostname:intf" format.
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        interfaces: Optional enriched interface list with switchport data.
    """
    # Step 1: Build VLAN indexes
    vlan_port_index = _build_vlan_port_index(facts_dirs)
    vlan_name_index = _build_vlan_name_index(facts_dirs)

    logger.info(
        "L2 enrichment: VLAN data for %d devices, %d total access port mappings",
        len(vlan_port_index),
        sum(len(ports) for ports in vlan_port_index.values()),
    )

    # Step 2: Enrich each link
    enriched_count = 0

    for link in links:
        local_device = link["local_device_id"]
        remote_device = link["remote_device_id"]

        local_intf_id = link["local_interface_id"]
        remote_intf_id = link["remote_interface_id"]

        # Split on first ":" to get the interface name
        # "dist-sw-01:GigabitEthernet1/0/3" → "GigabitEthernet1/0/3"
        local_intf_name = local_intf_id.split(":", 1)[1] if ":" in local_intf_id else ""
        remote_intf_name = remote_intf_id.split(":", 1)[1] if ":" in remote_intf_id else ""

        local_l2 = _resolve_l2_for_interface(
            local_device, local_intf_name,
            vlan_port_index, vlan_name_index,
        )
        remote_l2 = _resolve_l2_for_interface(
            remote_device, remote_intf_name,
            vlan_port_index, vlan_name_index,
        )

        # Set l2 block — null if neither endpoint has data
        if local_l2 is None and remote_l2 is None:
            link["l2"] = None
        else:
            link["l2"] = {
                "local": local_l2,
                "remote": remote_l2,
            }
            enriched_count += 1

    # Step 3: Trunk enrichment from interface switchport data
    trunk_enriched = 0
    if interfaces:
        # Interfaces and links use normalized short names, so direct
        # (device, name) lookup matches without normalization.
        sw_lookup: dict[tuple[str, str], dict[str, Any]] = {}
        for intf in interfaces:
            mode = intf.get("switchport_mode")
            if mode:
                sw_lookup[(intf.get("device_id", ""), intf.get("name", ""))] = intf

        # Port-channel member → parent PO lookup so physical member links
        # inherit trunk config from their parent port-channel.
        po_lookup: dict[tuple[str, str], str] = {}  # (device, member_name) → po_name
        for intf in interfaces:
            pc = intf.get("port_channel_int")
            if pc:
                po_lookup[(intf.get("device_id", ""), intf.get("name", ""))] = pc

        def _resolve_sw(device: str, intf_name: str) -> dict[str, Any] | None:
            """Look up switchport data: direct match, then parent PO inheritance."""
            hit = sw_lookup.get((device, intf_name))
            if hit:
                return hit
            # Inherit from parent port-channel
            parent_po = po_lookup.get((device, intf_name))
            if parent_po:
                return sw_lookup.get((device, parent_po))
            return None

        for link in links:
            local_device = link["local_device_id"]
            remote_device = link["remote_device_id"]
            local_intf_id = link["local_interface_id"]
            remote_intf_id = link["remote_interface_id"]
            local_intf_name = local_intf_id.split(":", 1)[1] if ":" in local_intf_id else ""
            remote_intf_name = remote_intf_id.split(":", 1)[1] if ":" in remote_intf_id else ""

            local_sw = _resolve_sw(local_device, local_intf_name)
            remote_sw = _resolve_sw(remote_device, remote_intf_name)

            if not local_sw and not remote_sw:
                continue

            # Only enrich trunk links that Step 2 missed or left with empty VLANs
            l2 = link.get("l2")
            if l2 and l2.get("local", {}) and l2["local"].get("trunk"):
                existing_vlans = l2["local"]["trunk"].get("vlans_carried", [])
                if existing_vlans:
                    continue  # already has populated trunk data

            local_mode = local_sw.get("switchport_mode") if local_sw else None
            remote_mode = remote_sw.get("switchport_mode") if remote_sw else None

            # Build local L2 block
            local_l2_new = None
            if local_mode == "trunk":
                trunk_vlans = local_sw.get("trunk_vlans") or []
                # No explicit allowed-vlan filter = all device VLANs pass
                if not trunk_vlans:
                    trunk_vlans = sorted(
                        int(v) for v in vlan_name_index.get(local_device, {})
                        if v.isdigit()
                    )
                local_l2_new = {
                    "mode": "trunk",
                    "trunk": {
                        "mode": "trunk",
                        "vlans_carried": [str(v) for v in trunk_vlans],
                        "native_vlan": local_sw.get("native_vlan"),
                    },
                }
            elif local_mode == "access":
                av = local_sw.get("access_vlan")
                if av is not None:
                    vlan_name = vlan_name_index.get(local_device, {}).get(str(av))
                    local_l2_new = {
                        "mode": "access",
                        "vlan": {"id": str(av), "name": vlan_name},
                    }

            # Build remote L2 block
            remote_l2_new = None
            if remote_mode == "trunk":
                trunk_vlans = remote_sw.get("trunk_vlans") or []
                # No explicit allowed-vlan filter = all device VLANs pass
                if not trunk_vlans:
                    trunk_vlans = sorted(
                        int(v) for v in vlan_name_index.get(remote_device, {})
                        if v.isdigit()
                    )
                remote_l2_new = {
                    "mode": "trunk",
                    "trunk": {
                        "mode": "trunk",
                        "vlans_carried": [str(v) for v in trunk_vlans],
                        "native_vlan": remote_sw.get("native_vlan"),
                    },
                }
            elif remote_mode == "access":
                av = remote_sw.get("access_vlan")
                if av is not None:
                    vlan_name = vlan_name_index.get(remote_device, {}).get(str(av))
                    remote_l2_new = {
                        "mode": "access",
                        "vlan": {"id": str(av), "name": vlan_name},
                    }

            if local_l2_new or remote_l2_new:
                # Merge with existing L2 data (preserve Step 2 results)
                if link.get("l2") is None:
                    link["l2"] = {"local": local_l2_new, "remote": remote_l2_new}
                else:
                    if local_l2_new and not link["l2"].get("local"):
                        link["l2"]["local"] = local_l2_new
                    if remote_l2_new and not link["l2"].get("remote"):
                        link["l2"]["remote"] = remote_l2_new
                trunk_enriched += 1
                if link.get("l2") is None:
                    enriched_count += 1  # newly enriched

    logger.info(
        "L2 enrichment: %d/%d links have L2 metadata (%d trunk-enriched)",
        enriched_count + trunk_enriched,
        len(links),
        trunk_enriched,
    )


# =========================================================================
# L3 Metadata Enrichment (IP / subnet / VRF)
# =========================================================================

def _build_interface_ip_index(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """
    Build a per-device, per-interface IP/prefix/VRF index.

    Scans genie_interface.json (Cisco) and fortigate_system_interface.json
    (FortiGate) to extract IP addressing for each interface. Used by
    enrich_l3_metadata() to populate L3 data on links.

    Genie Interface IP Schema::

        {
          "GigabitEthernet0/0": {
            "vrf": "Mgmt-vrf",           # optional; absent = global/default
            "ipv4": {
              "192.0.2.103/24": {"ip": "192.0.2.103", "prefix_length": "24",
                                 "secondary": false}
            }
          }
        }

    FortiGate IP Schema::

        {"results": [{"name": "port1", "ip": "192.0.2.1 255.255.255.0",
                      "vdom": "root"}]}

    Entries are keyed by CANONICAL interface name so lookups from link dicts
    (normalized short forms like "Gi0/0") match via canonicalize(). Only the
    PRIMARY IPv4 address is stored.

    Args:
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        facts_by_hostname: Dict mapping hostname → device_facts dict (used to
            detect FortiGate devices via the facts "os" field).

    Returns:
        Nested dict: hostname → canonical_interface → {"ip", "prefix_length", "vrf"}.
    """
    # hostname → canonical_intf → {ip, prefix_length, vrf}
    ip_index: dict[str, dict[str, dict[str, Any]]] = {}

    for hostname, facts_dir in facts_dirs.items():
        facts = facts_by_hostname.get(hostname, {})
        # The canonical facts carry the OS at top level ("fortios"/"ios-xe"/...).
        os_family = facts.get("os", "")

        intf_map: dict[str, dict[str, Any]] = {}

        # -----------------------------------------------------------------
        # Source 1: FortiGate system interface
        # -----------------------------------------------------------------
        if os_family == "fortios":
            fg_path = facts_dir / "fortigate_system_interface.json"
            fg_data = _load_json_file(fg_path)

            if fg_data:
                for iface in fg_data.get("results", []):
                    name = iface.get("name", "")
                    ip_field = iface.get("ip", "")
                    vdom = iface.get("vdom", "root")

                    parsed = _parse_fortigate_ip(ip_field)
                    if not parsed:
                        continue

                    ip_addr, prefix_length = parsed

                    # Store by both original and canonical name
                    entry = {
                        "ip": ip_addr,
                        "prefix_length": prefix_length,
                        "vrf": vdom if vdom != "root" else "default",
                    }
                    intf_map[name] = entry
                    canonical = canonicalize(name)
                    if canonical:
                        intf_map[canonical] = entry

            if intf_map:
                ip_index[hostname] = intf_map
            continue

        # -----------------------------------------------------------------
        # Source 2: Genie interface JSON (Cisco IOS XE/XR)
        # -----------------------------------------------------------------
        intf_path = facts_dir / "genie_interface.json"
        intf_data = _load_json_file(intf_path)

        if not intf_data:
            continue

        for intf_name, intf_info in intf_data.items():
            ipv4_block = intf_info.get("ipv4", {})
            vrf = intf_info.get("vrf", "default")

            # Find primary IP (skip DHCP-negotiated, secondary)
            for addr_key, addr_info in ipv4_block.items():
                ip_addr = addr_info.get("ip", "")
                prefix_length = addr_info.get("prefix_length", "")

                # Skip DHCP-negotiated or empty IPs
                if not ip_addr or ip_addr == "dhcp_negotiated":
                    continue
                if not prefix_length:
                    continue

                # Skip secondary addresses — use primary only
                if addr_info.get("secondary", False):
                    continue

                entry = {
                    "ip": ip_addr,
                    "prefix_length": str(prefix_length),
                    "vrf": vrf,
                }

                # Store by both original and canonical name
                intf_map[intf_name] = entry
                canonical = canonicalize(intf_name)
                if canonical:
                    intf_map[canonical] = entry

                # Take the first (primary) IP only
                break

        if intf_map:
            ip_index[hostname] = intf_map

    return ip_index


def enrich_l3_metadata(
    links: list[dict[str, Any]],
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> None:
    """
    Add L3 metadata (IP/subnet/VRF) to each link in-place.

    For each link, looks up both endpoint interfaces in the IP index and
    populates the "l3" key with addressing information.

    Subnet Computation:
        When both endpoints have IPs, the shared subnet is computed. If they
        match, that subnet is stored; if they differ (a misconfiguration on a
        single link), the local side's subnet is stored as best-effort.

    Output Schema::

        link["l3"] = {
            "local":  {"ip": "192.0.2.103", "prefix_length": "24", "vrf": "default"} | null,
            "remote": {"ip": "192.0.2.100", "prefix_length": "24", "vrf": "default"} | null,
            "subnet": "192.0.2.0/24" | null,
        } | null

    VRF Values:
        - "default" = global routing table (no VRF configured)
        - a named VRF (e.g. "Mgmt-vrf") on IOS XE
        - FortiGate: the VDOM name (or "default" for the root VDOM)

    Mutates each link dict in-place. No return value.

    Args:
        links: List of deduplicated link dicts.
        facts_dirs: Dict mapping hostname → Path to facts/ directory.
        facts_by_hostname: Dict mapping hostname → device_facts dict.
    """
    from ipaddress import ip_interface

    # Step 1: Build IP index
    ip_index = _build_interface_ip_index(facts_dirs, facts_by_hostname)

    total_ips = sum(len(intfs) for intfs in ip_index.values())
    logger.info(
        "L3 enrichment: IP data for %d devices, %d interface entries",
        len(ip_index),
        total_ips,
    )

    # Step 2: Enrich each link
    enriched_count = 0

    for link in links:
        local_device = link["local_device_id"]
        remote_device = link["remote_device_id"]

        local_intf_id = link["local_interface_id"]
        remote_intf_id = link["remote_interface_id"]

        local_intf_name = local_intf_id.split(":", 1)[1] if ":" in local_intf_id else ""
        remote_intf_name = remote_intf_id.split(":", 1)[1] if ":" in remote_intf_id else ""

        # Look up in IP index — try canonical name first, then original
        local_ip_data = None
        remote_ip_data = None

        device_ips = ip_index.get(local_device, {})
        local_canonical = canonicalize(local_intf_name)
        if local_canonical and local_canonical in device_ips:
            local_ip_data = device_ips[local_canonical]
        elif local_intf_name in device_ips:
            local_ip_data = device_ips[local_intf_name]

        device_ips = ip_index.get(remote_device, {})
        remote_canonical = canonicalize(remote_intf_name)
        if remote_canonical and remote_canonical in device_ips:
            remote_ip_data = device_ips[remote_canonical]
        elif remote_intf_name in device_ips:
            remote_ip_data = device_ips[remote_intf_name]

        # If neither endpoint has IP data → l3 = null
        if local_ip_data is None and remote_ip_data is None:
            link["l3"] = None
            continue

        # Build l3 block
        local_l3 = None
        remote_l3 = None
        subnet = None

        if local_ip_data:
            local_l3 = {
                "ip": local_ip_data["ip"],
                "prefix_length": local_ip_data["prefix_length"],
                "vrf": local_ip_data["vrf"],
            }

        if remote_ip_data:
            remote_l3 = {
                "ip": remote_ip_data["ip"],
                "prefix_length": remote_ip_data["prefix_length"],
                "vrf": remote_ip_data["vrf"],
            }

        # Compute shared subnet if both endpoints have IPs
        if local_ip_data and remote_ip_data:
            try:
                local_net = ip_interface(
                    f"{local_ip_data['ip']}/{local_ip_data['prefix_length']}"
                ).network
                remote_net = ip_interface(
                    f"{remote_ip_data['ip']}/{remote_ip_data['prefix_length']}"
                ).network
                # Use the local network if they match, otherwise local as best-effort
                if local_net == remote_net:
                    subnet = str(local_net)
                else:
                    subnet = str(local_net)
            except (ValueError, TypeError):
                subnet = None
        elif local_ip_data:
            try:
                subnet = str(ip_interface(
                    f"{local_ip_data['ip']}/{local_ip_data['prefix_length']}"
                ).network)
            except (ValueError, TypeError):
                subnet = None
        elif remote_ip_data:
            try:
                subnet = str(ip_interface(
                    f"{remote_ip_data['ip']}/{remote_ip_data['prefix_length']}"
                ).network)
            except (ValueError, TypeError):
                subnet = None

        link["l3"] = {
            "local": local_l3,
            "remote": remote_l3,
            "subnet": subnet,
        }
        enriched_count += 1

    logger.info(
        "L3 enrichment: %d/%d links have L3 metadata",
        enriched_count,
        len(links),
    )


# =========================================================================
# OSPF Adjacency + LSDB Extraction
# =========================================================================

def _area_id_to_int(area_id: str) -> int:
    """Convert a dotted-decimal OSPF area ID to integer.

    ``"0.0.0.2"`` → ``2``, ``"0.0.0.102"`` → ``102``, ``"0.0.0.0"`` → ``0``.
    """
    parts = area_id.split(".")
    if len(parts) == 4:
        try:
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        except ValueError:
            pass
    try:
        return int(area_id)
    except ValueError:
        return -1


def _default_area_type(area_id: str) -> str:
    """Return the default area type when no explicit config exists."""
    return "backbone" if area_id == "0.0.0.0" else "normal"


def _best_area_type(a: str | None, b: str | None) -> str:
    """Pick the most specific area type from two sides of an adjacency.

    Prefers: totally-* > stub/nssa > backbone > normal > None.
    """
    _RANK = {
        "totally-stub": 0, "totally-nssa": 0,
        "stub": 1, "nssa": 1,
        "backbone": 2,
        "normal": 3,
    }
    if a is None:
        return b or "normal"
    if b is None:
        return a
    return a if _RANK.get(a, 99) <= _RANK.get(b, 99) else b


def _build_router_id_to_hostname(
    facts_dirs: dict[str, Path],
) -> dict[str, str]:
    """
    Build a router-id → hostname lookup from all devices' genie_ospf.json.

    Genie OSPF Ops stores the router-id at:
        vrf[VRF_NAME]['address_family']['ipv4']['instance'][PROCESS_ID]['router_id']

    Router-ids are collected from ALL VRFs and process IDs. If the same
    router-id appears on different devices (config error), the last one wins
    (logged as a warning).

    Args:
        facts_dirs: hostname → Path mapping to each device's facts directory.

    Returns:
        Dictionary mapping router-id strings (e.g. "1.1.1.1") to hostnames.
    """
    rid_to_hostname: dict[str, str] = {}

    for hostname, facts_dir in facts_dirs.items():
        ospf_data = _load_json_file(facts_dir / "genie_ospf.json")
        if ospf_data is None:
            continue

        # Genie wraps everything under a top-level "vrf" key:
        #   {"vrf": {"default": {...}, "TENANT-VRF": {...}}}
        # Unwrap it first, falling back to the raw dict if the "vrf" wrapper is
        # absent (e.g., in unit tests with flat data).
        vrf_dict = ospf_data.get("vrf", ospf_data)
        for vrf_name, vrf_block in vrf_dict.items():
            af_block = vrf_block.get("address_family", {})
            ipv4_block = af_block.get("ipv4", {})
            instances = ipv4_block.get("instance", {})

            for process_id, proc_block in instances.items():
                router_id = proc_block.get("router_id")
                if not router_id:
                    continue

                # Check for router-id collision (different device, same RID)
                if router_id in rid_to_hostname and rid_to_hostname[router_id] != hostname:
                    logger.warning(
                        "Router-id %s conflict: %s vs %s — keeping %s",
                        router_id,
                        rid_to_hostname[router_id],
                        hostname,
                        hostname,
                    )

                rid_to_hostname[router_id] = hostname

    logger.info(
        "OSPF router-id lookup: %d router-ids from %d devices",
        len(rid_to_hostname),
        len(set(rid_to_hostname.values())),
    )
    return rid_to_hostname


def _build_interface_ip_to_hostname(
    facts_dirs: dict[str, Path],
) -> dict[str, str]:
    """Map every collected interface IP → hostname (Cisco ``genie_interface.json``
    + FortiGate ``fortigate_system_interface.json``).

    Used to resolve an OSPF neighbor by its *link interface address* when its
    router-id isn't a collected interface — e.g. a FortiGate, whose OSPF router-id
    is an arbitrary 32-bit ID never assigned to an interface (and which isn't in
    the Cisco-only router-id lookup at all), or a device whose router-id is an
    uncollected loopback. The neighbor's interface address is on the shared subnet,
    so it resolves reliably to the collected device.
    """
    ip_to_host: dict[str, str] = {}
    for hostname, facts_dir in facts_dirs.items():
        intf_data = _load_json_file(facts_dir / "genie_interface.json")
        if intf_data:
            for intf_info in intf_data.values():
                if not isinstance(intf_info, dict):
                    continue
                for cidr in (intf_info.get("ipv4") or {}):
                    ip = str(cidr).split("/")[0]
                    if ip:
                        ip_to_host.setdefault(ip, hostname)
        fg = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if fg:
            results = fg.get("results", fg)
            ifaces = results.values() if isinstance(results, dict) else results
            for iface in (ifaces or []):
                if not isinstance(iface, dict):
                    continue
                parsed = _parse_fortigate_ip(iface.get("ip", ""))
                if parsed and parsed[0]:
                    ip_to_host.setdefault(parsed[0], hostname)
    return ip_to_host


def extract_ospf_adjacencies(
    facts_dirs: dict[str, Path],
) -> list[dict[str, Any]]:
    """
    Extract OSPF neighbor adjacencies from genie_ospf.json files.

    Walks the Genie OSPF Ops structure for every device:
        vrf → address_family → ipv4 → instance → areas → interfaces → neighbors

    For each neighbor, resolves the neighbor_router_id to a hostname via the
    router-id lookup. If the neighbor router-id isn't in our inventory, device_b
    is set to the router-id string and peer_collected is False.

    Deduplication: if A reports B AND B reports A, they produce the same
    canonical pair key and merge into one bilateral adjacency. Multi-VRF
    neighbors between the same pair produce separate entries.

    Args:
        facts_dirs: hostname → Path mapping to each device's facts directory.

    Returns:
        List of adjacency dicts (protocol="ospf", device_a/device_b, state,
        process_id, area, vrf, per-side interface/cost/timer/router-id params,
        peer_collected, bilateral, ...).
    """
    # Step 1: Build router-id → hostname lookup
    rid_to_hostname = _build_router_id_to_hostname(facts_dirs)

    if not rid_to_hostname:
        logger.info("No OSPF data found — skipping adjacency extraction")
        return []

    # Step 1a: Build interface-IP → hostname fallback. When a neighbor's router-id
    # isn't a collected interface (e.g. a FortiGate, whose OSPF router-id is never
    # in the Cisco router-id lookup), the neighbor's link interface address still
    # resolves to the collected device — avoiding a phantom "external" peer.
    iface_ip_to_hostname = _build_interface_ip_to_hostname(facts_dirs)

    # Step 1b: Build per-hostname OSPF process config cache (running_config)
    process_configs: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
    for hostname, facts_dir in facts_dirs.items():
        cfg_path = facts_dir / "running_config.txt"
        if cfg_path.exists():
            try:
                process_configs[hostname] = parse_ospf_process_configs(
                    cfg_path.read_text(errors="replace")
                )
            except OSError:
                pass

    # Step 2: Collect raw one-directional adjacency observations
    observations: list[dict[str, Any]] = []

    for hostname, facts_dir in facts_dirs.items():
        ospf_data = _load_json_file(facts_dir / "genie_ospf.json")
        if ospf_data is None:
            continue

        # Walk: vrf → address_family → ipv4 → instance → areas → interfaces → neighbors
        vrf_dict = ospf_data.get("vrf", ospf_data)

        # Build process_id → router_id lookup from the "default" VRF (Genie only
        # stores router_id on the default VRF process; VRF-specific processes
        # inherit it but Genie omits it).
        default_rids: dict[str, str] = {}
        default_block = vrf_dict.get("default", {})
        for pid, pblk in default_block.get("address_family", {}).get(
            "ipv4", {}
        ).get("instance", {}).items():
            rid = pblk.get("router_id", "")
            if rid:
                default_rids[pid] = rid

        for vrf_name, vrf_block in vrf_dict.items():
            af_block = vrf_block.get("address_family", {})
            ipv4_block = af_block.get("ipv4", {})
            instances = ipv4_block.get("instance", {})

            for process_id, proc_block in instances.items():
                areas = proc_block.get("areas", {})

                for area_id, area_block in areas.items():
                    interfaces = area_block.get("interfaces", {})

                    for intf_name, intf_block in interfaces.items():
                        neighbors = intf_block.get("neighbors", {})

                        for neighbor_rid, nbr_block in neighbors.items():
                            # Resolve neighbor router-id to hostname
                            neighbor_hostname = rid_to_hostname.get(neighbor_rid)

                            # Fallback: router-id isn't a collected interface
                            # (e.g. FortiGate / uncollected loopback) — resolve by
                            # the neighbor's link interface address instead.
                            if neighbor_hostname is None:
                                nbr_addr = nbr_block.get("address", "")
                                if nbr_addr:
                                    neighbor_hostname = iface_ip_to_hostname.get(nbr_addr)

                            peer_collected = neighbor_hostname is not None

                            # Still unresolved → a genuinely external peer; use the
                            # router-id as its identity.
                            if neighbor_hostname is None:
                                neighbor_hostname = neighbor_rid

                            # Area type: Genie first, running_config fallback
                            genie_area_type = area_block.get("area_type")
                            proc_cfg = process_configs.get(hostname, {}).get(
                                (process_id, vrf_name), {}
                            )
                            rc_area_type = proc_cfg.get("area_types", {}).get(
                                _area_id_to_int(area_id)
                            )
                            # running_config distinguishes totally-* from plain;
                            # prefer it when Genie only says "stub"/"nssa"
                            if rc_area_type and rc_area_type.startswith("totally-"):
                                area_type = rc_area_type
                            else:
                                area_type = genie_area_type or rc_area_type or _default_area_type(area_id)

                            observations.append({
                                "reporting_device": hostname,
                                "neighbor_device": neighbor_hostname,
                                "vrf": vrf_name,
                                "area": area_id,
                                "process_id": process_id,
                                "interface": intf_name,
                                "neighbor_address": nbr_block.get("address", ""),
                                "state": nbr_block.get("state", "unknown"),
                                "peer_collected": peer_collected,
                                # Per-interface OSPF parameters
                                "cost": intf_block.get("cost"),
                                "hello_interval": intf_block.get("hello_interval"),
                                "dead_interval": intf_block.get("dead_interval"),
                                "network_type": intf_block.get("interface_type"),
                                "router_id": proc_block.get("router_id") or default_rids.get(process_id, ""),
                                # Process-level config
                                "area_type": area_type,
                                "passive_default": proc_cfg.get("passive_default", False),
                                "active_interfaces": proc_cfg.get("active_interfaces", []),
                                "vrf_lite": proc_cfg.get("capability_vrf_lite", False),
                                "redistribute": proc_cfg.get("redistribute", []),
                                "reference_bandwidth": proc_block.get("auto_cost", {}).get("reference_bandwidth"),
                            })

    logger.info("OSPF: %d raw neighbor observations collected", len(observations))

    if not observations:
        return []

    # Step 3: Dedup bilateral adjacencies.
    # Canonical key "devA:devB:vrf:area" (device names sorted). If both A→B and
    # B→A exist for the same VRF+area, they are bilateral.
    adjacency_groups: dict[str, list[dict[str, Any]]] = {}

    for obs in observations:
        dev_a, dev_b = sorted([obs["reporting_device"], obs["neighbor_device"]])
        key = f"{dev_a}:{dev_b}:{obs['vrf']}:{obs['area']}"

        if key not in adjacency_groups:
            adjacency_groups[key] = []
        adjacency_groups[key].append(obs)

    # Step 4: Build final adjacency entries.
    # "full" is the healthiest state, so if either side reports it we use it.
    _OSPF_STATE_PRIORITY = {"full": 0, "2way": 1, "init": 2, "down": 3, "unknown": 4}

    adjacencies: list[dict[str, Any]] = []

    for key, obs_list in adjacency_groups.items():
        dev_a, dev_b = sorted([obs_list[0]["reporting_device"],
                                obs_list[0]["neighbor_device"]])

        # Bilateral if observations from both devices
        reporting_devices = {obs["reporting_device"] for obs in obs_list}
        bilateral = len(reporting_devices) >= 2

        # Resolve interfaces and OSPF parameters for each side
        interface_a = None
        interface_b = None
        side_a: dict[str, Any] = {}
        side_b: dict[str, Any] = {}
        for obs in obs_list:
            if obs["reporting_device"] == dev_a:
                interface_a = obs["interface"]
                side_a = obs
            elif obs["reporting_device"] == dev_b:
                interface_b = obs["interface"]
                side_b = obs

        # Pick the best state (lowest priority number = healthiest)
        best_state = min(
            obs_list,
            key=lambda o: _OSPF_STATE_PRIORITY.get(o["state"], 99),
        )["state"]

        # Pick the best neighbor_address (prefer non-empty)
        neighbor_address = ""
        for obs in obs_list:
            if obs.get("neighbor_address"):
                neighbor_address = obs["neighbor_address"]
                break

        # Peer collected = True if at least one observation says so
        peer_collected = any(obs["peer_collected"] for obs in obs_list)

        adjacencies.append({
            "protocol": "ospf",
            "device_a": dev_a,
            "device_b": dev_b,
            "state": best_state,
            "process_id": obs_list[0]["process_id"],
            "area": obs_list[0]["area"],
            "vrf": obs_list[0]["vrf"],
            "interface_a": interface_a,
            "interface_b": interface_b,
            "neighbor_address": neighbor_address,
            "peer_collected": peer_collected,
            "bilateral": bilateral,
            # Per-side OSPF interface parameters
            "cost_a": side_a.get("cost"),
            "cost_b": side_b.get("cost"),
            "hello_a": side_a.get("hello_interval"),
            "hello_b": side_b.get("hello_interval"),
            "dead_a": side_a.get("dead_interval"),
            "dead_b": side_b.get("dead_interval"),
            "network_type_a": side_a.get("network_type"),
            "network_type_b": side_b.get("network_type"),
            # neighbor_address from side_a is B's IP (as seen by A), and vice versa
            "ip_a": side_b.get("neighbor_address", ""),
            "ip_b": side_a.get("neighbor_address", ""),
            "router_id_a": side_a.get("router_id", ""),
            "router_id_b": side_b.get("router_id", ""),
            # Process-level config
            "area_type": _best_area_type(
                side_a.get("area_type"), side_b.get("area_type")
            ),
            "passive_default_a": side_a.get("passive_default"),
            "passive_default_b": side_b.get("passive_default"),
            "active_interfaces_a": ",".join(side_a.get("active_interfaces", [])) or None,
            "active_interfaces_b": ",".join(side_b.get("active_interfaces", [])) or None,
            "vrf_lite_a": side_a.get("vrf_lite"),
            "vrf_lite_b": side_b.get("vrf_lite"),
            "redistribute_a": side_a.get("redistribute") or None,
            "redistribute_b": side_b.get("redistribute") or None,
            "reference_bandwidth_a": side_a.get("reference_bandwidth"),
            "reference_bandwidth_b": side_b.get("reference_bandwidth"),
        })

    # Sort for deterministic output
    adjacencies.sort(key=lambda a: (a["device_a"], a["device_b"], a["vrf"]))

    logger.info(
        "OSPF adjacencies: %d total (%d bilateral, %d unilateral)",
        len(adjacencies),
        sum(1 for a in adjacencies if a["bilateral"]),
        sum(1 for a in adjacencies if not a["bilateral"]),
    )

    return adjacencies


def _mask_to_cidr(ip: str, mask: str) -> str:
    """Convert IP + dotted-decimal mask to CIDR prefix.

    ``_mask_to_cidr("192.0.2.4", "255.255.255.252")`` → ``"192.0.2.4/30"``
    """
    try:
        import ipaddress
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net)
    except (ValueError, TypeError):
        return f"{ip}/{mask}"


def _extract_lsa_entries(
    lsa_types_block: dict[str, Any],
) -> list[dict[str, Any]]:
    """Parse LSA entries from a Genie ``database.lsa_types`` block.

    Returns list of flat dicts with: lsa_type, lsa_id, adv_router, prefix,
    metric, num_links (Type 1), fwd_addr (Type 5/7).
    """
    entries: list[dict[str, Any]] = []

    for lsa_type_str, type_block in lsa_types_block.items():
        try:
            lsa_type = int(lsa_type_str)
        except ValueError:
            continue

        lsas = type_block.get("lsas", {})
        for _key, lsa in lsas.items():
            header = lsa.get("ospfv2", {}).get("header", {})
            body = lsa.get("ospfv2", {}).get("body", {})
            lsa_id = header.get("lsa_id", lsa.get("lsa_id", ""))
            adv_router = header.get("adv_router", lsa.get("adv_router", ""))

            if lsa_type == 1:
                # Router LSA — topology graph node
                router_body = body.get("router", {})
                entries.append({
                    "lsa_type": 1,
                    "lsa_id": lsa_id,
                    "adv_router": adv_router,
                    "prefix": lsa_id,  # Router-ID
                    "metric": None,
                    "num_links": router_body.get("num_of_links", 0),
                })

            elif lsa_type == 3:
                # Summary LSA — inter-area prefix
                summary = body.get("summary", {})
                mask = summary.get("network_mask", "")
                metric = (summary.get("topologies", {})
                          .get("0", {}).get("metric"))
                prefix = _mask_to_cidr(lsa_id, mask) if mask else lsa_id
                entries.append({
                    "lsa_type": 3,
                    "lsa_id": lsa_id,
                    "adv_router": adv_router,
                    "prefix": prefix,
                    "metric": metric,
                })

            elif lsa_type in (5, 7):
                # External / NSSA External LSA
                ext = body.get("external", {})
                mask = ext.get("network_mask", "")
                topo = ext.get("topologies", {}).get("0", {})
                metric = topo.get("metric")
                fwd_addr = topo.get("forwarding_address", "")
                prefix = _mask_to_cidr(lsa_id, mask) if mask else lsa_id
                entry = {
                    "lsa_type": lsa_type,
                    "lsa_id": lsa_id,
                    "adv_router": adv_router,
                    "prefix": prefix,
                    "metric": metric,
                }
                if fwd_addr and fwd_addr != "0.0.0.0":
                    entry["fwd_addr"] = fwd_addr
                entries.append(entry)

    return entries


def extract_ospf_lsdb(
    facts_dirs: dict[str, Path],
) -> list[dict[str, Any]]:
    """Extract OSPF LSDB entries from genie_ospf.json files.

    Reads the ``default`` VRF LSDB (where Genie stores ``show ip ospf database``
    output regardless of actual VRF), then cross-references by process_id to
    determine the real VRF. For each (process_id, area_id), picks the device
    with the most LSAs as the authoritative source (typically the ABR).

    Args:
        facts_dirs: hostname → Path mapping.

    Returns:
        List of LSA dicts (area_id, vrf, process_id, lsa_type, lsa_id,
        adv_router, prefix, metric, ...).
    """
    # Step 1: process_id → actual VRF map from VRF-specific blocks
    pid_to_vrf: dict[str, str] = {}

    # Step 2: per (process_id, area_id) → {hostname: [lsa_entries]}
    area_lsdb: dict[tuple[str, str], dict[str, list[dict]]] = {}

    for hostname, facts_dir in facts_dirs.items():
        ospf_data = _load_json_file(facts_dir / "genie_ospf.json")
        if ospf_data is None:
            continue

        vrf_dict = ospf_data.get("vrf", ospf_data)

        # First pass: map process_id → VRF from non-default VRFs
        for vrf_name, vrf_block in vrf_dict.items():
            if vrf_name == "default":
                continue
            for pid in (vrf_block.get("address_family", {})
                        .get("ipv4", {}).get("instance", {})):
                pid_to_vrf[pid] = vrf_name

        # Second pass: extract LSDB from the "default" VRF (where Genie stores it)
        default_block = vrf_dict.get("default", {})
        for pid, proc_block in (default_block.get("address_family", {})
                                .get("ipv4", {}).get("instance", {}).items()):
            for area_id, area_block in proc_block.get("areas", {}).items():
                db = area_block.get("database", {}).get("lsa_types", {})
                if not db:
                    continue

                lsa_entries = _extract_lsa_entries(db)
                if lsa_entries:
                    key = (pid, area_id)
                    if key not in area_lsdb:
                        area_lsdb[key] = {}
                    area_lsdb[key][hostname] = lsa_entries

    # Step 3: For each (pid, area_id), pick the device with the most LSAs
    result: list[dict[str, Any]] = []
    for (pid, area_id), device_lsas in sorted(area_lsdb.items()):
        # Pick the device with the most complete view (ABR)
        best_host = max(device_lsas, key=lambda h: len(device_lsas[h]))
        vrf = pid_to_vrf.get(pid, "default")

        for entry in device_lsas[best_host]:
            entry["area_id"] = area_id
            entry["vrf"] = vrf
            entry["process_id"] = pid
            result.append(entry)

    logger.info(
        "OSPF LSDB: %d LSA entries across %d areas (from %d devices)",
        len(result),
        len(area_lsdb),
        len(facts_dirs),
    )
    return result


# =========================================================================
# BGP Adjacency Extraction
# =========================================================================

def _build_ip_to_hostname_lookup(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """
    Build an IP address → hostname lookup from all devices' interface data.

    Used to resolve BGP peer IPs to hostnames. Scans genie_interface.json
    (Cisco) and fortigate_system_interface.json (FortiGate). If the same IP
    appears on multiple devices (misconfiguration), the last one wins.

    Args:
        facts_dirs: hostname → Path mapping to each device's facts directory.
        facts_by_hostname: hostname → facts dict (FortiGate detection via
            facts.get("os", "")).

    Returns:
        Dictionary mapping IP address strings to hostnames.
    """
    ip_to_hostname: dict[str, str] = {}

    for hostname, facts_dir in facts_dirs.items():
        device_facts = facts_by_hostname.get(hostname, {})
        os_type = device_facts.get("os", "").lower()

        if os_type == "fortios":
            # FortiGate: "IP MASK" string per interface
            fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
            if fg_data and "results" in fg_data:
                for intf in fg_data["results"]:
                    ip_str = intf.get("ip", "")
                    if " " in ip_str:
                        ip_addr = ip_str.split()[0]
                        if ip_addr and ip_addr != "0.0.0.0":
                            ip_to_hostname[ip_addr] = hostname
        else:
            # Cisco: genie_interface.json → ipv4 → {"IP/PREFIX": {"ip": ...}}
            intf_data = _load_json_file(facts_dir / "genie_interface.json")
            if intf_data is None:
                continue

            for intf_name, intf_block in intf_data.items():
                ipv4_block = intf_block.get("ipv4", {})
                for prefix_key, ip_info in ipv4_block.items():
                    ip_addr = ip_info.get("ip", "")
                    if ip_addr and ip_addr != "0.0.0.0":
                        if ip_addr in ip_to_hostname and ip_to_hostname[ip_addr] != hostname:
                            logger.debug(
                                "IP %s collision: %s vs %s — keeping %s",
                                ip_addr,
                                ip_to_hostname[ip_addr],
                                hostname,
                                hostname,
                            )
                        ip_to_hostname[ip_addr] = hostname

    logger.info(
        "BGP IP→hostname lookup: %d IPs from %d devices",
        len(ip_to_hostname),
        len(set(ip_to_hostname.values())),
    )
    return ip_to_hostname


def _clean_bgp_description(desc: str | None) -> str | None:
    """Strip IOS XR ``** ... **`` markers from a BGP neighbor description."""
    if not desc:
        return desc
    desc = desc.strip()
    if desc.startswith("**") and desc.endswith("**"):
        desc = desc[2:-2].strip()
    return desc


def _extract_bgp_obs_enrichment(
    peer_block: dict[str, Any],
    peer_ip: str,
    bgp_neighbors_data: dict | None,
    rc_neighbors: dict[str, dict] | None,
) -> dict[str, Any]:
    """Extract per-observation enrichment fields from Genie + running config.

    ("obs"/"observation" here = one device's view of a peer, NOT a company.)
    Merges three sources:
      1. genie_bgp.json (summary or full learn) — operational state
      2. genie_bgp_neighbors.json (IOS XR only) — timer/capability detail
      3. running_config.txt (via bgp_config.py) — config-only fields
    """
    enrichment: dict[str, Any] = {}

    # --- From Genie BGP (summary or full learn) ---
    # Prefix count: XR summary uses state_pfxrcd in AF block; XE full uses prefixes.total_entries
    af_block = peer_block.get("address_family", {})
    pfx_received = None
    for af_data in af_block.values():
        if pfx_received is None:
            # XR summary format
            spfx = af_data.get("state_pfxrcd")
            if spfx is not None:
                try:
                    pfx_received = int(spfx)
                except (ValueError, TypeError):
                    pass
            # XE full learn format
            if pfx_received is None:
                pfx_info = af_data.get("prefixes", {})
                if "total_entries" in pfx_info:
                    pfx_received = pfx_info["total_entries"]

    enrichment["prefixes_received"] = pfx_received

    # Message counters: XR summary has them at AF level; XE full at neighbor level
    msg_sent = None
    msg_rcvd = None
    for af_data in af_block.values():
        if af_data.get("msg_sent") is not None:
            msg_sent = af_data["msg_sent"]
            msg_rcvd = af_data.get("msg_rcvd")
            break
    # XE/XR full learn has counters under bgp_neighbor_counters
    counters = peer_block.get("bgp_neighbor_counters", {}).get("messages", {})
    _BGP_MSG_TYPES = {"opens", "notifications", "updates", "keepalives", "route_refresh"}
    if counters and msg_sent is None:
        sent = counters.get("sent", {})
        rcvd = counters.get("received", {})
        # Sum only standard BGP message types (IOS XR adds non-message keys)
        msg_sent = sum(v for k, v in sent.items() if k in _BGP_MSG_TYPES and isinstance(v, (int, float))) if sent else None
        msg_rcvd = sum(v for k, v in rcvd.items() if k in _BGP_MSG_TYPES and isinstance(v, (int, float))) if rcvd else None

    enrichment["msg_sent"] = msg_sent
    enrichment["msg_rcvd"] = msg_rcvd

    # Uptime — AF-level (XR summary) or neighbor-level (XR/XE full learn)
    up_down = peer_block.get("up_time")
    if not up_down:
        for af_data in af_block.values():
            if "up_down" in af_data:
                up_down = af_data["up_down"]
                break
    # IOS XE fallback: last_reset in bgp_session_transport.connection
    if not up_down:
        session_transport = peer_block.get("bgp_session_transport", {})
        up_down = session_transport.get("connection", {}).get("last_reset")
    enrichment["up_down"] = up_down

    # Timers — negotiated sub-dict (XE) or direct neighbor keys (XR full learn)
    timers = peer_block.get("bgp_negotiated_keepalive_timers", {})
    enrichment["keepalive"] = (
        timers.get("keepalive_interval")
        or peer_block.get("keepalive_interval")
    )
    enrichment["hold_time"] = (
        timers.get("hold_time")
        or peer_block.get("holdtime")
    )

    # --- Merge from genie_bgp_neighbors.json (IOS XR neighbor detail) ---
    if bgp_neighbors_data:
        nbr_detail = None
        for inst_block in bgp_neighbors_data.get("instance", {}).values():
            for vrf_block in inst_block.get("vrf", {}).values():
                nbr_detail = vrf_block.get("neighbor", {}).get(peer_ip)
                if nbr_detail:
                    break
            if nbr_detail:
                break
        if nbr_detail:
            # Timers — sub-dict (XE) or direct keys (XR)
            if enrichment.get("keepalive") is None:
                ntimers = nbr_detail.get("bgp_negotiated_keepalive_timers", {})
                enrichment["keepalive"] = (
                    ntimers.get("keepalive_interval")
                    or nbr_detail.get("keepalive_interval")
                )
                enrichment["hold_time"] = (
                    ntimers.get("hold_time")
                    or nbr_detail.get("holdtime")
                )
            # Uptime
            if not enrichment.get("up_down"):
                enrichment["up_down"] = nbr_detail.get("up_time")
            # Session state (XR summary lacks this)
            if not enrichment.get("session_state"):
                enrichment["session_state"] = nbr_detail.get("session_state")
            # Counters
            if enrichment.get("msg_sent") is None:
                nc = nbr_detail.get("bgp_neighbor_counters", {}).get("messages", {})
                # IOS XR detail: messages dict at neighbor level (not in sub-dict)
                if not nc:
                    nc = nbr_detail.get("messages", {})
                if nc:
                    sent = nc.get("sent", {})
                    rcvd = nc.get("received", {})
                    enrichment["msg_sent"] = sum(
                        v for k, v in sent.items()
                        if k in _BGP_MSG_TYPES and isinstance(v, (int, float))
                    ) if sent else None
                    enrichment["msg_rcvd"] = sum(
                        v for k, v in rcvd.items()
                        if k in _BGP_MSG_TYPES and isinstance(v, (int, float))
                    ) if rcvd else None

    # --- From running config ---
    rc_nbr = (rc_neighbors or {}).get(peer_ip, {})
    enrichment["description"] = _clean_bgp_description(rc_nbr.get("description"))
    enrichment["route_policy_in"] = rc_nbr.get("route_policy_in")
    enrichment["route_policy_out"] = rc_nbr.get("route_policy_out")
    enrichment["bfd"] = rc_nbr.get("bfd", False)
    enrichment["graceful_restart"] = rc_nbr.get("graceful_restart", False)
    enrichment["password_configured"] = rc_nbr.get("password_configured", False)
    enrichment["maximum_prefix"] = rc_nbr.get("maximum_prefix")
    enrichment["update_source"] = rc_nbr.get("update_source")
    enrichment["send_community"] = rc_nbr.get("send_community", False)
    enrichment["next_hop_self"] = rc_nbr.get("next_hop_self", False)
    enrichment["soft_reconfiguration"] = rc_nbr.get("soft_reconfiguration", False)
    enrichment["route_reflector_client"] = rc_nbr.get("route_reflector_client", False)
    enrichment["allowas_in"] = rc_nbr.get("allowas_in", False)  # R1-BGP-2

    return enrichment


def extract_bgp_adjacencies(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Extract BGP peer adjacencies from genie_bgp.json files.

    Walks the Genie BGP Ops structure for every device:
        instance → default → vrf → <vrf_name> → neighbor → <peer_ip>

    Resolves each peer IP to a hostname via an IP lookup built from all
    devices' interface data. If the peer IP isn't in our inventory (e.g., an
    ISP transit peer), device_b is the raw IP string and peer_collected=False.

    Enriches each adjacency with bilateral per-side properties from Genie
    operational data, genie_bgp_neighbors.json (IOS XR detail), and
    running_config.txt (route policies, BFD, password, etc.).

    Args:
        facts_dirs: hostname → Path mapping to each device's facts directory.
        facts_by_hostname: hostname → facts dict (for IP lookup + FortiGate OS).

    Returns:
        List of adjacency dicts with bilateral ``_a/_b`` enrichment fields.
    """
    # Step 1: Build IP → hostname lookup for resolving BGP peer addresses
    ip_to_hostname = _build_ip_to_hostname_lookup(facts_dirs, facts_by_hostname)

    # Step 1b: Build per-hostname BGP config cache from running configs
    bgp_config_cache: dict[str, dict[str, Any]] = {}  # hostname → parsed config
    bgp_neighbors_cache: dict[str, dict] = {}  # hostname → genie_bgp_neighbors.json

    for hostname, facts_dir in facts_dirs.items():
        # Single source of truth: read the canonical bgp_config.json (written by
        # facts_builder via the same parse_bgp_process_config) instead of
        # re-parsing running_config.txt here. (R1 Phase 1.3 — removes the duplicate
        # re-parse and its silent except:pass; identical output by construction.)
        bc_cfg = _load_json_file(facts_dir / "bgp_config.json")
        if bc_cfg:
            bgp_config_cache[hostname] = bc_cfg

        # IOS XR neighbor detail (from enhanced collection)
        nbr_detail = _load_json_file(facts_dir / "genie_bgp_neighbors.json")
        if nbr_detail:
            bgp_neighbors_cache[hostname] = nbr_detail

    # Step 2: Collect raw one-directional BGP observations (with enrichment)
    observations: list[dict[str, Any]] = []

    for hostname, facts_dir in facts_dirs.items():
        bgp_data = _load_json_file(facts_dir / "genie_bgp.json")
        if bgp_data is None:
            continue

        rc_cfg = bgp_config_cache.get(hostname, {})
        rc_neighbors = rc_cfg.get("neighbors", {})
        nbr_detail_data = bgp_neighbors_cache.get(hostname)

        # Extract router-id from Genie data
        router_id = None
        instances = bgp_data.get("instance", {})
        for inst_name, inst_block in instances.items():
            local_as = inst_block.get("bgp_id")
            vrfs = inst_block.get("vrf", {})

            for vrf_name, vrf_block in vrfs.items():
                # Router ID: XE has it at vrf level, XR at address-family level
                if router_id is None:
                    router_id = vrf_block.get("router_id")
                if router_id is None:
                    for af_data in vrf_block.get("address_family", {}).values():
                        rid = af_data.get("router_id")
                        if rid:
                            router_id = rid
                            break

                # Also check running config for router-id
                if router_id is None:
                    router_id = rc_cfg.get("router_id")

                # Extract local_as from XR summary (at AF level)
                if local_as is None:
                    for af_data in vrf_block.get("address_family", {}).values():
                        la = af_data.get("local_as")
                        if la is not None:
                            local_as = la
                            break

                neighbors = vrf_block.get("neighbor", {})

                for peer_ip, peer_block in neighbors.items():
                    # Resolve peer IP to hostname
                    peer_hostname = ip_to_hostname.get(peer_ip)
                    peer_collected = peer_hostname is not None

                    # If unresolved, use the peer IP as device name
                    if peer_hostname is None:
                        peer_hostname = peer_ip

                    # Extract session state (normalize to lowercase)
                    raw_state = peer_block.get("session_state", "")
                    if not raw_state:
                        # IOS XR summary: infer from state_pfxrcd in AF block
                        for _af in peer_block.get("address_family", {}).values():
                            spfx = _af.get("state_pfxrcd", "")
                            if spfx:
                                try:
                                    int(spfx)
                                    raw_state = "established"
                                except (ValueError, TypeError):
                                    raw_state = spfx
                                break
                    state = (raw_state or "unknown").lower()

                    # Extract remote AS
                    remote_as = peer_block.get("remote_as")

                    # Extract address families from the neighbor level
                    af_block = peer_block.get("address_family", {})
                    address_families = sorted(af_block.keys()) if af_block else []

                    # Per-observation enrichment
                    enrich = _extract_bgp_obs_enrichment(
                        peer_block, peer_ip, nbr_detail_data, rc_neighbors,
                    )

                    # Override state from neighbors detail if summary lacked it
                    if state == "unknown" and enrich.get("session_state"):
                        state = enrich["session_state"].lower()
                    enrich.pop("session_state", None)

                    observations.append({
                        "reporting_device": hostname,
                        "peer_device": peer_hostname,
                        "peer_ip": peer_ip,
                        "vrf": vrf_name,
                        "local_as": local_as,
                        "remote_as": remote_as,
                        "state": state,
                        "address_families": address_families,
                        "peer_collected": peer_collected,
                        "router_id": router_id,
                        **enrich,
                    })

    logger.info("BGP: %d raw peer observations collected", len(observations))

    if not observations:
        return []

    # Step 3: Dedup bilateral adjacencies
    adjacency_groups: dict[str, list[dict[str, Any]]] = {}

    for obs in observations:
        dev_a, dev_b = sorted([obs["reporting_device"], obs["peer_device"]])
        key = f"{dev_a}:{dev_b}:{obs['vrf']}"

        if key not in adjacency_groups:
            adjacency_groups[key] = []
        adjacency_groups[key].append(obs)

    # Step 4: Build final adjacency entries with bilateral enrichment
    _BGP_STATE_PRIORITY = {
        "established": 0,
        "openconfirm": 1,
        "opensent": 2,
        "active": 3,
        "connect": 4,
        "idle": 5,
        "unknown": 6,
    }

    # Bilateral enrichment field names (stored as _a/_b per side)
    _BILATERAL_FIELDS = [
        "router_id", "description", "prefixes_received",
        "msg_sent", "msg_rcvd", "up_down",
        "keepalive", "hold_time",
        "route_policy_in", "route_policy_out",
        "bfd", "graceful_restart", "password_configured",
        "maximum_prefix", "update_source", "send_community",
        "next_hop_self", "soft_reconfiguration",
        "route_reflector_client", "allowas_in",  # R1-BGP-2
    ]

    adjacencies: list[dict[str, Any]] = []

    for key, obs_list in adjacency_groups.items():
        dev_a, dev_b = sorted([obs_list[0]["reporting_device"],
                                obs_list[0]["peer_device"]])

        # Check if bilateral
        reporting_devices = {obs["reporting_device"] for obs in obs_list}
        bilateral = len(reporting_devices) >= 2

        # Pick the best state
        best_state = min(
            obs_list,
            key=lambda o: _BGP_STATE_PRIORITY.get(o["state"], 99),
        )["state"]

        # Merge address families from all observations
        all_afs: set[str] = set()
        for obs in obs_list:
            all_afs.update(obs.get("address_families", []))

        # AS numbers from device_a's perspective
        local_as = None
        remote_as = None
        for obs in obs_list:
            if obs["reporting_device"] == dev_a:
                local_as = obs["local_as"]
                remote_as = obs["remote_as"]
                break
        if local_as is None:
            for obs in obs_list:
                if obs["reporting_device"] == dev_b:
                    local_as = obs["remote_as"]
                    remote_as = obs["local_as"]
                    break

        peer_collected = any(obs["peer_collected"] for obs in obs_list)

        # Session type
        session_type = "ibgp" if local_as == remote_as else "ebgp"

        # Build bilateral enrichment (_a from dev_a's observation, _b from dev_b's)
        obs_a = next((o for o in obs_list if o["reporting_device"] == dev_a), None)
        obs_b = next((o for o in obs_list if o["reporting_device"] == dev_b), None)

        bilateral_props: dict[str, Any] = {}
        for field in _BILATERAL_FIELDS:
            bilateral_props[f"{field}_a"] = obs_a.get(field) if obs_a else None
            bilateral_props[f"{field}_b"] = obs_b.get(field) if obs_b else None

        # Peer label for external peers (eBGP with uncollected peer).
        # The external peer is whichever side is NOT collected; its AS is the
        # remote_as from the collected device's perspective.
        peer_label = None
        if session_type == "ebgp" and not peer_collected:
            if obs_b and not obs_a:
                ext_as = obs_b.get("remote_as")
            elif obs_a and not obs_b:
                ext_as = obs_a.get("remote_as")
            else:
                ext_as = remote_as
            desc = bilateral_props.get("description_b") or bilateral_props.get("description_a")
            if desc and ext_as:
                peer_label = f"AS {ext_as} ({desc})"
            elif ext_as:
                peer_label = f"AS {ext_as}"

        # Network statements from running config
        rc_a = bgp_config_cache.get(dev_a, {})
        rc_b = bgp_config_cache.get(dev_b, {})
        net_stmts_a = rc_a.get("network_statements", [])
        net_stmts_b = rc_b.get("network_statements", [])

        # Route-reflector: a side that configured the other as route-reflector-client
        # is the reflector for this iBGP session; the other side is its client.
        rrc_a = bool(bilateral_props.get("route_reflector_client_a"))
        rrc_b = bool(bilateral_props.get("route_reflector_client_b"))
        rr_client = rrc_a or rrc_b
        rr_reflector = dev_a if rrc_a else (dev_b if rrc_b else None)

        adjacencies.append({
            "protocol": "bgp",
            "device_a": dev_a,
            "device_b": dev_b,
            "state": best_state,
            "local_as": local_as,
            "remote_as": remote_as,
            "vrf": obs_list[0]["vrf"],
            "address_families": sorted(all_afs),
            "peer_collected": peer_collected,
            "bilateral": bilateral,
            "session_type": session_type,
            "peer_label": peer_label,
            "network_statements_a": net_stmts_a,
            "network_statements_b": net_stmts_b,
            "rr_client": rr_client,
            "rr_reflector": rr_reflector,
            **bilateral_props,
        })

    # Sort for deterministic output
    adjacencies.sort(key=lambda a: (a["device_a"], a["device_b"], a["vrf"]))

    # Count iBGP vs eBGP for logging
    ibgp_count = sum(1 for a in adjacencies if a.get("session_type") == "ibgp")
    ebgp_count = len(adjacencies) - ibgp_count

    logger.info(
        "BGP adjacencies: %d total (%d bilateral, %d unilateral, "
        "%d iBGP, %d eBGP)",
        len(adjacencies),
        sum(1 for a in adjacencies if a["bilateral"]),
        sum(1 for a in adjacencies if not a["bilateral"]),
        ibgp_count,
        ebgp_count,
    )

    return adjacencies


# =========================================================================
# Shared Services Discovery
# =========================================================================

def _discover_shared_vlans(
    facts_dirs: dict[str, Path],
) -> list[dict[str, Any]]:
    """
    Discover VLANs shared across 2+ devices.

    Reads genie_vlan.json from each device and groups VLANs by ID. Only VLANs
    on 2+ devices are returned. Default infrastructure VLANs (1, 1002–1005) are
    excluded (they appear on every switch by default). FortiGate VLAN interfaces
    (from fortigate_system_interface.json type="vlan") are also included, and a
    subnet-membership pass adds devices whose interface IP is in a VLAN's subnet.

    Returns:
        List of shared VLAN dicts: {service_type:"vlan", identifier, name, members}.
    """
    # Default VLANs to exclude — appear on every switch, not meaningful as shared
    _DEFAULT_VLANS = {"1", "1002", "1003", "1004", "1005"}

    # vlan_id → {name: str|None, devices: set[str]}
    vlan_index: dict[str, dict[str, Any]] = {}

    for hostname, facts_dir in facts_dirs.items():
        vlan_data = _load_json_file(facts_dir / "genie_vlan.json")
        if vlan_data is None:
            continue

        # Genie wraps VLANs under a top-level "vlans" key
        vlans_dict = vlan_data.get("vlans", vlan_data)

        for vlan_id_str, vlan_block in vlans_dict.items():
            # Skip default infrastructure VLANs
            if vlan_id_str in _DEFAULT_VLANS:
                continue

            # Skip inactive/unsupported VLANs
            state = vlan_block.get("state", "")
            if state == "unsupport":
                continue

            if vlan_id_str not in vlan_index:
                vlan_index[vlan_id_str] = {
                    "name": vlan_block.get("name"),
                    "devices": set(),
                }

            vlan_index[vlan_id_str]["devices"].add(hostname)

            # Prefer a real name over a default "VLANxxxx" name
            current_name = vlan_index[vlan_id_str]["name"]
            candidate_name = vlan_block.get("name", "")
            if candidate_name and (
                not current_name
                or current_name.startswith("VLAN")
            ):
                vlan_index[vlan_id_str]["name"] = candidate_name

    # Include FortiGate VLAN interfaces (REST API, no genie_vlan.json)
    for hostname, facts_dir in facts_dirs.items():
        fg_intf = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if fg_intf is None:
            continue

        for intf in fg_intf.get("results", []):
            if intf.get("type") != "vlan":
                continue
            vlanid = intf.get("vlanid", 0)
            if not vlanid or vlanid <= 0:
                continue

            vlan_id_str = str(vlanid)
            if vlan_id_str in _DEFAULT_VLANS:
                continue

            if vlan_id_str not in vlan_index:
                vlan_index[vlan_id_str] = {
                    "name": None,
                    "devices": set(),
                }

            vlan_index[vlan_id_str]["devices"].add(hostname)

            # Use interface description/alias as the VLAN name if available
            desc = intf.get("description", "") or intf.get("alias", "")
            if desc:
                current_name = vlan_index[vlan_id_str]["name"]
                if not current_name or current_name.startswith("VLAN"):
                    vlan_index[vlan_id_str]["name"] = desc

    # Subnet-based VLAN membership enrichment: devices connected to a VLAN via
    # management ports don't have the VLAN locally, but their IP is in its subnet.
    import ipaddress as _ipaddress

    # Step 1: Build VLAN → subnet map from SVI/VLAN interfaces with IPs
    vlan_subnets: dict[str, _ipaddress.IPv4Network] = {}
    for hostname, facts_dir in facts_dirs.items():
        # Cisco: Genie interfaces with Vlan<N> naming
        intf_data = _load_json_file(facts_dir / "genie_interface.json")
        if intf_data:
            for intf_name, intf_info in intf_data.items():
                if not (intf_name.startswith("Vlan") or intf_name.startswith("Vl")):
                    continue
                vlan_num = intf_name.replace("Vlan", "").replace("Vl", "")
                if not vlan_num.isdigit():
                    continue
                ipv4 = intf_info.get("ipv4", {})
                for ip_cidr, ip_info in ipv4.items():
                    if "/" in ip_cidr:
                        try:
                            net = _ipaddress.ip_network(ip_cidr, strict=False)
                            if vlan_num not in vlan_subnets:
                                vlan_subnets[vlan_num] = net
                        except ValueError:
                            pass

        # FortiGate: interfaces with vlanid and IP
        fg_intf = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if fg_intf:
            for intf in fg_intf.get("results", []):
                if intf.get("type") != "vlan":
                    continue
                vlanid = intf.get("vlanid", 0)
                if not vlanid:
                    continue
                ip_list = intf.get("ip", [])
                if isinstance(ip_list, list) and len(ip_list) >= 2:
                    ip_addr = ip_list[0]
                    mask = ip_list[1]
                    if ip_addr and ip_addr != "0.0.0.0" and mask:
                        try:
                            net = _ipaddress.ip_network(f"{ip_addr}/{mask}", strict=False)
                            vlan_str = str(vlanid)
                            if vlan_str not in vlan_subnets:
                                vlan_subnets[vlan_str] = net
                        except ValueError:
                            pass

    # Step 2: Build device → all IPs map (for fast lookup)
    device_ips: dict[str, list[_ipaddress.IPv4Address]] = {}
    for hostname, facts_dir in facts_dirs.items():
        intf_data = _load_json_file(facts_dir / "genie_interface.json")
        if intf_data:
            for intf_name, intf_info in intf_data.items():
                for ip_cidr in intf_info.get("ipv4", {}).keys():
                    ip_str = ip_cidr.split("/")[0]
                    try:
                        device_ips.setdefault(hostname, []).append(
                            _ipaddress.ip_address(ip_str)
                        )
                    except ValueError:
                        pass
        # FortiGate IPs
        fg_intf = _load_json_file(facts_dir / "fortigate_system_interface.json")
        if fg_intf:
            for intf in fg_intf.get("results", []):
                ip_list = intf.get("ip", [])
                if isinstance(ip_list, list) and len(ip_list) >= 1:
                    ip_str = ip_list[0]
                    if ip_str and ip_str != "0.0.0.0":
                        try:
                            device_ips.setdefault(hostname, []).append(
                                _ipaddress.ip_address(ip_str)
                            )
                        except ValueError:
                            pass

    # Step 3: For each VLAN with a known subnet, add devices with IPs in it
    for vlan_id_str, subnet in vlan_subnets.items():
        if vlan_id_str in _DEFAULT_VLANS:
            continue
        for hostname, ips in device_ips.items():
            for ip in ips:
                if ip in subnet:
                    if vlan_id_str not in vlan_index:
                        vlan_index[vlan_id_str] = {"name": None, "devices": set()}
                    vlan_index[vlan_id_str]["devices"].add(hostname)
                    break  # One match per device is enough

    # Filter to VLANs present on 2+ devices
    shared_vlans: list[dict[str, Any]] = []
    for vlan_id_str, info in sorted(vlan_index.items(), key=lambda x: int(x[0])):
        if len(info["devices"]) >= 2:
            shared_vlans.append({
                "service_type": "vlan",
                "identifier": vlan_id_str,
                "name": info["name"],
                "members": sorted(info["devices"]),
            })

    logger.info(
        "Shared VLANs: %d (from %d total VLANs across devices)",
        len(shared_vlans),
        len(vlan_index),
    )
    return shared_vlans


def _discover_shared_subnets(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Discover IP subnets shared across 2+ devices.

    Reads genie_interface.json (Cisco) and fortigate_system_interface.json
    (FortiGate), computes each interface's network address, and groups by subnet.
    Only subnets with 2+ devices are returned. VRF is included to distinguish
    the same subnet in different VRFs (e.g. 192.0.2.0/24 in "default" vs
    "TENANT-VRF").

    Returns:
        List of shared subnet dicts: {service_type:"subnet", identifier, vrf,
        members:[{hostname, interface, ip}]}.
    """
    from ipaddress import ip_interface

    # subnet_str → {vrf: str, members: [{hostname, interface, ip}, ...]}
    subnet_index: dict[str, dict[str, Any]] = {}

    for hostname, facts_dir in facts_dirs.items():
        device_facts = facts_by_hostname.get(hostname, {})
        os_type = device_facts.get("os", "").lower()

        if os_type == "fortios":
            fg_data = _load_json_file(facts_dir / "fortigate_system_interface.json")
            if fg_data and "results" in fg_data:
                for intf in fg_data["results"]:
                    ip_str = intf.get("ip", "")
                    if " " not in ip_str:
                        continue
                    ip_parsed = _parse_fortigate_ip(ip_str)
                    if ip_parsed is None:
                        continue
                    try:
                        net = ip_interface(
                            f"{ip_parsed[0]}/{ip_parsed[1]}"
                        ).network
                        subnet_str = str(net)
                    except (ValueError, TypeError):
                        continue

                    intf_name = intf.get("name", "unknown")
                    vdom = intf.get("vdom", "root")
                    vrf = "default" if vdom == "root" else vdom

                    if subnet_str not in subnet_index:
                        subnet_index[subnet_str] = {"vrf": vrf, "members": []}
                    subnet_index[subnet_str]["members"].append({
                        "hostname": hostname,
                        "interface": intf_name,
                        "ip": ip_parsed[0],
                    })
        else:
            intf_data = _load_json_file(facts_dir / "genie_interface.json")
            if intf_data is None:
                continue

            for intf_name, intf_block in intf_data.items():
                vrf = intf_block.get("vrf", "default")
                ipv4_block = intf_block.get("ipv4", {})
                for prefix_key, ip_info in ipv4_block.items():
                    ip_addr = ip_info.get("ip", "")
                    prefix_len = ip_info.get("prefix_length", "")
                    if not ip_addr or ip_addr == "0.0.0.0" or not prefix_len:
                        continue

                    try:
                        net = ip_interface(f"{ip_addr}/{prefix_len}").network
                        subnet_str = str(net)
                    except (ValueError, TypeError):
                        continue

                    if subnet_str not in subnet_index:
                        subnet_index[subnet_str] = {"vrf": vrf, "members": []}
                    subnet_index[subnet_str]["members"].append({
                        "hostname": hostname,
                        "interface": intf_name,
                        "ip": ip_addr,
                    })

    # Filter to subnets with 2+ distinct devices
    shared_subnets: list[dict[str, Any]] = []
    for subnet_str, info in sorted(subnet_index.items()):
        unique_hosts = {m["hostname"] for m in info["members"]}
        if len(unique_hosts) >= 2:
            shared_subnets.append({
                "service_type": "subnet",
                "identifier": subnet_str,
                "vrf": info["vrf"],
                "members": sorted(info["members"], key=lambda m: m["hostname"]),
            })

    logger.info(
        "Shared subnets: %d (from %d total subnets across devices)",
        len(shared_subnets),
        len(subnet_index),
    )
    return shared_subnets


def _discover_shared_ospf_areas(
    facts_dirs: dict[str, Path],
) -> list[dict[str, Any]]:
    """
    Discover OSPF areas shared across 2+ devices.

    Reads genie_ospf.json from each device and groups by (VRF, area_id). Only
    areas with 2+ devices are returned. Area type is resolved (Genie >
    running_config > default).

    Returns:
        List of shared OSPF area dicts: {service_type:"ospf_area", identifier,
        vrf, process_id, members, area_type, spf_runs, lsa_count}.
    """
    # (vrf, area_id) → {process_id, devices, area_type, spf_runs, lsa_count}
    area_index: dict[tuple[str, str], dict[str, Any]] = {}

    # Build running_config process configs for area_type resolution
    rc_configs: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
    for hostname, facts_dir in facts_dirs.items():
        cfg_path = facts_dir / "running_config.txt"
        if cfg_path.exists():
            try:
                rc_configs[hostname] = parse_ospf_process_configs(
                    cfg_path.read_text(errors="replace")
                )
            except OSError:
                pass

    for hostname, facts_dir in facts_dirs.items():
        ospf_data = _load_json_file(facts_dir / "genie_ospf.json")
        if ospf_data is None:
            continue

        # Unwrap top-level "vrf" key (Genie Ops wrapper)
        vrf_dict = ospf_data.get("vrf", ospf_data)

        # Genie quirk: it copies every OSPF process under the "default" VRF
        # block regardless of the process's real VRF (the real RED/BLUE blocks
        # carry the same process with rid=None). A process that appears in any
        # non-default block belongs to that VRF — its "default" copy is the
        # quirk and must NOT make the device a member of the default-VRF area.
        # Collect the real non-default process ids so we can drop those copies.
        non_default_procs: set[str] = set()
        for vname, vblk in vrf_dict.items():
            if vname == "default":
                continue
            non_default_procs.update(
                vblk.get("address_family", {}).get("ipv4", {}).get("instance", {}).keys()
            )

        # Pre-collect area_type + stats from "default" VRF
        default_area_meta: dict[tuple[str, str], dict] = {}
        default_block = vrf_dict.get("default", {})
        for pid, pblk in default_block.get("address_family", {}).get(
            "ipv4", {}
        ).get("instance", {}).items():
            for aid, ablk in pblk.get("areas", {}).items():
                astats = ablk.get("statistics", {})
                default_area_meta[(pid, aid)] = {
                    "area_type": ablk.get("area_type"),
                    "spf_runs": astats.get("spf_runs_count"),
                    "lsa_count": astats.get("area_scope_lsa_count"),
                }

        for vrf_name, vrf_block in vrf_dict.items():
            af_block = vrf_block.get("address_family", {})
            ipv4_block = af_block.get("ipv4", {})
            instances = ipv4_block.get("instance", {})

            for process_id, proc_block in instances.items():
                # Drop the genie "default"-block copy of a process that really
                # lives in another VRF (the quirk) — the real block keys it.
                if vrf_name == "default" and process_id in non_default_procs:
                    continue
                areas = proc_block.get("areas", {})

                for area_id, area_block in areas.items():
                    key = (vrf_name, area_id)
                    if key not in area_index:
                        # Resolve area_type: Genie > running_config > default
                        genie_at = area_block.get("area_type")
                        dm = default_area_meta.get((process_id, area_id), {})
                        if not genie_at:
                            genie_at = dm.get("area_type")
                        rc_cfg = rc_configs.get(hostname, {}).get(
                            (process_id, vrf_name), {}
                        )
                        rc_at = rc_cfg.get("area_types", {}).get(
                            _area_id_to_int(area_id)
                        )
                        if rc_at and rc_at.startswith("totally-"):
                            area_type = rc_at
                        else:
                            area_type = genie_at or rc_at or _default_area_type(area_id)

                        astats = area_block.get("statistics", {})
                        area_index[key] = {
                            "process_id": process_id,
                            "devices": set(),
                            "area_type": area_type,
                            "spf_runs": astats.get("spf_runs_count") or dm.get("spf_runs"),
                            "lsa_count": astats.get("area_scope_lsa_count") or dm.get("lsa_count"),
                        }
                    area_index[key]["devices"].add(hostname)

    # Filter to areas with 2+ devices
    shared_areas: list[dict[str, Any]] = []
    for (vrf_name, area_id), info in sorted(area_index.items()):
        if len(info["devices"]) >= 2:
            shared_areas.append({
                "service_type": "ospf_area",
                "identifier": area_id,
                "vrf": vrf_name,
                "process_id": info["process_id"],
                "members": sorted(info["devices"]),
                "area_type": info.get("area_type"),
                "spf_runs": info.get("spf_runs"),
                "lsa_count": info.get("lsa_count"),
            })

    logger.info(
        "Shared OSPF areas: %d (from %d total areas across devices)",
        len(shared_areas),
        len(area_index),
    )
    return shared_areas


def _discover_shared_bgp_asns(
    facts_dirs: dict[str, Path],
) -> list[dict[str, Any]]:
    """
    Discover BGP AS numbers used by 2+ devices.

    Reads genie_bgp.json from each device and groups by local AS number
    (bgp_id). Only AS numbers with 2+ devices are returned.

    Returns:
        List of shared BGP AS dicts: {service_type:"bgp_asn", identifier, members}.
    """
    # as_number → set[hostname]
    asn_index: dict[int, set[str]] = {}

    for hostname, facts_dir in facts_dirs.items():
        bgp_data = _load_json_file(facts_dir / "genie_bgp.json")
        if bgp_data is None:
            continue

        instances = bgp_data.get("instance", {})
        for inst_name, inst_block in instances.items():
            bgp_id = inst_block.get("bgp_id")
            if bgp_id is not None:
                if bgp_id not in asn_index:
                    asn_index[bgp_id] = set()
                asn_index[bgp_id].add(hostname)

    # Filter to ASNs with 2+ devices
    shared_asns: list[dict[str, Any]] = []
    for asn, devices in sorted(asn_index.items()):
        if len(devices) >= 2:
            shared_asns.append({
                "service_type": "bgp_asn",
                "identifier": str(asn),
                "members": sorted(devices),
            })

    logger.info(
        "Shared BGP ASNs: %d (from %d total ASNs across devices)",
        len(shared_asns),
        len(asn_index),
    )
    return shared_asns


def discover_shared_services(
    facts_dirs: dict[str, Path],
    facts_by_hostname: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Discover all shared network services across devices.

    Aggregates 4 types of shared service: VLANs (same ID on 2+ switches),
    subnets (same IP subnet on 2+ devices), OSPF areas (same area on 2+
    routers), and BGP ASNs (same AS on 2+ devices). Each type is discovered
    independently and combined into one list.

    Args:
        facts_dirs: hostname → Path mapping to each device's facts directory.
        facts_by_hostname: hostname → facts dict (for FortiGate detection).

    Returns:
        List of shared service dicts (service_type, identifier, members + type-
        specific fields).
    """
    services: list[dict[str, Any]] = []

    services.extend(_discover_shared_vlans(facts_dirs))
    services.extend(_discover_shared_subnets(facts_dirs, facts_by_hostname))
    services.extend(_discover_shared_ospf_areas(facts_dirs))
    services.extend(_discover_shared_bgp_asns(facts_dirs))

    logger.info(
        "Shared services: %d total (vlan=%d, subnet=%d, ospf_area=%d, bgp_asn=%d)",
        len(services),
        sum(1 for s in services if s["service_type"] == "vlan"),
        sum(1 for s in services if s["service_type"] == "subnet"),
        sum(1 for s in services if s["service_type"] == "ospf_area"),
        sum(1 for s in services if s["service_type"] == "bgp_asn"),
    )

    return services
