"""
Interface type classifier for network model building.

This module classifies network interface names into categories
based on naming patterns. Classification enables:
- Link type analysis (physical vs logical connections)
- Topology filtering (show only physical uplinks)
- Operational queries (find all management interfaces)

Interface Categories:
    physical   - Physical ports (GigabitEthernet, HundredGigE, etc.)
    logical    - Virtual interfaces (Loopback, Tunnel, BDI/BVI)
    vlan       - VLAN interfaces (Vlan1, Vlan100)
    management - Management ports (MgmtEth, GigabitEthernet0/0)
    aggregated - LAG/Port-channel (Port-channel, Bundle-Ether)
    unknown    - Unrecognized patterns (logged as warning)

Design Principles:
    - Deterministic: Same name always produces same type
    - Pattern-based: Uses prefix matching, not inference
    - Explicit: Unknown patterns = "unknown" (never guessed)

Classification Strategy:
    We use startswith() pattern matching rather than regex because:
    1. Easier to read and maintain
    2. Faster execution for simple prefix checks
    3. Order of checks determines priority
    4. Explicit matches are clearer than regex groups
"""

from typing import Literal

# -------------------------------------------------------------------------
# Helper — tight 2-letter prefix matching
# -------------------------------------------------------------------------
# Several abbreviations from CDP/LLDP are 2 letters (Po, Lo, Vl, BE).
# A bare `name.startswith("Po")` matches "Pop3Manager" — too greedy.
# This helper requires the prefix to be followed immediately by a digit,
# matching real interface names (Po1, Lo0, Vl100, BE1) without false positives.
def _starts_with_abbrev(name: str, prefix: str) -> bool:
    """Return True if name starts with prefix AND the next char is a digit."""
    return name.startswith(prefix) and len(name) > len(prefix) and name[len(prefix)].isdigit()


# -------------------------------------------------------------------------
# Type Definition
# -------------------------------------------------------------------------
# Literal type restricts values to the exact strings listed.
# This gives us compile-time checking and better IDE support.
InterfaceType = Literal[
    "physical",
    "logical",
    "vlan",
    "management",
    "aggregated",
    "unknown",
]


def classify_interface(name: str, os_family: str) -> InterfaceType:
    """
    Classify an interface into a category based on its name.

    Uses prefix pattern matching to determine interface type.
    The classification is deterministic.

    Pattern Matching Strategy:
        1. Check management patterns FIRST (most specific)
        2. Check aggregated patterns (specific naming)
        3. Check vlan patterns
        4. Check logical patterns
        5. Check physical patterns (most common, but last)
        6. Default to "unknown" if nothing matches

    Why This Order?
        - "GigabitEthernet0/0" could match physical (Gi*), but on IOS XE
          it's typically the management port - so we check mgmt first
        - More specific patterns must come before general ones

    Args:
        name: Interface name (e.g., "GigabitEthernet0/0", "Vlan100")
        os_family: OS family ("iosxe" or "iosxr") for OS-specific rules

    Returns:
        Interface type: "physical", "logical", "vlan", "management",
        "aggregated", or "unknown"

    Examples:
        >>> classify_interface("GigabitEthernet0/0", "iosxe")
        'management'  # Special case: Gi0/0 on IOS XE is typically mgmt
        >>> classify_interface("HundredGigE1/0/1", "iosxe")
        'physical'
        >>> classify_interface("Vlan100", "iosxe")
        'vlan'
        >>> classify_interface("Bundle-Ether1", "iosxr")
        'aggregated'
    """
    # -------------------------------------------------------------------------
    # Handle edge cases — actually normalise
    # -------------------------------------------------------------------------
    # Empty / None / whitespace-only names: return unknown.
    # Leading/trailing whitespace: strip so " Po1" classifies the same as "Po1".
    name = name.strip() if name else ""
    if not name:
        return "unknown"

    # -------------------------------------------------------------------------
    # Dispatch to OS-specific classifier
    # -------------------------------------------------------------------------
    # Each OS has different interface naming conventions
    # IOS XE: GigabitEthernet, Port-channel, BDI
    # IOS XR: GigabitEthernet, Bundle-Ether, BVI, MgmtEth
    if os_family == "iosxe":
        return _classify_iosxe(name)
    elif os_family == "iosxr":
        return _classify_iosxr(name)
    else:
        # Unknown OS - try generic classification
        return _classify_generic(name)


def _classify_iosxe(name: str) -> InterfaceType:
    """
    Classify interface name using IOS XE patterns.

    IOS XE Interface Patterns:
        Management: Mgmt*, GigabitEthernet0/0 (special case)
        Aggregated: Port-channel*, Po* (abbreviated)
        Logical: Loopback*, Lo*, Tunnel*, Tu*, BDI*
        VLAN: Vlan*, Vl* (abbreviated)
        Physical: Gi*, Te*, Hu*, Fo*, Tw*, Fa*, Et* (and full names)

    Args:
        name: Interface name to classify

    Returns:
        Classified interface type
    """
    # -------------------------------------------------------------------------
    # MANAGEMENT - Check first (most specific)
    # -------------------------------------------------------------------------
    # Why check first? "GigabitEthernet0/0" would match physical patterns,
    # but it's specifically the management port on many Cisco devices.
    # We want the more specific classification to win.
    if name.startswith("Mgmt") or name.startswith("mgmt"):
        return "management"

    # GigabitEthernet0/0 is special - typically management on IOS XE
    # We check exact match, not just "starts with Gi0/0"
    if name == "GigabitEthernet0/0" or name == "Gi0/0":
        return "management"

    # -------------------------------------------------------------------------
    # AGGREGATED - Port-channels
    # -------------------------------------------------------------------------
    # Port-channel for LAG (Link Aggregation Group)
    # Po<digit> is the common abbreviation (Po1, Po10) — must require digit
    # suffix or "PolicyMap" / "Pop3Manager" would falsely match.
    if name.startswith("Port-channel") or _starts_with_abbrev(name, "Po"):
        return "aggregated"

    # -------------------------------------------------------------------------
    # LOGICAL - Virtual interfaces
    # -------------------------------------------------------------------------
    # Loopback: Used for router ID, management, always-up endpoint
    # Lo<digit> abbreviation must require digit suffix (else "LongHaul" matches).
    if name.startswith("Loopback") or _starts_with_abbrev(name, "Lo"):
        return "logical"

    # Tunnel: GRE, IPsec, MPLS TE tunnels
    # Tu<digit> abbreviation must require digit suffix.
    if name.startswith("Tunnel") or _starts_with_abbrev(name, "Tu"):
        return "logical"

    # BDI: Bridge Domain Interface (used in EVPN/VXLAN fabrics)
    if name.startswith("BDI"):
        return "logical"

    # -------------------------------------------------------------------------
    # VLAN - VLAN interfaces (SVI)
    # -------------------------------------------------------------------------
    # Vlan interfaces are the L3 gateway for VLANs
    # Vl<digit> abbreviation must require digit suffix (else "VlsmCalculator" matches).
    if name.startswith("Vlan") or _starts_with_abbrev(name, "Vl"):
        return "vlan"

    # -------------------------------------------------------------------------
    # PHYSICAL - Hardware interfaces
    # -------------------------------------------------------------------------
    # We check these last because they're the most general patterns
    # Order doesn't matter within this section since they're all physical
    physical_prefixes = (
        # Full names
        "GigabitEthernet",
        "TenGigabitEthernet",
        "TenGigE",
        "HundredGigE",
        "FortyGigE",
        "TwentyFiveGigE",
        "FastEthernet",
        "Ethernet",
        # Common abbreviations (CDP often uses these)
        "Gi",
        "Te",
        "Hu",
        "Hun",
        "Fo",
        "Tw",
        "Fa",
        "Et",
    )

    # Using startswith with a tuple checks all prefixes efficiently
    # This is a Python idiom: str.startswith(tuple) returns True if
    # the string starts with ANY of the tuple elements
    if name.startswith(physical_prefixes):
        return "physical"

    # -------------------------------------------------------------------------
    # UNKNOWN - Nothing matched
    # -------------------------------------------------------------------------
    # We explicitly return "unknown" rather than guessing
    # The model builder will log a warning for unknown interfaces
    return "unknown"


def _classify_iosxr(name: str) -> InterfaceType:
    """
    Classify interface name using IOS XR patterns.

    IOS XR Differences from IOS XE:
        - MgmtEth instead of Mgmt for management
        - Bundle-Ether instead of Port-channel for LAG
        - BVI instead of BDI for bridge virtual interface
        - tunnel-te/tunnel-ip instead of just Tunnel
        - Different slot/port numbering (0/0/0/0 format)

    Args:
        name: Interface name to classify

    Returns:
        Classified interface type
    """
    # -------------------------------------------------------------------------
    # MANAGEMENT
    # -------------------------------------------------------------------------
    # IOS XR uses MgmtEth for management ethernet (e.g., MgmtEth0/RP0/CPU0/0)
    # Also MgmtLan on some platforms. Abbreviated form: Mgmt0/RP0/CPU0/0
    if name.startswith("MgmtEth") or name.startswith("MgmtLan") or name.startswith("Mgmt"):
        return "management"

    # -------------------------------------------------------------------------
    # AGGREGATED - Bundle-Ether
    # -------------------------------------------------------------------------
    # IOS XR uses Bundle-Ether for LAG instead of Port-channel
    # BE<digit> is the common abbreviation — must require digit suffix
    # (else "BERtest" / "BEacon" would falsely match).
    if name.startswith("Bundle-Ether") or _starts_with_abbrev(name, "BE"):
        return "aggregated"

    # -------------------------------------------------------------------------
    # LOGICAL
    # -------------------------------------------------------------------------
    # Loopback: same concept as IOS XE
    if name.startswith("Loopback") or _starts_with_abbrev(name, "Lo"):
        return "logical"

    # IOS XR uses lowercase tunnel-te, tunnel-ip for MPLS TE tunnels
    if name.startswith("tunnel-") or name.startswith("Tunnel"):
        return "logical"

    # BVI: Bridge Virtual Interface (IOS XR equivalent of BDI)
    if name.startswith("BVI"):
        return "logical"

    # -------------------------------------------------------------------------
    # VLAN - Less common on IOS XR, but supported
    # -------------------------------------------------------------------------
    # Note: IOS XR typically uses BVI for L3 VLAN interfaces
    if name.startswith("Vlan") or _starts_with_abbrev(name, "Vl"):
        return "vlan"

    # -------------------------------------------------------------------------
    # PHYSICAL
    # -------------------------------------------------------------------------
    # IOS XR physical interfaces - similar to IOS XE
    # but with different slot/port format (0/0/0/0)
    physical_prefixes = (
        "GigabitEthernet",
        "TenGigE",
        "HundredGigE",
        "FortyGigE",
        "TwentyFiveGigE",
        # Common abbreviations
        "Gi",
        "Te",
        "Hu",
        "Hun",
        "Fo",
        "Tw",
    )

    if name.startswith(physical_prefixes):
        return "physical"

    # -------------------------------------------------------------------------
    # UNKNOWN
    # -------------------------------------------------------------------------
    return "unknown"


def _classify_generic(name: str) -> InterfaceType:
    """
    Generic classification for unknown OS types.

    Uses common patterns that work across platforms.
    Less specific than OS-specific classifiers.

    Args:
        name: Interface name to classify

    Returns:
        Classified interface type
    """
    # -------------------------------------------------------------------------
    # Check patterns common across platforms
    # -------------------------------------------------------------------------
    # Using lowercase comparison for case-insensitive matching
    lower_name = name.lower()

    # Management patterns
    if lower_name.startswith("mgmt"):
        return "management"

    # Aggregated patterns
    if lower_name.startswith("port-channel") or lower_name.startswith("bundle"):
        return "aggregated"

    # Logical patterns
    if lower_name.startswith("loopback") or lower_name.startswith("tunnel"):
        return "logical"
    if lower_name.startswith("bdi") or lower_name.startswith("bvi"):
        return "logical"

    # VLAN patterns
    if lower_name.startswith("vlan"):
        return "vlan"

    # Physical patterns — check common 2-letter abbreviations.
    # Same digit-suffix discipline as the OS-specific classifiers — else
    # "twoFactorAuth" / "foreignKey" / "telephone" would falsely match.
    physical_prefixes = ("gi", "te", "hu", "fo", "tw", "fa", "et")
    if any(_starts_with_abbrev(lower_name, p) for p in physical_prefixes):
        return "physical"

    return "unknown"
