"""
Interface name normalizer for CDP correlation and cross-source matching.

This module provides two complementary normalization functions:

1. normalize_interface_name(name) → short form for CDP display matching
   Maps all variants to the shortest abbreviation (e.g., "Hu", "Gi", "Te").
   Used by the model builder for CDP link correlation.

2. canonicalize(name) → full lowercase form for cross-source identity matching
   Maps all variants to full lowercase canonical names (e.g., "hundredgige",
   "gigabitethernet"). Used by the link builder to match the same interface
   across CDP, LLDP, ARP, MAC table, and device model sources.

The Problem:
    The same physical interface appears in different formats across sources:
    - CDP (IOS XR):  "Hu0/0/1/0"
    - CDP (IOS XE):  "Hun 1/0/1" (with space after abbreviation)
    - Genie learn():  "HundredGigE0/0/1/0"
    - LLDP port_id:   "HundredGigE0/0/1/0" or a MAC address
    - FortiGate:      "port1", "internal", "wan1"

    String comparison fails across all of these.

The Solution:
    normalize_interface_name() maps to shortest abbreviation (CDP display):
        HundredGigE, HundredGig, Hun, Hu → "Hu"
        TenGigabitEthernet, TenGigE, Te → "Te"
        GigabitEthernet, Gig, Gi → "Gi"

    canonicalize() maps to full lowercase (identity key):
        HundredGigE, HundredGig, Hun, Hu → "hundredgige"
        TenGigabitEthernet, TenGigE, Te → "tengigabitethernet"
        GigabitEthernet, Gig, Gi → "gigabitethernet"

Design Principles:
    - Deterministic: Same input always produces same output
    - Lossless: Slot/port numbers preserved exactly
    - Bidirectional: Can be used on both local and remote interface names
    - MAC rejection: canonicalize() returns None for MAC addresses (not matchable)
"""

import re


# -------------------------------------------------------------------------
# Normalization Mapping
# -------------------------------------------------------------------------
# Maps various interface prefixes to their canonical short form.
# Order matters! Longer prefixes must come before shorter ones
# (e.g., "HundredGigE" before "Hun" before "Hu")
#
# Each tuple is: (pattern_to_match, canonical_form)
INTERFACE_PREFIXES = [
    # Hundred Gigabit variants
    ("HundredGigE", "Hu"),
    ("HundredGig", "Hu"),
    ("Hun ", "Hu"),      # Note: with space (IOS XE CDP format)
    ("Hun", "Hu"),
    ("Hu", "Hu"),

    # Ten Gigabit variants
    ("TenGigabitEthernet", "Te"),
    ("TenGigE", "Te"),
    ("Ten ", "Te"),
    ("Te", "Te"),

    # Gigabit variants
    ("GigabitEthernet", "Gi"),
    ("Gig ", "Gi"),
    ("Gig", "Gi"),
    ("Gi", "Gi"),

    # Forty Gigabit
    ("FortyGigE", "Fo"),
    ("Fo", "Fo"),

    # Twenty-Five Gigabit
    ("TwentyFiveGigE", "Tw"),
    ("TwentyFiveGig", "Tw"),  # without trailing E
    ("Twe ", "Tw"),           # IOS XE CDP abbreviated form with space (e.g. "Twe 1/0/8")
    ("Twe", "Tw"),            # abbreviated form without space
    ("Tw", "Tw"),

    # Fast Ethernet
    ("FastEthernet", "Fa"),
    ("Fa", "Fa"),

    # Ethernet
    ("Ethernet", "Et"),
    ("Et", "Et"),

    # Port-channel / Bundle-Ether (aggregated)
    ("Port-channel", "Po"),
    ("Po", "Po"),
    ("Bundle-Ether", "BE"),
    ("BE", "BE"),

    # Loopback
    ("Loopback", "Lo"),
    ("Lo", "Lo"),

    # Tunnel
    ("Tunnel", "Tu"),
    ("tunnel-te", "Tu-te"),
    ("tunnel-ip", "Tu-ip"),
    ("Tu", "Tu"),

    # VLAN
    ("Vlan", "Vl"),
    ("Vl", "Vl"),

    # Management
    # IOS XR uses multiple forms: MgmtEth0/RP0/CPU0/0 (long), Mg0/RP0/CPU0/0 (short)
    # IOS XE CDP may report with space: MgmtEth 0/RP0/CPU0/0
    # All must normalize to same canonical form for CDP correlation
    ("MgmtEth ", "Mgmt"),  # with space (IOS XE CDP format)
    ("MgmtEth", "Mgmt"),
    ("MgmtLan", "Mgmt"),
    ("Mgmt", "Mgmt"),
    ("Mg ", "Mgmt"),       # with space variant
    ("Mg", "Mgmt"),        # short form from IOS XR "show interfaces brief"

    # BDI/BVI (bridge interfaces)
    ("BDI", "BDI"),
    ("BVI", "BVI"),
]


def normalize_interface_name(name: str) -> str:
    """
    Normalize an interface name to canonical short form.

    This enables matching interfaces across devices that use different
    abbreviation formats in their CDP output.

    Algorithm:
        1. Strip whitespace from ends
        2. Find matching prefix from INTERFACE_PREFIXES
        3. Replace with canonical form
        4. Keep slot/port numbers exactly as-is

    Args:
        name: Interface name in any format
              (e.g., "HundredGigE0/0/1/0", "Hun 1/0/1", "Hu0/0/1/0")

    Returns:
        Normalized name (e.g., "Hu0/0/1/0", "Hu1/0/1", "Hu0/0/1/0")

    Examples:
        >>> normalize_interface_name("HundredGigE0/0/1/0")
        'Hu0/0/1/0'
        >>> normalize_interface_name("Hun 1/0/1")
        'Hu1/0/1'
        >>> normalize_interface_name("GigabitEthernet0/0")
        'Gi0/0'
        >>> normalize_interface_name("Bundle-Ether1")
        'BE1'
        >>> normalize_interface_name("Mg0/RP0/CPU0/0")
        'Mgmt0/RP0/CPU0/0'
        >>> normalize_interface_name("MgmtEth0/RP0/CPU0/0")
        'Mgmt0/RP0/CPU0/0'
    """
    # Handle empty/None input
    if not name:
        return name

    # Strip leading/trailing whitespace
    name = name.strip()

    # -------------------------------------------------------------------------
    # Find matching prefix and replace with canonical form
    # -------------------------------------------------------------------------
    # We iterate through prefixes in order (longest first for each type)
    # and replace the first match
    for pattern, canonical in INTERFACE_PREFIXES:
        if name.startswith(pattern):
            # Replace prefix with canonical form
            # The rest of the string (slot/port) stays exactly as-is
            suffix = name[len(pattern):]

            # Remove any leading space from suffix (handles "Hun 1/0/1" case)
            suffix = suffix.lstrip()

            return canonical + suffix

    # No match found - return original
    # This handles unknown interface types gracefully
    return name


# -------------------------------------------------------------------------
# Canonicalization for Cross-Source Interface Matching
# -------------------------------------------------------------------------
# Unlike normalize_interface_name() which maps to SHORT forms for CDP display,
# canonicalize() maps ALL variants to FULL LOWERCASE forms for identity matching.
#
# This is used by the link builder to match the same physical interface across
# different data sources (CDP, LLDP, ARP, MAC table, Genie interface model).
#
# Example: CDP says "Hun 2/0/1", Genie says "HundredGigE2/0/1",
#          IOS XR CDP says "Hu2/0/1" → all canonicalize to "hundredgige2/0/1"
#
# The canonical form is the full Cisco interface type name in lowercase,
# concatenated directly with the slot/port numbers (no space).

# Maps abbreviated/variant prefixes to the canonical full lowercase form.
# Order matters: longer prefixes must come before shorter ones within each
# interface type to avoid partial matches (e.g., "HundredGigE" before "Hun").
CANONICAL_PREFIXES = [
    # ---- Hundred Gigabit ----
    # Full: HundredGigE (IOS XE/XR full form in Genie)
    ("hundredgige", "hundredgige"),        # already full form
    ("hundredgig ", "hundredgige"),         # rare, with space
    ("hundredgig", "hundredgige"),          # without trailing "E"
    ("hun ", "hundredgige"),               # IOS XE CDP: "Hun 2/0/1"
    ("hun", "hundredgige"),                # less common
    ("hu", "hundredgige"),                 # IOS XR CDP: "Hu0/0/1/0"

    # ---- Twenty-Five Gigabit ----
    # Full: TwentyFiveGigE (IOS XE)
    ("twentyfivegige", "twentyfivegige"),
    ("twentyfivegig", "twentyfivegige"),
    ("twe ", "twentyfivegige"),            # IOS XE CDP: "Twe 1/0/8"
    ("twe", "twentyfivegige"),
    ("tw", "twentyfivegige"),

    # ---- Ten Gigabit ----
    # Full: TenGigabitEthernet (IOS XE/XR)
    ("tengigabitethernet", "tengigabitethernet"),
    ("tengige", "tengigabitethernet"),
    ("ten ", "tengigabitethernet"),         # IOS XE CDP: "Ten 2/1/8"
    ("ten", "tengigabitethernet"),
    ("te", "tengigabitethernet"),

    # ---- Gigabit ----
    # Full: GigabitEthernet (IOS XE/XR)
    ("gigabitethernet", "gigabitethernet"),
    ("gig ", "gigabitethernet"),            # IOS XE CDP: "Gig 1/0/3"
    ("gig", "gigabitethernet"),
    ("gi", "gigabitethernet"),              # IOS XR CDP: "Gi1/0/10"

    # ---- Forty Gigabit ----
    # Full: FortyGigabitEthernet (IOS XE)
    ("fortygigabitethernet", "fortygigabitethernet"),
    ("fortygige", "fortygigabitethernet"),
    ("fo", "fortygigabitethernet"),

    # ---- Fast Ethernet ----
    ("fastethernet", "fastethernet"),
    ("fa", "fastethernet"),

    # ---- Ethernet ----
    ("ethernet", "ethernet"),
    ("et", "ethernet"),

    # ---- Port-channel (L2/L3 aggregate) ----
    # IMPORTANT: "port" (FortiGate) must come before "po" to avoid
    # "port1" being matched as Port-channel. "port-channel" is longer
    # than "port" so it matches first for actual port-channels.
    ("port-channel", "port-channel"),
    ("port", "port"),                      # FortiGate: port1, port2, etc.
    ("po", "port-channel"),

    # ---- Bundle-Ether (IOS XR aggregate) ----
    ("bundle-ether", "bundle-ether"),
    ("be", "bundle-ether"),

    # ---- Loopback ----
    ("loopback", "loopback"),
    ("lo", "loopback"),

    # ---- Tunnel ----
    ("tunnel-te", "tunnel-te"),
    ("tunnel-ip", "tunnel-ip"),
    ("tunnel", "tunnel"),
    ("tu-te", "tunnel-te"),
    ("tu-ip", "tunnel-ip"),
    ("tu", "tunnel"),

    # ---- VLAN ----
    ("vlan", "vlan"),
    ("vl", "vlan"),

    # ---- Management ----
    # IOS XR: MgmtEth0/RP0/CPU0/0 (full), Mg0/RP0/CPU0/0 (short)
    # IOS XE CDP: "MgmtEth 0/RP0/CPU0/0" (with space)
    ("mgmteth ", "mgmteth"),               # IOS XE CDP with space
    ("mgmteth", "mgmteth"),
    ("mgmtlan", "mgmteth"),
    ("mgmt ", "mgmteth"),                  # with space variant
    ("mgmt", "mgmteth"),
    ("mg ", "mgmteth"),                    # with space variant
    ("mg", "mgmteth"),                     # IOS XR short: "Mg0/RP0/CPU0/0"

    # ---- BDI/BVI (bridge interfaces) ----
    ("bdi", "bdi"),
    ("bvi", "bvi"),

    # ---- Null (IOS XR) ----
    ("null", "null"),

    # ---- NVE (VXLAN Network Virtual Endpoint) ----
    ("nve", "nve"),
]

# Regex pattern matching MAC addresses in two common formats:
#   - Colon-separated:  00:1a:2b:3c:4d:5e
#   - Cisco dot-quad:   001a.2b3c.4d5e
_MAC_PATTERN = re.compile(
    r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"          # colon-separated
    r"|^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$"  # dot-quad
    r"|^([0-9a-f]{2}-){5}[0-9a-f]{2}$",          # dash-separated
    re.IGNORECASE,
)


def canonicalize(name: str | None) -> str | None:
    """
    Canonicalize an interface name to full lowercase form for cross-source matching.

    This function maps ALL interface name variants — CDP abbreviations, LLDP
    port descriptions, Genie full forms — to a single canonical lowercase string.
    Two names that refer to the same physical interface will produce the same
    canonical output, enabling reliable matching across data sources.

    Unlike normalize_interface_name() which produces SHORT forms for display,
    this function produces FULL LOWERCASE forms for identity comparison.

    Algorithm:
        1. Reject None/empty → return None
        2. Strip whitespace and lowercase the input
        3. Reject MAC addresses → return None (not matchable by interface name)
        4. Match against CANONICAL_PREFIXES (longest match first per type)
        5. Replace matched prefix with canonical full form
        6. Concatenate with slot/port suffix (stripped of leading spaces)
        7. FortiGate names (port1, internal, wan1) pass through as lowercase

    Args:
        name: Interface name in any format. Can be:
              - CDP abbreviated: "Hun 2/0/1", "Gig 1/0/3", "Hu0/0/1/0"
              - Genie full form: "HundredGigE0/0/1/0", "GigabitEthernet1/0/3"
              - FortiGate: "port1", "internal", "wan1"
              - MAC address: "00:1a:2b:3c:4d:5e" → returns None
              - None or empty → returns None

    Returns:
        Canonical lowercase string, or None if input is empty/None/MAC address.

    Examples:
        >>> canonicalize("Gi1/0/1")
        'gigabitethernet1/0/1'
        >>> canonicalize("GigabitEthernet1/0/1")
        'gigabitethernet1/0/1'
        >>> canonicalize("Gig 1/0/3")
        'gigabitethernet1/0/3'
        >>> canonicalize("Hun 2/0/1")
        'hundredgige2/0/1'
        >>> canonicalize("HundredGigE0/0/1/0")
        'hundredgige0/0/1/0'
        >>> canonicalize("Hu0/0/1/0")
        'hundredgige0/0/1/0'
        >>> canonicalize("Bundle-Ether13")
        'bundle-ether13'
        >>> canonicalize("MgmtEth0/RP0/CPU0/0")
        'mgmteth0/rp0/cpu0/0'
        >>> canonicalize("port1")
        'port1'
        >>> canonicalize("00:1a:2b:3c:4d:5e")
        >>> canonicalize("")
        >>> canonicalize(None)
    """
    # -------------------------------------------------------------------------
    # Step 1: Reject None/empty input
    # -------------------------------------------------------------------------
    if not name:
        return None

    # -------------------------------------------------------------------------
    # Step 2: Strip whitespace and lowercase for case-insensitive matching
    # -------------------------------------------------------------------------
    name_lower = name.strip().lower()

    if not name_lower:
        return None

    # -------------------------------------------------------------------------
    # Step 3: Reject MAC addresses — these appear as LLDP port_id values
    # but cannot be matched to interface names
    # -------------------------------------------------------------------------
    if _MAC_PATTERN.match(name_lower):
        return None

    # -------------------------------------------------------------------------
    # Step 4: Match against canonical prefix table
    # -------------------------------------------------------------------------
    # CANONICAL_PREFIXES is ordered with longer prefixes first per interface
    # type, so the first match is the most specific (avoids "gi" matching
    # before "gigabitethernet").
    for pattern, canonical_form in CANONICAL_PREFIXES:
        if name_lower.startswith(pattern):
            # Extract the slot/port suffix after the matched prefix
            suffix = name_lower[len(pattern):]

            # Remove leading spaces from suffix (handles "Hun 2/0/1" case
            # where the space is part of the CDP abbreviation format)
            suffix = suffix.lstrip()

            return canonical_form + suffix

    # -------------------------------------------------------------------------
    # Step 5: No prefix matched — pass through as lowercase
    # -------------------------------------------------------------------------
    # This handles FortiGate names (port1, internal, wan1), numeric-only
    # names, and any unknown interface types. Returning lowercase ensures
    # consistent comparison even for unrecognized formats.
    return name_lower
