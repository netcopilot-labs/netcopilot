"""
Running Config Parser — extracts structured security and config evidence.

Parses show running-config text into four structured JSON files per device.
All functions are pure (text in, dict out) — zero I/O, easily unit-testable.
Called by the pyATS adapter after it captures the running config.

Also hosts ``parse_stack_ports_summary`` — a text fallback for one operational
show-command (``show switch stack-ports summary``) whose Genie parser fails on
valid C9300 output. Same pure text-in/dict-out contract.

Output files produced:
    facts/<hostname>/security_config.json     ← 15 CIS-relevant sections
    facts/<hostname>/parsed_management.json   ← management IP, SSH settings
    facts/<hostname>/parsed_route_policy.json ← route-map definitions
    facts/<hostname>/parsed_prefix_list.json  ← prefix-list entries

Architecture:
    show running-config (raw text)
            │
            ├──► parse_security_config()  → security_config.json
            │         │
            │         ├── _parse_aaa()
            │         ├── _parse_ssh()
            │         ├── _parse_ntp()
            │         ├── _parse_logging()
            │         ├── _parse_services()
            │         ├── _parse_vty_lines()
            │         ├── _parse_console()
            │         ├── _parse_snmp()
            │         ├── _parse_banner()
            │         ├── _parse_http_server()
            │         ├── _parse_cdp_lldp()
            │         ├── _parse_domain_lookup()
            │         ├── _parse_password_policy()
            │         ├── _parse_tacacs_radius()
            │         └── _parse_ip_source_routing()
            │
            ├──► parse_management()       → parsed_management.json
            ├──► parse_route_policies()   → parsed_route_policy.json
            └──► parse_prefix_lists()     → parsed_prefix_list.json

Design Principles:
    - Pure functions: text in, dict out — zero side effects, easy to test
    - IOS XE / IOS XR dual coverage: each section includes patterns for both
      OS families where syntax differs (SSH, VTY, HTTP, logging, ACL keywords)
    - Graceful degradation: unrecognised config returns {}; never raises
    - _parser_coverage metadata: tracks which of the 15 sections yielded data
    - Section "parsed" = at least one truthy or boolean value found
    - Section "empty"  = no matching config lines detected

IOS XE vs IOS XR key differences handled per section:
    SSH:     ip ssh version 2  vs  ssh server v2
    Logging: logging host <ip> vs  logging <ip>
    VTY:     line vty 0 15     vs  line default
    HTTP:    ip http server     vs  N/A (XR uses separate config model)
    Source:  no ip source-route vs  no ipv4 source-route
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import logging
import re
from typing import Any

# -------------------------------------------------------------------------
# Module logger
# -------------------------------------------------------------------------
log = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Private helpers
# -------------------------------------------------------------------------

def _extract_block(text: str, header_pattern: str) -> str:
    """
    Extract the indented sub-block under a section header line.

    Used to scope regex searches to a specific config section (e.g., only
    within 'line vty 0 15' rather than the entire running config).

    Args:
        text:           Full running config text.
        header_pattern: Regex matching the section header line (e.g. r'^line vty').

    Returns:
        Text between the header line and the next top-level (non-indented) line,
        or empty string if the header is not found.
    """
    m = re.search(header_pattern, text, re.MULTILINE)
    if not m:
        return ""
    rest = text[m.end():]
    # Top-level lines start with a letter, digit, or '!' at column 0.
    # Indented lines (sub-commands) start with whitespace.
    # We stop at the next top-level line — that marks the end of the block.
    end_m = re.search(r"\n[^ \t\n!]", rest)
    if end_m:
        return rest[: end_m.start()]
    return rest


def _has_data(section_dict: dict) -> bool:
    """
    Return True if the section dict contains at least one meaningful value.

    Coverage rule:
      - Any boolean value → True   (we made a determination about this feature)
      - Any non-None, non-empty-list/dict value → True
      - All-None or all-empty-list dicts → False (no matching config lines)

    A section with all-False booleans (e.g. no banners configured) still
    returns True — knowing banners are absent IS a meaningful CIS finding.
    A section with only empty lists (e.g. SNMP not configured) returns False.

    Args:
        section_dict: Dict returned by a _parse_*() function.

    Returns:
        True if the section dict has meaningful content, False if empty.
    """
    for v in section_dict.values():
        if isinstance(v, bool):
            # Any boolean (True or False) means we scanned for this feature
            return True
        if v:
            # Non-empty string, non-zero int, non-empty list/dict
            return True
    return False


# -------------------------------------------------------------------------
# Section parsers (called by parse_security_config)
# -------------------------------------------------------------------------

def _parse_aaa(text: str) -> dict:
    """
    Extract AAA authentication, authorisation, and accounting config.

    IOS XE and IOS XR share the same 'aaa authentication/authorization/
    accounting' global config syntax — no OS-specific branches needed.
    """
    result: dict[str, Any] = {}
    m = re.search(r"^aaa authentication login default (.+)$", text, re.MULTILINE)
    if m:
        result["authentication_login_default"] = m.group(1).strip()
    m = re.search(r"^aaa authorization exec default (.+)$", text, re.MULTILINE)
    if m:
        result["authorization_exec_default"] = m.group(1).strip()
    # accounting_configured is a boolean — False means no AAA accounting lines
    result["accounting_configured"] = bool(
        re.search(r"^aaa accounting\b", text, re.MULTILINE)
    )
    return result


def _parse_ssh(text: str) -> dict:
    """
    Extract SSH version, timeout, max-retries, and source-interface.

    IOS XE: ip ssh version 2 / ip ssh time-out <n> / ip ssh authentication-retries <n>
    IOS XR: ssh server v2 / ssh timeout <n>
    """
    result: dict[str, Any] = {}

    # SSH version — XE uses 'ip ssh version', XR uses 'ssh server v2'
    if re.search(r"^(?:ip ssh version 2|ssh server v2\b)", text, re.MULTILINE):
        result["version"] = 2
    elif re.search(r"^(?:ip ssh version 1|ssh server v1\b)", text, re.MULTILINE):
        result["version"] = 1

    # Timeout — XE: "ip ssh time-out <n>"; XR: "ssh timeout <n>"
    m = re.search(r"^ip ssh time-out (\d+)", text, re.MULTILINE)
    if not m:
        m = re.search(r"^ssh timeout (\d+)", text, re.MULTILINE)
    if m:
        result["timeout"] = int(m.group(1))

    # Max retries — XE only; XR uses session-limit (different concept)
    m = re.search(r"^ip ssh authentication-retries (\d+)", text, re.MULTILINE)
    if m:
        result["max_retries"] = int(m.group(1))

    # Source interface — XE: "ip ssh source-interface <intf>"
    m = re.search(r"^ip ssh source-interface (\S+)", text, re.MULTILINE)
    if m:
        result["source_interface"] = m.group(1)

    return result


def _parse_ntp(text: str) -> dict:
    """
    Extract NTP authentication state, trusted keys, and authenticated server count.

    Both IOS XE and IOS XR use the same 'ntp authenticate', 'ntp trusted-key',
    and 'ntp server ... key' syntax — no OS-specific branches needed.
    """
    result: dict[str, Any] = {}
    result["authentication_enabled"] = bool(
        re.search(r"^ntp authenticate\b", text, re.MULTILINE)
    )
    trusted_keys = re.findall(r"^ntp trusted-key (\d+)", text, re.MULTILINE)
    result["trusted_keys"] = [int(k) for k in trusted_keys]
    # Count NTP servers that require key authentication (key <n> parameter present)
    result["servers_with_key"] = len(
        re.findall(r"^ntp server \S+ key \d+", text, re.MULTILINE)
    )
    return result


def _parse_logging(text: str) -> dict:
    """
    Extract logging buffer size, trap level, remote hosts, and source interface.

    IOS XE: 'logging host <ip>'    — explicit 'host' keyword
    IOS XR: 'logging <ip>'         — no 'host' keyword (just the IP directly)
    Both patterns are tried so the result is OS-agnostic.
    """
    result: dict[str, Any] = {}
    m = re.search(r"^logging buffered (\d+)", text, re.MULTILINE)
    if m:
        result["buffered_size"] = int(m.group(1))
    m = re.search(r"^logging trap (\S+)", text, re.MULTILINE)
    if m:
        result["trap_level"] = m.group(1)

    # Capture all remote syslog hosts.
    # XE: "logging host 10.x.x.x" or "logging 10.x.x.x"
    # XR: "logging 10.x.x.x" (no 'host' keyword)
    hosts = re.findall(
        r"^logging (?:host )?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        text,
        re.MULTILINE,
    )
    result["hosts"] = hosts

    m = re.search(r"^logging source-interface (\S+)", text, re.MULTILINE)
    if m:
        result["source_interface"] = m.group(1)
    return result


def _parse_services(text: str) -> dict:
    """
    Extract 'service' hardening settings.

    IOS XE and IOS XR coverage:
      timestamps_log       — both OS families support 'service timestamps log'
      password_encryption  — IOS XE only; XR uses native type-9 secrets instead
      tcp_keepalives_in/out— IOS XE only; XR has no equivalent global command

    On a pure IOS XR device, password_encryption and tcp_keepalives will be
    False. That is the correct result — XR relies on strong secret types (8/9)
    rather than the reversible type-7 encryption that service password-encryption
    provides on XE.
    """
    result: dict[str, Any] = {}
    result["password_encryption"] = bool(
        re.search(r"^service password-encryption\b", text, re.MULTILINE)
    )
    result["tcp_keepalives_in"] = bool(
        re.search(r"^service tcp-keepalives-in\b", text, re.MULTILINE)
    )
    result["tcp_keepalives_out"] = bool(
        re.search(r"^service tcp-keepalives-out\b", text, re.MULTILINE)
    )
    result["timestamps_log"] = bool(
        re.search(r"^service timestamps log\b", text, re.MULTILINE)
    )
    return result


def _parse_vty_lines(text: str) -> dict:
    """
    Extract VTY line hardening settings.

    IOS XE: configured under 'line vty 0 <n>' block
    IOS XR: configured under 'line default' block

    Block extraction scopes searches so we don't accidentally match
    console or aux line settings.
    """
    result: dict[str, Any] = {}
    # Try IOS XE 'line vty' first, fall back to IOS XR 'line default'
    block = _extract_block(text, r"^line vty \d+")
    if not block:
        block = _extract_block(text, r"^line default\b")
    if not block:
        return result

    m = re.search(r"transport input (.+)", block)
    if m:
        result["transport_input"] = m.group(1).strip()

    # access-class restricts which hosts can Telnet/SSH to the device
    m = re.search(r"access-class (\S+) in", block)
    if m:
        result["access_class_in"] = m.group(1)

    # exec-timeout in minutes (first number); 0 = no timeout (CIS concern)
    m = re.search(r"exec-timeout (\d+)", block)
    if m:
        result["exec_timeout_minutes"] = int(m.group(1))

    return result


def _parse_console(text: str) -> dict:
    """
    Extract console line hardening settings.

    IOS XE: 'line con 0'
    IOS XR: 'line console'
    """
    result: dict[str, Any] = {}
    # Try IOS XE form first, then IOS XR
    block = _extract_block(text, r"^line con 0\b")
    if not block:
        block = _extract_block(text, r"^line console\b")
    if not block:
        return result

    m = re.search(r"exec-timeout (\d+)", block)
    if m:
        result["exec_timeout_minutes"] = int(m.group(1))
    result["logging_synchronous"] = bool(re.search(r"logging synchronous", block))
    return result


def _parse_snmp(text: str) -> dict:
    """
    Extract SNMP communities, trap hosts, v3 users, and associated ACLs.

    Both IOS XE and IOS XR use 'snmp-server community' and 'snmp-server host'
    syntax — these patterns apply to both OS families.
    """
    result: dict[str, Any] = {}

    # Community strings with their mode (RO/RW) and optional ACL
    communities = []
    for m in re.finditer(
        r"^snmp-server community (\S+) (?:view \S+ )?(RO|RW|ro|rw)(?:\s+(\S+))?",
        text,
        re.MULTILINE,
    ):
        communities.append(
            {
                "name": m.group(1),
                "mode": m.group(2).upper(),
                "acl": m.group(3),  # None if no ACL applied
            }
        )
    result["communities"] = communities

    result["hosts"] = re.findall(r"^snmp-server host (\S+)", text, re.MULTILINE)
    result["v3_users"] = re.findall(r"^snmp-server user (\S+)", text, re.MULTILINE)
    # Collect unique ACLs applied to SNMP communities (security hardening check)
    result["acls"] = sorted({c["acl"] for c in communities if c.get("acl")})
    return result


def _parse_banner(text: str) -> dict:
    """
    Detect presence of login, MOTD, and exec banners.

    Both IOS XE and IOS XR support banner login / motd / exec.
    Returns booleans — False means no banner configured (CIS finding).
    """
    result: dict[str, Any] = {}
    result["login_present"] = bool(
        re.search(r"^banner login\b", text, re.MULTILINE)
    )
    result["motd_present"] = bool(
        re.search(r"^banner motd\b", text, re.MULTILINE)
    )
    result["exec_present"] = bool(
        re.search(r"^banner exec\b", text, re.MULTILINE)
    )
    return result


def _parse_http_server(text: str) -> dict:
    """
    Detect HTTP / HTTPS server status and access ACL.

    IOS XE: 'ip http server' / 'ip http secure-server' / 'ip http access-class'
    IOS XR: 'http server vrf <vrf>' or bare 'http server' in some configurations.

    The regex `^(?:ip )?http server\b` deliberately omits the 'ip' prefix as
    optional — this makes it cover both 'ip http server' (XE) and 'http server'
    (XR variant) with a single pattern. IOS XR WAN routers rarely expose the
    HTTP management plane; False results on XR are correct.
    """
    result: dict[str, Any] = {}
    # Optional 'ip ' prefix: matches IOS XE 'ip http server' and IOS XR 'http server'
    result["http_enabled"] = bool(
        re.search(r"^(?:ip )?http server\b", text, re.MULTILINE)
    )
    result["https_enabled"] = bool(
        re.search(r"^(?:ip )?http secure-server\b", text, re.MULTILINE)
    )
    m = re.search(r"^(?:ip )?http access-class (\S+)", text, re.MULTILINE)
    if m:
        result["acl"] = m.group(1)
    return result


def _parse_cdp_lldp(text: str, os_family: str = "ios-xe") -> dict:
    """
    Detect CDP and LLDP enablement.

    The enable/disable model is inverted between OS families:

    IOS XE — opt-out model:
      CDP:  enabled by default; 'no cdp run' is required to disable it globally
      LLDP: disabled by default; 'lldp run' is required to enable it

    IOS XR — opt-in model:
      CDP:  disabled by default; bare 'cdp' global command enables it
      LLDP: disabled by default; bare 'lldp' global command enables it (no 'run')

    Without os_family we would incorrectly report XR devices as having CDP
    enabled (because 'no cdp run' is absent, which means enabled on XE but
    disabled on XR). The os_family parameter resolves this ambiguity.
    """
    result: dict[str, Any] = {}

    if os_family.replace("-", "") == "iosxr":
        # XR opt-in: presence of the global 'cdp' / 'lldp' command = enabled
        result["cdp_enabled"] = bool(re.search(r"^cdp\b", text, re.MULTILINE))
        result["lldp_enabled"] = bool(re.search(r"^lldp\b", text, re.MULTILINE))
    else:
        # XE opt-out: enabled unless 'no cdp run' explicitly disables it
        result["cdp_enabled"] = not bool(
            re.search(r"^no cdp run\b", text, re.MULTILINE)
        )
        # LLDP is opt-in on XE even though CDP is opt-out — 'lldp run' enables it
        result["lldp_enabled"] = bool(re.search(r"^lldp run\b", text, re.MULTILINE))

    return result


def _parse_domain_lookup(text: str) -> dict:
    """
    Detect whether DNS domain lookups are enabled.

    IOS XE: 'no ip domain lookup' or 'no ip domain-lookup' disables it.
    IOS XR: 'domain lookup disable' disables it.

    CIS recommends disabling domain lookup on infrastructure devices to prevent
    accidental long waits from unresolvable hostnames in typo'd commands.
    """
    result: dict[str, Any] = {}
    # Both 'no ip domain lookup' (space) and 'no ip domain-lookup' (hyphen) are valid XE
    disabled_xe = bool(
        re.search(r"^no ip domain.?lookup\b", text, re.MULTILINE)
    )
    disabled_xr = bool(
        re.search(r"^domain lookup disable\b", text, re.MULTILINE)
    )
    result["enabled"] = not (disabled_xe or disabled_xr)
    return result


def _parse_password_policy(text: str, os_family: str = "ios-xe") -> dict:
    """
    Extract password minimum length and secret encryption type.

    Secret types: 0=cleartext, 5=MD5, 7=reversible, 8=PBKDF2-SHA256, 9=scrypt
    Types 8 and 9 are CIS-recommended.

    IOS XE:
      min_length:             'security passwords min-length <n>'
      secret_encryption_type: digit after 'enable secret <type> <hash>'

    IOS XR:
      min_length:             'min-length <n>' inside 'aaa password-policy <name>' block
      secret_encryption_type: digit after 'secret <type> <hash>' inside 'username <n>' block
                              (XR uses per-user secrets rather than a global enable secret)
    """
    result: dict[str, Any] = {}

    if os_family.replace("-", "") == "iosxr":
        # XR password policy is configured in a named 'aaa password-policy' section
        block = _extract_block(text, r"^aaa password-policy \S+")
        if block:
            m = re.search(r"min-length (\d+)", block)
            if m:
                result["min_length"] = int(m.group(1))
        # XR secret type: indented 'secret <type> <hash>' under 'username <name>' block
        # The digit (0/5/7/8/9) immediately follows the 'secret' keyword
        m = re.search(r"^\s+secret (\d)\b", text, re.MULTILINE)
        if m:
            result["secret_encryption_type"] = int(m.group(1))
    else:
        # XE: global min-length command and 'enable secret <type>' line
        m = re.search(r"^security passwords min-length (\d+)", text, re.MULTILINE)
        if m:
            result["min_length"] = int(m.group(1))
        # The digit after 'enable secret' is the type indicator
        m = re.search(r"^enable secret (\d)", text, re.MULTILINE)
        if m:
            result["secret_encryption_type"] = int(m.group(1))

    return result


def _parse_tacacs_radius(text: str) -> dict:
    """
    Extract TACACS+ and RADIUS server references and key configuration status.

    Named servers (IOS XE 15.x+): 'tacacs server <name>' block with
      'address ipv4 <ip>' and optional 'key <secret>' inside.
    Legacy (IOS XE older / IOS XR): 'tacacs-server host <ip>'
    Both forms are collected and deduplicated.
    """
    result: dict[str, Any] = {}

    # TACACS: named server blocks (XE 15.x+)
    # Parse both the server name AND the address inside the block
    tacacs_servers = []
    key_found = False
    for m in re.finditer(
        r"^tacacs server (\S+)\n((?:[ \t]+\S.*\n)*)",
        text, re.MULTILINE,
    ):
        name = m.group(1)
        block = m.group(2)
        addr = re.search(r"address ipv4 (\S+)", block)
        ip = addr.group(1) if addr else None
        entry = f"{name} ({ip})" if ip else name
        tacacs_servers.append(entry)
        if re.search(r"\bkey\b", block):
            key_found = True

    # Legacy host lines
    tacacs_servers += re.findall(r"^tacacs-server host (\S+)", text, re.MULTILINE)
    result["tacacs_servers"] = sorted(set(tacacs_servers))

    # RADIUS: named server blocks (XE 15.x+)
    radius_servers = []
    for m in re.finditer(
        r"^radius server (\S+)\n((?:[ \t]+\S.*\n)*)",
        text, re.MULTILINE,
    ):
        name = m.group(1)
        block = m.group(2)
        addr = re.search(r"address ipv4 (\S+)", block)
        ip = addr.group(1) if addr else None
        entry = f"{name} ({ip})" if ip else name
        radius_servers.append(entry)
        if re.search(r"\bkey\b", block):
            key_found = True

    # Legacy host lines
    radius_servers += re.findall(r"^radius-server host (\S+)", text, re.MULTILINE)
    result["radius_servers"] = sorted(set(radius_servers))

    # key_configured: found inside a server block OR on a legacy line
    # Legacy format has key on indented line after 'tacacs-server host' line
    if not key_found:
        key_found = bool(
            re.search(
                r"^(?:tacacs|radius).*(?:\n[ \t]+.*)*\bkey\b",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
        )
    result["key_configured"] = key_found
    return result


def _parse_ip_source_routing(text: str) -> dict:
    """
    Detect whether IP source routing is enabled.

    IOS XE: 'no ip source-route' disables it (enabled by default)
    IOS XR: 'no ipv4 source-route' disables it

    CIS recommends disabling source routing on all infrastructure devices.
    """
    result: dict[str, Any] = {}
    disabled = bool(
        re.search(r"^no (?:ip|ipv4) source-route\b", text, re.MULTILINE)
    )
    result["enabled"] = not disabled
    return result


# -------------------------------------------------------------------------
# Ordered section registry
# -------------------------------------------------------------------------
# Maps section names to their parser functions.
# Order determines _parser_coverage detail dict ordering.
# Adding a new section = add an entry here + write a _parse_*() function.
#
# OS-aware parsers (_parse_cdp_lldp, _parse_password_policy) accept an
# os_family keyword argument. All others take only the config text.
# parse_security_config() dispatches accordingly.
_SECURITY_SECTIONS: list[tuple[str, Any]] = [
    ("aaa",              _parse_aaa),
    ("ssh",              _parse_ssh),
    ("ntp",              _parse_ntp),
    ("logging",          _parse_logging),
    ("services",         _parse_services),
    ("vty_lines",        _parse_vty_lines),
    ("console",          _parse_console),
    ("snmp",             _parse_snmp),
    ("banner",           _parse_banner),
    ("http_server",      _parse_http_server),
    ("cdp_lldp",         _parse_cdp_lldp),         # OS-aware
    ("domain_lookup",    _parse_domain_lookup),
    ("password_policy",  _parse_password_policy),   # OS-aware
    ("tacacs_radius",    _parse_tacacs_radius),
    ("ip_source_routing", _parse_ip_source_routing),
]

# Sections whose parsers need the os_family argument
_OS_AWARE_SECTIONS = {"cdp_lldp", "password_policy"}


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------

def parse_security_config(running_config: str, os_family: str = "ios-xe") -> dict:
    """
    Parse running config text into 15 CIS-relevant security sections.

    Calls each section parser in _SECURITY_SECTIONS order, then appends
    a _parser_coverage metadata block showing which sections yielded data.

    Args:
        running_config: Raw text output of 'show running-config'.
            Empty string → all sections empty, coverage sections_parsed=0.
        os_family: 'ios-xe' (default) or 'ios-xr' (the hyphenated form is
            normalised internally). Controls OS-specific parsing
            logic in cdp_lldp (opt-out vs opt-in model) and password_policy
            (security passwords vs aaa password-policy section).

    Returns:
        Dict with 15 section keys plus '_parser_coverage'. Example structure:
        {
            "aaa":   {"authentication_login_default": "group AAA-GROUP local", ...},
            "ssh":   {"version": 2, "timeout": 60, ...},
            ...
            "_parser_coverage": {
                "sections_attempted": 15,
                "sections_parsed":    12,
                "sections_empty":      3,
                "sections_detail":    {"aaa": "parsed", "snmp": "empty", ...}
            }
        }
    """
    result: dict[str, Any] = {}
    section_status: dict[str, str] = {}

    for section_name, parser_fn in _SECURITY_SECTIONS:
        try:
            if section_name in _OS_AWARE_SECTIONS:
                # Pass os_family to parsers whose logic branches on OS type
                section_data = parser_fn(running_config, os_family=os_family)
            else:
                section_data = parser_fn(running_config)
        except Exception as exc:  # noqa: BLE001
            # Individual section failure must never abort the whole parse.
            # Log and record as empty — collection continues.
            log.warning("Security section '%s' parse failed: %s", section_name, exc)
            section_data = {}

        result[section_name] = section_data
        section_status[section_name] = "parsed" if _has_data(section_data) else "empty"

    sections_parsed = sum(1 for s in section_status.values() if s == "parsed")
    sections_empty = len(section_status) - sections_parsed

    result["_parser_coverage"] = {
        "sections_attempted": len(_SECURITY_SECTIONS),
        "sections_parsed":    sections_parsed,
        "sections_empty":     sections_empty,
        "sections_detail":    section_status,
    }

    log.debug(
        "parse_security_config: %d/%d sections parsed",
        sections_parsed,
        len(_SECURITY_SECTIONS),
    )
    return result


def parse_management(running_config: str) -> dict:
    """
    Extract management plane settings from running config.

    Captures the management interface IP address (Loopback0 on IOS XE,
    MgmtEth0/0/CPU0/0 on IOS XR), SSH source interface, and management
    VRF binding. Used to populate the network model's management plane facts.

    Args:
        running_config: Raw text output of 'show running-config'.

    Returns:
        Dict with management fields, or {} if nothing found. Example:
        {
            "management_interface":  "Loopback0",
            "management_ip":         "192.0.2.103",
            "ssh_source_interface":  "Loopback0",
            "management_vrf":        "MGMT"
        }
    """
    result: dict[str, Any] = {}

    # -------------------------------------------------------------------------
    # Management interface and IP
    # -------------------------------------------------------------------------
    # Strategy: look for the Loopback0 or Management interface block and
    # extract the primary IP address. Loopback0 is the standard management
    # interface on IOS XE distribution/core switches.
    # IOS XR uses MgmtEth0/0/CPU0/0 for out-of-band management.
    mgmt_patterns = [
        r"^interface (Loopback0)\b",
        r"^interface (MgmtEth\S+)",
        r"^interface (Management\S+)",
    ]
    for pattern in mgmt_patterns:
        block = _extract_block(running_config, pattern)
        if block:
            m_intf = re.search(pattern, running_config, re.MULTILINE)
            if m_intf:
                result["management_interface"] = m_intf.group(1)
            ip_m = re.search(
                r"ip(?:v4)? address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", block
            )
            if ip_m:
                result["management_ip"] = ip_m.group(1)
            break

    # -------------------------------------------------------------------------
    # SSH source interface
    # -------------------------------------------------------------------------
    m = re.search(r"^ip ssh source-interface (\S+)", running_config, re.MULTILINE)
    if m:
        result["ssh_source_interface"] = m.group(1)

    # -------------------------------------------------------------------------
    # Management VRF
    # -------------------------------------------------------------------------
    # IOS XE: "ip vrf forwarding MGMT" under management interface
    # IOS XR: "vrf MGMT" under management interface
    m = re.search(r"(?:ip vrf forwarding|vrf) (MGMT\S*)", running_config, re.MULTILINE)
    if m:
        result["management_vrf"] = m.group(1)

    return result


def parse_route_policies(running_config: str) -> dict:
    """
    Extract route-map definitions from running config.

    Parses route-map stanzas into a structured dict keyed by route-map name.
    Each sequence entry includes the permit/deny action and lists of match
    and set clauses.

    Args:
        running_config: Raw text output of 'show running-config'.

    Returns:
        Dict keyed by route-map name, or {} if none found. Example:
        {
            "REDISTRIBUTE-OSPF-TO-BGP": {
                "sequences": [
                    {
                        "seq":    10,
                        "action": "permit",
                        "match":  ["ip address prefix-list OSPF-ROUTES"],
                        "set":    ["local-preference 150"]
                    }
                ]
            }
        }
    """
    result: dict[str, Any] = {}

    # Each route-map stanza: "route-map <name> permit|deny <seq>"
    # Collect all stanza headers first, then extract the sub-block for each
    for m in re.finditer(
        r"^route-map (\S+) (permit|deny) (\d+)", running_config, re.MULTILINE
    ):
        name, action, seq = m.group(1), m.group(2), int(m.group(3))
        block = _extract_block(running_config, re.escape(m.group(0)))

        match_clauses = re.findall(r"^\s+match (.+)$", block, re.MULTILINE)
        set_clauses = re.findall(r"^\s+set (.+)$", block, re.MULTILINE)

        sequence_entry = {
            "seq":    seq,
            "action": action,
            "match":  [c.strip() for c in match_clauses],
            "set":    [c.strip() for c in set_clauses],
        }

        if name not in result:
            result[name] = {"sequences": []}
        result[name]["sequences"].append(sequence_entry)

    return result


def parse_prefix_lists(running_config: str) -> dict:
    """
    Extract ip prefix-list entries from running config.

    Both IOS XE and IOS XR use 'ip prefix-list <name> seq <n> permit|deny <prefix>'
    syntax. IPv6 prefix-lists use 'ipv6 prefix-list' — both are captured.

    Args:
        running_config: Raw text output of 'show running-config'.

    Returns:
        Dict keyed by prefix-list name, or {} if none found. Example:
        {
            "OSPF-ROUTES": {
                "entries": [
                    {"seq": 10, "action": "permit", "prefix": "192.0.2.0/24"}
                ]
            }
        }
    """
    result: dict[str, Any] = {}

    # Match both "ip prefix-list" (XE/XR IPv4) and "ipv6 prefix-list" (IPv6)
    for m in re.finditer(
        r"^(?:ip|ipv6) prefix-list (\S+) seq (\d+) (permit|deny) (\S+)",
        running_config,
        re.MULTILINE,
    ):
        name = m.group(1)
        entry = {
            "seq":    int(m.group(2)),
            "action": m.group(3),
            "prefix": m.group(4),
        }
        if name not in result:
            result[name] = {"entries": []}
        result[name]["entries"].append(entry)

    return result


# Data row of `show switch stack-ports summary` (C9300 traditional StackWise):
#   Sw#/Port#  Port Status  Neighbor/Port  Cable Length  Link OK  Link Active  Sync OK  ...
#   1/1        OK           3/2            50cm          Yes      Yes          Yes      ...
_STACK_PORT_ROW = re.compile(
    r"^(?P<sw_port>\d+/\d+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<neighbor>\S+)\s+"
    r"(?P<cable>\S+)\s+"
    r"(?P<link_ok>Yes|No)\s+"
    r"(?P<link_active>Yes|No)\s+"
    r"(?P<sync_ok>Yes|No)\b"
)


def parse_stack_ports_summary(text: str) -> dict:
    """
    Parse ``show switch stack-ports summary`` (C9300 traditional StackWise).

    This is NOT a running-config parser — it is a text fallback for the one
    operational show-command whose Genie parser (ShowSwitchStackPortsSummary)
    raises on valid output from real C9300 stacks, leaving traditional-stack
    health unmonitored. The pyATS adapter calls this on the raw output it
    captured after the Genie parse failed, and writes the result as
    ``genie_stack_ports.json`` so the model consumer
    (``parse.cisco_native.stack._parse_c9300_stack_ports``) is unchanged —
    it produces exactly the Genie ShowSwitchStackPortsSummary schema.

    Args:
        text: Raw output of ``show switch stack-ports summary``.

    Returns:
        ``{"stackports": {"1/1": {"stackport_id": "1/1", "port_status": "OK",
        "neighbor": "3/2", "cable_length": "50cm", "link_ok": "Yes",
        "link_active": "Yes", "sync_ok": "Yes"}, ...}}`` — or ``{}`` when no
        data rows match (a non-stacked device yields only a header/banner).
    """
    stackports: dict[str, Any] = {}
    for line in text.splitlines():
        m = _STACK_PORT_ROW.match(line.strip())
        if not m:
            continue
        sw_port = m.group("sw_port")
        stackports[sw_port] = {
            "stackport_id": sw_port,
            "port_status":  m.group("status"),
            "neighbor":     m.group("neighbor"),
            "cable_length": m.group("cable"),
            "link_ok":      m.group("link_ok"),
            "link_active":  m.group("link_active"),
            "sync_ok":      m.group("sync_ok"),
        }

    return {"stackports": stackports} if stackports else {}
