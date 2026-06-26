"""Protocol discovery — decide which Genie families to learn per device.

The pyATS adapter does not blindly call ``device.learn()`` for every protocol.
Each unconfigured ``learn()`` wastes seconds and returns nothing, so we gate the
calls on what the device actually runs. The decision is hybrid:

* **Core set** — six families every device has (interfaces, ARP, MAC table,
  routing, ...), collected unconditionally.
* **Config-driven** — extra families detected by scanning ``show running-config``
  for anchored keywords (``router ospf``, ``router bgp``, ``spanning-tree``, ...).

The function is pure: running-config text in, sorted family list out. No I/O, so
it is trivially unit-testable and patterns cover both IOS XE and IOS XR where
their syntax diverges (multicast, VRF, ACL, static routing, HSRP, IGMP, MLD).
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)


#: Six families present on every device regardless of configuration. Collected
#: unconditionally so even a pure-L2 switch with no routing protocols still has
#: a baseline evidence set (interfaces, hardware, neighbours, ARP, MAC, routes).
ALWAYS_COLLECT: list[str] = [
    "interface",  # every device has interfaces — the primary model source
    "platform",   # hardware info, environment, stack state
    "lldp",       # neighbour discovery, supplements CDP from the command profile
    "arp",        # L3 neighbour table — populated on any routed interface
    "fdb",        # L2 MAC forwarding database — empty on pure-L3 routers (harmless)
    "routing",    # IP routing table — present on every device (at least a default)
]


#: Config-driven families: collected only when their keyword appears in the
#: running config. A typical distribution switch runs 5-8 of these, not all of
#: them, so gating avoids a pile of empty ``learn()`` calls.
#:
#: Pattern design:
#:   - ``re.MULTILINE`` so ``^`` anchors to each config line, not just the start.
#:   - ``\b`` word boundaries to avoid partial matches.
#:   - Line-start anchoring to avoid matching descriptions/comments.
#:   - Each family lists IOS XE patterns first, then IOS XR where syntax differs;
#:     ``any()`` short-circuits on the first match.
PROTOCOL_KEYWORDS: dict[str, list[str]] = {
    # ---- Routing protocols (XE and XR share "router <proto>" headers) ----
    "ospf":           [r"^router ospf\b"],
    "bgp":            [r"^router bgp\b"],
    "isis":           [r"^router isis\b"],
    "eigrp":          [r"^router eigrp\b"],   # IOS XE only
    "rip":            [r"^router rip\b"],      # IOS XE only

    # ---- First-hop redundancy ----
    # IOS XE: per-interface "standby <group> ..." (indented).
    # IOS XR: global "router hsrp" section header.
    "hsrp":           [r"^\s+standby \d+",
                       r"^router hsrp\b"],

    # ---- Spanning tree (never matches on L3-only IOS XR — correct) ----
    "stp":            [r"^spanning-tree\b"],

    # ---- Time sync (identical keywords on XE and XR) ----
    "ntp":            [r"^ntp server\b", r"^ntp peer\b"],

    # ---- Multicast ----
    # pim and mcast both fire on multicast-routing — intentional; learn('pim')
    # and learn('mcast') return distinct Genie structures.
    "pim":            [r"^ip pim\b", r"^ip multicast-routing\b",  # IOS XE
                       r"^router pim\b"],                           # IOS XR
    "igmp":           [r"^\s+ip igmp\b",   # IOS XE: interface sub-mode
                       r"^router igmp\b"],  # IOS XR: global section
    "mcast":          [r"^ip multicast-routing\b",  # IOS XE
                       r"^multicast-routing\b"],     # IOS XR
    "msdp":           [r"^ip msdp\b",      # IOS XE
                       r"^router msdp\b"],  # IOS XR
    "mld":            [r"^\s+ipv6 mld\b",  # IOS XE: interface sub-mode
                       r"^router mld\b"],   # IOS XR: global section

    # ---- VRF ----
    # IOS XE 15.x+: "vrf definition"; legacy: "ip vrf". IOS XR: global "vrf <name>".
    "vrf":            [r"^vrf definition\b", r"^ip vrf\b",  # IOS XE
                       r"^vrf \S+"],                         # IOS XR

    # ---- Security / policy ----
    "acl":            [r"^ip access-list\b", r"^access-list \d+",       # IOS XE
                       r"^ipv4 access-list\b", r"^ipv6 access-list\b"],  # IOS XR
    "dot1x":          [r"^dot1x\b", r"^\s+authentication port-control\b"],  # IOS XE

    # ---- L2 switching (never matches on L3-only IOS XR) ----
    # Also fires on switchport trunk/access so VTP-managed or minimal-config
    # switches without explicit "vlan <n>" entries still collect VLAN data.
    "vlan":           [r"^vlan \d+", r"^\s+switchport mode (?:trunk|access)"],

    # ---- Overlay technologies (IOS XE only) ----
    "lisp":           [r"^router lisp\b"],
    "vxlan":          [r"^interface nve\b", r"^\s+vxlan\b"],

    # ---- IPv6 neighbour discovery (interface sub-mode, XE and XR) ----
    "nd":             [r"^\s+ipv6 nd\b"],

    # ---- Static routing ----
    "static_routing": [r"^ip route\b", r"^ipv6 route\b",  # IOS XE
                       r"^router static\b"],               # IOS XR
}

#: Patterns compiled once at import time (not per call) — the regex engine
#: builds each state machine a single time even when N devices run in parallel.
_COMPILED_KEYWORDS: dict[str, list[re.Pattern]] = {
    family: [re.compile(pattern, re.MULTILINE) for pattern in patterns]
    for family, patterns in PROTOCOL_KEYWORDS.items()
}


def discover_protocols(running_config_text: str) -> list[str]:
    """Return the sorted Genie families to learn for a device.

    Combines the six :data:`ALWAYS_COLLECT` core families with any extra
    families whose keyword appears in ``running_config_text``. Only the returned
    families get a ``device.learn()`` call in the pyATS adapter.

    Args:
        running_config_text: Raw ``show running-config`` text. Empty or
            whitespace-only input returns the core set alone (a device that
            could not return its config still gets baseline collection).

    Returns:
        Sorted, deduplicated family names — at minimum the six core families.
        Example for a core IOS XE switch running OSPF, BGP, NTP, VLANs, STP and
        HSRP::

            ['arp', 'bgp', 'fdb', 'hsrp', 'interface', 'lldp', 'ntp',
             'ospf', 'platform', 'routing', 'stp', 'vlan']
    """
    discovered: set[str] = set(ALWAYS_COLLECT)

    # A device that failed to return its running config still gets the core set
    # rather than an error — collection continues gracefully.
    if not running_config_text or not running_config_text.strip():
        log.debug("discover_protocols: empty config — returning core set only")
        return sorted(discovered)

    # any() short-circuits on the first matching pattern per family.
    for family, compiled_patterns in _COMPILED_KEYWORDS.items():
        if any(pat.search(running_config_text) for pat in compiled_patterns):
            discovered.add(family)
            log.debug("discover_protocols: detected '%s'", family)

    result = sorted(discovered)
    log.debug("discover_protocols: %d families — %s", len(result), ", ".join(result))
    return result
