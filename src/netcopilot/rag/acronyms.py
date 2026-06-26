"""Networking acronym expansion for RAG embedding quality.

Embedding models like all-MiniLM-L6-v2 are trained on general text — they
don't know "OSPF" means "Open Shortest Path First". Expanding acronyms
before embedding raises retrieval recall on operator queries that use the
short form.

Applied at BOTH:
    - Ingest time: chunk text gets acronyms appended in parentheses once
    - Query time:  user query gets acronyms appended in parentheses once

We append the expansion (rather than replacing) so that exact-match terms
still survive — useful for cases where the doc itself only uses the acronym.
"""

from __future__ import annotations

import re

ACRONYMS: dict[str, str] = {
    # Routing protocols
    "OSPF": "Open Shortest Path First routing protocol",
    "BGP": "Border Gateway Protocol",
    "EIGRP": "Enhanced Interior Gateway Routing Protocol",
    "RIP": "Routing Information Protocol",
    "ISIS": "Intermediate System to Intermediate System routing",
    "IS-IS": "Intermediate System to Intermediate System routing",
    "PIM": "Protocol Independent Multicast",
    "MPLS": "Multiprotocol Label Switching",
    "LDP": "Label Distribution Protocol",
    "RSVP": "Resource Reservation Protocol",
    "SR": "Segment Routing",
    "SR-MPLS": "Segment Routing over MPLS",
    "SRv6": "Segment Routing over IPv6",
    "EVPN": "Ethernet Virtual Private Network",
    "VXLAN": "Virtual Extensible LAN overlay",
    # First-hop redundancy
    "VRRP": "Virtual Router Redundancy Protocol",
    "HSRP": "Hot Standby Router Protocol",
    "GLBP": "Gateway Load Balancing Protocol",
    # L2
    "STP": "Spanning Tree Protocol",
    "RSTP": "Rapid Spanning Tree Protocol",
    "MSTP": "Multiple Spanning Tree Protocol",
    "PVST": "Per VLAN Spanning Tree",
    "VLAN": "Virtual LAN",
    "VTP": "VLAN Trunking Protocol",
    "DTP": "Dynamic Trunking Protocol",
    "LACP": "Link Aggregation Control Protocol",
    "PAgP": "Port Aggregation Protocol",
    "LLDP": "Link Layer Discovery Protocol",
    "CDP": "Cisco Discovery Protocol",
    "UDLD": "UniDirectional Link Detection",
    "BPDU": "Bridge Protocol Data Unit",
    # VPN / overlay
    "DMVPN": "Dynamic Multipoint Virtual Private Network",
    "NHRP": "Next Hop Resolution Protocol",
    "GRE": "Generic Routing Encapsulation tunnel",
    "IPsec": "Internet Protocol Security",
    "IKE": "Internet Key Exchange",
    "SSL": "Secure Sockets Layer",
    "TLS": "Transport Layer Security",
    # Forwarding / VRF
    "VRF": "Virtual Routing and Forwarding instance",
    "RD": "Route Distinguisher",
    "RT": "Route Target",
    "FIB": "Forwarding Information Base",
    "RIB": "Routing Information Base",
    "CEF": "Cisco Express Forwarding",
    # Security
    "ACL": "Access Control List",
    "AAA": "Authentication Authorization and Accounting",
    "TACACS": "Terminal Access Controller Access-Control System",
    "TACACS+": "Terminal Access Controller Access-Control System Plus",
    "RADIUS": "Remote Authentication Dial-In User Service",
    "MAB": "MAC Authentication Bypass",
    "DAI": "Dynamic ARP Inspection",
    "DHCPSnoop": "DHCP Snooping",
    "uRPF": "Unicast Reverse Path Forwarding",
    "DAC": "Dynamic Access Control",
    "CTS": "Cisco TrustSec",
    "SGT": "Security Group Tag",
    "MACsec": "Media Access Control Security",
    # NAT / addressing
    "NAT": "Network Address Translation",
    "PAT": "Port Address Translation",
    "DHCP": "Dynamic Host Configuration Protocol",
    "DNS": "Domain Name System",
    "ARP": "Address Resolution Protocol",
    "ND": "Neighbor Discovery",
    # QoS
    "QoS": "Quality of Service",
    "CoS": "Class of Service",
    "DSCP": "Differentiated Services Code Point",
    "WRED": "Weighted Random Early Detection",
    "CBWFQ": "Class-Based Weighted Fair Queueing",
    "LLQ": "Low Latency Queueing",
    "MQC": "Modular QoS CLI",
    "CIR": "Committed Information Rate",
    "PIR": "Peak Information Rate",
    # Management
    "SNMP": "Simple Network Management Protocol",
    "SNMPv3": "Simple Network Management Protocol version 3",
    "NTP": "Network Time Protocol",
    "PTP": "Precision Time Protocol",
    "syslog": "system logging",
    "NETCONF": "Network Configuration Protocol",
    "RESTCONF": "REST-based Configuration Protocol",
    "YANG": "YANG data modeling language",
    "gNMI": "gRPC Network Management Interface",
    # Hardware / platform
    "HA": "High Availability cluster",
    "VSS": "Virtual Switching System",
    "VSL": "Virtual Switch Link",
    "SVL": "StackWise Virtual Link",
    "FHRP": "First Hop Redundancy Protocol",
    "ASIC": "Application Specific Integrated Circuit",
    "TCAM": "Ternary Content Addressable Memory",
    # FortiGate specific
    "FGSP": "FortiGate Session Life Support Protocol",
    "FGCP": "FortiGate Cluster Protocol",
    "VDOM": "Virtual Domain",
    "SD-WAN": "Software Defined WAN",
    "SDWAN": "Software Defined WAN",
    # General
    "MTU": "Maximum Transmission Unit",
    "TTL": "Time To Live",
    "ECMP": "Equal Cost Multi Path routing",
    "L2": "Layer 2 data link",
    "L3": "Layer 3 network",
    "WAN": "Wide Area Network",
    "LAN": "Local Area Network",
    "DC": "Data Center",
    "SP": "Service Provider",
    "ISP": "Internet Service Provider",
    "AS": "Autonomous System",
    "ASN": "Autonomous System Number",
    "POE": "Power over Ethernet",
    "PoE": "Power over Ethernet",
}

# Build a single regex that matches any acronym as a whole word.
# Word boundary semantics: we match acronyms surrounded by non-alphanumeric
# characters (or string ends), case-sensitive — we do NOT want to expand
# "as" inside "asymmetric".
_ACRONYM_KEYS = sorted(ACRONYMS.keys(), key=len, reverse=True)
_ACRONYM_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(" + "|".join(re.escape(k) for k in _ACRONYM_KEYS) + r")(?![A-Za-z0-9])"
)


def expand(text: str) -> str:
    """Append the expansion of each known acronym after its first occurrence.

    Idempotent: subsequent occurrences of the same acronym are NOT re-expanded
    in the same string. This keeps embeddings clean and avoids quadratic blow-up
    on long chunks.

    Example:
        >>> expand("Configure OSPF on the BGP router. OSPF requires...")
        'Configure OSPF (Open Shortest Path First routing protocol) on the BGP (Border Gateway Protocol) router. OSPF requires...'
    """
    if not text:
        return text
    seen: set[str] = set()

    def _sub(match: re.Match[str]) -> str:
        token = match.group(1)
        if token in seen:
            return token
        seen.add(token)
        return f"{token} ({ACRONYMS[token]})"

    return _ACRONYM_PATTERN.sub(_sub, text)


def known_acronyms() -> list[str]:
    """Return a sorted list of known acronyms (for diagnostics/tests)."""
    return sorted(ACRONYMS.keys())
