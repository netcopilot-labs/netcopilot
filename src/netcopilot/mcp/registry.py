"""MCP tool registry — schemas (for the LLM) + dispatch to handlers.

Schemas use the normalized shape the LLM abstraction expects:
``{name, description, parameters}``. The orchestrator passes these to the provider
and routes the model's tool calls back through ``dispatch``.
"""

from __future__ import annotations

import logging
import os

from .tools import (
    analysis,
    analyze,
    correlation,
    device,
    explain,
    findings,
    firewall,
    neighborhood,
    onboarding,
    ospf,
    path_tracer,
    rag,
    report,
    redundancy,
    routing,
    security,
    security_policies,
    shared_services,
    site_summary,
    topology,
    traffic_shapers,
)

log = logging.getLogger(__name__)

MAX_RESULT_CHARS = int(os.environ.get("MCP_MAX_RESULT_CHARS", "32000"))

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "query_topology",
        "description": (
            "Get network topology: devices, physical links, routing adjacencies "
            "(OSPF/BGP). Call this first for any question about network structure, "
            "device inventory, or site connectivity."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "site": {
                    "type": "string",
                    "description": "Filter by site name. Omit to use the current run's site.",
                },
                "device_filter": {
                    "type": "string",
                    "description": "Filter devices by name substring (case-insensitive).",
                },
                "include_links": {
                    "type": "boolean",
                    "description": "Include physical link data. Default: true.",
                },
                "include_services": {
                    "type": "boolean",
                    "description": "Include shared services (VLANs, BGP ASNs). Default: false.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_findings",
        "description": (
            "Get deterministic rule-engine findings. Use for any question about "
            "problems, compliance violations, or network health. Filter by device, "
            "severity, or category to narrow results."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Exact device name."},
                "severity": {"type": "string", "enum": ["critical", "high", "low", "info"]},
                "category": {
                    "type": "string",
                    "enum": ["bgp", "ospf", "security", "interface", "topology", "routing", "cluster", "qos"],
                },
                "acknowledged": {
                    "type": "boolean",
                    "description": "Filter by acknowledgement status. Omit for all.",
                },
                "limit": {"type": "integer", "description": "Max findings. Default: 20."},
            },
            "required": [],
        },
    },
    {
        "name": "blast_radius",
        "description": (
            "Analyse the impact of a device failure: directly affected devices, links "
            "lost, and redundancy degradation. Use for 'what happens if X fails?' questions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Target device name (required)."},
                "member": {"type": "integer", "description": "Cluster member ID for single-member failure analysis."},
                "interface": {"type": "string", "description": "Specific interface (optional)."},
                "max_hops": {"type": "integer", "description": "Traversal depth. Default: 3."},
            },
            "required": ["device"],
        },
    },
    {
        "name": "explain_finding",
        "description": (
            "Remediation for one rule: why it matters + OS-specific CLI to fix it "
            "(interpolated from the finding's evidence). Use for 'why does this "
            "matter', 'how do I fix <rule>'. Pass device for OS-specific CLI."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "Rule identifier (required)."},
                "device": {"type": "string", "description": "Device for OS-specific remediation CLI."},
            },
            "required": ["rule_id"],
        },
    },
    {
        "name": "analyze_findings",
        "description": (
            "Full analysis of a rule: per-device priority ranking by blast-radius "
            "risk, correlation patterns, and per-OS remediation CLI with real values. "
            "Use for 'analyze', 'prioritize', 'what should I fix first', 'remediate "
            "<rule>'. Present ALL sections fully."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "Rule identifier (required)."},
                "device": {"type": "string", "description": "Limit analysis to this device."},
            },
            "required": ["rule_id"],
        },
    },
    {
        "name": "get_device_detail",
        "description": (
            "Full state for one device: metadata, interfaces, BGP/OSPF adjacencies, "
            "routing summary, findings, and security config. Call this first for "
            "'what is / tell me about / purpose of' a device. NOT for 'what is "
            "connected to X' — use get_network_neighborhood."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name (required)."},
                "sections": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["interfaces", "routing", "bgp", "ospf", "findings", "security"]},
                    "description": "Limit to these sections. Omit for all.",
                },
            },
            "required": ["device"],
        },
    },
    {
        "name": "get_shared_services",
        "description": (
            "VLAN / subnet / OSPF-area / BGP-ASN membership. Use for 'which devices "
            "share VLAN 99?', 'what VRFs on device X?', 'which devices are in OSPF "
            "area 0.0.0.10?', or an IP-owner lookup (ip= param)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "service_type": {"type": "string", "description": "Filter by type (vlan, subnet, ospf_area, bgp_asn)."},
                "name": {"type": "string", "description": "Specific service identifier/name to show membership for."},
                "device": {"type": "string", "description": "Show all services for this device."},
                "ip": {"type": "string", "description": "Look up which device/interface/VLAN owns this IP."},
            },
            "required": [],
        },
    },
    {
        "name": "get_systemic_patterns",
        "description": (
            "Systemic issues spanning multiple devices — shared vulnerabilities "
            "between redundant pairs, multi-plane authentication gaps, and area-wide "
            "rule violations. Use for 'any systemic patterns?', 'shared "
            "vulnerabilities?'. NOT for single-device failures (use blast_radius)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "insight_type": {"type": "string", "enum": ["auth_surface", "shared_vulnerabilities", "area_patterns"], "description": "Filter to one pattern type."},
                "device": {"type": "string", "description": "Filter to patterns involving this device."},
            },
            "required": [],
        },
    },
    {
        "name": "get_redundancy_assessment",
        "description": (
            "Network redundancy + single-point-of-failure analysis: HA/cluster status, "
            "path redundancy, LAG uplinks, and what gets isolated if each device fails. "
            "Use for 'is the network redundant?', 'what are the single points of "
            "failure?'. For failure IMPACT of one device, use blast_radius instead."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Per-device assessment. Omit for a network-wide overview."},
            },
            "required": [],
        },
    },
    {
        "name": "trace_path",
        "description": (
            "Trace traffic hop-by-hop across L2 trunks, L3 routing, VRF boundaries, "
            "firewalls, and BGP exits. ALWAYS use for 'how does traffic reach the "
            "internet?', 'what path does X take?', 'does traffic cross the firewall?', "
            "and '[service] has no internet' (use service= param — searches interface "
            "descriptions, works on any network)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "source_device": {"type": "string", "description": "Starting device name."},
                "service": {"type": "string", "description": "Service/customer keyword to resolve to a source device + VRF."},
                "destination": {"type": "string", "description": "Destination IP or 'internet' (default)."},
                "vrf": {"type": "string", "description": "VRF to trace through (auto-picked if omitted)."},
                "max_hops": {"type": "integer", "description": "Max hops (default 10, capped at 20)."},
            },
            "required": [],
        },
    },
    {
        "name": "get_security_posture",
        "description": (
            "Security configuration: AAA, SSH, SNMP, NTP, logging, TACACS/RADIUS, "
            "console/VTY, services. Per-device, or a network-wide overview when no "
            "device is given. Use for 'is SSH secure?', 'security posture', 'SNMP "
            "configuration'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name. Omit for a network-wide overview."},
            },
            "required": [],
        },
    },
    {
        "name": "get_security_policies",
        "description": (
            "Cisco ACLs (with per-ACE detail incl. DENY rows), IOS XE route-maps / "
            "IOS XR route-policies (inline body), and prefix-lists / prefix-sets. "
            "Use for 'what ACLs on border-rtr-01?', 'explain the route policies on "
            "this border router', 'show prefix-sets'. NOT for FortiGate — use "
            "get_firewall_policies for that."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name (required)."},
                "kind": {"type": "string", "enum": ["all", "acl", "route-policy", "prefix-set"], "description": "Filter by kind. Default all."},
                "name": {"type": "string", "description": "Substring match on the policy/ACL/prefix-set name."},
            },
            "required": ["device"],
        },
    },
    {
        "name": "get_firewall_policies",
        "description": (
            "FortiGate zone-based firewall rules and Cisco ACLs (with resolved "
            "addresses + services). Filter by device, zone pair, action, or service. "
            "Use for 'what firewall rules exist?', 'is traffic from X to Y permitted?', "
            "'show deny rules on fw-01'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Filter by device name."},
                "source_zone": {"type": "string", "description": "Filter by source zone/interface."},
                "dest_zone": {"type": "string", "description": "Filter by destination zone/interface."},
                "action": {"type": "string", "description": "Filter by action (accept/permit/deny)."},
                "service": {"type": "string", "description": "Filter by service name substring."},
            },
            "required": [],
        },
    },
    {
        "name": "get_traffic_shapers",
        "description": (
            "QoS policers and shapers on switch ports: per-policy summary (no device "
            "filter) or per-interface detail (with device). Shows CIR rates and "
            "drop/exceed counters. For multi-device queries call ONCE without a device "
            "filter — do not loop per device."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Per-interface detail for this device. Omit for a network-wide summary."},
                "policy_name": {"type": "string", "description": "Filter by QoS policy name substring."},
                "min_rate": {"type": "integer", "description": "Only policies with CIR >= this many Mbps."},
            },
            "required": [],
        },
    },
    {
        "name": "get_network_neighborhood",
        "description": (
            "N-hop graph traversal from a device: direct neighbors with link types, "
            "shared VLANs/OSPF areas, BGP sessions, and per-neighbor finding counts. "
            "PREFER this over query_topology for 'what is connected to X?', 'show me "
            "the neighborhood', 'what is 2 hops from X?'. hops=1-4 (default 1)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name (required)."},
                "hops": {"type": "integer", "description": "Traversal depth 1-4. Default 1."},
            },
            "required": ["device"],
        },
    },
    {
        "name": "get_site_summary",
        "description": (
            "Per-site operational summary: devices by role, redundancy (HA clusters), "
            "OSPF areas, BGP sessions, finding counts, and uplinks to other sites. "
            "Use for 'summarize site X', 'how many devices in <site>?', 'which sites "
            "have critical findings?'. Omit the param for a network-wide rollup."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "building": {"type": "string", "description": "Site/building label to summarize. Omit for all."},
            },
            "required": [],
        },
    },
    {
        "name": "get_routing_table",
        "description": (
            "Routing table for a device, with protocol, next-hop, AD, and metric. "
            "Use for traffic-path questions, backup routes, 'how does traffic reach X?'. "
            "Filter by VRF or protocol."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name (required)."},
                "vrf": {"type": "string", "description": "Filter by VRF name."},
                "protocol": {"type": "string", "description": "Filter by protocol (ospf, bgp, static, connected)."},
            },
            "required": ["device"],
        },
    },
    {
        "name": "get_ospf_detail",
        "description": (
            "OSPF processes, areas, interfaces, neighbors, timers, and authentication. "
            "Use for 'is OSPF authenticated?', 'which devices in area X?', or an OSPF "
            "overview. Omit both params for the network-wide area overview."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name for per-device OSPF detail."},
                "area": {"type": "string", "description": "OSPF area id for area membership/adjacencies."},
            },
            "required": [],
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a NetCopilot report (shown in the dashboard's LEFT panel). "
            "scope='general' = operational status (health, finding delta, top "
            "criticals); scope='conversation' = a case-file of the recent chat "
            "investigation. Preview-then-confirm: it shows the report but never sends "
            "email automatically. Call only on explicit user request."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scope": {"type": "string", "enum": ["general", "conversation"], "description": "Report scope. Default general."},
                "title": {"type": "string", "description": "1-sentence topic (conversation scope)."},
                "question": {"type": "string", "description": "The last user question (conversation scope)."},
                "facts": {"type": "array", "items": {"type": "string"}, "description": "Key facts learned (conversation scope)."},
                "devices_mentioned": {"type": "array", "items": {"type": "string"}, "description": "Devices touched in the chat."},
                "finding_ids_mentioned": {"type": "array", "items": {"type": "string"}, "description": "Finding IDs cited."},
                "tools_used": {"type": "array", "items": {"type": "string"}, "description": "MCP tools called."},
                "conclusions": {"type": "string", "description": "Action items / next steps."},
            },
            "required": [],
        },
    },
    {
        "name": "lookup_vendor_docs",
        "description": (
            "Vendor CLI / configuration documentation (Cisco IOS-XE, IOS-XR, FortiOS) "
            "via RAG over the ingested doc corpus. Use for HOW-TO questions: 'how do I "
            "configure VRRP on a Cisco IOS-XE switch?', 'BGP MD5 auth syntax on IOS-XR?'. "
            "Returns chunks with source citation (document, page). WORKS WITHOUT NETWORK DATA."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The how-to / syntax question (required)."},
                "vendor": {"type": "string", "description": "Filter: cisco | fortinet."},
                "os_family": {"type": "string", "description": "Filter: iosxe | iosxr | fortios."},
                "doc_type": {"type": "string", "description": "Filter by document type."},
                "n_results": {"type": "integer", "description": "Max chunks (1-5). Default 5."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "lookup_network_knowledge",
        "description": (
            "General networking concept questions across all vendor docs (no vendor "
            "filter). Use for 'explain VRRP vs HSRP', 'what is DMVPN?', 'how does OSPF "
            "area 0 work?'. WORKS WITHOUT NETWORK DATA — useful for training and "
            "explanations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The networking concept question (required)."},
                "n_results": {"type": "integer", "description": "Max chunks (1-5). Default 5."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "about_netcopilot",
        "description": (
            "Return the canonical NetCopilot product description. Call for any "
            "identity question about the system itself ('what is NetCopilot', "
            "'what does NetCopilot do'). Quote the result verbatim. No network data needed."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "dashboard_guide",
        "description": (
            "Return the dashboard tour. Call for orientation questions ('how does "
            "the dashboard work', 'give me a tour', 'what are these buttons'). "
            "Quote the result verbatim. No network data needed."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_capabilities",
        "description": (
            "Return the categorized capability menu, auto-derived from the live tool "
            "registry. Call for meta questions ('what can you do', 'menu', 'show me "
            "the capabilities'). Quote the result verbatim. No network data needed."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
]

_HANDLERS = {
    "query_topology": topology.query_topology,
    "get_findings": findings.get_findings,
    "blast_radius": analysis.blast_radius,
    "explain_finding": explain.explain_finding,
    "analyze_findings": analyze.analyze_findings,
    "get_device_detail": device.get_device_detail,
    "get_shared_services": shared_services.get_shared_services,
    "get_network_neighborhood": neighborhood.get_network_neighborhood,
    "get_site_summary": site_summary.get_site_summary,
    "get_firewall_policies": firewall.get_firewall_policies,
    "get_traffic_shapers": traffic_shapers.get_traffic_shapers,
    "get_security_posture": security.get_security_posture,
    "get_security_policies": security_policies.get_security_policies,
    "trace_path": path_tracer.trace_path,
    "get_systemic_patterns": correlation.get_systemic_patterns,
    "get_redundancy_assessment": redundancy.get_redundancy_assessment,
    "lookup_vendor_docs": rag.lookup_vendor_docs,
    "lookup_network_knowledge": rag.lookup_network_knowledge,
    "generate_report": report.generate_report,
    "get_routing_table": routing.get_routing_table,
    "get_ospf_detail": ospf.get_ospf_detail,
    "about_netcopilot": onboarding.about_netcopilot,
    "dashboard_guide": onboarding.dashboard_guide,
    "list_capabilities": onboarding.list_capabilities,
}


async def dispatch(tool_name: str, arguments: dict, context: dict) -> str:
    """Route a tool call to its handler. Never raises; caps result length."""
    if tool_name not in _HANDLERS:
        return f"Unknown tool '{tool_name}'. Available: {', '.join(sorted(_HANDLERS))}"
    try:
        result = await _HANDLERS[tool_name](**arguments, context=context)
    except Exception as exc:
        log.exception("Tool '%s' failed with args %s", tool_name, arguments)
        return f"Tool '{tool_name}' failed: {exc}"
    if len(result) > MAX_RESULT_CHARS:
        result = result[:MAX_RESULT_CHARS] + f"\n\n[Result truncated at {MAX_RESULT_CHARS} chars.]"
    return result
