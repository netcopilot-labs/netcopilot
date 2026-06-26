"""Onboarding tools — first-touch help that needs no network data.

Three tools:
  - about_netcopilot  → verbatim product description (package-data text)
  - dashboard_guide   → verbatim dashboard tour (package-data text)
  - list_capabilities → categorized capability menu, auto-derived from the
                        live tool registry so it can never go stale

The about/guide texts are static and quoted verbatim per the system prompt.
The capability menu's categories reflect operator mental models (not tool
taxonomy); the per-category tool list is derived from TOOL_SCHEMAS at call time,
and any tool missing from the mapping below lands in an OTHER bucket so it stays
visible (a coverage test flags the omission).
"""

from __future__ import annotations

from netcopilot.prompts import load_about, load_dashboard_guide


async def about_netcopilot(*, context: dict) -> str:
    """Return the canonical NetCopilot product description, verbatim."""
    return load_about()


async def dashboard_guide(*, context: dict) -> str:
    """Return the canonical NetCopilot dashboard tour, verbatim."""
    return load_dashboard_guide()


# ── Capability menu ──────────────────────────────────────────────────────────
# Operator-mental-model buckets, not technical taxonomy. When you add a tool to
# the registry, add it here too — the coverage test fails otherwise.

_CAT_EXPLORE = "explore"
_CAT_TROUBLESHOOT = "troubleshoot"
_CAT_TRACE = "trace"
_CAT_SECURITY = "security"
_CAT_VENDOR_DOCS = "vendor_docs"
_CAT_REPORTS = "reports"
_CAT_ABOUT = "about"
_CAT_OTHER = "other"

_TOOL_CATEGORIES: dict[str, str] = {
    # 🔍 EXPLORE THE NETWORK
    "query_topology":            _CAT_EXPLORE,
    "get_device_detail":         _CAT_EXPLORE,
    "get_network_neighborhood":  _CAT_EXPLORE,
    "get_site_summary":          _CAT_EXPLORE,
    "get_shared_services":       _CAT_EXPLORE,
    # 🔥 TROUBLESHOOT PROBLEMS
    "get_findings":              _CAT_TROUBLESHOOT,
    "explain_finding":           _CAT_TROUBLESHOOT,
    "analyze_findings":          _CAT_TROUBLESHOOT,
    "get_systemic_patterns":     _CAT_TROUBLESHOOT,
    # 🛣 TRACE TRAFFIC AND IMPACT
    "trace_path":                _CAT_TRACE,
    "blast_radius":              _CAT_TRACE,
    "get_redundancy_assessment": _CAT_TRACE,
    "get_routing_table":         _CAT_TRACE,
    "get_ospf_detail":           _CAT_TRACE,
    # 🛡 SECURITY AND POLICIES
    "get_security_posture":      _CAT_SECURITY,
    "get_firewall_policies":     _CAT_SECURITY,
    "get_security_policies":     _CAT_SECURITY,
    "get_traffic_shapers":       _CAT_SECURITY,
    # 📚 LOOK UP VENDOR DOCUMENTATION
    "lookup_vendor_docs":        _CAT_VENDOR_DOCS,
    "lookup_network_knowledge":  _CAT_VENDOR_DOCS,
    # 📊 REPORTS & DOCUMENTS
    "generate_report":           _CAT_REPORTS,
    # 📖 ABOUT NETCOPILOT
    "about_netcopilot":          _CAT_ABOUT,
    "dashboard_guide":           _CAT_ABOUT,
    "list_capabilities":         _CAT_ABOUT,
}

_CATEGORIES_ORDER = [
    _CAT_EXPLORE,
    _CAT_TROUBLESHOOT,
    _CAT_TRACE,
    _CAT_SECURITY,
    _CAT_VENDOR_DOCS,
    _CAT_REPORTS,
    _CAT_ABOUT,
]

_CATEGORY_RENDER: dict[str, dict] = {
    _CAT_EXPLORE: {
        "header": "🔍 EXPLORE THE NETWORK",
        "subtitle": "What's in here? Who's connected to what?",
        "bullets": [
            "Devices, links, and how the network is structured",
            "Detailed information about a single device",
            "What is connected to a device, and how",
            "Operational summary of a site",
            "VLANs, subnets, OSPF areas, BGP ASNs, IP lookups",
        ],
        "examples": [
            "What devices are in my network?",
            "What is connected to core-rtr-01?",
        ],
    },
    _CAT_TROUBLESHOOT: {
        "header": "🔥 TROUBLESHOOT PROBLEMS",
        "subtitle": "What's broken? What matters most? How do I fix it?",
        "bullets": [
            "Active findings and compliance violations",
            "Why a finding matters and how to fix it",
            "Priority ranking and per-device remediation steps",
            "Systemic issues spanning multiple devices",
        ],
        "examples": [
            "What are the most critical findings right now?",
            "How do I fix the BGP authentication issue on border-rtr-01?",
        ],
    },
    _CAT_TRACE: {
        "header": "🛣 TRACE TRAFFIC AND IMPACT",
        "subtitle": "Where does traffic flow? What breaks if X fails?",
        "bullets": [
            "Hop-by-hop path tracing across the network",
            "What breaks if a device or member fails",
            "Single points of failure and HA status",
            "Routing table for any device or VRF",
            "OSPF processes, areas, neighbors, and timers",
        ],
        "examples": [
            "How does traffic reach the internet?",
            "What happens if the firewall fails?",
        ],
    },
    _CAT_SECURITY: {
        "header": "🛡 SECURITY AND POLICIES",
        "subtitle": "Is the network secure? What rules are enforced?",
        "bullets": [
            "Security configuration: AAA, SSH, SNMP, NTP, logging",
            "Firewall rules and access lists",
            "QoS traffic shaping and policing",
        ],
        "examples": [
            "Is the security posture acceptable on the core router?",
            "Show me the firewall rules on fw-01",
        ],
    },
    _CAT_VENDOR_DOCS: {
        "header": "📚 LOOK UP VENDOR DOCUMENTATION",
        "subtitle": "How do I configure X? What does this command do?",
        "bullets": [
            "Cisco IOS-XE, IOS-XR, and FortiOS CLI reference",
            "Conceptual networking knowledge across vendors",
        ],
        "footer": (
            "Works without any network data loaded — useful for onboarding, "
            "training, or quick syntax lookups."
        ),
        "examples": [
            "How do I configure VRRP on a Cisco IOS-XE switch?",
            "Explain BGP route reflectors in plain English",
        ],
    },
    _CAT_REPORTS: {
        "header": "📊 REPORTS & DOCUMENTS",
        "subtitle": "Save the network state. Email the next shift.",
        "bullets": [
            "Shift handover report (network health, finding delta, top criticals)",
            "Investigation snapshot (case file from the current chat conversation)",
            "Send by email or download as PDF",
        ],
        "examples": [
            "Make a general report and send it by email",
            "Make a report of this conversation",
        ],
    },
    _CAT_ABOUT: {
        "header": "📖 ABOUT NETCOPILOT",
        "subtitle": "What is this? How does it work?",
        "bullets": [
            "What NetCopilot is and what makes it different",
            "How the dashboard is organized and what each panel does",
            "This menu, anytime",
        ],
        "examples": [
            "What is NetCopilot?",
            "How does this dashboard work?",
        ],
    },
}

_OPENING_LINE = (
    "NetCopilot is a network operations assistant. Here's what I can help "
    "you with — organized by what you're trying to do:"
)


def _category_for(tool_name: str) -> str:
    """Return a tool's category, falling back to OTHER if uncategorized."""
    return _TOOL_CATEGORIES.get(tool_name, _CAT_OTHER)


def _render_category(cat_key: str) -> str:
    """Render one category as plain text."""
    cat = _CATEGORY_RENDER[cat_key]
    lines = [cat["header"], f"   {cat['subtitle']}", ""]
    for bullet in cat["bullets"]:
        lines.append(f"   • {bullet}")
    if cat.get("footer"):
        lines.append("")
        lines.append(f"   {cat['footer']}")
    lines.append("")
    lines.append("   Try:")
    for ex in cat["examples"]:
        lines.append(f'     "{ex}"')
    return "\n".join(lines)


def _render_other_bucket(uncategorized_tools: list[str]) -> str:
    """Render the fallback bucket for tools not in _TOOL_CATEGORIES."""
    if not uncategorized_tools:
        return ""
    from netcopilot.mcp.registry import TOOL_SCHEMAS

    schemas_by_name = {s["name"]: s for s in TOOL_SCHEMAS}
    lines = ["🆕 OTHER CAPABILITIES", "   Recently added — not yet categorized.", ""]
    for name in uncategorized_tools:
        desc = schemas_by_name.get(name, {}).get("description", "")
        if desc:
            short_desc = desc.split(".")[0].strip()
            if len(short_desc) > 100:
                short_desc = short_desc[:100] + "…"
            lines.append(f"   • {short_desc}")
        else:
            lines.append(f"   • {name}")
    return "\n".join(lines)


async def list_capabilities(*, context: dict) -> str:
    """Return the categorized capability menu, auto-derived from TOOL_SCHEMAS."""
    from netcopilot.mcp.registry import TOOL_SCHEMAS

    by_category: dict[str, list[str]] = {cat: [] for cat in _CATEGORIES_ORDER}
    by_category[_CAT_OTHER] = []
    for schema in TOOL_SCHEMAS:
        by_category.setdefault(_category_for(schema["name"]), []).append(schema["name"])

    parts: list[str] = [_OPENING_LINE, "", ""]
    for cat_key in _CATEGORIES_ORDER:
        parts.append(_render_category(cat_key))
        parts.append("")
        parts.append("")

    other_tools = by_category.get(_CAT_OTHER, [])
    if other_tools:
        parts.append(_render_other_bucket(other_tools))
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def get_categorized_tool_names() -> dict[str, list[str]]:
    """Diagnostic helper for tests — the tool→category grouping the menu renders."""
    from netcopilot.mcp.registry import TOOL_SCHEMAS

    by_cat: dict[str, list[str]] = {}
    for schema in TOOL_SCHEMAS:
        by_cat.setdefault(_category_for(schema["name"]), []).append(schema["name"])
    return by_cat
