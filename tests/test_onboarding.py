"""F4b-1: onboarding tools — about / dashboard_guide / list_capabilities.

Static/registry-derived, no Neo4j. Verifies verbatim returns, menu coverage of
the live registry, and that the OSS-excluded tools never surface.
"""

import asyncio

from netcopilot.mcp import registry
from netcopilot.mcp.tools import onboarding
from netcopilot.prompts import load_about, load_dashboard_guide

EXCLUDED = {
    "query_catalyst_center", "get_netbox_device", "get_netbox_site",
    "list_netbox_pending_writes", "get_netbox_write_history",
}


def test_about_returns_verbatim_text():
    out = asyncio.run(onboarding.about_netcopilot(context={}))
    assert out == load_about()
    assert "NetCopilot is the expert network operations assistant" in out
    # OSS build does not claim Catalyst Center / NetBox integration.
    low = out.lower()
    assert "catalyst center" not in low and "netbox" not in low


def test_dashboard_guide_returns_verbatim_text():
    out = asyncio.run(onboarding.dashboard_guide(context={}))
    assert out == load_dashboard_guide()
    # all 5 view modes named
    for view in ["Physical", "MGMT", "L2/L3", "OSPF", "BGP"]:
        assert view in out


def test_list_capabilities_renders_categories():
    out = asyncio.run(onboarding.list_capabilities(context={}))
    for header in ["EXPLORE THE NETWORK", "TROUBLESHOOT PROBLEMS",
                   "TRACE TRAFFIC AND IMPACT", "SECURITY AND POLICIES",
                   "LOOK UP VENDOR DOCUMENTATION", "ABOUT NETCOPILOT"]:
        assert header in out
    # no leftover EXTERNAL / DECLARED STATE categories from the source
    assert "EXTERNAL SYSTEMS" not in out and "DECLARED STATE" not in out


def test_every_registered_tool_is_categorized():
    """Coverage gate: nothing lands in the OTHER bucket (all tools categorized)."""
    grouped = onboarding.get_categorized_tool_names()
    assert grouped.get(onboarding._CAT_OTHER, []) == [], (
        f"uncategorized tools: {grouped.get(onboarding._CAT_OTHER)}"
    )
    # every registered tool name appears in exactly one category
    registered = {s["name"] for s in registry.TOOL_SCHEMAS}
    categorized = {name for names in grouped.values() for name in names}
    assert registered == categorized


def test_no_excluded_tools_in_categories():
    for tool in EXCLUDED:
        assert tool not in onboarding._TOOL_CATEGORIES


def test_dispatch_routes_onboarding_tools():
    for name in ["about_netcopilot", "dashboard_guide", "list_capabilities"]:
        out = asyncio.run(registry.dispatch(name, {}, {"run_id": "x"}))
        assert out and "tool" not in out[:20].lower()  # not an error string
