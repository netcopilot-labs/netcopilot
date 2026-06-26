"""F4a-3: the agent system prompt — loads, describes the OSS tool set, no leaks.

The prompt is the highest-prose-density artifact in the agent layer, so it gets
an explicit guard test in addition to the denylist scan.
"""

from netcopilot.orchestrator import SYSTEM_PROMPT
from netcopilot.prompts import load_system_prompt

# The 5 tools excluded from the OSS build (Catalyst Center + 4 NetBox).
EXCLUDED_TOOLS = [
    "query_catalyst_center",
    "get_netbox_device",
    "get_netbox_site",
    "list_netbox_pending_writes",
    "get_netbox_write_history",
]

# A sample of the 24 OSS tools that must have routing rules.
OSS_TOOLS = [
    "get_device_detail", "query_topology", "get_findings", "blast_radius",
    "explain_finding", "get_routing_table", "get_firewall_policies",
    "get_security_policies", "lookup_vendor_docs", "generate_report",
    "trace_path", "list_capabilities",
]


def test_prompt_loads_and_is_cached():
    assert load_system_prompt() is load_system_prompt()  # lru_cache
    assert SYSTEM_PROMPT == load_system_prompt()
    assert len(SYSTEM_PROMPT) > 1000


def test_no_excluded_tools_referenced():
    for tool in EXCLUDED_TOOLS:
        assert tool not in SYSTEM_PROMPT, f"excluded tool '{tool}' leaked into the prompt"
    # No NetBox / Catalyst Center prose either.
    low = SYSTEM_PROMPT.lower()
    assert "netbox" not in low and "catalyst center" not in low


def test_all_sampled_oss_tools_present():
    for tool in OSS_TOOLS:
        assert tool in SYSTEM_PROMPT, f"OSS tool '{tool}' missing routing rule"

# Note: private-environment-marker coverage on the prompt is enforced by
# internal/vet/denylist-scan.sh (runs on every commit, scans every file
# including agent_system.txt). A test that hardcoded those markers would
# itself trip the scanner, so the canonical gate owns that check.
