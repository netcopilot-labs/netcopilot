"""F4a-3: the agent system prompt — loads, describes the OSS tool set, no leaks.

The prompt is the highest-prose-density artifact in the agent layer, so it gets
an explicit guard test in addition to the denylist scan.
"""

from netcopilot.orchestrator import SYSTEM_PROMPT
from netcopilot.prompts import load_system_prompt

# Tools excluded from the OSS build. History: the 4 NetBox tools were on this
# list from extraction until s11 (ADR-0013) reinstated NetBox as the
# declared-state layer — they are now required, see OSS_TOOLS.
EXCLUDED_TOOLS = [
    "query_catalyst_center",
]

# A sample of the OSS tools that must have routing rules (incl. the s11
# NetBox declared-state tools).
OSS_TOOLS = [
    "get_device_detail", "query_topology", "get_findings", "blast_radius",
    "explain_finding", "get_routing_table", "get_firewall_policies",
    "get_cisco_policies", "lookup_vendor_docs", "generate_report",
    "trace_path", "list_capabilities",
    "get_netbox_device", "list_netbox_pending_writes", "get_netbox_write_history",
]


def test_prompt_loads_and_is_cached():
    assert load_system_prompt() is load_system_prompt()  # lru_cache
    assert SYSTEM_PROMPT == load_system_prompt()
    assert len(SYSTEM_PROMPT) > 1000


def test_no_excluded_tools_referenced():
    for tool in EXCLUDED_TOOLS:
        assert tool not in SYSTEM_PROMPT, f"excluded tool '{tool}' leaked into the prompt"
    # No Catalyst Center prose (NetBox prose is expected since s11).
    low = SYSTEM_PROMPT.lower()
    assert "catalyst center" not in low


def test_all_sampled_oss_tools_present():
    for tool in OSS_TOOLS:
        assert tool in SYSTEM_PROMPT, f"OSS tool '{tool}' missing routing rule"

# Note: private-environment-marker coverage on the prompt is enforced by
# internal/vet/denylist-scan.sh (runs on every commit, scans every file
# including agent_system.txt). A test that hardcoded those markers would
# itself trip the scanner, so the canonical gate owns that check.
