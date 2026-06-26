"""Legend metadata endpoint — single source of truth for severity + role styling.

The frontend fetches this on app load (LegendContext) instead of hardcoding JS
constants. No auth required (same as /health) — static display configuration,
not user data.
"""

from fastapi import APIRouter

router = APIRouter()

# ── Severity legend ──────────────────────────────────────────────────────────
# Order + colors match what the rules engine produces and what the findings
# pages, severity filters, and topology map expect. The keys are the single
# source of truth for severity ids.
SEVERITY_LEGEND = [
    {"id": "critical", "order": 0, "color": "#DC2626", "bg": "#FEF2F2"},
    {"id": "high",     "order": 1, "color": "#EA580C", "bg": "#FFF7ED"},
    {"id": "low",      "order": 2, "color": "#CA8A04", "bg": "#FEFCE8"},
    {"id": "info",     "order": 3, "color": "#6B7280", "bg": "#F9FAFB"},
    {"id": "cis",      "order": 4, "color": "#64748B", "bg": "#F8FAFC"},
]

# ── Role legend ──────────────────────────────────────────────────────────────
# Tier = vertical position on the topology map (0 = top, 5 = bottom).
# Color = Cytoscape.js node border/text color.
#
# Standard access/aggregation roles. When a new role appears in your inventory,
# add it HERE and the frontend picks it up on next page load — no JS edit. Any
# role not listed falls back to DEFAULT_ROLE.
ROLE_LEGEND = [
    {"id": "border_router",       "tier": 0, "color": "#1D4ED8"},  # Blue — WAN edge
    {"id": "firewall",            "tier": 1, "color": "#C2410C"},  # Orange — security boundary
    {"id": "core_switch",         "tier": 2, "color": "#6D28D9"},  # Violet — aggregation
    {"id": "dmz_switch",          "tier": 2, "color": "#DC2626"},  # Red — security zone
    {"id": "distribution_switch", "tier": 3, "color": "#7C3AED"},  # Purple — mid-tier
    {"id": "services_switch",     "tier": 3, "color": "#0891B2"},  # Cyan — services layer
    {"id": "access_switch",       "tier": 4, "color": "#6B7280"},  # Grey — edge/access
    {"id": "mgmt_switch",         "tier": 4, "color": "#6B7280"},  # Grey — management plane
    {"id": "external",            "tier": 5, "color": "#9CA3AF"},  # Light grey — uncollected peers
    {"id": "unknown",             "tier": 3, "color": "#9CA3AF"},  # Light grey — catch-all
]

# Default for any role not in the list above.
DEFAULT_ROLE = {"tier": 3, "color": "#9CA3AF"}


@router.get("/api/legend")
def get_legend():
    """Return the full severity + role legend metadata.

    Called by the frontend's LegendContext on app load. Deterministic — same
    response every time. No Neo4j queries, no dynamic data.
    """
    return {
        "severities": SEVERITY_LEGEND,
        "roles": ROLE_LEGEND,
        "default_role": DEFAULT_ROLE,
    }
