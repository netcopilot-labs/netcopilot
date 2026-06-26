"""Deprecated-rule manifest — single source of truth for rules whose findings
must not be rendered in the dashboard (DeviceDetail Audit tab, FindingsPage).

A rule lands here when it has been marked ``is_enabled() → False`` in its
implementation and we also want pre-existing findings from past runs hidden
from the UI (rule code alone only blocks NEW findings; historical findings
are already persisted to Neo4j / JSON).

Invariant (enforced by the deprecated-rule contract test):
    rule.is_enabled() == False  ⇔  rule.rule_id in DEPRECATED_RULE_IDS

If you disable a rule, add its rule_id here. If you re-enable a rule, remove
its rule_id from here.
"""

# Rules whose findings the dashboard hides at render time. Each entry has a
# matching ``is_enabled() → False`` override in the rule implementation.
#
# - STATIC_ROUTE_NO_REDUNDANCY (rules/rules/static_route_rules.py): a single
#   next-hop is valid design when only one L3 path exists; the rule cannot
#   detect whether a backup is physically possible.
# - VLAN_MISSING_SVI (rules/rules/routing_advanced.py): L2-only VLANs are a
#   valid design choice without declared-intent data.
# - INTF_ADMIN_DOWN (rules/rules/intf_advanced.py): no declared-intent data to
#   validate an administratively-down state.
DEPRECATED_RULE_IDS: frozenset[str] = frozenset({
    "STATIC_ROUTE_NO_REDUNDANCY",
    "VLAN_MISSING_SVI",
    "INTF_ADMIN_DOWN",
})
