"""Graph schema — Neo4j node labels, relationship types, properties, and indexes.

Single source of truth for Neo4j naming so loader and query code use consistent
strings. Constants are plain strings (importable without a Neo4j connection).
Multi-site isolation: every node carries ``site`` + ``run_id``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node labels
# ---------------------------------------------------------------------------
RUN = "Run"
DEVICE = "Device"
INTERFACE = "Interface"
SHARED_SERVICE = "SharedService"
VLAN = "Vlan"
OSPF_LSA = "OspfLsa"
ROUTE = "Route"
FIREWALL_POLICY = "FirewallPolicy"
ARP_ENTRY = "ArpEntry"
FINDING = "Finding"
SECURITY_CONFIG = "SecurityConfig"
ROUTE_POLICY = "RoutePolicy"
PREFIX_SET_ENTRY = "PrefixSetEntry"

# User UI state (kept out of run-data; not deleted by run cleanup)
LAYOUT_POSITION = "LayoutPosition"   # saved node positions per view: (site, view, node_id)
ACKNOWLEDGEMENT = "Acknowledgement"  # finding ack: (site, finding_id), persists across runs
ANNOTATION = "Annotation"            # run-scoped finding note: (run_id, finding_id)


# ---------------------------------------------------------------------------
# Relationship types
# ---------------------------------------------------------------------------
HAS_INTERFACE = "HAS_INTERFACE"           # Device → Interface
HAS_VLAN = "HAS_VLAN"                     # Device → Vlan
PHYSICAL_LINK = "PHYSICAL_LINK"           # Device → Device (legacy)
CONNECTS_TO = "CONNECTS_TO"               # Interface → Interface (port-to-port)
ROUTING_ADJACENCY = "ROUTING_ADJACENCY"   # Device → Device (OSPF/BGP)
MEMBER_OF = "MEMBER_OF"                   # Device → SharedService

# Typed link relationships
PHYSICAL_CABLE = "PHYSICAL_CABLE"         # Device → Device (physical data-plane)
MGMT_LINK = "MGMT_LINK"                   # Device → Device (management plane)
L3_REACHABILITY = "L3_REACHABILITY"       # Device → Device (L3/virtual)
INFERRED_LINK = "INFERRED_LINK"           # Device → Device (subnet-only inference)
INFRASTRUCTURE_LINK = "INFRASTRUCTURE_LINK"  # Device → Device (mgmt-switch cables)
STACK_LINK = "STACK_LINK"                 # Device → Device (self-loop for stack members)

# Domain-specific edges
HAS_LSA = "HAS_LSA"                       # SharedService(ospf_area) → OspfLsa
HAS_ROUTE = "HAS_ROUTE"                   # Device → Route
HAS_POLICY = "HAS_POLICY"                 # Device → FirewallPolicy
HAS_ARP = "HAS_ARP"                       # Device → ArpEntry
HAS_ROUTE_POLICY = "HAS_ROUTE_POLICY"     # Device → RoutePolicy
HAS_PREFIX_ENTRY = "HAS_PREFIX_ENTRY"     # Device → PrefixSetEntry
HAS_FINDING = "HAS_FINDING"               # Device → Finding
HAS_SECURITY_CONFIG = "HAS_SECURITY_CONFIG"  # Device → SecurityConfig


# Mapping from model link_type → Neo4j relationship type
LINK_RELATIONSHIP_MAP = {
    "physical": PHYSICAL_CABLE,
    "management": MGMT_LINK,
    "l3_reachability": L3_REACHABILITY,
    "subnet_association": INFERRED_LINK,
    "stack_interconnect": STACK_LINK,
    "infrastructure": INFRASTRUCTURE_LINK,
}

ALL_LINK_TYPES = [
    PHYSICAL_CABLE, MGMT_LINK, L3_REACHABILITY, INFERRED_LINK, STACK_LINK, INFRASTRUCTURE_LINK
]


# ---------------------------------------------------------------------------
# Common property names (constants prevent silent Cypher typos)
# ---------------------------------------------------------------------------
PROP_SITE = "site"
PROP_RUN_ID = "run_id"
PROP_NAME = "name"
PROP_DEVICE = "device"
PROP_STATUS = "status"
PROP_PINNED = "pinned"
PROP_LABEL = "label"
PROP_LOADED_AT = "loaded_at"


# ---------------------------------------------------------------------------
# Indexes — (label, property_list, index_name)
# ---------------------------------------------------------------------------
INDEX_DEFINITIONS = [
    (RUN, ["site", "run_id"], "idx_run_site"),
    (DEVICE, ["site", "run_id", "name"], "idx_device_site_run"),
    (INTERFACE, ["site", "run_id", "device"], "idx_interface_site_run"),
    (SHARED_SERVICE, ["site", "run_id", "service_type"], "idx_shared_service"),
    (VLAN, ["site", "run_id", "vlan_id"], "idx_vlan_site_run"),
    (OSPF_LSA, ["site", "run_id", "lsa_type"], "idx_ospf_lsa_site_run"),
    (ROUTE, ["site", "run_id", "device"], "idx_route_site_run_device"),
    (FIREWALL_POLICY, ["site", "run_id", "device"], "idx_fw_policy_site_run"),
    (ARP_ENTRY, ["site", "run_id", "device"], "idx_arp_entry_site_run"),
    (FINDING, ["site", "run_id", "device"], "idx_finding_site_run_device"),
    (SECURITY_CONFIG, ["site", "run_id", "device"], "idx_secconfig_site_run"),
    (LAYOUT_POSITION, ["site", "view", "node_id"], "idx_layout_position"),
    (ACKNOWLEDGEMENT, ["site", "finding_id"], "idx_acknowledgement"),
    (ANNOTATION, ["run_id", "finding_id"], "idx_annotation"),
]


def ensure_indexes(driver) -> int:
    """Create composite indexes if they don't exist (idempotent). Returns the count ensured."""
    created = 0
    with driver.session() as session:
        for label, properties, index_name in INDEX_DEFINITIONS:
            prop_list = ", ".join(f"n.{p}" for p in properties)
            session.run(
                f"CREATE INDEX {index_name} IF NOT EXISTS FOR (n:{label}) ON ({prop_list})"
            )
            logger.debug("Index ensured: %s on %s(%s)", index_name, label, ", ".join(properties))
            created += 1
    logger.info("Neo4j: %d indexes ensured", created)
    return created
