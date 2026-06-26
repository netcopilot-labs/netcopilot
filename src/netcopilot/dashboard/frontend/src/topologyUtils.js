// =============================================================================
// Shared utilities for topology visualization — C9S8 refactored.
//
// Severity and role constants (SEVERITY_ORDER, SEV_COLORS, ROLE_TIERS,
// ROLE_COLORS) have been REMOVED.  They now come from the backend via
// GET /api/legend, served through LegendContext / useLegend().
//
// What remains here: TOPOLOGY_VIEWS (static config), computePositions
// (layout function taking roleTiers as parameter), and formatRole
// (pure string formatter).
// =============================================================================

// Topology view definitions — used by Level 2 tab bar and findings panel
export const TOPOLOGY_VIEWS = [
  { id: 'physical', label: 'Physical', enabled: true },
  { id: 'mgmt', label: 'MGMT', enabled: true },
  { id: 'l2vlan', label: 'L2/L3', enabled: true },
  { id: 'ospf', label: 'OSPF', enabled: true },
  { id: 'bgp', label: 'BGP', enabled: true },
]

/**
 * Compute (x, y) positions for nodes based on role tiers.
 * Nodes are grouped by tier and spread horizontally within each tier.
 *
 * @param {Array} nodes - Cytoscape node data array
 * @param {number} containerWidth - Available width in pixels
 * @param {Object} roleTiers - Role-to-tier mapping from useLegend()
 * @param {Object} [defaultRole] - Fallback {tier, color} for unknown roles
 */
export function computePositions(nodes, containerWidth, roleTiers, defaultRole) {
  const defaultTier = (defaultRole && defaultRole.tier) ?? 3

  // Group nodes by tier
  const byTier = {}
  nodes.forEach(node => {
    const role = node.data.role || 'external'
    const tier = roleTiers[role] ?? defaultTier
    if (!byTier[tier]) byTier[tier] = []
    byTier[tier].push(node)
  })

  const TIER_SPACING_Y = 120
  const START_Y = 80
  const positions = {}

  Object.entries(byTier).forEach(([tier, tierNodes]) => {
    const y = START_Y + Number(tier) * TIER_SPACING_Y
    const spacing = containerWidth / (tierNodes.length + 1)
    tierNodes.forEach((node, i) => {
      positions[node.data.id] = { x: spacing * (i + 1), y }
    })
  })

  return positions
}

/**
 * Format a role string for display (replace underscores, title case).
 */
export function formatRole(role) {
  if (!role) return ''
  return role.replace(/_/g, ' ')
}
