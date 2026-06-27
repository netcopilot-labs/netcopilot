import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import cytoscape from 'cytoscape'
import { TOPOLOGY_VIEWS, computePositions } from '../topologyUtils.js'
import { useLegend } from '../contexts/LegendContext.jsx'

// =============================================================================
// Cytoscape Style Selectors — matches approved visual prototype
// =============================================================================
const CYTOSCAPE_STYLE = [
  // ── Base node style ──
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'shape': 'round-rectangle',
      'text-valign': 'center',
      'text-halign': 'center',
      'font-size': '10px',
      'font-weight': '700',
      'font-family': 'Arial, sans-serif',
      'width': 80,
      'height': 44,
      'background-color': '#FFFFFF',
      'border-width': 2,
      // Default border + text colour come from the legend's per-role colour
      // (data(roleColor), set in buildElements from the /api/legend source of
      // truth). This means EVERY role renders with its legend colour — incl.
      // services_switch (cyan), mgmt_switch, dmz_switch — instead of falling
      // back to grey, so the map and the legend can't drift apart. Roles with an
      // explicit selector below additionally get a light background tint.
      'border-color': 'data(roleColor)',
      'color': 'data(roleColor)',
      'text-wrap': 'wrap',
      'text-max-width': '74px',
    },
  },

  // ── Role-specific colors — background tint always visible, border + text show role color ──
  {
    selector: 'node[role = "border_router"]',
    style: {
      'color': '#1D4ED8',
      'border-color': '#1D4ED8',
      'background-color': '#EFF6FF',
    },
  },
  {
    selector: 'node[role = "core_switch"]',
    style: {
      'color': '#6D28D9',
      'border-color': '#6D28D9',
      'background-color': '#F5F3FF',
    },
  },
  {
    selector: 'node[role = "distribution_switch"]',
    style: {
      'color': '#7C3AED',
      'border-color': '#7C3AED',
      'background-color': '#F5F3FF',
    },
  },
  {
    selector: 'node[role = "access_switch"]',
    style: {
      'color': '#374151',
      'border-color': '#6B7280',
      'background-color': '#F9FAFB',
    },
  },
  {
    selector: 'node[role = "firewall"]',
    style: {
      'color': '#C2410C',
      'border-color': '#C2410C',
      'background-color': '#FFF7ED',
    },
  },
  {
    selector: 'node[role = "external"]',
    style: {
      'color': '#9CA3AF',
      'border-color': '#9CA3AF',
      'width': 100,
      'height': 44,
      'font-size': '8px',
      'border-style': 'dashed',
      'border-width': 2,
      'background-color': '#F9FAFB',
      'text-wrap': 'wrap',
      'text-max-width': '90px',
    },
  },
  // ── Unreachable device (in inventory but not collected) — red styling ──
  {
    selector: 'node[?isUnreachable]',
    style: {
      'color': '#DC2626',
      'border-color': '#DC2626',
      'border-width': 3,
      'border-style': 'dashed',
      'background-color': '#FEF2F2',
    },
  },

  // ── Findings indicators ──
  // Nodes with critical findings: thick red border + glow
  {
    selector: 'node[?has_critical]',
    style: {
      'border-color': '#DC2626',
      'border-width': 4,
      'border-opacity': 1,
      'overlay-color': '#DC2626',
      'overlay-padding': 6,
      'overlay-opacity': 0.08,
    },
  },
  // Nodes with findings (non-critical): amber border
  {
    selector: 'node[findings_count > 0][!has_critical]',
    style: {
      'border-width': 3,
      'border-color': '#F59E0B',
    },
  },

  // ── Selected / focused node ──
  {
    selector: 'node:selected',
    style: {
      'background-color': 'data(roleColor)',
      'color': '#FFFFFF',
      'border-width': 3,
      'overlay-color': 'data(roleColor)',
      'overlay-padding': 4,
      'overlay-opacity': 0.15,
    },
  },

  // ── Dimmed nodes (when focus mode active) ──
  {
    selector: 'node.dimmed',
    style: {
      'opacity': 0.15,
    },
  },

  // ── Collapsed compound node (stack/HA device, children hidden) ──
  {
    selector: 'node[?isCollapsed]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#F8FAFC',
      'background-opacity': 0.6,
      'border-width': 2,
      'border-style': 'solid',
      'width': 90,
      'height': 50,
      'font-size': '9px',
      'font-weight': '700',
      'text-wrap': 'wrap',
      'text-max-width': '84px',
      'text-valign': 'center',
      'text-halign': 'center',
    },
  },

  // ── Expanded compound parent node (stacked/HA device container) ──
  {
    selector: 'node[?isCompound]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#F8FAFC',
      'background-opacity': 0.6,
      'border-width': 2,
      'border-style': 'solid',
      'padding': '12px',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': 4,
      'font-size': '9px',
      'font-weight': '700',
      'text-wrap': 'wrap',
      'text-max-width': '150px',
      'compound-sizing-wrt-labels': 'include',
    },
  },

  // ── Child member node (inside compound parent) ──
  {
    selector: 'node[parent]',
    style: {
      'width': 32,
      'height': 32,
      'font-size': '8px',
      'font-weight': '600',
      'border-width': 1.5,
      'background-color': '#FFFFFF',
      'text-valign': 'center',
      'text-halign': 'center',
      'text-wrap': 'none',
      'text-max-width': '30px',
    },
  },

  // ── FortiGate passive member dimmed ──
  {
    selector: 'node[memberRole = "Passive"]',
    style: {
      'opacity': 0.4,
    },
  },

  // ── Base edge style ──
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#94A3B8',
      'curve-style': 'bezier',
      'target-arrow-shape': 'none',
      // Port labels
      'source-label': 'data(sourcePort)',
      'target-label': 'data(targetPort)',
      'source-text-offset': 25,
      'target-text-offset': 25,
      'font-size': '7px',
      'font-family': 'monospace, Courier, monospace',
      'source-text-rotation': 'autorotate',
      'target-text-rotation': 'autorotate',
      'color': '#94A3B8',
      'text-background-color': '#FFFFFF',
      'text-background-opacity': 0.8,
      'text-background-padding': '2px',
    },
  },

  // ── Discovery priority styling (lower = more confident) ──
  {
    selector: 'edge[discovery_priority <= 2]',
    style: {
      'width': 3,
      'line-style': 'solid',
      'opacity': 1.0,
    },
  },
  {
    selector: 'edge[discovery_priority >= 3][discovery_priority <= 5]',
    style: {
      'width': 2,
      'line-style': 'solid',
      'opacity': 1.0,
    },
  },
  {
    selector: 'edge[discovery_priority >= 6][discovery_priority <= 8]',
    style: {
      'width': 2,
      'line-style': 'dashed',
      'opacity': 0.8,
    },
  },
  {
    selector: 'edge[discovery_priority >= 9][discovery_priority <= 10]',
    style: {
      'width': 1.5,
      'line-style': 'dotted',
      'opacity': 0.7,
    },
  },
  {
    selector: 'edge[discovery_priority >= 11]',
    style: {
      'width': 1,
      'line-style': 'dotted',
      'opacity': 0.5,
    },
  },

  // ── Confidence overrides (trump discovery priority) ──
  // High confidence links (fdb_firewall, lacp_bilateral, lacp_fg_unilateral) must
  // always render as solid — consistent with the legend.
  {
    selector: 'edge[confidence = "high"]',
    style: {
      'line-style': 'solid',
    },
  },

  // ── Edge status: "up" override ──
  {
    selector: 'edge[status = "up"]',
    style: {
      'line-color': '#64748B',
    },
  },

  // ── Cable type styling (physical + mgmt views) ──
  {
    selector: 'edge[cable_type = "fiber"]',
    style: {
      'line-color': '#1E3A5F',
    },
  },
  {
    selector: 'edge[cable_type = "rj45"]',
    style: {
      'line-color': '#0284C7',
    },
  },

  // ── OOB management edges — always solid (real cables, even if ARP-discovered) ──
  {
    selector: 'edge[mgmt_type = "oob"]',
    style: {
      'line-style': 'solid',
      'line-color': '#6B7280',
    },
  },

  // ── In-band management edges (management-plane devices via firewall) ──
  {
    selector: 'edge[mgmt_type = "inband"]',
    style: {
      'line-color': '#3B82F6',
      'target-arrow-color': '#3B82F6',
      'source-arrow-color': '#3B82F6',
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
      'width': 1.5,
      'opacity': 0.85,
    },
  },
  // Inband MGMT with VLAN label (ADR-172)
  {
    selector: 'edge[mgmt_type = "inband"][mgmt_vlan]',
    style: {
      'label': 'data(mgmt_vlan)',
      'source-label': '',
      'target-label': '',
      'font-size': '7px',
      'color': '#1D9E75',
      'text-background-color': '#D1FAE5',
      'text-background-opacity': 0.8,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
    },
  },
  // (down status override moved to end of stylesheet for cascade priority)

  // ── Stack interconnect edges — base (C9300 stack cable) ──
  {
    selector: 'edge[linkType = "stack_interconnect"]',
    style: {
      'width': 4,
      'line-color': '#EA580C',
      'line-style': 'solid',
      'opacity': 0.9,
      'curve-style': 'bezier',
      'source-label': 'data(sourcePort)',
      'target-label': 'data(targetPort)',
    },
  },
  // Stack interconnect — C9500 SVL (virtual stack, purple)
  {
    selector: 'edge[stackSubtype = "svl"]',
    style: {
      'width': 5,
      'line-color': '#7C3AED',
      'line-style': 'solid',
      'opacity': 0.85,
    },
  },
  // Stack interconnect — FortiGate HA cable (orange, thinner)
  {
    selector: 'edge[stackSubtype = "ha"]',
    style: {
      'width': 3,
      'line-color': '#EA580C',
      'line-style': 'solid',
      'opacity': 0.7,
    },
  },
  // Stack interconnect — DAD (Dual Active Detection) black dashed + center label
  {
    selector: 'edge[stackSubtype = "dad"]',
    style: {
      'width': 2,
      'line-style': 'dashed',
      'line-color': '#1E293B',
      'opacity': 0.7,
      'label': 'DAD',
      'font-size': '7px',
      'font-weight': '700',
      'color': '#1E293B',
      'text-background-color': '#FFFFFF',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
      'text-rotation': 'autorotate',
    },
  },
  // (down status override moved to end of stylesheet for cascade priority)

  // ── OSPF adjacency edge — solid green with area label ──
  {
    selector: 'edge[edgeType = "adjacency"]',
    style: {
      'width': 3,
      'line-style': 'solid',
      'line-color': '#059669',
      'target-arrow-shape': 'none',
      'source-arrow-shape': 'none',
      'label': 'data(label)',
      'font-size': '8px',
      'font-weight': '700',
      'color': '#059669',
      'text-background-color': '#FFFFFF',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
      'text-rotation': 'autorotate',
      'curve-style': 'bezier',
      'z-index': 10,
      // Override port labels — adjacency edges don't have ports
      'source-label': '',
      'target-label': '',
    },
  },
  // OSPF adjacency — non-full state (amber warning, NOT red)
  {
    selector: 'edge[edgeType = "adjacency"][state != "full"]',
    style: {
      'line-color': '#D97706',
      'color': '#D97706',
    },
  },

  // ── BGP adjacency edges — orange ──
  {
    selector: 'edge[protocol = "bgp"]',
    style: {
      'line-color': '#EA580C',
      'color': '#EA580C',
    },
  },
  // iBGP — dashed orange
  {
    selector: 'edge[protocol = "bgp"][session_type = "ibgp"]',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [8, 4],
      'line-color': '#EA580C',
      'color': '#EA580C',
    },
  },
  // eBGP — solid orange
  {
    selector: 'edge[protocol = "bgp"][session_type = "ebgp"]',
    style: {
      'line-style': 'solid',
      'line-color': '#EA580C',
      'color': '#EA580C',
    },
  },

  // ── External peer node in BGP view — same shape, dashed border ──
  {
    selector: 'node[role = "external"][device_type = "external"]',
    style: {
      'shape': 'round-rectangle',
      'width': 100,
      'height': 44,
      'border-style': 'dashed',
      'border-width': 2,
      'border-color': '#9CA3AF',
      'background-color': '#F3F4F6',
      'color': '#6B7280',
      'font-size': '8px',
      'text-wrap': 'wrap',
      'text-max-width': '90px',
    },
  },

  // ── BGP route reflector node — double indigo border + badge (set in label) ──
  // core_switch already renders violet, so a double border-style (vs the solid
  // border every other node uses) is what visually marks the reflector.
  {
    selector: 'node[?is_route_reflector]',
    style: {
      'border-style': 'double',
      'border-width': 6,
      'border-color': '#4338CA',
      // Slightly larger so the extra "◆ RR" label line stays readable.
      'width': 96,
      'height': 58,
      'font-size': '9px',
    },
  },

  // ── Edge with findings ──
  {
    selector: 'edge[?has_findings]',
    style: {
      'line-color': '#EF4444',
      'width': 3,
    },
  },

  // ── Edge status: down/admin_down — last in cascade to override all link types ──
  {
    selector: 'edge[status = "down"]',
    style: {
      'line-color': '#EF4444',
      'line-style': 'dotted',
      'width': 2.5,
      'target-arrow-color': '#EF4444',
      'source-arrow-color': '#EF4444',
    },
  },
  {
    selector: 'edge[status = "admin_down"]',
    style: {
      'line-color': '#CBD5E1',
      'line-style': 'dotted',
      'width': 1.5,
    },
  },

  // ── Dimmed edges ──
  {
    selector: 'edge.dimmed',
    style: {
      'opacity': 0.1,
    },
  },

  // ── Selected edge (S19A-8: edge click) ──
  {
    selector: 'edge.edge-selected',
    style: {
      'line-color': '#1D9E75',
      'width': 4,
      'opacity': 1,
      'z-index': 10,
    },
  },


  // ── Edge endpoint highlight (S19A-8) ──
  {
    selector: 'node.edge-endpoint',
    style: {
      'border-width': 3,
      'overlay-color': '#1D9E75',
      'overlay-padding': 4,
      'overlay-opacity': 0.12,
    },
  },

  // ── VLAN overlay: node with IP secondary label ──
  {
    selector: 'node[vlanIp]',
    style: {
      'label': ele => `${ele.data('label')}\n${ele.data('vlanIp')}`,
      'text-wrap': 'wrap',
      'font-size': '9px',
    },
  },

  // ── VLAN overlay: active elements (full visibility) ──
  {
    selector: '.vlan-active',
    style: {
      'opacity': 1,
    },
  },
  // ── VLAN overlay: inactive elements (filtered out — hidden) ──
  // When a VLAN is selected the view FILTERS to that VLAN: non-member nodes and
  // edges are hidden (display:none) rather than dimmed, so only the selected
  // VLAN's devices + links are shown. Deselecting (ALL) removes these classes.
  {
    selector: 'node.vlan-inactive',
    style: {
      'display': 'none',
    },
  },
  {
    selector: 'edge.vlan-inactive',
    style: {
      'display': 'none',
    },
  },

  // ── VLAN overlay: active edge mode label ──
  {
    selector: 'edge.vlan-active[vlanLabel]',
    style: {
      'label': 'data(vlanLabel)',
      'font-size': '9px',
      'color': '#1D4ED8',
      'text-rotation': 'autorotate',
      'text-background-color': '#EFF6FF',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
    },
  },

  // ── L2/VLAN merged edge: VLAN count center label ──
  {
    selector: 'edge[vlanCountLabel]',
    style: {
      'label': 'data(vlanCountLabel)',
      'font-size': '9px',
      'color': '#6D28D9',
      'text-rotation': 'autorotate',
      'text-background-color': '#F5F3FF',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
    },
  },

  // ── Port-channel (LAG) edge label ──
  {
    selector: 'edge[lag_label]',
    style: {
      'label': 'data(lag_label)',
      'font-size': 8,
      'color': '#6B7280',
      'text-rotation': 'autorotate',
      'text-background-color': '#FFFFFF',
      'text-background-opacity': 0.85,
      'text-background-padding': '2px',
      'text-margin-y': -6,
    },
  },
]

// Abbreviate a full interface name for display on edge labels.
// "HundredGigE1/0/49" → "Hu1/0/49", "TwentyFiveGigE1/0/17" → "Tw1/0/17"
// Short-form and FortiGate names (port33, Hu1/0/49) pass through unchanged.
const _INTF_ABBREV = [
  ['TwentyFiveGigE', 'Tw'], ['TwentyFiveGigabitEthernet', 'Tw'],
  ['HundredGigE', 'Hu'], ['HundredGigabitEthernet', 'Hu'],
  ['TenGigabitEthernet', 'Te'], ['GigabitEthernet', 'Gi'],
  ['FastEthernet', 'Fa'], ['FortyGigabitEthernet', 'Fo'],
  ['FiveGigabitEthernet', 'Fi'], ['Port-channel', 'Po'],
  ['Bundle-Ether', 'Be'], ['Loopback', 'Lo'], ['Tunnel', 'Tu'],
  ['Vlan', 'Vl'], ['MgmtEth', 'Mg'], ['BDI', 'BDI'], ['BVI', 'BVI'],
  ['Null', 'Nu'],
]

function abbreviateIntf(name) {
  if (!name) return name
  for (const [long, short] of _INTF_ABBREV) {
    if (name.startsWith(long)) return short + name.slice(long.length)
  }
  return name
}

// Abbreviate a LAG/port-channel name for edge labels.
// "Port-channel34" → "Po34", "Bundle-Ether13" → "Be13"
function abbreviateLag(name) {
  if (!name) return null
  const m = name.match(/^[Pp]ort-[Cc]hannel(\d+)$/)
  if (m) return `Po${m[1]}`
  const m2 = name.match(/^[Bb]undle-[Ee]ther(\d+)$/)
  if (m2) return `Be${m2[1]}`
  // Fallback: strip non-digit prefix, return first 2 chars + number
  const m3 = name.match(/^([A-Za-z-]+?)(\d+)$/)
  if (m3) return m3[1].replace('-', '').slice(0, 2) + m3[2]
  return name
}

// =============================================================================
// Per-view rendering predicates
// =============================================================================
// Views that always render every compound collapsed and hide the Expand/Collapse
// toolbar buttons. L2/L3 has been like this since Sprint 18; OSPF and BGP joined
// 2026-05-18 — those views are representative protocol diagrams, not literal
// physical maps, so compound interiors add noise without adding meaning.
const COLLAPSED_VIEWS = new Set(['l2vlan', 'ospf', 'bgp'])

// Views that always render every compound expanded and hide the Expand/Collapse
// toolbar buttons. Carlos 2026-05-18: Physical + MGMT should always show full
// detail — multi-RP device internals + every site member visible by default.
// Underlying expandedNodes state + handleExpandAll/handleCollapseAll handlers
// are intentionally retained so the toolbar buttons can come back per-view if
// needed later (the gate at the toolbar render site checks both predicate
// sets — adding a 6th view outside both sets would surface the buttons again).
const EXPANDED_VIEWS = new Set(['physical', 'mgmt'])

// Views that suppress the physical/cable edge layer entirely and render ONLY
// protocol-adjacency edges. Carlos's mental model: "one BGP cable between the
// two devices that are peering, nothing more" — physical lines are a separate
// view (Physical/MGMT) and overlap is just noise here.
const PROTOCOL_ONLY_VIEWS = new Set(['ospf', 'bgp'])

// Reroute a `parent:child` endpoint to its parent compound when that compound
// is currently collapsed. Returns the endpoint unchanged otherwise. Shared by
// the physical-edge loop AND the OSPF/BGP adjacency loops so collapsed-compound
// edges render as compound-to-compound lines instead of being silently dropped
// by the nodeIdSet membership check (children are removed from the nodes array
// when their parent is collapsed — see line ~733).
function rerouteToCollapsedParent(endpoint, compoundNodeIds, expandedNodes) {
  if (!endpoint) return endpoint
  const colon = endpoint.indexOf(':')
  if (colon <= 0) return endpoint
  const parentId = endpoint.substring(0, colon)
  if (compoundNodeIds.has(parentId) && !expandedNodes.has(parentId)) {
    return parentId
  }
  return endpoint
}

// =============================================================================
// Build Cytoscape elements with visual attributes
// =============================================================================
function buildElements(topologyData, findingsData, expandedNodes, selectedView, ospfVrf, roleColors) {
  // Exclude acknowledged findings from topology indicators (ADR-174)
  const findings = (findingsData?.findings || []).filter(f => !f.acknowledged)

  // Count findings: aggregate (for collapsed), per-member (for children), device-only (for expanded parent)
  const deviceFindings = {}           // hostname → total count (aggregate)
  const deviceHasCritical = {}        // hostname → boolean
  const memberFindings = {}           // "hostname:memberId" → count
  const memberHasCritical = {}        // "hostname:memberId" → boolean
  const deviceOnlyFindings = {}       // hostname → count (findings without member_id)
  const deviceOnlyHasCritical = {}    // hostname → boolean

  findings.forEach(f => {
    // Extract device from evidence.element_id or finding_id
    const elementId = f.evidence?.element_id || f.finding_id || ''
    const memberId = f.evidence?.member_id
    let devName = ''
    if (elementId.includes('::')) {
      devName = elementId.split('::')[1]
    } else {
      devName = elementId
    }
    // Handle link-style IDs: DEVA:intf--DEVB:intf
    if (devName.includes('--')) {
      devName.split('--').forEach(part => {
        const d = part.split(':')[0].split('/')[0]
        if (d) {
          deviceFindings[d] = (deviceFindings[d] || 0) + 1
          if (f.severity === 'critical') deviceHasCritical[d] = true
          // Link findings are device-level (no member attribution)
          deviceOnlyFindings[d] = (deviceOnlyFindings[d] || 0) + 1
          if (f.severity === 'critical') deviceOnlyHasCritical[d] = true
        }
      })
    } else {
      const d = devName.split(':')[0].split('/')[0]
      if (d) {
        // Aggregate count (always)
        deviceFindings[d] = (deviceFindings[d] || 0) + 1
        if (f.severity === 'critical') deviceHasCritical[d] = true
        // Per-member or device-only
        if (memberId !== undefined && memberId !== null) {
          const key = `${d}:${memberId}`
          memberFindings[key] = (memberFindings[key] || 0) + 1
          if (f.severity === 'critical') memberHasCritical[key] = true
        } else {
          deviceOnlyFindings[d] = (deviceOnlyFindings[d] || 0) + 1
          if (f.severity === 'critical') deviceOnlyHasCritical[d] = true
        }
      }
    }
  })

  // Identify compound nodes for collapse/expand logic
  const compoundNodeIds = new Set(
    topologyData.nodes.filter(n => n.data.isCompound).map(n => n.data.id)
  )

  // VRF-scoped participation: when a VRF is selected, only devices that have
  // an adjacency in that VRF should render (Carlos 2026-05-18: "when I select
  // the VRF I only want to see the two devices doing OSPF with
  // SDV"). Today only OSPF has a per-view VRF selector; trivially extensible
  // to BGP if a bgpVrf param is added.
  let participatingIds = null
  let participatingCompoundIds = null
  if (selectedView === 'ospf' && ospfVrf && topologyData.adjacencies) {
    participatingIds = new Set()
    topologyData.adjacencies.forEach(a => {
      const d = a.data
      if (d.protocol !== 'ospf') return
      if (d.vrf !== ospfVrf) return
      if (d.source) participatingIds.add(d.source)
      if (d.target) participatingIds.add(d.target)
    })
    // Compound parents whose children participate must also render so the
    // collapsed-compound view stays consistent. The compound id may be the
    // hostname itself when participatingIds already contains it; this set
    // handles the site-as-compound case where the parent id differs.
    participatingCompoundIds = new Set()
    topologyData.nodes.forEach(n => {
      if (n.data.parent && participatingIds.has(n.data.id)) {
        participatingCompoundIds.add(n.data.parent)
      }
    })
  }

  const nodes = []
  topologyData.nodes.forEach(n => {
    const d = n.data
    const isChild = !!d.parent

    // VRF-scoped participation filter (skip non-participating devices)
    if (participatingIds) {
      if (d.isCompound) {
        if (!participatingIds.has(d.id) && !participatingCompoundIds.has(d.id)) return
      } else if (isChild) {
        if (!participatingIds.has(d.id)) return
      } else {
        if (!participatingIds.has(d.id)) return
      }
    }

    // Skip children of collapsed (non-expanded) compound nodes
    if (isChild && compoundNodeIds.has(d.parent) && !expandedNodes.has(d.parent)) {
      return
    }

    const isCollapsedCompound = d.isCompound && !expandedNodes.has(d.id)

    // Child: member label (M1, M2, Active, Passive)
    // Collapsed compound: device name + ×N badge
    // Regular node: device name only (site suppressed — redundant with run selector)
    let label
    if (isChild) {
      label = d.label || `M${d.memberId}`
    } else if (isCollapsedCompound) {
      const badge = `\u00d7${d.memberCount || 2}`
      label = `${d.id}\n${badge}`
    } else {
      label = d.id
    }

    const parentHostname = isChild ? d.parent : d.id
    const roleColor = roleColors[d.role] || '#6B7280'

    // Determine findings count based on node type and expand state
    let findingsCount, hasCritical
    if (isChild) {
      // Child: show member-specific findings only
      const memberKey = `${d.parent}:${d.memberId}`
      findingsCount = memberFindings[memberKey] || 0
      hasCritical = memberHasCritical[memberKey] || false
    } else if (d.isCompound && !isCollapsedCompound) {
      // Expanded parent: show device-level findings (without member_id)
      findingsCount = deviceOnlyFindings[d.id] || 0
      hasCritical = deviceOnlyHasCritical[d.id] || false
    } else {
      // Collapsed compound or regular node: aggregate all findings
      findingsCount = deviceFindings[parentHostname] || 0
      hasCritical = deviceHasCritical[parentHostname] || false
    }

    const isUnreachable = d.collected === false && d.role !== 'external'

    nodes.push({
      group: 'nodes',
      data: {
        ...d,
        // Override isCompound: only true when expanded (drives container styling)
        isCompound: d.isCompound && !isCollapsedCompound,
        isExpandable: !!d.isCompound,
        isCollapsed: isCollapsedCompound || false,
        isUnreachable,
        roleColor,
        findings_count: findingsCount,
        has_critical: hasCritical,
        label,
      },
    })
  })

  // Build node ID set for edge validation (skip edges with missing endpoints)
  const nodeIdSet = new Set(nodes.map(n => n.data.id))

  const edges = []
  // Physical/cable edges are suppressed in protocol-only views (OSPF, BGP) so
  // those diagrams render with adjacency lines only.
  if (!PROTOCOL_ONLY_VIEWS.has(selectedView)) {
  topologyData.edges.forEach(e => {
    const d = e.data
    let source = rerouteToCollapsedParent(d.source, compoundNodeIds, expandedNodes)
    let target = rerouteToCollapsedParent(d.target, compoundNodeIds, expandedNodes)

    // Skip self-loops created by collapsing internal edges (e.g., stack interconnect)
    if (source === target) return

    // Skip edges with endpoints not in the current view's node set
    if (!nodeIdSet.has(source) || !nodeIdSet.has(target)) return

    // Compute abbreviated LAG label from both sides
    const srcLag = abbreviateLag(d.lag_group)
    const tgtLag = abbreviateLag(d.lag_group_target)
    const lag_label = srcLag && tgtLag
      ? `${srcLag} / ${tgtLag}`
      : srcLag || tgtLag || undefined

    edges.push({
      group: 'edges',
      data: {
        ...d,
        source,
        target,
        // Abbreviate interface names for edge labels (ADR-170)
        sourcePort: abbreviateIntf(d.sourcePort),
        targetPort: abbreviateIntf(d.targetPort),
        lag_label,
        has_findings: false,
        discovery_priority: d.discovery_priority ?? 7,
        // Format VLAN label for inband MGMT edges (ADR-172)
        mgmt_vlan: d.mgmt_vlan ? `Vlan${d.mgmt_vlan}` : undefined,
        // L2/VLAN merged edge: VLAN count center label
        vlanCountLabel: d.vlan_count ? `${d.vlan_count} VLANs` : undefined,
      },
    })
  })
  }

  // OSPF view: add adjacency edges as dashed overlay + build RID map for nodes
  const ospfRidMap = {}  // hostname → router_id (for node labels)
  if (selectedView === 'ospf' && topologyData.adjacencies) {
    // Count distinct VRFs to decide if VRF label is needed
    const ospfVrfs = new Set()
    topologyData.adjacencies.forEach(a => {
      if (a.data.protocol === 'ospf' && a.data.vrf) ospfVrfs.add(a.data.vrf)
    })
    const multiVrf = ospfVrfs.size > 1

    // Dedupe: at most one OSPF edge per unordered device-pair after compound
    // rerouting (Carlos 2026-05-18: "one connection per device, nothing more").
    const seenOspf = new Set()
    topologyData.adjacencies.forEach(a => {
      const d = a.data
      if (d.protocol !== 'ospf') return

      // VRF filter
      if (ospfVrf && d.vrf !== ospfVrf) return

      // Build the RID map from the VRF-filtered adjacencies, so a multi-VRF
      // device's node label shows the router-id for the VRF being viewed rather
      // than an arbitrary one. (genie stores every RID under "default"; the model
      // resolves the real per-VRF RID on the adjacency.) R1 Phase 2 / O1 view fix.
      if (d.router_id_a && d.source) ospfRidMap[d.source] = d.router_id_a
      if (d.router_id_b && d.target) ospfRidMap[d.target] = d.router_id_b

      // Reroute child endpoints to parent when parent is collapsed (OSPF view
      // force-collapses all compounds via COLLAPSED_VIEWS).
      const source = rerouteToCollapsedParent(d.source, compoundNodeIds, expandedNodes)
      const target = rerouteToCollapsedParent(d.target, compoundNodeIds, expandedNodes)
      if (source === target) return
      if (!nodeIdSet.has(source) || !nodeIdSet.has(target)) return

      // Unordered-pair dedup so two devices in the same compound peering with
      // a third don't render as parallel lines after rerouting.
      const pairKey = [source, target].sort().join('--')
      if (seenOspf.has(pairKey)) return
      seenOspf.add(pairKey)

      // Edge label: include VRF abbreviation when multi-VRF
      let edgeLabel = `Area ${d.area || '0'}`
      if (multiVrf && d.vrf) {
        const vrfShort = d.vrf.replace(/-VRF$/i, '').replace(/-/g, '')
        edgeLabel += ` (${vrfShort})`
      }

      edges.push({
        group: 'edges',
        data: {
          id: d.id,
          source,
          target,
          edgeType: 'adjacency',
          protocol: 'ospf',
          state: d.state,
          area: d.area,
          process_id: d.process_id,
          vrf: d.vrf,
          bilateral: d.bilateral,
          interface_a: d.interface_a,
          interface_b: d.interface_b,
          cost_a: d.cost_a,
          cost_b: d.cost_b,
          hello_a: d.hello_a,
          hello_b: d.hello_b,
          dead_a: d.dead_a,
          dead_b: d.dead_b,
          network_type_a: d.network_type_a,
          network_type_b: d.network_type_b,
          ip_a: d.ip_a,
          ip_b: d.ip_b,
          router_id_a: d.router_id_a,
          router_id_b: d.router_id_b,
          label: edgeLabel,
        },
      })
    })

    // Enrich node labels with Router ID
    nodes.forEach(n => {
      const rid = ospfRidMap[n.data.id]
      if (rid) {
        n.data.label = `${n.data.label}\nRID ${rid}`
      }
    })
  }

  // BGP view: add adjacency edges + external peer labels
  const bgpRidMap = {}  // hostname → router_id
  if (selectedView === 'bgp' && topologyData.adjacencies) {
    // Dedupe: at most one BGP edge per unordered device-pair after compound
    // rerouting (Carlos 2026-05-18: "one BGP cable between the two devices
    // that are peering, nothing more").
    const seenBgp = new Set()
    topologyData.adjacencies.forEach(a => {
      const d = a.data
      if (d.protocol !== 'bgp') return

      // Build RID map
      if (d.router_id_a && d.source) bgpRidMap[d.source] = d.router_id_a
      if (d.router_id_b && d.target) bgpRidMap[d.target] = d.router_id_b

      // Edge label — iBGP shows the shared AS, eBGP shows the remote-side peer label
      let edgeLabel
      if (d.session_type === 'ibgp') {
        const bgpAs = d.local_as || d.remote_as
        edgeLabel = bgpAs ? `iBGP AS${bgpAs}` : 'iBGP'
        // Mark route-reflector ↔ client sessions (config-only; genie omits it).
        if (d.rr_client) edgeLabel += ' · RR-client'
      } else {
        edgeLabel = `eBGP ${d.peer_label || ''}`
      }

      // Reroute child endpoints to parent when parent is collapsed (BGP view
      // force-collapses all compounds via COLLAPSED_VIEWS).
      const source = rerouteToCollapsedParent(d.source, compoundNodeIds, expandedNodes)
      const target = rerouteToCollapsedParent(d.target, compoundNodeIds, expandedNodes)
      if (source === target) return
      if (!nodeIdSet.has(source) || !nodeIdSet.has(target)) return

      // Unordered-pair dedup so multiple sessions across parallel transit
      // collapse to one visible line.
      const pairKey = [source, target].sort().join('--')
      if (seenBgp.has(pairKey)) return
      seenBgp.add(pairKey)

      edges.push({
        group: 'edges',
        data: {
          id: d.id,
          source,
          target,
          edgeType: 'adjacency',
          protocol: 'bgp',
          session_type: d.session_type,
          state: d.state,
          bilateral: d.bilateral,
          peer_label: d.peer_label,
          local_as: d.local_as,
          remote_as: d.remote_as,
          description_a: d.description_a,
          description_b: d.description_b,
          router_id_a: d.router_id_a,
          router_id_b: d.router_id_b,
          label: edgeLabel,
          // Pass through all BGP detail fields for link click
          ...Object.fromEntries(
            Object.entries(d).filter(([k]) =>
              k.endsWith('_a') || k.endsWith('_b') ||
              ['session_type', 'peer_label', 'rr_client', 'rr_reflector',
               'address_families',
               'network_statements_a', 'network_statements_b'].includes(k)
            )
          ),
        },
      })
    })

    // Enrich node labels — collected devices get RID, external peers get peer_label
    nodes.forEach(n => {
      const nd = n.data
      if (nd.device_type === 'external' && nd.peer_label) {
        nd.label = nd.peer_label
      } else {
        const rid = bgpRidMap[nd.id]
        if (rid) {
          nd.label = `${nd.label}\nRID ${rid}`
        }
        if (nd.is_route_reflector) {
          // Compact marker so the node label stays legible; the full
          // "Route Reflector · cluster …" detail lives in the BGP tab.
          nd.label = `${nd.label}\n◆ RR`
        }
      }
    })
  }

  return { nodes, edges, compoundNodeIds }
}

// =============================================================================
// TopologyMap Component
// =============================================================================
export default function TopologyMap({
  topologyData,
  findingsData,
  selectedDevice,
  onDeviceSelect,
  onLinkSelect,
  selectedView,
  severityFilters,
  onToggleSeverity,
  selectedRun,
  collapsedPositions = {},
  expandedPositions = {},
  onCollapsedPositionsChange,
  onExpandedPositionsChange,
  selectedVlan,
  vlanData,
  ospfVrf,
  highlightPath,
}) {
  const { roleColors, sevColors, severityOrder, roleTiers, defaultRole } = useLegend()
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const [tooltip, setTooltip] = useState(null)
  const [expandedNodes, setExpandedNodes] = useState(() => new Set())
  const compoundNodeIdsRef = useRef(new Set())
  const isExpandToggleRef = useRef(false)
  const draggedPositionsRef = useRef({})  // snapshot of user-dragged positions across expand/collapse
  const [showLegend, setShowLegend] = useState(false)
  const [pinSaved, setPinSaved] = useState(false)
  // Block 13 F2 — surface Pin Layout failures (was silent: see handlePinLayout)
  const [pinError, setPinError] = useState(null)

  // Clear dragged position cache when topology data changes (run/view switch)
  useEffect(() => {
    draggedPositionsRef.current = {}
  }, [topologyData])

  // 2026-05-18: Clear dragged position cache ALSO when the active view changes
  // (Topology↔Audit tab switch, Topology view-button click). Without this, a
  // node dragged in one view leaves its position in the cache; on view change
  // the rebuild overlays that stale position onto the new view's layout —
  // symptom: switching Topology+OSPF → Audit leaves the map in a half-OSPF
  // half-Physical layout instead of resetting to a clean Physical render.
  useEffect(() => {
    draggedPositionsRef.current = {}
  }, [selectedView])

  // Initialize / update Cytoscape
  useEffect(() => {
    if (!topologyData || !containerRef.current) return

    // Per-view compound state. Predicate sets at top of file.
    // - COLLAPSED_VIEWS (L2/L3, OSPF, BGP): every compound collapsed.
    // - EXPANDED_VIEWS (Physical, MGMT): every compound expanded.
    // - Else (no view today; future views): respect user expandedNodes state.
    let effectiveExpanded
    if (COLLAPSED_VIEWS.has(selectedView)) {
      effectiveExpanded = new Set()
    } else if (EXPANDED_VIEWS.has(selectedView)) {
      effectiveExpanded = new Set(
        topologyData.nodes.filter(n => n.data.isCompound).map(n => n.data.id)
      )
    } else {
      effectiveExpanded = expandedNodes
    }
    const { nodes, edges, compoundNodeIds } = buildElements(topologyData, findingsData, effectiveExpanded, selectedView, ospfVrf, roleColors)
    compoundNodeIdsRef.current = compoundNodeIds
    const elements = [...nodes, ...edges]

    // Step 1: Compute tier-based positions for all non-child nodes
    const containerWidth = containerRef.current.clientWidth || 800
    const positionableNodes = nodes.filter(n => !n.data.parent)
    const positions = computePositions(positionableNodes.map(n => ({ data: n.data })), containerWidth, roleTiers, defaultRole)

    // Step 2: Save zoom/pan + snapshot from previous Cytoscape instance
    let prevZoom, prevPan
    if (cyRef.current) {
      if (isExpandToggleRef.current) {
        prevZoom = cyRef.current.zoom()
        prevPan = { ...cyRef.current.pan() }
        // Snapshot all current node positions so expand/collapse preserves dragged locations
        const snap = {}
        cyRef.current.nodes().forEach(n => {
          snap[n.id()] = { x: n.position('x'), y: n.position('y') }
        })
        Object.assign(draggedPositionsRef.current, snap)
        isExpandToggleRef.current = false
      }
      cyRef.current.destroy()
    }

    // Step 3: Overlay pinned positions (BEFORE child positioning so parent pos is correct)
    // Pick the right set based on whether compounds are currently expanded
    const isExpanded = expandedNodes.size > 0
    const activePositions = isExpanded ? expandedPositions : collapsedPositions
    if (activePositions && Object.keys(activePositions).length > 0) {
      Object.assign(positions, activePositions)
    }

    // Step 4: Overlay session-local dragged positions (highest priority)
    if (Object.keys(draggedPositionsRef.current).length > 0) {
      Object.assign(positions, draggedPositionsRef.current)
    }

    // Step 5: Position child nodes inside their compound parent.
    // Uses the parent's final position (tier → pinned → dragged) so children
    // inherit the correct location. Existing saved child positions are preserved.
    const childrenByParent = {}
    nodes.forEach(n => {
      if (n.data.parent) {
        if (!childrenByParent[n.data.parent]) childrenByParent[n.data.parent] = []
        childrenByParent[n.data.parent].push(n)
      }
    })
    Object.entries(childrenByParent).forEach(([parentId, children]) => {
      const parentPos = positions[parentId]
      if (!parentPos) return
      const spacing = 55
      children.sort((a, b) => (a.data.memberId ?? 0) - (b.data.memberId ?? 0))
      const totalWidth = (children.length - 1) * spacing
      children.forEach((child, i) => {
        // Only compute default offset if child has no saved/dragged position
        if (!positions[child.data.id]) {
          positions[child.data.id] = {
            x: parentPos.x - totalWidth / 2 + i * spacing,
            y: parentPos.y,
          }
        }
      })
      // Remove parent position — Cytoscape auto-computes it from children bounding box
      delete positions[parentId]
    })

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: CYTOSCAPE_STYLE,
      layout: {
        name: 'preset',
        positions: function (node) {
          return positions[node.id()] || { x: containerWidth / 2, y: 300 }
        },
        fit: true,
        padding: 40,
      },
      minZoom: 0.2,
      maxZoom: 4,
    })

    // Restore zoom/pan after collapse/expand toggle (not on first render or view switch)
    if (prevZoom !== undefined) {
      cy.viewport({ zoom: prevZoom, pan: prevPan })
    }

    // Click node → focus mode (dim unrelated, show device detail)
    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      const nodeData = node.data()

      // Pass actual node ID (child ID like sw-01:1 enables member-specific detail panel)
      const deviceId = node.id()

      // Get connected neighborhood (include parent + children for compound nodes)
      let neighborhood = node.closedNeighborhood()
      if (nodeData.isCompound) {
        // Compound parent: also un-dim all children
        neighborhood = neighborhood.union(node.children())
      } else if (nodeData.parent) {
        // Child: also un-dim the parent and siblings
        const parentNode = cy.getElementById(nodeData.parent)
        neighborhood = neighborhood.union(parentNode).union(parentNode.children())
          .union(parentNode.closedNeighborhood())
      }

      // Dim everything, clear edge selection
      cy.elements().addClass('dimmed')
      cy.edges().removeClass('edge-selected')
      cy.nodes().removeClass('edge-endpoint')

      // Un-dim the neighborhood
      neighborhood.removeClass('dimmed')

      // Select the clicked node
      cy.nodes().unselect()
      node.select()

      // Update React state for right panel
      onDeviceSelect(deviceId)
    })

    // Click background → clear focus + edge selection
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass('dimmed')
        cy.edges().removeClass('edge-selected')
        cy.nodes().removeClass('edge-endpoint')
        cy.nodes().unselect()
        onDeviceSelect(null)
        if (onLinkSelect) onLinkSelect(null)
        setTooltip(null)
      }
    })

    // Hover node → tooltip
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target
      const d = node.data()
      const pos = node.renderedPosition()

      let content
      if (d.parent) {
        // Child member tooltip
        content = [
          `${d.parent} — ${d.memberRole || d.label}`,
          d.platform ? `Platform: ${d.platform}` : null,
          d.serial ? `Serial: ${d.serial}` : null,
          d.state ? `State: ${d.state}` : null,
        ]
      } else {
        // Regular or compound parent tooltip
        content = [
          d.id,
          d.isUnreachable ? 'Unreachable device' : null,
          d.platform ? `Platform: ${d.platform}` : null,
          d.role ? `Role: ${d.role.replace(/_/g, ' ')}` : null,
          d.management_ip ? `IP: ${d.management_ip}` : null,
          d.findings_count ? `Findings: ${d.findings_count}` : null,
          d.memberCount ? `Members: ${d.memberCount}` : null,
          d.isCollapsed ? 'Double-click to expand' : null,
          d.isCompound ? 'Double-click to collapse' : null,
        ]
      }

      setTooltip({
        x: pos.x,
        y: pos.y - 30,
        content: content.filter(Boolean),
      })
    })

    cy.on('mouseout', 'node', () => setTooltip(null))

    // Hover edge → tooltip
    cy.on('mouseover', 'edge', (evt) => {
      const edge = evt.target
      const d = edge.data()
      const midpoint = edge.renderedMidpoint()

      let content
      if (d.linkType === 'stack_interconnect') {
        // Stack interconnect edge — show type-specific label
        const subtypeLabels = { cable: 'Stack Cable', svl: 'SVL', ha: 'HA Link', dad: 'DAD' }
        const subtype = subtypeLabels[d.stackSubtype] || 'Stack'
        content = [
          `${subtype}: ${d.source} \u2194 ${d.target}`,
          d.sourcePort && d.targetPort ? `${d.sourcePort} \u2194 ${d.targetPort}` : null,
          d.status ? `Status: ${d.status}` : null,
        ]
      } else {
        content = [
          `${d.source} \u2194 ${d.target}`,
          d.sourcePort && d.targetPort ? `${d.sourcePort} \u2194 ${d.targetPort}` : null,
          d.lag_label ? `LAG: ${d.lag_label}` : null,
          d.discovery_method ? `Method: ${d.discovery_method}` : null,
          d.confidence ? `Confidence: ${d.confidence}` : null,
          d.l3_subnet ? `Subnet: ${d.l3_subnet}` : null,
          d.status ? `Status: ${d.status}` : null,
        ]
      }

      setTooltip({
        x: midpoint.x,
        y: midpoint.y - 20,
        content: content.filter(Boolean),
      })
    })

    cy.on('mouseout', 'edge', () => setTooltip(null))

    // S19A-8: Click edge → link detail panel
    cy.on('tap', 'edge', (evt) => {
      evt.stopPropagation()
      const edge = evt.target
      const d = edge.data()

      // Highlight the clicked edge and its endpoints
      cy.elements().addClass('dimmed')
      cy.edges().removeClass('edge-selected')
      cy.nodes().removeClass('edge-endpoint')
      edge.removeClass('dimmed').addClass('edge-selected')
      const srcNode = cy.getElementById(d.source)
      const tgtNode = cy.getElementById(d.target)
      srcNode.removeClass('dimmed').addClass('edge-endpoint')
      tgtNode.removeClass('dimmed').addClass('edge-endpoint')
      cy.nodes().unselect()

      // Notify App of link selection
      if (onLinkSelect) onLinkSelect(d)
    })

    // Double-click compound node → toggle expand/collapse (disabled in L2/L3 view)
    cy.on('dbltap', 'node[?isExpandable]', (evt) => {
      if (selectedView === 'l2vlan') return
      const nodeId = evt.target.data('id')
      isExpandToggleRef.current = true
      setExpandedNodes(prev => {
        const next = new Set(prev)
        if (next.has(nodeId)) {
          next.delete(nodeId)
        } else {
          next.add(nodeId)
        }
        return next
      })
    })

    cyRef.current = cy

    // S19A-1: ResizeObserver for panel resize → cy.resize() + debounced cy.fit()
    let resizeTimer = null
    const ro = new ResizeObserver(() => {
      if (cyRef.current) {
        cyRef.current.resize()
        clearTimeout(resizeTimer)
        resizeTimer = setTimeout(() => {
          if (cyRef.current) cyRef.current.fit(undefined, 40)
        }, 200)
      }
    })
    if (containerRef.current) ro.observe(containerRef.current)

    return () => {
      ro.disconnect()
      clearTimeout(resizeTimer)
      cy.destroy()
      cyRef.current = null
    }
  }, [topologyData, findingsData, onDeviceSelect, onLinkSelect, expandedNodes, selectedView, ospfVrf])

  // Sync selected device from external source (e.g., findings panel click)
  useEffect(() => {
    // Small delay to ensure Cytoscape graph is fully rendered after expand
    const timer = setTimeout(() => {
      const cy = cyRef.current
      if (!cy) return

      if (selectedDevice) {
        // 2026-05-18: Per-view rendering predicates (COLLAPSED_VIEWS /
        // EXPANDED_VIEWS) force the compound state regardless of the
        // `expandedNodes` user-state. The selection effect must reflect
        // EFFECTIVE expansion (what's actually rendered), otherwise on
        // force-expanded views (Physical, MGMT) the iterative
        // setExpandedNodes-then-return dance loops for several 100ms
        // cycles, sometimes never converging before the user clicks
        // elsewhere — symptom: clicking a finding sometimes paints the
        // map, sometimes leaves the full topology untouched.
        const isForceExpanded = EXPANDED_VIEWS.has(selectedView)
        const isForceCollapsed = COLLAPSED_VIEWS.has(selectedView)
        const isEffectivelyExpanded = (compoundId) => {
          if (isForceExpanded) return true
          if (isForceCollapsed) return false
          return expandedNodes.has(compoundId)
        }

        // Collect all compound nodes that need expanding
        // Use raw topology data (React props) — NOT Cytoscape API
        const toExpand = new Set()
        const deviceBase = selectedDevice.includes(':')
          ? selectedDevice.substring(0, selectedDevice.indexOf(':'))
          : selectedDevice

        // Expand the selected device if it's compound
        if (!isEffectivelyExpanded(deviceBase)) {
          // Check if deviceBase is a compound (has children in topology data)
          const hasChildren = topologyData?.nodes?.some(n => n.data.parent === deviceBase)
          if (hasChildren) toExpand.add(deviceBase)
        }

        // Expand any compound neighbor connected via edges
        if (topologyData?.edges) {
          topologyData.edges.forEach(e => {
            const src = e.data.source || ''
            const tgt = e.data.target || ''
            const srcBase = src.includes(':') ? src.substring(0, src.indexOf(':')) : src
            const tgtBase = tgt.includes(':') ? tgt.substring(0, tgt.indexOf(':')) : tgt

            // If one end belongs to our device, check if the other end's parent needs expanding
            if (srcBase === deviceBase && tgt.includes(':')) {
              if (!isEffectivelyExpanded(tgtBase)) toExpand.add(tgtBase)
            }
            if (tgtBase === deviceBase && src.includes(':')) {
              if (!isEffectivelyExpanded(srcBase)) toExpand.add(srcBase)
            }
          })
        }

        // Expand all at once, then re-render — but ONLY for views where the
        // user-state actually controls expansion. Force-expanded views are
        // already expanded; force-collapsed views ignore expansion anyway.
        if (toExpand.size > 0 && !isForceExpanded && !isForceCollapsed) {
          setExpandedNodes(prev => {
            const next = new Set(prev)
            toExpand.forEach(id => next.add(id))
            return next
          })
          return
        }

        // All compounds expanded — find and select the target node
        let node = cy.getElementById(selectedDevice)
        if (!node.length && selectedDevice.includes(':')) {
          node = cy.getElementById(deviceBase)
        }

        if (node.length) {
          const nodeData = node.data()
          // Focus mode — include parent/children in neighborhood
          let neighborhood = node.closedNeighborhood()
          if (nodeData.isCompound) {
            // Compound parent: include children AND their connected edges/nodes
            const children = node.children()
            neighborhood = neighborhood.union(children)
            children.forEach(c => {
              neighborhood = neighborhood.union(c.closedNeighborhood())
            })
          } else if (nodeData.parent) {
            // Child/member node: show this member's cables + the parent container
            // but NOT the sibling member's cables (blast_radius member failure)
            const parentNode = cy.getElementById(nodeData.parent)
            neighborhood = neighborhood.union(parentNode)
          }
          // For any child node in neighborhood, include its parent compound container
          // (so the container box is visible, not dimmed)
          neighborhood.nodes().forEach(n => {
            const pid = n.data('parent')
            if (pid) {
              neighborhood = neighborhood.union(cy.getElementById(pid))
            }
          })
          cy.elements().addClass('dimmed')
          neighborhood.removeClass('dimmed')
          cy.nodes().unselect()
          node.select()
          cy.animate({ center: { eles: node }, duration: 300 })
        }
      } else {
        // Clear focus
        cy.elements().removeClass('dimmed')
        cy.nodes().unselect()
      }
    }, 100)
    return () => clearTimeout(timer)
  }, [selectedDevice, expandedNodes, selectedView])

  // Highlight path: multiple devices along a trace_path route
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !highlightPath || highlightPath.length === 0) return

    // Clear previous state
    cy.elements().removeClass('dimmed')
    cy.nodes().unselect()

    // Collect all path nodes and their neighborhoods (edges between them)
    let pathElements = cy.collection()
    for (const deviceName of highlightPath) {
      const node = cy.getElementById(deviceName)
      if (node.length) {
        pathElements = pathElements.union(node)
        // Include edges connecting path devices to each other
        node.connectedEdges().forEach(edge => {
          const srcId = edge.source().id()
          const tgtId = edge.target().id()
          // Include edge if both endpoints are in the path
          // Also include if one end is a child of a path device
          const srcBase = srcId.includes(':') ? srcId.substring(0, srcId.indexOf(':')) : srcId
          const tgtBase = tgtId.includes(':') ? tgtId.substring(0, tgtId.indexOf(':')) : tgtId
          if (highlightPath.includes(srcBase) && highlightPath.includes(tgtBase)) {
            pathElements = pathElements.union(edge)
          }
        })
        // Include parent compound if node is a child
        const parent = node.data('parent')
        if (parent) pathElements = pathElements.union(cy.getElementById(parent))
        // Include children if node is a compound
        if (node.data('isCompound')) {
          pathElements = pathElements.union(node.children())
        }
      }
    }

    if (pathElements.length > 0) {
      cy.elements().addClass('dimmed')
      pathElements.removeClass('dimmed')
      pathElements.nodes().select()
      cy.animate({ fit: { eles: pathElements, padding: 50 }, duration: 500 })
    }
  }, [highlightPath])

  // S19B-4: VLAN illuminate/dim overlay
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    // Clear previous VLAN overlay classes, IP labels, and edge labels
    cy.elements().removeClass('vlan-active vlan-inactive')
    cy.nodes().removeData('vlanIp')
    cy.edges().removeData('vlanLabel')

    if (!selectedVlan || !vlanData?.vlans) return

    const vlan = vlanData.vlans.find(v => v.vlan_id === selectedVlan)
    if (!vlan) return

    // Build set of active device hostnames from VLAN members
    const activeHostnames = new Set(vlan.members.map(m => m.hostname))

    // Determine active nodes: device is a member, or compound parent has an active child
    const activeNodeIds = new Set()
    cy.nodes().forEach(node => {
      const d = node.data()
      const hostname = d.parent ? d.parent : d.id
      // Child node: check parent hostname
      if (d.parent) {
        if (activeHostnames.has(d.parent)) activeNodeIds.add(node.id())
      } else if (d.isCompound) {
        // Compound parent: active if any child would be active
        if (activeHostnames.has(d.id)) activeNodeIds.add(node.id())
      } else {
        if (activeHostnames.has(hostname)) activeNodeIds.add(node.id())
      }
    })

    // Determine active edges: l2_vlans_carried contains the VLAN, or both endpoints active
    const activeEdgeIds = new Set()
    cy.edges().forEach(edge => {
      const d = edge.data()
      const carried = d.l2_vlans_carried
      if (Array.isArray(carried) && carried.map(String).includes(String(selectedVlan))) {
        activeEdgeIds.add(edge.id())
      } else if (activeNodeIds.has(d.source) && activeNodeIds.has(d.target)) {
        // Fallback: both endpoints are VLAN members
        activeEdgeIds.add(edge.id())
      }
    })

    // Activate L3 devices: endpoints of VLAN-carrying edges (routed/access peers)
    const edgeEndpoints = new Set()
    cy.edges().forEach(edge => {
      if (activeEdgeIds.has(edge.id())) {
        edgeEndpoints.add(edge.data('source'))
        edgeEndpoints.add(edge.data('target'))
      }
    })
    cy.nodes().forEach(node => {
      if (activeNodeIds.has(node.id())) return  // already active
      const d = node.data()
      const hostname = d.parent ? d.parent : d.id
      if (edgeEndpoints.has(hostname) || edgeEndpoints.has(d.id)) {
        activeNodeIds.add(node.id())
      }
    })

    // Apply classes
    cy.nodes().forEach(node => {
      if (activeNodeIds.has(node.id())) {
        node.addClass('vlan-active')
      } else {
        node.addClass('vlan-inactive')
      }
    })
    cy.edges().forEach(edge => {
      if (activeEdgeIds.has(edge.id())) {
        edge.addClass('vlan-active')
      } else {
        edge.addClass('vlan-inactive')
      }
    })

    // S19B-6: Set VLAN mode label on active edges
    const memberModes = {}
    vlan.members.forEach(m => { memberModes[m.hostname] = m.mode })
    cy.edges().forEach(edge => {
      if (!activeEdgeIds.has(edge.id())) return
      const d = edge.data()
      // Determine mode from source or target member
      const srcMode = memberModes[d.source]
      const tgtMode = memberModes[d.target]
      const mode = srcMode || tgtMode || 'trunk'
      edge.data('vlanLabel', `${mode} \u00b7 VLAN ${selectedVlan}`)
    })

    // S19B-5: Extract VLAN IP for each active node from edge L3 data
    const vlanSubnet = vlan.subnet
    if (vlanSubnet) {
      const nodeIps = {}
      cy.edges().forEach(edge => {
        const d = edge.data()
        if (d.l3_subnet !== vlanSubnet) return
        if (d.l3_local_ip && d.source) nodeIps[d.source] = d.l3_local_ip
        if (d.l3_remote_ip && d.target) nodeIps[d.target] = d.l3_remote_ip
      })
      Object.entries(nodeIps).forEach(([nodeId, ip]) => {
        const node = cy.getElementById(nodeId)
        if (node.length) node.data('vlanIp', ip)
      })
    }
  }, [selectedVlan, vlanData])

  const handleZoomIn = useCallback(() => {
    if (cyRef.current) {
      const z = cyRef.current.zoom()
      cyRef.current.animate({ zoom: { level: z * 1.3, renderedPosition: { x: containerRef.current.clientWidth / 2, y: containerRef.current.clientHeight / 2 } }, duration: 200 })
    }
  }, [])

  const handleZoomOut = useCallback(() => {
    if (cyRef.current) {
      const z = cyRef.current.zoom()
      cyRef.current.animate({ zoom: { level: z / 1.3, renderedPosition: { x: containerRef.current.clientWidth / 2, y: containerRef.current.clientHeight / 2 } }, duration: 200 })
    }
  }, [])

  const handleFitAll = useCallback(() => {
    if (cyRef.current) {
      cyRef.current.elements().removeClass('dimmed')
      cyRef.current.edges().removeClass('edge-selected')
      cyRef.current.nodes().removeClass('edge-endpoint')
      cyRef.current.nodes().unselect()
      cyRef.current.fit(undefined, 40)
      onDeviceSelect(null)
      if (onLinkSelect) onLinkSelect(null)
    }
  }, [onDeviceSelect, onLinkSelect])

  const handleExpandAll = useCallback(() => {
    isExpandToggleRef.current = true
    setExpandedNodes(new Set(compoundNodeIdsRef.current))
  }, [])

  const handleCollapseAll = useCallback(() => {
    isExpandToggleRef.current = true
    setExpandedNodes(new Set())
  }, [])

  // S19A-11: Severity counts for summary bar (exclude acknowledged, ADR-174)
  const sevCounts = useMemo(() => {
    const counts = {}
    const findings = (findingsData?.findings || []).filter(f => !f.acknowledged)
    findings.forEach(f => {
      const s = f.severity || 'info'
      counts[s] = (counts[s] || 0) + 1
    })
    return counts
  }, [findingsData])

  // Active view label
  const viewLabel = useMemo(() => {
    const v = TOPOLOGY_VIEWS.find(v => v.id === selectedView)
    return v ? v.label : 'Physical'
  }, [selectedView])

  const hasCompounds = compoundNodeIdsRef.current.size > 0

  const handlePinLayout = useCallback(async () => {
    if (!cyRef.current || !selectedRun) return
    const pos = {}
    cyRef.current.nodes().forEach(n => {
      // Exclude compound parents — their position is derived from children
      if (n.children().length === 0) {
        pos[n.id()] = { x: n.position('x'), y: n.position('y') }
      }
    })
    // Save to separate Neo4j key based on expand state
    const isExp = expandedNodes.size > 0
    const viewKey = isExp ? selectedView + '_expanded' : selectedView
    // Block 13 F2 — was silent-fail (Block 4 deferred TODO):
    //   - No response.ok check → 401/4xx/5xx silently set pinSaved=true
    //     ("Saved!" toast despite no save). Pre-Block-11 F2, the WWW-Authenticate
    //     dialog timing meant first click could 401 before browser cached creds.
    //   - catch { /* silent */ } swallowed network errors.
    // Now: explicit response.ok branch + caught exception surfaces pinError.
    try {
      const res = await fetch('/api/topology/positions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: selectedRun, view: viewKey, positions: pos }),
      })
      if (!res.ok) {
        console.warn('Pin Layout: save failed —', res.status, res.statusText)
        setPinError(`Save failed (HTTP ${res.status}). Click again to retry.`)
        setTimeout(() => setPinError(null), 3000)
        return
      }
      // Update the correct in-memory position set
      if (isExp) {
        if (onExpandedPositionsChange) onExpandedPositionsChange(pos)
      } else {
        if (onCollapsedPositionsChange) onCollapsedPositionsChange(pos)
      }
      setPinSaved(true)
      setTimeout(() => setPinSaved(false), 2000)
    } catch (err) {
      console.warn('Pin Layout: network error —', err)
      setPinError('Network error. Try again when connection restores.')
      setTimeout(() => setPinError(null), 3000)
    }
  }, [selectedRun, selectedView, expandedNodes, onCollapsedPositionsChange, onExpandedPositionsChange])

  if (!topologyData) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        Select a run to view topology
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      {/* Cytoscape container */}
      <div ref={containerRef} className="w-full h-full" />

      {/* Honest empty-state for the MGMT view: when a network has no out-of-band
          management fabric there are no MGMT_LINK edges, so we show the devices
          unconnected with this note rather than a misleading data backbone. */}
      {selectedView === 'mgmt' && (topologyData.edges || []).length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="bg-white/90 border border-gray-200 rounded-lg px-4 py-3 shadow-sm text-center max-w-sm">
            <div className="text-gray-700 font-semibold text-sm">
              No out-of-band management discovered
            </div>
            <div className="text-gray-500 text-xs mt-1">
              This network has no dedicated management switch or OOB management
              links — there is no management fabric to map. Devices are shown
              unconnected.
            </div>
          </div>
        </div>
      )}

      {/* ── S19A-10: Toolbar — 3 groups ── */}
      <div className="absolute top-3 right-3 flex items-center gap-1">
        {/* Group 1: Zoom */}
        <button
          onClick={handleZoomIn}
          className="bg-white border border-gray-300 rounded-md px-2 py-1.5 text-xs text-gray-600 hover:bg-gray-50 shadow-sm"
          title="Zoom in"
        >
          +
        </button>
        <button
          onClick={handleZoomOut}
          className="bg-white border border-gray-300 rounded-md px-2 py-1.5 text-xs text-gray-600 hover:bg-gray-50 shadow-sm"
          title="Zoom out"
        >
          &minus;
        </button>
        <button
          onClick={handleFitAll}
          className="bg-white border border-gray-300 rounded-md px-2.5 py-1.5 text-xs text-gray-600 hover:bg-gray-50 shadow-sm"
          title="Fit all nodes in view"
        >
          Fit
        </button>

        {/* Group 2: Compound controls. Today every view is in COLLAPSED_VIEWS or
            EXPANDED_VIEWS so this conditional renders nothing; handlers + state
            are intentionally retained so a future view outside both predicate
            sets surfaces the buttons again automatically. */}
        {hasCompounds && !COLLAPSED_VIEWS.has(selectedView) && !EXPANDED_VIEWS.has(selectedView) && (
          <>
            <div className="w-px h-5 bg-gray-300 mx-0.5" />
            <button
              onClick={handleExpandAll}
              className="bg-white border border-gray-300 rounded-md px-2.5 py-1.5 text-xs text-gray-600 hover:bg-gray-50 shadow-sm"
              title="Expand all compound nodes"
            >
              Expand
            </button>
            <button
              onClick={handleCollapseAll}
              className="bg-white border border-gray-300 rounded-md px-2.5 py-1.5 text-xs text-gray-600 hover:bg-gray-50 shadow-sm"
              title="Collapse all compound nodes"
            >
              Collapse
            </button>
          </>
        )}

        {/* Group 3: Legend toggle */}
        <div className="w-px h-5 bg-gray-300 mx-0.5" />
        <button
          onClick={() => setShowLegend(v => !v)}
          className={`border rounded-md px-2.5 py-1.5 text-xs font-medium shadow-sm ${
            showLegend
              ? 'bg-blue-50 border-blue-300 text-blue-700'
              : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50'
          }`}
          title={showLegend ? 'Hide legend' : 'Show legend'}
        >
          Legend
        </button>

        {/* Group 4: Pin layout */}
        <div className="w-px h-5 bg-gray-300 mx-0.5" />
        <button
          onClick={handlePinLayout}
          disabled={!selectedRun}
          className={`border rounded-md px-2.5 py-1.5 text-xs font-medium shadow-sm transition-colors ${
            pinSaved
              ? 'bg-green-50 border-green-300 text-green-700'
              : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50 disabled:opacity-40'
          }`}
          title="Save current node positions (persists across sessions)"
        >
          {pinSaved ? 'Saved!' : 'Pin Layout'}
        </button>
        {/* Block 13 F2: error feedback (was silent-fail). Sits inline with toolbar. */}
        {pinError && (
          <div
            className="ml-2 px-2.5 py-1.5 text-xs font-medium rounded-md border bg-red-50 border-red-300 text-red-700 shadow-sm"
            role="alert"
            title={pinError}
          >
            {pinError}
          </div>
        )}
      </div>

      {/* ── S19A-12: Topology Legend ── */}
      {showLegend && (
        <div
          className="absolute top-12 right-3 z-40 bg-white border border-gray-200 rounded-lg shadow-md text-xs"
          style={{ width: 200, padding: 12 }}
        >
          <p className="font-bold text-gray-700 mb-2">Nodes</p>
          {[
            // Role colours come from the legend source of truth (roleColors,
            // from /api/legend) so the swatches can't drift from the map.
            ['Border Router', roleColors.border_router || '#1D4ED8', 'solid'],
            ['Core Switch', roleColors.core_switch || '#6D28D9', 'solid'],
            ['Distribution', roleColors.distribution_switch || '#7C3AED', 'solid'],
            ['Services Switch', roleColors.services_switch || '#0891B2', 'solid'],
            ['Access Switch', roleColors.access_switch || '#6B7280', 'solid'],
            ['Mgmt Switch', roleColors.mgmt_switch || '#6B7280', 'solid'],
            ['DMZ Switch', roleColors.dmz_switch || '#DC2626', 'solid'],
            ['Firewall', roleColors.firewall || '#C2410C', 'solid'],
            ['External', roleColors.external || '#9CA3AF', 'dashed'],
            ['Unreachable', '#DC2626', 'dashed'],
            // Route reflector is marked by a double border on its role colour
            // (core_switch), matching node[?is_route_reflector] on the map.
            ['Route Reflector', roleColors.core_switch || '#6D28D9', 'double'],
          ].map(([label, color, shape]) => (
            <div key={label} className="flex items-center gap-2 mb-1">
              <span
                className="shrink-0 rounded-sm"
                style={{
                  width: 10,
                  height: 10,
                  border: `${shape === 'double' ? 3 : 2}px solid ${color}`,
                  borderStyle: shape === 'dashed' ? 'dashed' : shape === 'double' ? 'double' : 'solid',
                  background: '#FFF',
                }}
              />
              <span className="text-gray-600">{label}</span>
            </div>
          ))}

          <p className="font-bold text-gray-700 mt-3 mb-2">Edges</p>
          {[
            // Line COLOUR encodes link type / status (matches the edge selectors).
            ['Managed link', '#94A3B8', 'solid', 2],
            ['Link up', '#64748B', 'solid', 2.5],
            ['OSPF adjacency', '#059669', 'solid', 2.5],
            ['Fiber cable', '#1E3A5F', 'solid', 2.5],
            ['Copper cable', '#0284C7', 'solid', 2.5],
            ['Inband mgmt', '#3B82F6', 'dashed', 1.5],
            ['OOB mgmt', '#6B7280', 'solid', 1.5],
            ['Stack interconnect', '#EA580C', 'solid', 4],
            ['Link down', '#EF4444', 'dashed', 2.5],
          ].map(([label, color, style, width]) => (
            <div key={label} className="flex items-center gap-2 mb-1">
              <svg width="20" height="8" className="shrink-0">
                <line
                  x1="0" y1="4" x2="20" y2="4"
                  stroke={color}
                  strokeWidth={width}
                  strokeDasharray={style === 'dashed' ? '4,2' : style === 'dotted' ? '2,2' : 'none'}
                />
              </svg>
              <span className="text-gray-600">{label}</span>
            </div>
          ))}

          <p className="text-gray-400 italic mt-1.5 mb-1" style={{ fontSize: 10 }}>
            Line thickness/solid = higher discovery confidence; thin/dotted = lower.
          </p>

          <p className="font-bold text-gray-700 mt-3 mb-2">Indicators</p>
          {[
            ['Critical findings', '#DC2626'],
            ['High findings', '#F59E0B'],
          ].map(([label, color]) => (
            <div key={label} className="flex items-center gap-2 mb-1">
              <span
                className="shrink-0 rounded-full"
                style={{ width: 8, height: 8, background: color }}
              />
              <span className="text-gray-600">{label}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── S19A-11: Enhanced summary bar ── */}
      <div className="absolute bottom-3 left-3 right-3 flex items-center gap-3 bg-white/90 border border-gray-200 rounded-lg px-3 py-1.5 shadow-sm text-xs">
        <span className="font-semibold text-gray-700">{viewLabel} View</span>
        <span className="text-gray-400">|</span>
        <span className="text-gray-600">
          {topologyData.nodes.filter(n => !n.data.isCompound && n.data.collected !== false).length} devices
        </span>
        <span className="text-gray-400">&middot;</span>
        <span className="text-gray-600">{topologyData.edges.filter(e => e.data?.linkType !== 'stack_interconnect').length} links</span>
        <span className="text-gray-400">|</span>
        <div className="flex items-center gap-1.5">
          {severityOrder.map(sev => {
            const count = sevCounts[sev] || 0
            if (!count) return null
            const sc = sevColors[sev]
            const isActive = !severityFilters || severityFilters.has(sev)
            return (
              <button
                key={sev}
                onClick={() => onToggleSeverity?.(sev)}
                className="flex items-center gap-0.5 cursor-pointer"
                style={{ opacity: isActive ? 1 : 0.35 }}
                title={`${isActive ? 'Hide' : 'Show'} ${sev} findings`}
              >
                <span
                  className="rounded-full"
                  style={{ width: 6, height: 6, background: sc.color }}
                />
                <span style={{ color: sc.color, fontWeight: 600 }}>{count}</span>
              </button>
            )
          })}
        </div>
        {selectedRun && (
          <>
            <span className="text-gray-400">|</span>
            <span className="text-gray-400 truncate">{selectedRun}</span>
          </>
        )}
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute z-50 bg-gray-800 text-white text-xs rounded-md px-3 py-2 shadow-lg pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y,
            transform: 'translate(-50%, -100%)',
          }}
        >
          {tooltip.content.map((line, i) => (
            <div key={i} className={i === 0 ? 'font-semibold' : 'text-gray-300'}>
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
