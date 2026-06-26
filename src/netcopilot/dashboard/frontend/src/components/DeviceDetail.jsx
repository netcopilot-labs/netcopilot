import { useState, useEffect, useMemo, Fragment } from 'react'
import { formatRole } from '../topologyUtils.js'
import { useLegend } from '../contexts/LegendContext.jsx'

// Protocol badge colors
const PROTOCOL_BADGES = {
  ospf: { bg: '#DBEAFE', color: '#2563EB', label: 'OSPF' },
  bgp: { bg: '#EDE9FE', color: '#7C3AED', label: 'BGP' },
}

function StatusDot({ status }) {
  const color = status === 'up' ? '#22C55E'
    : status === 'down' ? '#EF4444'
    : '#9CA3AF'
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
}

// ── Format helpers ──
function formatSpeed(speed) {
  if (!speed) return null
  const s = String(speed).toLowerCase()
  if (s.includes('100000') || s.includes('100g')) return '100G'
  if (s.includes('25000') || s.includes('25g')) return '25G'
  if (s.includes('10000') || s.includes('10g')) return '10G'
  if (s.includes('1000') || s.includes('1g')) return '1G'
  if (s.includes('100')) return '100M'
  return speed
}

function formatMedia(media) {
  if (!media) return null
  const m = String(media).toLowerCase()
  if (m === 'fiber-sr') return 'Fiber SR'
  if (m === 'fiber-lr') return 'Fiber LR'
  if (m === 'fiber-er') return 'Fiber ER'
  if (m === 'fiber-zr') return 'Fiber ZR'
  if (m === 'fiber-mm') return 'Fiber MM'
  if (m === 'fiber-aoc') return 'Fiber AOC'
  if (m === 'fiber') return 'Fiber'
  if (m === 'copper' || m === 'copper-sfp') return 'Copper'
  return media
}

function formatCir(bps) {
  if (!bps) return null
  const n = Number(bps)
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} Gbps`
  if (n >= 1e6) return `${(n / 1e6).toFixed(0)} Mbps`
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)} Kbps`
  return `${n} bps`
}

// =============================================================================
// IOS interface sort order: SVI → Mgmt → Physical → Port-channel → Other
// =============================================================================
function interfaceSortKey(name) {
  if (!name) return [9, 0, 0, 0]
  if (name.startsWith('Vlan')) {
    const num = parseInt(name.slice(4), 10) || 0
    return [1, num, 0, 0]
  }
  if (/^(Gi|GigabitEthernet)0\/0$/.test(name)) return [2, 0, 0, 0]
  if (/^(Gi|Te|Tw|Hu|Fo|Et|TwentyFiveGigE|HundredGigE|TenGigabit|GigabitEthernet|FastEthernet)/.test(name)) {
    const nums = name.match(/\d+/g)?.map(Number) || []
    return [3, ...nums, 0, 0]
  }
  if (name.startsWith('Port-channel')) {
    const num = parseInt(name.slice(12), 10) || 0
    return [4, num, 0, 0]
  }
  // Loopback, Tunnel, Bluetooth, etc.
  const nums = name.match(/\d+/g)?.map(Number) || []
  return [5, ...nums, 0, 0]
}

function compareArrays(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const av = a[i] ?? 0, bv = b[i] ?? 0
    if (av !== bv) return av - bv
  }
  return 0
}

// =============================================================================
// Network Summary (shown when no device/link focused)
// =============================================================================
function NetworkSummary({ topologyData, networkSummary, findingsData, onDeviceSelect }) {
  const { sevColors, severityOrder } = useLegend()
  const summary = findingsData?.summary || {}
  const bySeverity = summary.by_severity || {}
  const totalFindings = summary.total_findings || findingsData?.findings?.length || 0
  const ns = networkSummary || {}
  const physicalDevices = ns.physicalDevices ?? 0
  const clusters = ns.clusters ?? 0
  const externalPeers = ns.externalPeers ?? 0
  const unreachable = ns.unreachable ?? 0
  const fiberLinks = ns.fiber ?? 0
  const rj45Links = ns.rj45 ?? 0
  const mgmtOob = ns.mgmtOob ?? 0
  const svlLinks = ns.svl ?? 0
  const stackCables = ns.stack ?? 0
  const haLinks = ns.ha ?? 0
  const downLinks = ns.down ?? 0

  const rulesCount = useMemo(() => {
    if (!findingsData?.findings) return 0
    return new Set(findingsData.findings.map(f => f.rule_id).filter(Boolean)).size
  }, [findingsData])

  const deviceItems = useMemo(() => {
    if (!topologyData?.nodes) return []
    const findings = findingsData?.findings || []
    const counts = {}
    findings.forEach(f => {
      const eid = f.evidence?.element_id || f.finding_id || ''
      let dev = eid.includes('::') ? eid.split('::')[1] : eid
      if (dev.includes('--')) {
        dev.split('--').forEach(p => {
          const d = p.split(':')[0].split('/')[0]
          if (d) counts[d] = (counts[d] || 0) + 1
        })
      } else {
        const d = dev.split(':')[0].split('/')[0]
        if (d) counts[d] = (counts[d] || 0) + 1
      }
    })
    return topologyData.nodes
      .filter(n => !n.data.parent)
      .map(n => ({ id: n.data.id, site: n.data.site || '', role: n.data.role, findings: counts[n.data.id] || 0 }))
      .sort((a, b) => b.findings - a.findings)
  }, [topologyData, findingsData])

  const maxSev = Math.max(...severityOrder.map(s => bySeverity[s] || 0), 1)

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0F4F3A' }}>Network Summary</h2>
      </div>
      <div className="grid grid-cols-3 gap-2 p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        {[
          { label: 'Physical Devices', value: physicalDevices, color: '#2563EB' },
          { label: 'Clusters', value: clusters, color: '#7C3AED' },
          { label: 'External Peers', value: externalPeers, color: '#6B7280' },
          { label: 'Unreachable', value: unreachable, color: unreachable > 0 ? '#DC2626' : '#6B7280' },
          { label: 'Fiber Links', value: fiberLinks, color: '#1E3A5F' },
          { label: 'RJ45 Links', value: rj45Links, color: '#0284C7' },
          { label: 'Mgmt OOB', value: mgmtOob, color: '#6B7280' },
          { label: 'SVL Links', value: svlLinks, color: '#7C3AED' },
          { label: 'Stack Cables', value: stackCables, color: '#7C3AED' },
          { label: 'HA Links', value: haLinks, color: '#EA580C' },
          { label: 'Down Links', value: downLinks, color: downLinks > 0 ? '#DC2626' : '#6B7280' },
          { label: 'Findings', value: totalFindings, color: totalFindings > 0 ? '#DC2626' : '#059669' },
        ].map(stat => (
          <div key={stat.label} className="rounded-lg p-2 text-center" style={{ background: '#F8FAFC' }}>
            <p className="text-lg font-bold" style={{ color: stat.color }}>{stat.value}</p>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Severity Distribution</p>
        <div className="space-y-1.5">
          {severityOrder.map(sev => {
            const count = bySeverity[sev] || 0
            if (count === 0) return null
            const sc = sevColors[sev]
            const width = Math.max((count / maxSev) * 100, 4)
            return (
              <div key={sev} className="flex items-center gap-2">
                <span className="text-xs text-gray-500 capitalize w-14">{sev}</span>
                <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ background: sc.bg }}>
                  <div className="h-full rounded-full" style={{ width: `${width}%`, background: sc.color }} />
                </div>
                <span className="text-xs font-medium text-gray-700 w-8 text-right">{count}</span>
              </div>
            )
          })}
        </div>
      </div>
      <div className="flex-1 overflow-y-auto">
        <div className="px-3 pt-3 pb-1">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Devices</p>
        </div>
        {deviceItems.map(d => (
          <button
            key={d.id}
            onClick={() => onDeviceSelect(d.id)}
            className="w-full text-left px-3 py-2 border-b hover:bg-gray-50 transition-colors flex items-center justify-between"
            style={{ borderColor: '#F3F4F6' }}
          >
            <div className="min-w-0">
              <p className="text-xs font-medium text-gray-700 truncate">{d.id}</p>
              {d.site && <p className="text-xs text-gray-400 truncate">{d.site}</p>}
            </div>
            {d.findings > 0 && (
              <span className="text-xs font-medium px-1.5 py-0.5 rounded-full shrink-0 ml-2"
                style={{ background: sevColors.high.bg, color: sevColors.high.color }}>
                {d.findings}
              </span>
            )}
          </button>
        ))}
      </div>
    </div>
  )
}

// =============================================================================
// OSPF LSDB Section (ADR-220) — reused in adjacency panel and OspfTab
// =============================================================================
const LSA_TYPE_LABELS = { 1: 'Router', 2: 'Network', 3: 'Summary', 5: 'External', 7: 'NSSA External' }

function OspfLsdbSection({ lsas, areaId }) {
  const [expanded, setExpanded] = useState(false)
  if (!lsas || lsas.length === 0) return null

  // Group by type
  const byType = {}
  for (const l of lsas) {
    const t = l.lsa_type
    if (!byType[t]) byType[t] = []
    byType[t].push(l)
  }
  const type1Count = (byType[1] || []).length
  const type3 = byType[3] || []
  const type5 = byType[5] || []
  const type7 = byType[7] || []
  const routeTypes = [
    { type: 3, label: 'Inter-Area (Type 3)', lsas: type3, color: '#2563EB' },
    { type: 7, label: 'NSSA External (Type 7)', lsas: type7, color: '#7C3AED' },
    { type: 5, label: 'External (Type 5)', lsas: type5, color: '#DC2626' },
  ].filter(g => g.lsas.length > 0)

  return (
    <div className="mt-3">
      <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
          LSDB &mdash; Area {areaId || '0'}
        </p>
        <span className="text-xs text-gray-400">
          {lsas.length} LSAs {expanded ? '\u25B2' : '\u25BC'}
        </span>
      </div>
      {expanded && (
        <div className="mt-1.5 space-y-2">
          {type1Count > 0 && (
            <p className="text-xs text-gray-500">{type1Count} Router LSAs (Type 1)</p>
          )}
          {routeTypes.map(g => (
            <div key={g.type}>
              <p className="text-xs font-medium mb-0.5" style={{ color: g.color }}>
                {g.label} ({g.lsas.length})
              </p>
              <div className="max-h-32 overflow-y-auto border border-gray-200 rounded" style={{ fontSize: 10 }}>
                <table className="w-full">
                  <thead>
                    <tr className="bg-gray-100 text-gray-500 sticky top-0">
                      <th className="px-1.5 py-0.5 text-left font-medium">Prefix</th>
                      <th className="px-1.5 py-0.5 text-left font-medium">Adv Router</th>
                      <th className="px-1.5 py-0.5 text-left font-medium">Metric</th>
                      {g.type >= 5 && <th className="px-1.5 py-0.5 text-left font-medium">Fwd Addr</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {g.lsas.map((l, i) => (
                      <tr key={`${l.prefix}-${l.adv_router}-${i}`} className={i % 2 === 0 ? 'bg-gray-50' : ''}>
                        <td className="px-1.5 py-0.5 font-mono text-gray-700">{l.prefix || l.lsa_id}</td>
                        <td className="px-1.5 py-0.5 font-mono text-gray-500">{l.adv_router}</td>
                        <td className="px-1.5 py-0.5 font-mono text-gray-400">{l.metric ?? '\u2014'}</td>
                        {g.type >= 5 && <td className="px-1.5 py-0.5 font-mono text-gray-400">{l.fwd_addr || '\u2014'}</td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// =============================================================================
// Link Detail (S19A-8: shown when edge is clicked)
// =============================================================================
function OspfAdjacencyDetail({ linkData, findingsData, selectedRun, onClose }) {
  const { sevColors } = useLegend()
  const d = linkData
  const stateColor = d.state === 'full' ? '#059669' : '#DC2626'
  const stateBg = d.state === 'full' ? '#ECFDF5' : '#FEF2F2'

  // Fetch routing tables for both devices — used for OSPF learned networks + full routes via link
  const [exchangedRoutes, setExchangedRoutes] = useState(null)
  const [allRoutesViaLink, setAllRoutesViaLink] = useState(null)
  useEffect(() => {
    if (!selectedRun || !d.source || !d.target) return
    const runId = selectedRun.run_id || selectedRun
    Promise.all([
      fetch(`/api/device/${encodeURIComponent(d.source)}/routing?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
      fetch(`/api/device/${encodeURIComponent(d.target)}/routing?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
    ]).then(([srcData, tgtData]) => {
      const tgtIp = d.ip_b || ''
      const srcIp = d.ip_a || ''
      const vrf = d.vrf || ''

      // OSPF-specific learned networks (filtered to this adjacency's VRF)
      const fromTarget = (srcData.routes || []).filter(r =>
        r.protocol === 'ospf' && r.next_hop === tgtIp && (!vrf || r.vrf === vrf)
      )
      const fromSource = (tgtData.routes || []).filter(r =>
        r.protocol === 'ospf' && r.next_hop === srcIp && (!vrf || r.vrf === vrf)
      )
      setExchangedRoutes({ fromTarget, fromSource })

      // Full routes via link — all protocols, all VRFs (ADR-219: consistent across views)
      // Collect all IPs for each device from their routing data to match next-hops
      const srcRoutes = srcData.routes || []
      const tgtRoutes = tgtData.routes || []
      const fullRoutes = []
      // Source routes with next-hop = target IP (any VRF, any protocol)
      if (tgtIp) {
        srcRoutes.filter(r => r.next_hop === tgtIp).forEach(r => {
          fullRoutes.push({ ...r, device: d.source, direction: `${d.source} → ${d.target}` })
        })
      }
      // Target routes with next-hop = source IP (any VRF, any protocol)
      if (srcIp) {
        tgtRoutes.filter(r => r.next_hop === srcIp).forEach(r => {
          fullRoutes.push({ ...r, device: d.target, direction: `${d.target} → ${d.source}` })
        })
      }
      setAllRoutesViaLink(fullRoutes.length > 0 ? fullRoutes : null)
    }).catch(() => { setExchangedRoutes(null); setAllRoutesViaLink(null) })
  }, [selectedRun, d.source, d.target, d.ip_a, d.ip_b, d.vrf])

  // Fetch LSDB for this adjacency's area (ADR-220)
  const [lsdbData, setLsdbData] = useState(null)
  useEffect(() => {
    if (!selectedRun || !d.area) return
    const runId = selectedRun.run_id || selectedRun
    const vrf = d.vrf || 'default'
    fetch(`/api/topology/area/${encodeURIComponent(d.area)}/lsdb?run_id=${encodeURIComponent(runId)}&vrf=${encodeURIComponent(vrf)}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => setLsdbData(data?.lsas?.length > 0 ? data.lsas : null))
      .catch(() => setLsdbData(null))
  }, [selectedRun, d.area, d.vrf])

  // Filter OSPF findings scoped to this specific adjacency
  const ospfFindings = useMemo(() => {
    if (!findingsData?.findings) return []
    const src = d.source, tgt = d.target
    const area = d.area || ''
    const intfA = d.interface_a || '', intfB = d.interface_b || ''
    // Patterns to match in element_id:
    //   area-level: "hostname/ospf/.../area/{area}/..."
    //   interface-level: "hostname/ospf/.../intf/{interface}"
    //   cross-device: element_id contains both src and tgt
    const areaPattern = area ? `/area/${area}` : null
    return findingsData.findings.filter(f => {
      const rid = f.rule_id || ''
      if (!rid.startsWith('OSPF_') && !rid.startsWith('XD_OSPF_')) return false
      const eid = f.evidence?.element_id || ''
      // Cross-device findings: must mention both endpoints
      if (rid.startsWith('XD_OSPF_')) {
        return eid.includes(src) && eid.includes(tgt)
      }
      // Single-device findings: must be on one of the endpoints
      const onSrc = eid.startsWith(src + '/')
      const onTgt = eid.startsWith(tgt + '/')
      if (!onSrc && !onTgt) return false
      // Interface-specific findings: must match one of this adjacency's interfaces
      if (eid.includes('/intf/')) {
        return (intfA && eid.includes(`/intf/${intfA}`)) || (intfB && eid.includes(`/intf/${intfB}`))
      }
      // Area-specific findings: must match this adjacency's area
      if (areaPattern && eid.includes('/area/')) {
        return eid.includes(areaPattern)
      }
      // Process-level findings (no area in eid): include if on either device
      return true
    })
  }, [findingsData, d.source, d.target, d.area, d.interface_a, d.interface_b])

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <h2 style={{ fontSize: 14, fontWeight: 800, color: '#0F4F3A' }} className="truncate">
              OSPF Adjacency
            </h2>
            <p className="text-xs text-gray-600 mt-0.5">
              {d.source} &harr; {d.target}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none ml-2 shrink-0">&times;</button>
        </div>
        <div className="flex items-center gap-2 mt-1.5">
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded"
            style={{ color: stateColor, background: stateBg }}
          >
            {(d.state || 'unknown').toUpperCase()}
          </span>
          <span className="text-xs text-gray-500">Area {d.area || '0'}</span>
          {d.area_type && (
            <span className={`text-xs font-bold px-1 py-0 rounded ${
              d.area_type === 'backbone' ? 'bg-blue-50 text-blue-600' :
              d.area_type?.includes('stub') ? 'bg-amber-50 text-amber-600' :
              d.area_type?.includes('nssa') ? 'bg-purple-50 text-purple-600' :
              'bg-gray-100 text-gray-500'
            }`} style={{ fontSize: 10 }}>
              {d.area_type}
            </span>
          )}
          <span className="text-xs text-gray-400">Process {d.process_id}</span>
          {d.vrf && <span className="text-xs text-gray-400">VRF: {d.vrf}</span>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {/* Bilateral parameters table */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Interface Parameters</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="py-1 pr-2 font-medium"></th>
                <th className="py-1 pr-2 font-medium">{d.source}</th>
                <th className="py-1 font-medium">{d.target}</th>
              </tr>
            </thead>
            <tbody className="text-gray-600">
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Interface</td>
                <td className="py-1 pr-2 font-mono">{d.interface_a || '—'}</td>
                <td className="py-1 font-mono">{d.interface_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">IP Address</td>
                <td className="py-1 pr-2 font-mono">{d.ip_a || '—'}</td>
                <td className="py-1 font-mono">{d.ip_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Router ID</td>
                <td className="py-1 pr-2 font-mono">{d.router_id_a || '—'}</td>
                <td className="py-1 font-mono">{d.router_id_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Cost</td>
                <td className="py-1 pr-2">{d.cost_a ?? '—'}</td>
                <td className="py-1">{d.cost_b ?? '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Hello / Dead</td>
                <td className="py-1 pr-2">{d.hello_a ?? '—'}s / {d.dead_a ?? '—'}s</td>
                <td className="py-1">{d.hello_b ?? '—'}s / {d.dead_b ?? '—'}s</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Network Type</td>
                <td className="py-1 pr-2">{d.network_type_a || '—'}</td>
                <td className="py-1">{d.network_type_b || '—'}</td>
              </tr>
            </tbody>
          </table>
        </div>

        {d.bilateral != null && (
          <div className="text-xs text-gray-400 mt-2">
            {d.bilateral ? 'Bilateral (confirmed from both sides)' : 'Unilateral (reported by one side only)'}
          </div>
        )}

        {/* Process Configuration (ADR-220) */}
        {(d.area_type || d.passive_default_a || d.passive_default_b || d.redistribute_a || d.redistribute_b || d.reference_bandwidth_a || d.reference_bandwidth_b) && (
          <div className="mt-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Process Configuration</p>
            {d.area_type && (
              <div className="flex items-center gap-1.5 mb-1.5">
                <span className="text-xs text-gray-400">Area Type:</span>
                <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                  d.area_type === 'backbone' ? 'bg-blue-50 text-blue-700' :
                  d.area_type?.includes('stub') ? 'bg-amber-50 text-amber-700' :
                  d.area_type?.includes('nssa') ? 'bg-purple-50 text-purple-700' :
                  'bg-gray-100 text-gray-600'
                }`}>
                  {d.area_type}
                </span>
              </div>
            )}
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-400 text-left">
                  <th className="py-1 pr-2 font-medium"></th>
                  <th className="py-1 pr-2 font-medium">{d.source}</th>
                  <th className="py-1 font-medium">{d.target}</th>
                </tr>
              </thead>
              <tbody className="text-gray-600">
                {(d.passive_default_a != null || d.passive_default_b != null) && (
                  <tr className="border-t border-gray-100">
                    <td className="py-1 pr-2 text-gray-400">Passive Default</td>
                    <td className="py-1 pr-2">{d.passive_default_a ? 'Yes' : '\u2014'}</td>
                    <td className="py-1">{d.passive_default_b ? 'Yes' : '\u2014'}</td>
                  </tr>
                )}
                {(d.active_interfaces_a || d.active_interfaces_b) && (
                  <tr className="border-t border-gray-100">
                    <td className="py-1 pr-2 text-gray-400">Active Intfs</td>
                    <td className="py-1 pr-2 font-mono" style={{ fontSize: 10 }}>{d.active_interfaces_a || '\u2014'}</td>
                    <td className="py-1 font-mono" style={{ fontSize: 10 }}>{d.active_interfaces_b || '\u2014'}</td>
                  </tr>
                )}
                {(d.vrf_lite_a != null || d.vrf_lite_b != null) && (
                  <tr className="border-t border-gray-100">
                    <td className="py-1 pr-2 text-gray-400">VRF-Lite</td>
                    <td className="py-1 pr-2">{d.vrf_lite_a ? 'Yes' : '\u2014'}</td>
                    <td className="py-1">{d.vrf_lite_b ? 'Yes' : '\u2014'}</td>
                  </tr>
                )}
                {(d.redistribute_a || d.redistribute_b) && (
                  <tr className="border-t border-gray-100">
                    <td className="py-1 pr-2 text-gray-400">Redistribute</td>
                    <td className="py-1 pr-2">
                      {d.redistribute_a ? d.redistribute_a.split(',').map(p => (
                        <span key={p} className="inline-block bg-gray-100 text-gray-600 px-1 py-0 rounded mr-0.5 mb-0.5" style={{ fontSize: 10 }}>{p.trim()}</span>
                      )) : '\u2014'}
                    </td>
                    <td className="py-1">
                      {d.redistribute_b ? d.redistribute_b.split(',').map(p => (
                        <span key={p} className="inline-block bg-gray-100 text-gray-600 px-1 py-0 rounded mr-0.5 mb-0.5" style={{ fontSize: 10 }}>{p.trim()}</span>
                      )) : '\u2014'}
                    </td>
                  </tr>
                )}
                {(d.reference_bandwidth_a != null || d.reference_bandwidth_b != null) && (
                  <tr className="border-t border-gray-100">
                    <td className="py-1 pr-2 text-gray-400">Ref BW</td>
                    <td className="py-1 pr-2">{d.reference_bandwidth_a ?? '\u2014'}</td>
                    <td className="py-1">{d.reference_bandwidth_b ?? '\u2014'}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Area LSDB (ADR-220) */}
        {lsdbData && <OspfLsdbSection lsas={lsdbData} areaId={d.area} />}

        {/* Exchanged OSPF routes */}
        {exchangedRoutes && (exchangedRoutes.fromTarget.length > 0 || exchangedRoutes.fromSource.length > 0) && (
          <div className="mt-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              OSPF Learned Networks ({exchangedRoutes.fromTarget.length + exchangedRoutes.fromSource.length})
            </p>
            {[
              { label: `Learned from ${d.target}`, routes: exchangedRoutes.fromTarget, color: '#059669' },
              { label: `Learned from ${d.source}`, routes: exchangedRoutes.fromSource, color: '#059669' },
            ].filter(g => g.routes.length > 0).map(g => (
              <div key={g.label} className="mb-2">
                <p className="text-xs font-medium text-gray-500 mb-0.5">{g.label} ({g.routes.length})</p>
                <div className="max-h-32 overflow-y-auto border border-gray-200 rounded" style={{ fontSize: 10 }}>
                  <table className="w-full">
                    <thead>
                      <tr className="bg-gray-100 text-gray-500 sticky top-0">
                        <th className="px-1.5 py-0.5 text-left font-medium">Prefix</th>
                        <th className="px-1.5 py-0.5 text-left font-medium">Next-Hop</th>
                        <th className="px-1.5 py-0.5 text-left font-medium">AD/Metric</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.routes.map((r, i) => (
                        <tr key={`${r.prefix}-${i}`} className={i % 2 === 0 ? 'bg-gray-50' : ''}>
                          <td className="px-1.5 py-0.5 font-mono text-gray-700">{r.prefix}</td>
                          <td className="px-1.5 py-0.5 font-mono text-gray-500">{r.next_hop}</td>
                          <td className="px-1.5 py-0.5 font-mono text-gray-400">
                            {r.ad != null ? r.ad : '—'}{r.metric != null ? `/${r.metric}` : ''}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* All routes via link — all VRFs, all protocols (consistent across views) */}
        <RoutesViaLink routes={allRoutesViaLink} />

        {/* Related OSPF findings */}
        {ospfFindings.length > 0 && (
          <div className="mt-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Related Findings ({ospfFindings.length})</p>
            <div className="space-y-1">
              {ospfFindings.map((f, i) => {
                const sevColor = sevColors[f.severity]?.color || '#6B7280'
                return (
                  <div key={i} className="flex items-start gap-1.5 text-xs">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0 mt-1" style={{ background: sevColor }} />
                    <div className="min-w-0">
                      <span className="font-medium text-gray-600">{f.rule_id}</span>
                      <p className="text-gray-400 truncate">{f.message || f.evidence?.message || ''}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

const PROTO_COLORS = {
  ospf: '#059669', bgp: '#7C3AED', static: '#2563EB',
  connected: '#6B7280', local: '#9CA3AF',
}
const PROTO_ORDER = ['ospf', 'bgp', 'static', 'connected', 'local']

function RoutesViaLink({ routes }) {
  const [vrfFilter, setVrfFilter] = useState('__all__')

  if (!routes || routes.length === 0) return null

  // Collect unique VRFs
  const vrfs = [...new Set(routes.map(r => r.vrf || 'default'))].sort()
  const multiVrf = vrfs.length > 1

  // Filter by selected VRF
  const filtered = vrfFilter === '__all__' ? routes : routes.filter(r => (r.vrf || 'default') === vrfFilter)

  // Group by protocol
  const byProto = {}
  filtered.forEach(r => {
    const p = (r.protocol || 'static').toLowerCase()
    if (!byProto[p]) byProto[p] = []
    byProto[p].push(r)
  })
  const sorted = Object.entries(byProto).sort(
    ([a], [b]) => (PROTO_ORDER.indexOf(a) === -1 ? 99 : PROTO_ORDER.indexOf(a))
      - (PROTO_ORDER.indexOf(b) === -1 ? 99 : PROTO_ORDER.indexOf(b))
  )

  return (
    <div>
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
        Routes via this Link ({filtered.length}{vrfFilter !== '__all__' ? ` of ${routes.length}` : ''})
      </p>
      {/* VRF selector + protocol pills row */}
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        {multiVrf && (
          <select
            value={vrfFilter}
            onChange={e => setVrfFilter(e.target.value)}
            className="text-xs border border-gray-300 rounded px-1.5 py-0.5 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
            style={{ fontSize: 10 }}
          >
            <option value="__all__">All VRFs</option>
            {vrfs.map(v => <option key={v} value={v}>{v}</option>)}
          </select>
        )}
        <div className="flex gap-1 flex-wrap">
          {sorted.map(([proto, items]) => (
            <span key={proto} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-white font-medium" style={{ fontSize: 9, backgroundColor: PROTO_COLORS[proto] || '#6B7280' }}>
              {proto.toUpperCase()} {items.length}
            </span>
          ))}
        </div>
      </div>
      <div className="mt-1 max-h-64 overflow-y-auto border border-gray-200 rounded" style={{ fontSize: 10 }}>
        <table className="w-full">
          <thead>
            <tr className="bg-gray-100 text-gray-500 sticky top-0">
              <th className="px-1.5 py-0.5 text-left font-medium">Proto</th>
              {multiVrf && vrfFilter === '__all__' && <th className="px-1.5 py-0.5 text-left font-medium">VRF</th>}
              <th className="px-1.5 py-0.5 text-left font-medium">Direction</th>
              <th className="px-1.5 py-0.5 text-left font-medium">Prefix</th>
              <th className="px-1.5 py-0.5 text-left font-medium">Next-Hop</th>
              <th className="px-1.5 py-0.5 text-left font-medium">AD/Metric</th>
            </tr>
          </thead>
          <tbody>
            {sorted.flatMap(([proto, items]) =>
              items.map((r, i) => (
                <tr key={`${proto}-${r.device}-${r.prefix}-${r.vrf}-${i}`} className={i % 2 === 0 ? 'bg-gray-50' : ''}>
                  <td className="px-1.5 py-0.5 font-medium" style={{ color: PROTO_COLORS[proto] || '#6B7280' }}>
                    {proto === 'connected' ? 'C' : proto === 'local' ? 'L' : proto.toUpperCase()}
                  </td>
                  {multiVrf && vrfFilter === '__all__' && (
                    <td className="px-1.5 py-0.5 font-mono text-gray-500 whitespace-nowrap">{r.vrf || 'default'}</td>
                  )}
                  <td className="px-1.5 py-0.5 font-mono text-gray-700 whitespace-nowrap">{r.direction || r.device}</td>
                  <td className="px-1.5 py-0.5 font-mono text-gray-700">{r.prefix}</td>
                  <td className="px-1.5 py-0.5 font-mono text-gray-500">{r.next_hop || '—'}</td>
                  <td className="px-1.5 py-0.5 font-mono text-gray-400">
                    {r.ad != null ? r.ad : '—'}{r.metric != null ? `/${r.metric}` : ''}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// BGP Adjacency Detail Panel (S19C-8)
// ---------------------------------------------------------------------------
function BgpAdjacencyDetail({ linkData, findingsData, selectedRun, onClose }) {
  const { sevColors } = useLegend()
  const d = linkData
  const isIbgp = d.session_type === 'ibgp'
  const stateColor = (d.state || '').toLowerCase() === 'established' ? '#059669' : '#DC2626'
  const stateBg = (d.state || '').toLowerCase() === 'established' ? '#ECFDF5' : '#FEF2F2'
  const sideALabel = d.source || 'Side A'
  const sideBLabel = d.target || 'Side B'
  const isExternal = !d.bilateral

  // Fetch BGP learned routes — per-peer route files + routing table fallback
  const [bgpRoutes, setBgpRoutes] = useState(null)
  useEffect(() => {
    if (!selectedRun || !d.source || !d.target) return
    const runId = selectedRun.run_id || selectedRun
    // Try per-peer route files first (collected for summary-only devices),
    // then fall back to filtering the full routing table
    const srcPeerIp = d.source  // external peer IP or device name
    const tgtPeerIp = d.target
    Promise.all([
      // Per-peer routes: target device's routes from source peer
      fetch(`/api/bgp-peer-routes/${encodeURIComponent(d.target)}/${encodeURIComponent(srcPeerIp)}?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
      // Per-peer routes: source device's routes from target peer
      fetch(`/api/bgp-peer-routes/${encodeURIComponent(d.source)}/${encodeURIComponent(tgtPeerIp)}?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
      // Routing table fallback
      fetch(`/api/device/${encodeURIComponent(d.source)}/routing?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
      fetch(`/api/device/${encodeURIComponent(d.target)}/routing?run_id=${encodeURIComponent(runId)}`).then(r => r.ok ? r.json() : { routes: [] }),
    ]).then(([peerRoutesFromSrc, peerRoutesFromTgt, srcRoutingData, tgtRoutingData]) => {
      const routes = []

      // Per-peer routes (from genie_bgp_routes files)
      ;(peerRoutesFromSrc.routes || []).forEach(r => {
        routes.push({ prefix: r.prefix, next_hop: r.next_hop, admin_distance: r.local_pref, direction: `from ${srcPeerIp}`, path: r.path })
      })
      ;(peerRoutesFromTgt.routes || []).forEach(r => {
        routes.push({ prefix: r.prefix, next_hop: r.next_hop, admin_distance: r.local_pref, direction: `from ${tgtPeerIp}`, path: r.path })
      })

      // Routing table fallback (for devices with full RIB)
      if (routes.length === 0) {
        const tgtIp = d.router_id_b || d.target
        const srcIp = d.router_id_a || d.source
        const srcRoutes = (srcRoutingData.routes || []).filter(r => r.protocol === 'bgp')
        const tgtRoutes = (tgtRoutingData.routes || []).filter(r => r.protocol === 'bgp')
        srcRoutes.filter(r => r.next_hop === tgtIp).forEach(r => {
          routes.push({ ...r, device: d.source, direction: `via ${d.target}` })
        })
        tgtRoutes.filter(r => r.next_hop === srcIp).forEach(r => {
          routes.push({ ...r, device: d.target, direction: `via ${d.source}` })
        })
      }

      setBgpRoutes(routes.length > 0 ? routes : null)
    }).catch(() => setBgpRoutes(null))
  }, [selectedRun, d.source, d.target, d.router_id_a, d.router_id_b])

  // Filter BGP findings
  const bgpFindings = useMemo(() => {
    if (!findingsData?.findings) return []
    const src = d.source, tgt = d.target
    return findingsData.findings.filter(f => {
      const rid = f.rule_id || ''
      if (!rid.startsWith('BGP_') && !rid.startsWith('XD_BGP_')) return false
      const eid = f.evidence?.element_id || ''
      if (rid.startsWith('XD_BGP_')) {
        return eid.includes(src) && eid.includes(tgt)
      }
      return eid.startsWith(src + '/') || eid.startsWith(tgt + '/')
    })
  }, [findingsData, d.source, d.target])

  const BoolBadge = ({ value, label }) => {
    if (value === undefined || value === null) return <span className="text-gray-300">—</span>
    return (
      <span className={`text-xs font-bold px-1 py-0.5 rounded ${
        value ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-400'
      }`} style={{ fontSize: 10 }}>
        {label || (value ? 'Yes' : 'No')}
      </span>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <h2 style={{ fontSize: 14, fontWeight: 800, color: '#0F4F3A' }} className="truncate">
              BGP Session
            </h2>
            <p className="text-xs text-gray-600 mt-0.5">
              {sideALabel} &harr; {sideBLabel}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none ml-2 shrink-0">&times;</button>
        </div>
        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded"
            style={{ color: isIbgp ? '#7C3AED' : '#7C3AED', background: '#EDE9FE' }}
          >
            {isIbgp ? 'iBGP' : 'eBGP'}
          </span>
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded"
            style={{ color: stateColor, background: stateBg }}
          >
            {(d.state || 'unknown').toUpperCase()}
          </span>
          {d.local_as && <span className="text-xs text-gray-500">AS {d.local_as}</span>}
          {d.remote_as && d.remote_as !== d.local_as && (
            <span className="text-xs text-gray-500">&harr; AS {d.remote_as}</span>
          )}
          {d.peer_label && <span className="text-xs text-gray-400">{d.peer_label}</span>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 p-3 space-y-3">
        {/* Session Overview — bilateral table */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Session Overview</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="py-1 pr-2 font-medium"></th>
                <th className="py-1 pr-2 font-medium">{sideALabel}</th>
                <th className="py-1 font-medium">{isExternal ? 'External' : sideBLabel}</th>
              </tr>
            </thead>
            <tbody className="text-gray-600">
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Router ID</td>
                <td className="py-1 pr-2 font-mono">{d.router_id_a || '—'}</td>
                <td className="py-1 font-mono">{d.router_id_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Description</td>
                <td className="py-1 pr-2">{d.description_a || '—'}</td>
                <td className="py-1">{d.description_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Prefixes Received</td>
                <td className="py-1 pr-2">{d.prefixes_received_a ?? '—'}</td>
                <td className="py-1">{d.prefixes_received_b ?? '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Messages Sent</td>
                <td className="py-1 pr-2">{d.msg_sent_a ?? '—'}</td>
                <td className="py-1">{d.msg_sent_b ?? '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Messages Received</td>
                <td className="py-1 pr-2">{d.msg_rcvd_a ?? '—'}</td>
                <td className="py-1">{d.msg_rcvd_b ?? '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Uptime</td>
                <td className="py-1 pr-2">{d.up_down_a || '—'}</td>
                <td className="py-1">{d.up_down_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Keepalive / Hold</td>
                <td className="py-1 pr-2">{d.keepalive_a ?? '—'}s / {d.hold_time_a ?? '—'}s</td>
                <td className="py-1">{d.keepalive_b ?? '—'}s / {d.hold_time_b ?? '—'}s</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Session Configuration — bilateral table */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Session Configuration</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="py-1 pr-2 font-medium"></th>
                <th className="py-1 pr-2 font-medium">{sideALabel}</th>
                <th className="py-1 font-medium">{isExternal ? 'External' : sideBLabel}</th>
              </tr>
            </thead>
            <tbody className="text-gray-600">
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Route Policy In</td>
                <td className="py-1 pr-2 font-mono text-xs">{d.route_policy_in_a || '—'}</td>
                <td className="py-1 font-mono text-xs">{d.route_policy_in_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Route Policy Out</td>
                <td className="py-1 pr-2 font-mono text-xs">{d.route_policy_out_a || '—'}</td>
                <td className="py-1 font-mono text-xs">{d.route_policy_out_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">BFD</td>
                <td className="py-1 pr-2"><BoolBadge value={d.bfd_a} /></td>
                <td className="py-1"><BoolBadge value={d.bfd_b} /></td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Graceful Restart</td>
                <td className="py-1 pr-2"><BoolBadge value={d.graceful_restart_a} /></td>
                <td className="py-1"><BoolBadge value={d.graceful_restart_b} /></td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Password</td>
                <td className="py-1 pr-2"><BoolBadge value={d.password_configured_a} /></td>
                <td className="py-1"><BoolBadge value={d.password_configured_b} /></td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Max Prefix</td>
                <td className="py-1 pr-2">{d.maximum_prefix_a != null ? d.maximum_prefix_a.toLocaleString() : '—'}</td>
                <td className="py-1">{d.maximum_prefix_b != null ? d.maximum_prefix_b.toLocaleString() : '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Update Source</td>
                <td className="py-1 pr-2 font-mono">{d.update_source_a || '—'}</td>
                <td className="py-1 font-mono">{d.update_source_b || '—'}</td>
              </tr>
              <tr className="border-t border-gray-100">
                <td className="py-1 pr-2 text-gray-400">Send Community</td>
                <td className="py-1 pr-2"><BoolBadge value={d.send_community_a} /></td>
                <td className="py-1"><BoolBadge value={d.send_community_b} /></td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Address Families */}
        {d.address_families && d.address_families.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Address Families</p>
            <div className="flex flex-wrap gap-1">
              {(Array.isArray(d.address_families) ? d.address_families : [d.address_families]).map(af => (
                <span key={af} className="text-xs px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 font-mono">
                  {af}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Network Statements */}
        {(d.network_statements_a || d.network_statements_b) && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Network Statements</p>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-400 text-left">
                  <th className="py-1 pr-2 font-medium">{sideALabel}</th>
                  <th className="py-1 font-medium">{isExternal ? '' : sideBLabel}</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t border-gray-100">
                  <td className="py-1 pr-2 align-top">
                    {(d.network_statements_a || []).map(ns => (
                      <div key={ns} className="font-mono text-gray-600">{ns}</div>
                    ))}
                    {(!d.network_statements_a || d.network_statements_a.length === 0) && <span className="text-gray-300">—</span>}
                  </td>
                  <td className="py-1 align-top">
                    {(d.network_statements_b || []).map(ns => (
                      <div key={ns} className="font-mono text-gray-600">{ns}</div>
                    ))}
                    {(!d.network_statements_b || d.network_statements_b.length === 0) && <span className="text-gray-300">—</span>}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* BGP Learned Routes */}
        {bgpRoutes && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              BGP Learned Routes <span className="text-gray-400 font-normal">({bgpRoutes.length})</span>
            </p>
            <div className="max-h-48 overflow-y-auto border border-gray-100 rounded">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-white">
                  <tr className="text-gray-400 text-left border-b border-gray-100">
                    <th className="py-1 px-1.5 font-medium">Prefix</th>
                    <th className="py-1 px-1.5 font-medium">Next Hop</th>
                    <th className="py-1 px-1.5 font-medium">AS Path</th>
                  </tr>
                </thead>
                <tbody className="text-gray-600">
                  {bgpRoutes.slice(0, 100).map((r, i) => (
                    <tr key={i} className="border-t border-gray-50">
                      <td className="py-0.5 px-1.5 font-mono">{r.prefix}</td>
                      <td className="py-0.5 px-1.5 font-mono">{r.next_hop || r.direction || ''}</td>
                      <td className="py-0.5 px-1.5 font-mono">{r.path || ''}</td>
                    </tr>
                  ))}
                  {bgpRoutes.length > 100 && (
                    <tr><td colSpan={3} className="py-1 px-1.5 text-gray-400 text-center">
                      … {bgpRoutes.length - 100} more routes
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Related Findings */}
        {bgpFindings.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Related Findings <span className="text-gray-400 font-normal">({bgpFindings.length})</span>
            </p>
            <div className="space-y-1">
              {bgpFindings.map((f, i) => {
                const sev = f.severity || 'info'
                const sevColor = sevColors[sev] || sevColors.info
                return (
                  <div key={i} className="flex items-start gap-1.5 p-1.5 rounded" style={{ background: sevColor.bg }}>
                    <span className="text-xs font-bold shrink-0 mt-0.5" style={{ color: sevColor.color }}>
                      {sev.toUpperCase()}
                    </span>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-gray-700 truncate">{f.rule_id}</div>
                      <div className="text-xs text-gray-500 truncate">{f.message || f.evidence?.detail || ''}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {d.bilateral != null && (
          <div className="text-xs text-gray-400 mt-2">
            {d.bilateral ? 'Bilateral (confirmed from both sides)' : 'Unilateral (one side is external/uncollected)'}
          </div>
        )}
      </div>
    </div>
  )
}


function LinkDetail({ linkData, findingsData, selectedRun, onClose }) {
  const { sevColors } = useLegend()
  if (!linkData) return null

  // BGP adjacency edge → dedicated detail panel (check BEFORE OSPF)
  if (linkData.edgeType === 'adjacency' && linkData.protocol === 'bgp') {
    return <BgpAdjacencyDetail linkData={linkData} findingsData={findingsData} selectedRun={selectedRun} onClose={onClose} />
  }

  // OSPF adjacency edge → dedicated detail panel
  if (linkData.edgeType === 'adjacency') {
    return <OspfAdjacencyDetail linkData={linkData} findingsData={findingsData} selectedRun={selectedRun} onClose={onClose} />
  }

  const d = linkData
  const sourcePort = d.sourcePort || ''
  const targetPort = d.targetPort || ''
  const srcLagLabel = d.lag_group ? ` (${d.lag_group})` : ''
  const tgtLagLabel = d.lag_group_target ? ` (${d.lag_group_target})` : ''

  // Find findings directly related to this link or its ports
  const linkFindings = useMemo(() => {
    if (!findingsData?.findings) return []
    const src = d.source, tgt = d.target
    if (!src || !tgt) return []
    // Build set of relevant identifiers: link_id pattern + specific port IDs
    const srcPort = d.sourcePort || ''
    const tgtPort = d.targetPort || ''
    const srcId = srcPort ? `${src}:${srcPort}` : ''
    const tgtId = tgtPort ? `${tgt}:${tgtPort}` : ''
    // Also match base hostnames for compound nodes (e.g. "core-rtr-01:1" → "core-rtr-01")
    const baseSrc = src.includes(':') ? src.split(':')[0] : src
    const baseTgt = tgt.includes(':') ? tgt.split(':')[0] : tgt
    const baseSrcId = srcPort ? `${baseSrc}:${srcPort}` : ''
    const baseTgtId = tgtPort ? `${baseTgt}:${tgtPort}` : ''
    // Exact port match: id must be followed by -- or end-of-string (not another digit)
    const portMatch = (eid, portId) => {
      const idx = eid.indexOf(portId)
      if (idx === -1) return false
      const after = idx + portId.length
      return after >= eid.length || eid[after] === '-'
    }
    return findingsData.findings.filter(f => {
      const eid = f.evidence?.element_id || ''
      // Match link-level findings (element_id = "DEV-A:intf--DEV-B:intf")
      if (eid.includes('--') && eid.includes(baseSrc) && eid.includes(baseTgt)) return true
      // Match port-level findings (exact port, not substring — Tw1/0/2 must not match Tw1/0/25)
      if (srcId && portMatch(eid, srcId)) return true
      if (tgtId && portMatch(eid, tgtId)) return true
      if (baseSrcId && baseSrcId !== srcId && portMatch(eid, baseSrcId)) return true
      if (baseTgtId && baseTgtId !== tgtId && portMatch(eid, baseTgtId)) return true
      return false
    })
  }, [findingsData, d.source, d.target, d.sourcePort, d.targetPort])

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <h2 style={{ fontSize: 14, fontWeight: 800, color: '#0F4F3A' }} className="truncate">
              {d.source} &harr; {d.target}
            </h2>
            <p className="text-xs text-gray-500 mt-0.5" style={{ fontFamily: 'monospace' }}>
              {sourcePort}{srcLagLabel} &mdash; {targetPort}{tgtLagLabel}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none ml-2 shrink-0">&times;</button>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          {d.discovery_method && <span>{d.discovery_method}</span>}
          {d.confidence && <span className="ml-1">({d.confidence})</span>}
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {/* Port-Channel (LAG) */}
        {(d.lag_group || d.lag_group_target) && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Port-Channel</p>
            <div className="text-xs text-gray-600 space-y-0.5">
              {d.lag_group && <p>Source: <span className="font-medium font-mono">{d.lag_group}</span></p>}
              {d.lag_group_target && <p>Target: <span className="font-medium font-mono">{d.lag_group_target}</span></p>}
              <p className="text-gray-400">Physical members bundled into this aggregate link</p>
            </div>
          </div>
        )}

        {/* Merged link physical members (L2/VLAN view) — above L1 */}
        {d.member_count > 1 && d.member_edges && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
              Physical Members ({d.member_count})
            </p>
            <div className="text-xs text-gray-600 space-y-0.5">
              {d.member_edges.map((m, i) => (
                <p key={i} className="font-mono">{m.sourcePort} &harr; {m.targetPort}</p>
              ))}
            </div>
          </div>
        )}

        {/* L1 — bilateral two-column table (ADR-198) */}
        {(() => {
          const l1Rows = [
            { label: 'Speed', local: formatSpeed(d.l1_local_speed), remote: formatSpeed(d.l1_remote_speed) },
            { label: 'Duplex', local: d.l1_local_duplex, remote: d.l1_remote_duplex },
            { label: 'MTU', local: d.l1_local_mtu, remote: d.l1_remote_mtu },
            { label: 'Media', local: d.l1_local_media_type, remote: d.l1_remote_media_type },
            { label: 'SFP', local: d.l1_local_sfp_pid, remote: d.l1_remote_sfp_pid },
          ].filter(r => r.local || r.remote)
          const hasL1 = l1Rows.length > 0
          return (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Layer 1</p>
              {!hasL1 ? (
                <p className="text-xs text-gray-400">No L1 data</p>
              ) : (
                <div className="border border-gray-200 rounded overflow-hidden" style={{ fontSize: 10 }}>
                  <table className="w-full">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="px-1.5 py-1 text-left font-medium text-gray-500"></th>
                        <th className="px-1.5 py-1 text-left font-medium text-gray-600">{d.source}</th>
                        <th className="px-1.5 py-1 text-left font-medium text-gray-600">{d.target}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {l1Rows.map((r, i) => {
                        const mismatch = r.local && r.remote && String(r.local) !== String(r.remote)
                        return (
                          <tr key={r.label} className={i % 2 === 0 ? 'bg-gray-50' : ''}>
                            <td className="px-1.5 py-0.5 font-medium text-gray-500">{r.label}</td>
                            <td className={`px-1.5 py-0.5 font-mono ${mismatch ? 'text-red-600 font-semibold' : 'text-gray-700'}`}>{r.local || '—'}</td>
                            <td className={`px-1.5 py-0.5 font-mono ${mismatch ? 'text-red-600 font-semibold' : 'text-gray-700'}`}>{r.remote || '—'}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )
        })()}

        {/* L2 — bilateral unified view (ADR-198, ADR-214) */}
        {(d.l2_local_trunk_mode || d.l2_local_vlans_carried || d.vlan_count || d.l2_local_mode ||
          d.l2_remote_mode || d.l2_remote_vlans_carried || d.l2_local_vlan_id != null || d.l2_remote_vlan_id != null) && (() => {
          const localMode = d.l2_local_mode || d.l2_local_trunk_mode
          const remoteMode = d.l2_remote_mode || d.l2_remote_trunk_mode
          const localVlans = Array.isArray(d.l2_local_vlans_carried) ? d.l2_local_vlans_carried : []
          const remoteVlans = Array.isArray(d.l2_remote_vlans_carried) ? d.l2_remote_vlans_carried : []
          const localCount = d.vlan_count || localVlans.length
          const remoteCount = remoteVlans.length
          const localNative = d.l2_local_native_vlan
          const remoteNative = d.l2_remote_native_vlan
          const accessVlan = d.l2_local_vlan_id || d.l2_remote_vlan_id

          // Bilateral mode display
          const modeDisplay = localMode && remoteMode && localMode !== remoteMode
            ? `${localMode} / ${remoteMode}`
            : localMode || remoteMode || null

          return (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Layer 2</p>
              <div className="text-xs text-gray-600 space-y-0.5">
                {modeDisplay && <p>Mode: {modeDisplay}</p>}
                {accessVlan != null && <p>Access VLAN: <span className="font-medium font-mono">{accessVlan}</span></p>}
                {localCount > 0 && <p>VLANs carried: <span className="font-medium">{localCount}</span></p>}
                {localNative && <p>Native VLAN: <span className="font-medium">{localNative}</span></p>}
              </div>
            </div>
          )
        })()}

        {/* L2 mismatch warning — positioned above Subnets on Trunk (ADR-198) */}
        {(() => {
          const localVlans = Array.isArray(d.l2_local_vlans_carried) ? d.l2_local_vlans_carried : []
          const remoteVlans = Array.isArray(d.l2_remote_vlans_carried) ? d.l2_remote_vlans_carried : []
          const localMode = d.l2_local_mode || d.l2_local_trunk_mode
          const remoteMode = d.l2_remote_mode || d.l2_remote_trunk_mode
          const mismatches = []
          if (localMode && remoteMode && localMode !== remoteMode) mismatches.push(`mode: ${d.source}=${localMode}, ${d.target}=${remoteMode}`)
          if (localVlans.length > 0 && remoteVlans.length > 0 && localVlans.length !== remoteVlans.length) {
            let detail = `${d.source} allows ${localVlans.length} VLANs, ${d.target} allows ${remoteVlans.length}`
            const mm = d.l2_vlan_mismatch
            if (mm) {
              const parts = []
              if (mm.only_source && mm.only_source.length > 0) parts.push(`only on ${d.source}: ${mm.only_source.slice(0, 8).join(', ')}${mm.only_source.length > 8 ? '...' : ''}`)
              if (mm.only_target && mm.only_target.length > 0) parts.push(`only on ${d.target}: ${mm.only_target.slice(0, 8).join(', ')}${mm.only_target.length > 8 ? '...' : ''}`)
              if (parts.length > 0) detail += ` (${parts.join('; ')})`
            }
            mismatches.push(detail)
          }
          if (d.l2_local_native_vlan && d.l2_remote_native_vlan && String(d.l2_local_native_vlan) !== String(d.l2_remote_native_vlan)) mismatches.push(`native VLAN: ${d.source}=${d.l2_local_native_vlan}, ${d.target}=${d.l2_remote_native_vlan}`)
          if (mismatches.length === 0) return null
          return (
            <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-2 py-1">
              {mismatches.map((m, i) => <p key={i}>⚠ L2 mismatch: {m}</p>)}
            </div>
          )
        })()}

        {/* Management VLAN/VRF (ADR-172) */}
        {(d.mgmt_vlan || d.mgmt_vrf) && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Management</p>
            <div className="text-xs text-gray-600 space-y-0.5">
              {d.mgmt_vlan && <p>VLAN: <span className="font-medium font-mono">{d.mgmt_vlan}</span></p>}
              {d.mgmt_vrf && <p>VRF: <span className="font-medium font-mono">{d.mgmt_vrf}</span></p>}
              {d.mgmt_type && <p>Type: {d.mgmt_type}</p>}
            </div>
          </div>
        )}

        {/* L3 — point-to-point subnet */}
        {(d.l3_local_ip || d.l3_remote_ip) && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Layer 3</p>
            <div className="text-xs text-gray-600 space-y-0.5">
              {d.l3_subnet && <p>Subnet: <span className="font-mono font-medium">{d.l3_subnet}</span></p>}
              {(d.l3_local_vrf || d.l3_remote_vrf) && <p>VRF: <span className="font-mono">{d.l3_local_vrf || d.l3_remote_vrf}</span></p>}
              {d.l3_local_ip && <p>Local: <span className="font-mono">{d.l3_local_ip}</span> <span className="text-gray-400">({d.source})</span></p>}
              {d.l3_remote_ip && <p>Remote: <span className="font-mono">{d.l3_remote_ip}</span> <span className="text-gray-400">({d.target})</span></p>}
            </div>
          </div>
        )}

        {/* VLANs on trunk — shows all VLANs, with subnet/gateway when available */}
        {d.trunk_subnets && d.trunk_subnets.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
              VLANs on the Link ({d.trunk_subnets.length})
            </p>
            <div className="mt-1 max-h-64 overflow-y-auto border border-gray-200 rounded" style={{ fontSize: 10 }}>
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-100 sticky top-0">
                    <th className="px-1.5 py-1 text-left font-medium text-gray-500">VLAN</th>
                    <th className="px-1.5 py-1 text-left font-medium text-gray-500">Subnet</th>
                    <th className="px-1.5 py-1 text-left font-medium text-gray-500">Gateway</th>
                  </tr>
                </thead>
                <tbody>
                  {d.trunk_subnets.map((s, i) => (
                    <tr key={s.vlan_id} className={i % 2 === 0 ? 'bg-gray-50' : ''}>
                      <td className="px-1.5 py-0.5 font-mono text-gray-700 whitespace-nowrap">
                        <span className="font-medium">{s.vlan_id}</span>
                        {s.name && <span className="text-gray-400 ml-1">{s.name}</span>}
                      </td>
                      <td className="px-1.5 py-0.5 font-mono text-gray-700">{s.subnet || <span className="text-gray-300">—</span>}</td>
                      <td className="px-1.5 py-0.5 font-mono text-gray-500">{s.gateway || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Routes via this link — all protocols (ADR-216/218) */}
        <RoutesViaLink routes={d.routes_via_link || d.static_routes} />

        {/* Status & type */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Link Info</p>
          <div className="text-xs text-gray-600 space-y-0.5">
            <p>Status: <span style={{ color: d.status === 'up' ? '#22C55E' : '#EF4444' }}>{d.status || 'unknown'}</span></p>
            {d.link_type && <p>Type: {d.link_type}</p>}
            {d.stack_subtype && <p>Subtype: {d.stack_subtype}</p>}
          </div>
        </div>

        {/* Findings on this link */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
            Findings ({linkFindings.length})
          </p>
          {linkFindings.length === 0 ? (
            <p className="text-xs text-gray-400">No findings on this link</p>
          ) : (
            linkFindings.map((f, idx) => {
              const sc = sevColors[f.severity] || sevColors.info
              return (
                <div key={f.finding_id || idx} className="text-xs py-1 border-b" style={{ borderColor: '#F3F4F6', borderLeft: `3px solid ${sc.color}`, paddingLeft: 8 }}>
                  <span className="font-medium px-1 py-0.5 rounded capitalize" style={{ background: sc.bg, color: sc.color, fontSize: 9 }}>{f.severity}</span>
                  <span className="ml-1 text-gray-500">{f.rule_id}</span>
                  {f.message && <p className="text-gray-600 mt-0.5 line-clamp-2">{f.message}</p>}
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}

// =============================================================================
// Overview Tab (S19A-4)
// =============================================================================
function OverviewTab({ deviceData, selectedMemberId }) {
  const { sevColors, severityOrder } = useLegend()
  const device = deviceData.device || {}
  const interfaces = deviceData.interfaces || []
  const protocols = deviceData.protocols || {}
  const findings = deviceData.findings || []

  const upCount = interfaces.filter(i => i.oper_status === 'up').length
  const downCount = interfaces.filter(i => i.oper_status === 'down' && i.admin_status === 'up').length
  const adminDownCount = interfaces.filter(i => i.admin_status === 'down').length

  // Finding counts by severity
  const findingCounts = useMemo(() => {
    const counts = {}
    findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })
    return counts
  }, [findings])

  return (
    <div className="p-3 space-y-3 overflow-y-auto">
      {/* Device info */}
      <div className="space-y-1 text-xs">
        {device.platform && <p><span className="text-gray-500">Platform:</span> <span className="text-gray-700 font-medium">{device.platform}</span></p>}
        {device.os_version && <p><span className="text-gray-500">OS Version:</span> <span className="text-gray-700">{device.os_version}</span></p>}
        {/* Serial: single for non-stack, member-specific when member selected, all members when compound selected */}
        {device.cluster_members?.length > 0 ? (
          selectedMemberId !== null && selectedMemberId !== undefined ? (
            // Specific member selected — show that member's serial
            (() => {
              const m = device.cluster_members.find(m => m.member_id === selectedMemberId)
              return m?.serial_number
                ? <p><span className="text-gray-500">Serial:</span> <span className="text-gray-700">{m.serial_number}</span></p>
                : null
            })()
          ) : (
            // Compound (whole stack) selected — list all member serials
            <div>
              <span className="text-gray-500">Serials:</span>
              <div className="ml-2 mt-0.5 space-y-0.5">
                {device.cluster_members.map(m => (
                  <p key={m.member_id}>
                    <span className="text-gray-400 mr-1">M{m.member_id}</span>
                    <span className="text-gray-700">{m.serial_number || '—'}</span>
                    {m.role && <span className="text-gray-400 ml-1 capitalize">({m.role})</span>}
                  </p>
                ))}
              </div>
            </div>
          )
        ) : (
          device.serial && <p><span className="text-gray-500">Serial:</span> <span className="text-gray-700">{device.serial}</span></p>
        )}
        {device.management_ip && <p><span className="text-gray-500">Management IP:</span> <span className="text-gray-700">{device.management_ip}</span></p>}
        {device.site && <p><span className="text-gray-500">Site:</span> <span className="text-gray-700">{device.site}</span></p>}
        {device.cluster_size && <p><span className="text-gray-500">Stack:</span> <span className="text-gray-700">{device.cluster_size} members</span></p>}
      </div>

      {/* Protocol badges */}
      {Object.keys(protocols).length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Protocols</p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(protocols).map(([proto, data]) => {
              const badge = PROTOCOL_BADGES[proto]
              const style = badge
                ? { background: badge.bg, color: badge.color }
                : { background: '#F3F4F6', color: '#6B7280' }
              return (
                <span key={proto} className="text-xs font-medium px-2 py-0.5 rounded-full" style={style}>
                  {badge?.label || proto.toUpperCase()}
                  {proto === 'ospf' && data?.areas?.length > 0 && <span className="opacity-70 ml-1">Area {data.areas.join(',')}</span>}
                  {proto === 'bgp' && data?.local_as && <span className="opacity-70 ml-1">AS{data.local_as}</span>}
                </span>
              )
            })}
          </div>
        </div>
      )}

      {/* Interface summary */}
      <div>
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Interfaces</p>
        <p className="text-xs text-gray-600">
          {interfaces.length} total &mdash;{' '}
          <span style={{ color: '#22C55E' }}>{upCount} up</span>
          {downCount > 0 && <>, <span style={{ color: '#EF4444' }}>{downCount} down</span></>}
          {adminDownCount > 0 && <>, <span className="text-gray-400">{adminDownCount} admin-down</span></>}
        </p>
      </div>

      {/* Finding summary */}
      <div>
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Findings</p>
        {findings.length === 0 ? (
          <p className="text-xs text-green-600">No findings</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {severityOrder.map(sev => {
              const count = findingCounts[sev]
              if (!count) return null
              const sc = sevColors[sev]
              return (
                <span key={sev} className="text-xs font-medium px-1.5 py-0.5 rounded" style={{ background: sc.bg, color: sc.color }}>
                  {count} {sev}
                </span>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// =============================================================================
// Interfaces Tab (S19A-5)
// =============================================================================
function InterfacesTab({ deviceData }) {
  const interfaces = deviceData.interfaces || []
  const [expandedIntf, setExpandedIntf] = useState(null)
  const [searchFilter, setSearchFilter] = useState('')

  // Sort by IOS order and apply search filter
  const sortedInterfaces = useMemo(() => {
    let filtered = interfaces
    if (searchFilter) {
      const q = searchFilter.toLowerCase()
      filtered = interfaces.filter(i =>
        (i.name || '').toLowerCase().includes(q) ||
        (i.description || '').toLowerCase().includes(q)
      )
    }
    return [...filtered].sort((a, b) =>
      compareArrays(interfaceSortKey(a.name), interfaceSortKey(b.name))
    )
  }, [interfaces, searchFilter])

  return (
    <div className="flex flex-col h-full">
      {/* Search box */}
      <div className="p-2 border-b" style={{ borderColor: '#E5E7EB' }}>
        <input
          type="text"
          placeholder="Filter interfaces..."
          value={searchFilter}
          onChange={e => setSearchFilter(e.target.value)}
          className="w-full text-xs px-2 py-1.5 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
        />
      </div>

      {/* Interface list */}
      <div className="flex-1 overflow-y-auto">
        {sortedInterfaces.map((intf, idx) => {
          const isExpanded = expandedIntf === intf.name
          const isDown = intf.oper_status === 'down' && intf.admin_status === 'up'
          const isAdminDown = intf.admin_status === 'down'
          const statusColor = isAdminDown ? '#9CA3AF' : isDown ? '#EF4444' : '#22C55E'
          const statusText = isAdminDown ? 'Admin-Down' : isDown ? 'Down' : 'Up'
          const pcLabel = intf.port_channel_int ? ` (${intf.port_channel_int})` : ''

          return (
            <div key={intf.name || idx}>
              {/* Collapsed row */}
              <button
                onClick={() => setExpandedIntf(isExpanded ? null : intf.name)}
                className="w-full text-left px-3 py-1.5 border-b hover:bg-gray-50 transition-colors"
                style={{ borderColor: '#F3F4F6', opacity: isAdminDown ? 0.6 : 1 }}
              >
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-gray-400 shrink-0" style={{ fontSize: 8 }}>
                    {isExpanded ? '\u25BC' : '\u25B6'}
                  </span>
                  <span style={{ fontFamily: 'monospace', fontWeight: 600, color: isDown ? '#EF4444' : '#374151' }} className="shrink-0">
                    {intf.name}{pcLabel}
                  </span>
                  {intf.description && (
                    <span className="text-gray-400 truncate">{intf.description}</span>
                  )}
                  {intf.switchport_mode === 'access' && intf.access_vlan && (
                    <span className="text-blue-600 shrink-0" style={{ fontSize: 10 }}>VLAN {intf.access_vlan}</span>
                  )}
                  {intf.switchport_mode === 'trunk' && intf.trunk_vlans?.length > 0 && (
                    <span className="text-green-700 shrink-0" style={{ fontSize: 10 }}>
                      VLANs {intf.trunk_vlans.length > 5
                        ? `${intf.trunk_vlans.slice(0, 3).join(', ')} +${intf.trunk_vlans.length - 3} more`
                        : intf.trunk_vlans.join(', ')}
                      {intf.native_vlan != null && <span className="text-amber-600"> (native: {intf.native_vlan})</span>}
                    </span>
                  )}
                  {!intf.switchport_mode && intf.name?.startsWith('Vlan') && (
                    <span className="text-purple-600 shrink-0" style={{ fontSize: 10 }}>L3 &middot; {intf.ip_address || 'unassigned'}</span>
                  )}
                  <span className="ml-auto flex items-center gap-1.5 shrink-0">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: statusColor }} />
                    <span style={{ color: statusColor, fontWeight: 500 }}>{statusText}</span>
                    {intf.speed && <span className="text-gray-400">{formatSpeed(intf.speed)}</span>}
                    {intf.duplex && <span className="text-gray-400">{intf.duplex}</span>}
                  </span>
                </div>
              </button>

              {/* Expanded detail */}
              {isExpanded && (
                <div className="px-6 py-2 border-b text-xs space-y-2" style={{ background: '#FAFBFC', borderColor: '#F3F4F6' }}>
                  {/* L1 */}
                  <div>
                    <p className="font-semibold text-gray-500 mb-0.5">L1</p>
                    <div className="text-gray-600 grid grid-cols-2 gap-x-4 gap-y-0.5">
                      <span>Speed: {formatSpeed(intf.speed) || '—'}</span>
                      <span>Duplex: {intf.duplex || '—'}</span>
                      <span>MTU: {intf.mtu || '—'}</span>
                      <span>Media: {formatMedia(intf.media_type) || '—'}</span>
                      {intf.sfp_pid && <span className="col-span-2 font-mono">SFP: {intf.sfp_pid}</span>}
                    </div>
                  </div>
                  {/* L2 */}
                  {intf.switchport_mode && (
                    <div>
                      <p className="font-semibold text-gray-500 mb-0.5">L2</p>
                      <div className="text-gray-600 grid grid-cols-2 gap-x-4 gap-y-0.5">
                        <span>Mode: {intf.switchport_mode}</span>
                        {intf.switchport_mode === 'access' && intf.access_vlan != null && (
                          <span>Access VLAN: {intf.access_vlan}</span>
                        )}
                        {intf.switchport_mode === 'trunk' && intf.native_vlan != null && (
                          <span>Native VLAN: {intf.native_vlan}</span>
                        )}
                        {intf.switchport_mode === 'trunk' && intf.trunk_vlans?.length > 0 && (
                          <span className="col-span-2">Trunk VLANs: {intf.trunk_vlans.join(', ')}</span>
                        )}
                      </div>
                    </div>
                  )}
                  {/* L3 */}
                  {(intf.ip_address || intf.vrf) && (
                    <div>
                      <p className="font-semibold text-gray-500 mb-0.5">L3</p>
                      <div className="text-gray-600 grid grid-cols-2 gap-x-4 gap-y-0.5">
                        {intf.vrf && <span>VRF: <span className="font-medium font-mono">{intf.vrf}</span></span>}
                        {intf.ip_address && <span>IP: {intf.ip_address}{intf.prefix_length != null ? `/${intf.prefix_length}` : ''}</span>}
                      </div>
                    </div>
                  )}
                  {/* QoS */}
                  {intf.qos && (
                    <div>
                      <p className="font-semibold text-gray-500 mb-0.5">QoS</p>
                      <div className="text-gray-600 space-y-0.5">
                        {intf.qos.input && (
                          <p>In: {intf.qos.input.policy_name} ({intf.qos.input.type}){intf.qos.input.cir_bps ? ` — ${formatCir(intf.qos.input.cir_bps)}` : ''}</p>
                        )}
                        {intf.qos.output && (
                          <p>Out: {intf.qos.output.policy_name} ({intf.qos.output.type}){intf.qos.output.cir_bps ? ` — ${formatCir(intf.qos.output.cir_bps)}` : ''}</p>
                        )}
                      </div>
                    </div>
                  )}
                  {/* Port-channel membership */}
                  {intf.port_channel_int && (
                    <p className="text-gray-600">Member of: <span className="font-medium font-mono">{intf.port_channel_int}</span></p>
                  )}
                  {/* Port-channel members list (when this IS a Port-channel interface) */}
                  {intf.port_channel_members?.length > 0 && (
                    <div>
                      <p className="font-semibold text-gray-500 mb-0.5">Members</p>
                      <div className="space-y-0.5">
                        {intf.port_channel_members.map(member => {
                          const m = interfaces.find(i => i.name === member)
                          const mDown = m?.oper_status === 'down' && m?.admin_status === 'up'
                          const mAdminDown = m?.admin_status === 'down'
                          const mColor = m ? (mAdminDown ? '#9CA3AF' : mDown ? '#EF4444' : '#22C55E') : '#D1D5DB'
                          return (
                            <p key={member} className="text-gray-600 flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: mColor }} />
                              <span className="font-mono">{member}</span>
                              {m?.speed && <span className="text-gray-400">{formatSpeed(m.speed)}</span>}
                            </p>
                          )
                        })}
                      </div>
                    </div>
                  )}
                  {/* Peer */}
                  {intf.peer_device && (
                    <p className="text-gray-600">Connected to: <span className="font-medium">{intf.peer_device}</span>{intf.peer_interface && ` (${intf.peer_interface})`}</p>
                  )}
                </div>
              )}
            </div>
          )
        })}
        {sortedInterfaces.length === 0 && (
          <p className="p-4 text-xs text-gray-400 text-center">
            {searchFilter ? 'No interfaces match filter' : 'No interfaces'}
          </p>
        )}
      </div>
    </div>
  )
}

// =============================================================================
// FortiGate Interfaces Tab (merged Interfaces + VLANs, ADR-209)
// =============================================================================
function FortiGateInterfacesTab({ hostname, selectedRun }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [expandedGroups, setExpandedGroups] = useState(new Set())
  const [expandedChild, setExpandedChild] = useState(null)
  const [searchFilter, setSearchFilter] = useState('')

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    fetch(`/api/device/${encodeURIComponent(hostname)}/vlans?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.json())
      .then(d => {
        setData(d)
        // Expand all groups by default
        if (d.interface_groups) {
          setExpandedGroups(new Set(d.interface_groups.map(g => g.name)))
        }
      })
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  const groups = data?.interface_groups || []

  const filteredGroups = useMemo(() => {
    if (!searchFilter) return groups
    const q = searchFilter.toLowerCase()
    return groups.map(g => {
      const matchGroup = g.name.toLowerCase().includes(q) ||
        (g.alias || '').toLowerCase().includes(q) ||
        (g.members || []).some(m => m.toLowerCase().includes(q))
      if (matchGroup) return g
      const matchedChildren = (g.children || []).filter(c =>
        c.name.toLowerCase().includes(q) ||
        String(c.vlanid || '').includes(q) ||
        (c.description || '').toLowerCase().includes(q) ||
        (c.subnet || '').includes(q) ||
        (c.type || '').toLowerCase().includes(q)
      )
      if (matchedChildren.length > 0) return { ...g, children: matchedChildren }
      return null
    }).filter(Boolean)
  }, [groups, searchFilter])

  const toggleGroup = (name) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const toggleChild = (name) => {
    setExpandedChild(prev => prev === name ? null : name)
  }

  if (loading) return <p className="p-4 text-xs text-gray-400">Loading...</p>
  if (!data) return <p className="p-4 text-xs text-gray-400">No data</p>

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b" style={{ borderColor: '#E5E7EB' }}>
        <input
          type="text"
          placeholder="Filter by name, VLAN ID, subnet, type..."
          value={searchFilter}
          onChange={e => setSearchFilter(e.target.value)}
          className="w-full text-xs px-2 py-1.5 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
        />
      </div>
      <div className="flex-1 overflow-y-auto">
        {filteredGroups.map(g => {
          const isExpanded = expandedGroups.has(g.name)
          const childCount = (g.children || []).length
          const isOther = g.type === 'other'

          return (
            <div key={g.name} className="mb-0.5">
              {/* Group header */}
              <button
                onClick={() => toggleGroup(g.name)}
                className="w-full px-2 py-1.5 flex items-center gap-2 hover:bg-gray-100 transition-colors"
                style={{ background: '#F1F5F9' }}
              >
                <span style={{ fontSize: 8 }} className="text-gray-400 w-3 shrink-0">
                  {isExpanded ? '▼' : '▶'}
                </span>
                <span className="text-xs font-bold text-gray-700">{g.name}</span>
                {g.alias && <span className="text-xs text-gray-400 truncate">({g.alias})</span>}
                {g.members && g.members.length > 0 && (
                  <span className="text-xs font-mono text-gray-500">{g.members.join(', ')}</span>
                )}
                <span className="ml-auto flex items-center gap-2 shrink-0">
                  {!isOther && g.speed && (
                    <span className="text-xs font-mono text-gray-500">{formatSpeed(g.speed)}</span>
                  )}
                  <span className="flex items-center gap-1">
                    <StatusDot status={g.status} />
                    <span className="text-xs" style={{ color: g.status === 'up' ? '#22C55E' : '#9CA3AF', fontWeight: 500 }}>
                      {isOther ? `${childCount}` : g.status}
                    </span>
                  </span>
                </span>
              </button>

              {isExpanded && (
                <div>
                  {/* L1 detail for aggregate/physical parents */}
                  {!isOther && (
                    <div className="px-5 py-1 bg-gray-50 border-b" style={{ borderColor: '#F3F4F6' }}>
                      <div className="text-xs text-gray-500 flex flex-wrap gap-x-4 gap-y-0.5">
                        {g.speed && <span>Speed: {formatSpeed(g.speed)}</span>}
                        {g.duplex && <span>Duplex: {g.duplex}</span>}
                        {g.mtu && <span>MTU: {g.mtu}</span>}
                        {g.media_type && <span>Media: {formatMedia(g.media_type)}</span>}
                        {g.sfp_pid && <span>SFP: {g.sfp_pid}</span>}
                      </div>
                      {g.peer_device && (
                        <div className="text-xs text-blue-600 mt-0.5">
                          Peer: {g.peer_device}{g.peer_interface ? ` (${g.peer_interface})` : ''}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Children (VLANs or Other interfaces) */}
                  {(g.children || []).map(c => {
                    const isChildExpanded = expandedChild === c.name
                    const isUp = c.status === 'up'
                    const isVlan = c.type === 'vlan'

                    return (
                      <div key={c.name}>
                        <button
                          onClick={() => toggleChild(c.name)}
                          className="w-full flex items-center px-2 py-1 border-b hover:bg-gray-50 transition-colors"
                          style={{ borderColor: '#F3F4F6', paddingLeft: 20 }}
                        >
                          <span style={{ fontSize: 8 }} className="text-gray-400 w-3 shrink-0">
                            {(isVlan && c.ip) || (!isVlan && (c.ip || c.description))
                              ? (isChildExpanded ? '▼' : '▶')
                              : ''}
                          </span>
                          {isVlan ? (
                            <>
                              <span className="font-mono font-medium text-gray-700 w-12 text-left" style={{ fontSize: 12 }}>
                                {c.vlanid}
                              </span>
                              <span className="text-xs text-gray-600 truncate" style={{ maxWidth: 140 }}>
                                {c.description || c.name}
                              </span>
                            </>
                          ) : (
                            <>
                              <span className="text-xs font-medium text-gray-700 truncate" style={{ maxWidth: 120 }}>
                                {c.name}
                              </span>
                              <span className="text-xs text-gray-400 ml-2">{c.type}</span>
                            </>
                          )}
                          <span className="ml-auto flex items-center gap-2 shrink-0">
                            {c.subnet && (
                              <span className="font-mono text-gray-500" style={{ fontSize: 10 }}>
                                {c.subnet}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full shrink-0"
                                style={{ background: isUp ? '#22C55E' : '#9CA3AF' }} />
                              <span style={{ color: isUp ? '#22C55E' : '#9CA3AF', fontWeight: 500, fontSize: 10 }}>
                                {c.status}
                              </span>
                            </span>
                          </span>
                        </button>
                        {isChildExpanded && (c.ip || c.description) && (
                          <div className="px-8 py-1 bg-gray-50 border-b text-xs text-gray-500" style={{ borderColor: '#F3F4F6' }}>
                            {c.ip && <span>IP: {c.ip}</span>}
                            {c.ip && c.subnet && <span className="ml-4">Subnet: {c.subnet}</span>}
                            {!isVlan && c.description && (
                              <span className={c.ip ? 'ml-4' : ''}>{c.description}</span>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
        {filteredGroups.length === 0 && (
          <p className="p-4 text-xs text-gray-400 text-center">
            {searchFilter ? 'No interfaces match filter' : 'No interfaces'}
          </p>
        )}
      </div>
    </div>
  )
}

// =============================================================================
// Findings Tab (S19A-6)
// =============================================================================
function FindingsTab({ deviceData, selectedMemberId }) {
  const { sevColors, severityOrder } = useLegend()
  const allFindings = deviceData.findings || []
  const [sevFilter, setSevFilter] = useState(() => new Set(severityOrder))

  // Filter by member when compound member selected
  const memberFindings = useMemo(() => {
    if (selectedMemberId === null || selectedMemberId === undefined) return allFindings
    return allFindings.filter(f => {
      const fMemberId = f.evidence?.member_id
      return fMemberId === selectedMemberId || fMemberId === undefined || fMemberId === null
    })
  }, [allFindings, selectedMemberId])

  // Apply severity filter and sort
  const filteredFindings = useMemo(() => {
    return memberFindings
      .filter(f => sevFilter.has(f.severity))
      .sort((a, b) => {
        const ai = severityOrder.indexOf(a.severity)
        const bi = severityOrder.indexOf(b.severity)
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })
  }, [memberFindings, sevFilter])

  const toggleSev = (sev) => {
    setSevFilter(prev => {
      const next = new Set(prev)
      if (next.has(sev)) next.delete(sev)
      else next.add(sev)
      return next
    })
  }

  return (
    <div className="flex flex-col h-full">
      {/* Severity filter badges */}
      <div className="p-2 border-b flex flex-wrap gap-1" style={{ borderColor: '#E5E7EB' }}>
        {severityOrder.map(sev => {
          const count = memberFindings.filter(f => f.severity === sev).length
          const sc = sevColors[sev]
          const active = sevFilter.has(sev)
          return (
            <button key={sev} onClick={() => toggleSev(sev)}
              className="text-xs font-medium px-1.5 py-0.5 rounded transition-colors"
              style={active
                ? { background: sc.bg, color: sc.color, border: `1px solid ${sc.color}` }
                : { background: '#F9FAFB', color: '#9CA3AF', border: '1px solid #E5E7EB' }
              }
            >
              {sev.slice(0, 1).toUpperCase() + sev.slice(1)} {count}
            </button>
          )
        })}
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto">
        {filteredFindings.length === 0 ? (
          <div className="px-3 py-4 text-xs text-gray-400 text-center">
            No findings for this device
          </div>
        ) : (
          filteredFindings.map((f, idx) => {
            const sev = f.severity || 'info'
            const sc = sevColors[sev] || sevColors.info
            return (
              <div key={f.finding_id || idx}
                className="px-3 py-1.5 border-b text-xs flex items-start gap-2"
                style={{ borderColor: '#F3F4F6', borderLeft: `3px solid ${sc.color}` }}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-medium px-1.5 py-0.5 rounded capitalize"
                      style={{ background: sc.bg, color: sc.color, fontSize: 9 }}>
                      {sev}
                    </span>
                    {f.evidence?.member_id !== undefined && f.evidence?.member_id !== null && (
                      <span className="text-xs font-medium px-1 py-0.5 rounded"
                        style={{ background: '#EFF6FF', color: '#2563EB', fontSize: 9 }}>
                        M{f.evidence.member_id}
                      </span>
                    )}
                    {f.acknowledged && (
                      <span className="text-xs font-medium px-1 py-0.5 rounded cursor-help"
                        style={{ background: '#F3F4F6', color: '#6B7280', fontSize: 9 }}
                        title={f.acknowledged_reason || 'Acknowledged'}>
                        ACK
                      </span>
                    )}
                    <span className="font-medium text-gray-500 truncate">{f.rule_id}</span>
                  </div>
                  <p className="text-gray-600 mt-0.5 line-clamp-2">{f.message || f.title}</p>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

// =============================================================================
// Routing Tab (S19A-7)
// =============================================================================
const PROTO_FILTERS = ['All', 'Static', 'OSPF', 'BGP', 'Connected', 'Other']
const PROTO_MAP = {
  S: 'Static', O: 'OSPF', B: 'BGP', C: 'Connected', L: 'Local',
  // Full protocol names from Genie source_protocol / FortiGate
  static: 'Static', ospf: 'OSPF', bgp: 'BGP', connected: 'Connected', local: 'Local',
}

function RoutingTab({ hostname, selectedRun }) {
  const [routes, setRoutes] = useState(null)
  const [loading, setLoading] = useState(false)
  const [protoFilter, setProtoFilter] = useState('All')
  const [vrfFilter, setVrfFilter] = useState(null)
  const [summaryOnly, setSummaryOnly] = useState(false)

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    setVrfFilter(null)
    fetch(`/api/device/${encodeURIComponent(hostname)}/routing?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : { routes: [] })
      .then(data => {
        setRoutes(data.routes || [])
        setSummaryOnly(!!data.routing_summary_only)
      })
      .catch(() => setRoutes([]))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  const vrfList = useMemo(() => {
    if (!routes) return []
    return [...new Set(routes.map(r => r.vrf))].sort()
  }, [routes])

  // Auto-select VRF: prefer the VRF with the most routes (most useful view).
  // Falls back to "default" if tied, then first alphabetically.
  useEffect(() => {
    if (vrfList.length > 0 && (vrfFilter === null || !vrfList.includes(vrfFilter))) {
      const countByVrf = vrfList.reduce((acc, vrf) => {
        acc[vrf] = routes ? routes.filter(r => r.vrf === vrf).length : 0
        return acc
      }, {})
      const best = vrfList.reduce((a, b) => {
        if (countByVrf[b] !== countByVrf[a]) return countByVrf[b] > countByVrf[a] ? b : a
        if (a === 'default') return a
        if (b === 'default') return b
        return a < b ? a : b
      })
      setVrfFilter(best)
    }
  }, [vrfList, vrfFilter, routes])

  const filteredRoutes = useMemo(() => {
    if (!routes || !vrfFilter) return []
    let filtered = routes.filter(r => r.vrf === vrfFilter)
    if (protoFilter !== 'All') {
      filtered = filtered.filter(r => {
        // The graph loader tags full-Internet-table devices with
        // `protocol = "bgp (synthesized)"` to represent "this device carries
        // ~1M BGP routes that weren't enumerated". Semantically still BGP —
        // classify by the first token so the BGP filter catches it.
        const protoKey = (r.protocol || '').split(/\s/)[0]
        const label = PROTO_MAP[protoKey] || 'Other'
        return label === protoFilter || (protoFilter === 'Other' && !Object.values(PROTO_MAP).includes(label))
      })
    }
    return filtered
  }, [routes, protoFilter, vrfFilter])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading routing table...</div>
  if (!routes || routes.length === 0) return <div className="p-4 text-xs text-gray-400">No routing data for this device</div>

  return (
    <div className="flex flex-col h-full">
      {/* Filters: VRF selector + Protocol */}
      <div className="p-2 border-b flex items-center gap-3" style={{ borderColor: '#E5E7EB' }}>
        {vrfList.length > 1 && (
          <select
            value={vrfFilter || ''}
            onChange={e => setVrfFilter(e.target.value)}
            className="text-xs font-medium px-1.5 py-0.5 rounded border"
            style={{ borderColor: '#D1D5DB', background: '#F9FAFB', color: '#374151', maxWidth: 160 }}
          >
            {vrfList.map(vrf => (
              <option key={vrf} value={vrf}>{vrf} ({routes.filter(r => r.vrf === vrf).length})</option>
            ))}
          </select>
        )}
        <div className="flex flex-wrap gap-1">
          {PROTO_FILTERS.map(pf => (
            <button key={pf} onClick={() => setProtoFilter(pf)}
              className="text-xs font-medium px-2 py-0.5 rounded transition-colors"
              style={protoFilter === pf
                ? { background: '#2563EB', color: '#FFFFFF' }
                : { background: '#F3F4F6', color: '#6B7280' }
              }
            >
              {pf}
            </button>
          ))}
        </div>
      </div>

      {/* Info message when BGP filter active on summary-only device */}
      {protoFilter === 'BGP' && summaryOnly && (
        <div className="mx-2 my-2 p-3 rounded text-xs" style={{ background: '#EFF6FF', border: '1px solid #BFDBFE', color: '#1E40AF' }}>
          <span className="font-semibold">Partial BGP routing table</span> — full RIB not collected to prevent memory issues with large internet routing tables (~1M routes). Only routes from peers with small prefix counts are shown below.
        </div>
      )}

      {/* Route table */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-50">
            <tr className="text-left text-gray-500 uppercase" style={{ fontSize: 9 }}>
              <th className="px-2 py-1.5">Proto</th>
              <th className="px-2 py-1.5">Prefix</th>
              <th className="px-2 py-1.5">Next-hop</th>
              <th className="px-2 py-1.5">Intf</th>
              <th className="px-2 py-1.5">AD</th>
            </tr>
          </thead>
          <tbody>
            {filteredRoutes.map((r, idx) => {
              const isInactive = r.active === false
              const isBlackhole = (r.next_hop || '').includes('Null') || (r.interface || '').includes('Null')
              return (
                <tr key={idx} className="border-b" style={{
                  borderColor: '#F3F4F6',
                  color: isInactive ? '#9CA3AF' : isBlackhole ? '#DC2626' : '#374151',
                  textDecoration: 'none',
                  background: isBlackhole ? '#FEF2F2' : 'transparent',
                }}>
                  <td className="px-2 py-1 font-mono font-medium">{r.protocol}</td>
                  <td className="px-2 py-1 font-mono">{r.prefix}</td>
                  <td className="px-2 py-1">{r.next_hop || '—'}</td>
                  <td className="px-2 py-1">{r.interface || '—'}</td>
                  <td className="px-2 py-1">{r.ad ?? '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// =============================================================================
// VLANs Tab (Sprint 19B, ADR-194)
// =============================================================================
function VlansTab({ hostname, selectedRun }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [searchFilter, setSearchFilter] = useState('')

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    fetch(`/api/device/${encodeURIComponent(hostname)}/vlans?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : { vlans: [] })
      .then(d => setData(d))
      .catch(() => setData({ vlans: [] }))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading VLANs...</div>
  if (!data) return <div className="p-4 text-xs text-gray-400">No VLAN data for this device</div>

  // Cisco flat view
  const vlans = data.vlans || []
  if (vlans.length === 0) return <div className="p-4 text-xs text-gray-400">No VLAN data for this device</div>

  return <CiscoVlansView vlans={vlans} searchFilter={searchFilter} setSearchFilter={setSearchFilter} />
}

function CiscoVlansView({ vlans, searchFilter, setSearchFilter }) {
  const [expandedVlan, setExpandedVlan] = useState(null)

  const filteredVlans = useMemo(() => {
    if (!searchFilter) return vlans
    const q = searchFilter.toLowerCase()
    return vlans.filter(v =>
      String(v.vlan_id).includes(q) ||
      (v.name || '').toLowerCase().includes(q) ||
      (v.interfaces || []).some(i => i.toLowerCase().includes(q))
    )
  }, [vlans, searchFilter])

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b" style={{ borderColor: '#E5E7EB' }}>
        <input
          type="text"
          placeholder="Filter by VLAN ID, name, or port..."
          value={searchFilter}
          onChange={e => setSearchFilter(e.target.value)}
          className="w-full text-xs px-2 py-1.5 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
        />
      </div>
      <div className="flex-1 overflow-y-auto">
        {/* Header row */}
        <div className="sticky top-0 bg-gray-50 flex text-left text-gray-500 uppercase px-2 py-1.5" style={{ fontSize: 9 }}>
          <span className="w-10 shrink-0">&nbsp;</span>
          <span className="w-14 shrink-0">VLAN</span>
          <span className="flex-1">Name</span>
          <span className="w-16 shrink-0">Status</span>
          <span className="w-20 shrink-0 text-right">Ports</span>
        </div>
        {filteredVlans.map(v => {
          const isActive = v.state === 'active' && !v.shutdown
          const isExpanded = expandedVlan === v.vlan_id
          const ports = v.interfaces || []
          return (
            <div key={v.vlan_id}>
              <button
                onClick={() => setExpandedVlan(isExpanded ? null : v.vlan_id)}
                className="w-full text-left px-2 py-1.5 border-b hover:bg-gray-50 transition-colors flex items-center text-xs"
                style={{ borderColor: '#F3F4F6' }}
              >
                <span className="w-10 shrink-0 text-gray-400" style={{ fontSize: 8 }}>
                  {ports.length > 0 ? (isExpanded ? '\u25BC' : '\u25B6') : '\u00A0'}
                </span>
                <span className="w-14 shrink-0 font-mono font-medium text-gray-700">{v.vlan_id}</span>
                <span className="flex-1 text-gray-600 truncate">{v.name || '—'}</span>
                <span className="w-16 shrink-0 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: isActive ? '#22C55E' : '#9CA3AF' }} />
                  <span style={{ color: isActive ? '#22C55E' : '#9CA3AF', fontWeight: 500 }}>
                    {v.shutdown ? 'shut' : v.state || '—'}
                  </span>
                </span>
                <span className="w-20 shrink-0 text-right text-gray-400 font-mono" style={{ fontSize: 10 }}>
                  {ports.length > 0 ? `${ports.length} port${ports.length !== 1 ? 's' : ''}` : '—'}
                </span>
              </button>
              {isExpanded && ports.length > 0 && (
                <div className="px-6 py-2 border-b text-xs" style={{ background: '#FAFBFC', borderColor: '#F3F4F6' }}>
                  <div className="text-gray-600 font-mono flex flex-wrap gap-x-3 gap-y-0.5" style={{ fontSize: 10 }}>
                    {ports.map(p => <span key={p}>{p}</span>)}
                  </div>
                </div>
              )}
            </div>
          )
        })}
        {filteredVlans.length === 0 && (
          <p className="p-4 text-xs text-gray-400 text-center">No VLANs match filter</p>
        )}
      </div>
    </div>
  )
}

// =============================================================================
// OspfTab — per-device OSPF detail (ADR-217)
// =============================================================================
function OspfTab({ hostname, selectedRun }) {
  const [ospfData, setOspfData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedArea, setExpandedArea] = useState(null)

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    setExpandedArea(null)
    fetch(`/api/device/${encodeURIComponent(hostname)}/ospf?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : { processes: [] })
      .then(data => setOspfData(data))
      .catch(() => setOspfData({ processes: [] }))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading OSPF data...</div>

  // Filter: only show processes with at least one interface, and only areas with interfaces
  const filteredProcesses = (ospfData?.processes || [])
    .map(proc => ({
      ...proc,
      areas: proc.areas.filter(a => a.interfaces.length > 0),
    }))
    .filter(proc => proc.areas.length > 0)

  if (filteredProcesses.length === 0) {
    return <div className="p-4 text-xs text-gray-400">No OSPF data for this device</div>
  }

  const stateColor = (s) => {
    if (s === 'full') return '#059669'
    if (s === 'down' || s === 'unknown') return '#DC2626'
    return '#D97706'
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {filteredProcesses.map(proc => (
        <div key={`${proc.vrf}-${proc.process_id}`} className="border-b" style={{ borderColor: '#E5E7EB' }}>
          {/* Process header */}
          <div className="px-3 py-2" style={{ background: '#F8FAFC' }}>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-gray-700">Process {proc.process_id}</span>
              <span className="text-xs text-gray-500">VRF: {proc.vrf}</span>
              {proc.router_id && (
                <span className="text-xs text-gray-400 font-mono">RID: {proc.router_id}</span>
              )}
            </div>
            {/* Health indicator pills */}
            <div className="flex flex-wrap items-center gap-1.5 mt-1">
              <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                style={{ background: proc.graceful_restart ? '#ECFDF5' : '#FEF2F2', color: proc.graceful_restart ? '#059669' : '#DC2626', fontSize: 10 }}>
                GR {proc.graceful_restart ? 'ON' : 'OFF'}
              </span>
              <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                style={{ background: proc.bfd ? '#ECFDF5' : '#FEF2F2', color: proc.bfd ? '#059669' : '#DC2626', fontSize: 10 }}>
                BFD {proc.bfd ? 'ON' : 'OFF'}
              </span>
              {proc.stub_router && (
                <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: '#FEF3C7', color: '#D97706', fontSize: 10 }}>
                  Stub Router
                </span>
              )}
              {proc.spf_throttle && (
                <span className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F3F4F6', color: '#6B7280', fontSize: 10 }}>
                  SPF {proc.spf_throttle.start}/{proc.spf_throttle.hold}/{proc.spf_throttle.maximum}ms
                </span>
              )}
              {proc.max_lsa && (
                <span className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F3F4F6', color: '#6B7280', fontSize: 10 }}>
                  Max LSA {proc.max_lsa}
                </span>
              )}
              {proc.passive_default && (
                <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: '#FEF3C7', color: '#D97706', fontSize: 10 }}>
                  Passive Default
                </span>
              )}
              {proc.capability_vrf_lite && (
                <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: '#EDE9FE', color: '#7C3AED', fontSize: 10 }}>
                  VRF-Lite
                </span>
              )}
              {proc.redistribute?.length > 0 && proc.redistribute.map(p => (
                <span key={p} className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F0F9FF', color: '#0369A1', fontSize: 10 }}>
                  redist:{p}
                </span>
              ))}
              {proc.active_interfaces?.length > 0 && (
                <span className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F3F4F6', color: '#6B7280', fontSize: 10 }}>
                  Active: {proc.active_interfaces.join(', ')}
                </span>
              )}
            </div>
          </div>

          {/* Areas */}
          {proc.areas.map(area => {
            const areaKey = `${proc.vrf}-${proc.process_id}-${area.area_id}`
            const isExpanded = expandedArea === areaKey
            const totalNeighbors = area.interfaces.reduce((sum, i) => sum + i.neighbors.length, 0)

            return (
              <div key={areaKey}>
                <button
                  onClick={() => setExpandedArea(isExpanded ? null : areaKey)}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-50 flex items-center gap-2 text-xs border-t"
                  style={{ borderColor: '#F3F4F6' }}
                >
                  <span className="text-gray-400" style={{ fontSize: 8 }}>
                    {isExpanded ? '\u25BC' : '\u25B6'}
                  </span>
                  <span className="font-medium text-gray-600">Area {area.area_id}</span>
                  {area.area_type && area.area_type !== 'normal' && (
                    <span className={`px-1 py-0.5 rounded font-medium ${
                      area.area_type === 'backbone' ? 'bg-blue-50 text-blue-600' :
                      area.area_type?.includes('stub') ? 'bg-amber-50 text-amber-600' :
                      area.area_type?.includes('nssa') ? 'bg-purple-50 text-purple-600' :
                      'bg-gray-100 text-gray-500'
                    }`} style={{ fontSize: 9 }}>
                      {area.area_type}
                    </span>
                  )}
                  {area.spf_runs != null && (
                    <span style={{ color: area.spf_runs > 100 ? '#D97706' : '#9CA3AF', fontSize: 10 }}>
                      {area.spf_runs} SPF
                    </span>
                  )}
                  {area.lsa_count != null && (
                    <span style={{ color: '#9CA3AF', fontSize: 10 }}>
                      {area.lsa_count} LSA
                    </span>
                  )}
                  <span className="text-gray-400">
                    {area.interfaces.length} intf{area.interfaces.length !== 1 ? 's' : ''}
                    {totalNeighbors > 0 && `, ${totalNeighbors} nbr${totalNeighbors !== 1 ? 's' : ''}`}
                  </span>
                </button>

                {isExpanded && (
                  <div className="px-3 py-2" style={{ background: '#FAFBFC' }}>
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-gray-400 text-left" style={{ fontSize: 9 }}>
                          <th className="py-1 pr-2 font-medium">Interface</th>
                          <th className="py-1 pr-2 font-medium">Cost</th>
                          <th className="py-1 pr-2 font-medium">Type</th>
                          <th className="py-1 pr-2 font-medium">Hello/Dead</th>
                          <th className="py-1 font-medium">State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {area.interfaces.map(intf => (
                          <Fragment key={intf.name}>
                            <tr className="border-t" style={{ borderColor: '#F3F4F6' }}>
                              <td className="py-1 pr-2 font-mono text-gray-700">
                                {intf.name}
                                {intf.passive && <span className="ml-1 text-gray-400">(passive)</span>}
                              </td>
                              <td className="py-1 pr-2 text-gray-600">{intf.cost ?? '—'}</td>
                              <td className="py-1 pr-2 text-gray-600">{intf.network_type || '—'}</td>
                              <td className="py-1 pr-2 text-gray-600">{intf.hello_interval ?? '—'}s / {intf.dead_interval ?? '—'}s</td>
                              <td className="py-1">
                                <span style={{ color: intf.state === 'point-to-point' || intf.state === 'dr' || intf.state === 'bdr' || intf.state === 'up' ? '#059669' : '#9CA3AF' }}>
                                  {intf.state || '—'}
                                </span>
                              </td>
                            </tr>
                            {/* Neighbor rows */}
                            {intf.neighbors.map(nbr => (
                              <tr key={nbr.router_id} style={{ background: '#F1F5F9' }}>
                                <td className="py-0.5 pr-2 pl-4 text-gray-500" colSpan={3}>
                                  <span className="font-mono">{nbr.address}</span>
                                  <span className="ml-1 text-gray-400">RID: {nbr.router_id}</span>
                                </td>
                                <td className="py-0.5 pr-2 text-gray-400 font-mono">{nbr.dead_timer}</td>
                                <td className="py-0.5">
                                  <span className="font-bold" style={{ color: stateColor(nbr.state) }}>
                                    {nbr.state}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </Fragment>
                        ))}
                      </tbody>
                    </table>
                    {/* Area LSDB from per-device OSPF API (ADR-220) */}
                    {area.lsdb && area.lsdb.length > 0 && (
                      <OspfLsdbSection lsas={area.lsdb} areaId={area.area_id} />
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}

// =============================================================================
// BgpTab — per-device BGP detail (S19C-9)
// =============================================================================
function BgpTab({ hostname, selectedRun }) {
  const [bgpData, setBgpData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedNbr, setExpandedNbr] = useState(null)

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    setExpandedNbr(null)
    fetch(`/api/device/${encodeURIComponent(hostname)}/bgp?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : { processes: [] })
      .then(data => setBgpData(data))
      .catch(() => setBgpData({ processes: [] }))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading BGP data...</div>

  const processes = bgpData?.processes || []
  if (processes.length === 0) {
    return <div className="p-4 text-xs text-gray-400">No BGP data for this device</div>
  }

  const stateColor = (s) => {
    const sl = (s || '').toLowerCase()
    if (sl === 'established') return '#059669'
    if (sl === 'idle' || sl === 'active') return '#DC2626'
    return '#D97706'
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {processes.map((proc, pi) => (
        <div key={pi} className="border-b" style={{ borderColor: '#E5E7EB' }}>
          {/* Process header */}
          <div className="px-3 py-2" style={{ background: '#F8FAFC' }}>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-gray-700">AS {proc.as_number}</span>
              {proc.router_id && (
                <span className="text-xs text-gray-400 font-mono">RID: {proc.router_id}</span>
              )}
              <span className="text-xs text-gray-500">VRF: {proc.vrf}</span>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-1">
              <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                style={{ background: proc.graceful_restart ? '#ECFDF5' : '#FEF2F2', color: proc.graceful_restart ? '#059669' : '#DC2626', fontSize: 10 }}>
                GR {proc.graceful_restart ? 'ON' : 'OFF'}
              </span>
              {proc.is_route_reflector && (
                <span className="text-xs px-1.5 py-0.5 rounded font-bold"
                  style={{ background: '#EEF2FF', color: '#4338CA', fontSize: 10 }}>
                  ◆ Route Reflector{proc.cluster_id ? ` · cluster ${proc.cluster_id}` : ''}
                </span>
              )}
              {proc.log_neighbor_changes && (
                <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: '#F0F9FF', color: '#0369A1', fontSize: 10 }}>
                  Log Changes
                </span>
              )}
              {proc.bestpath && (
                <span className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F3F4F6', color: '#6B7280', fontSize: 10 }}>
                  bestpath: {proc.bestpath}
                </span>
              )}
              {proc.redistribute?.length > 0 && proc.redistribute.map(p => (
                <span key={p} className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#F0F9FF', color: '#0369A1', fontSize: 10 }}>
                  redist:{p}
                </span>
              ))}
            </div>
          </div>

          {/* Network Statements */}
          {proc.network_statements?.length > 0 && (
            <div className="px-3 py-1.5 border-t" style={{ borderColor: '#F3F4F6' }}>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Network Statements</p>
              <div className="flex flex-wrap gap-1">
                {proc.network_statements.map(ns => (
                  <span key={ns} className="text-xs px-1.5 py-0.5 rounded font-mono bg-purple-50 text-purple-700">
                    {ns}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Neighbor Table */}
          <div className="px-3 py-1.5">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
              Neighbors ({(proc.neighbors || []).length})
            </p>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-400 text-left">
                  <th className="py-1 pr-1 font-medium"></th>
                  <th className="py-1 pr-1 font-medium">Peer IP</th>
                  <th className="py-1 pr-1 font-medium">Remote AS</th>
                  <th className="py-1 pr-1 font-medium">State</th>
                  <th className="py-1 pr-1 font-medium">Pfx</th>
                  <th className="py-1 font-medium">Type</th>
                </tr>
              </thead>
              <tbody className="text-gray-600">
                {(proc.neighbors || []).map(nbr => {
                  const nbrKey = nbr.peer_ip
                  const isExpanded = expandedNbr === nbrKey
                  return (
                    <Fragment key={nbrKey}>
                      <tr
                        className="border-t border-gray-100 cursor-pointer hover:bg-gray-50"
                        onClick={() => setExpandedNbr(isExpanded ? null : nbrKey)}
                      >
                        <td className="py-1 pr-1 text-gray-400" style={{ fontSize: 8 }}>
                          {isExpanded ? '▼' : '▶'}
                        </td>
                        <td className="py-1 pr-1 font-mono">{nbr.peer_ip}</td>
                        <td className="py-1 pr-1">{nbr.remote_as}</td>
                        <td className="py-1 pr-1">
                          <span className="font-bold" style={{ color: stateColor(nbr.state), fontSize: 10 }}>
                            {(nbr.state || 'unknown').toUpperCase()}
                          </span>
                        </td>
                        <td className="py-1 pr-1">{nbr.prefixes_received ?? '—'}</td>
                        <td className="py-1">
                          <span className="px-1 py-0.5 rounded font-bold" style={{
                            background: '#EDE9FE', color: '#7C3AED', fontSize: 10
                          }}>
                            {nbr.session_type === 'ibgp' ? 'iBGP' : 'eBGP'}
                          </span>
                          {nbr.route_reflector_client && (
                            <span className="ml-1 px-1 py-0.5 rounded font-bold" style={{
                              background: '#EEF2FF', color: '#4338CA', fontSize: 10
                            }}>
                              RR-client
                            </span>
                          )}
                          {nbr.route_reflector && (
                            <span className="ml-1 px-1 py-0.5 rounded font-bold" style={{
                              background: '#EEF2FF', color: '#4338CA', fontSize: 10
                            }}>
                              ◆ RR
                            </span>
                          )}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-gray-50">
                          <td colSpan={6} className="p-2">
                            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                              {nbr.description && (
                                <><span className="text-gray-400">Description</span><span>{nbr.description}</span></>
                              )}
                              {nbr.up_down && (
                                <><span className="text-gray-400">Uptime</span><span>{nbr.up_down}</span></>
                              )}
                              {nbr.keepalive != null && (
                                <><span className="text-gray-400">Keepalive / Hold</span><span>{nbr.keepalive}s / {nbr.hold_time}s</span></>
                              )}
                              <><span className="text-gray-400">Messages Sent</span><span>{nbr.msg_sent ?? '—'}</span></>
                              <><span className="text-gray-400">Messages Rcvd</span><span>{nbr.msg_rcvd ?? '—'}</span></>
                              {nbr.route_policy_in && (
                                <><span className="text-gray-400">Route Policy In</span><span className="font-mono">{nbr.route_policy_in}</span></>
                              )}
                              {nbr.route_policy_out && (
                                <><span className="text-gray-400">Route Policy Out</span><span className="font-mono">{nbr.route_policy_out}</span></>
                              )}
                              <><span className="text-gray-400">BFD</span><span>{nbr.bfd ? 'Enabled' : 'Disabled'}</span></>
                              <><span className="text-gray-400">Password</span><span>{nbr.password_configured ? 'Configured' : 'None'}</span></>
                              <><span className="text-gray-400">Graceful Restart</span><span>{nbr.graceful_restart ? 'Enabled' : 'Disabled'}</span></>
                              {nbr.maximum_prefix != null && (
                                <><span className="text-gray-400">Max Prefix</span><span>{nbr.maximum_prefix.toLocaleString()}</span></>
                              )}
                              {nbr.update_source && (
                                <><span className="text-gray-400">Update Source</span><span className="font-mono">{nbr.update_source}</span></>
                              )}
                              <><span className="text-gray-400">Send Community</span><span>{nbr.send_community ? 'Yes' : 'No'}</span></>
                              <><span className="text-gray-400">Next-Hop Self</span><span>{nbr.next_hop_self ? 'Yes' : 'No'}</span></>
                              {nbr.address_families?.length > 0 && (
                                <><span className="text-gray-400">Address Families</span>
                                <span>{nbr.address_families.join(', ')}</span></>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  )
}

// =============================================================================
// FirewallPoliciesTab — FortiGate firewall policies (S19D-4)
// =============================================================================
function FirewallPoliciesTab({ hostname, selectedRun }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedRow, setExpandedRow] = useState(null)
  const [zoneFilter, setZoneFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [searchText, setSearchText] = useState('')

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    setExpandedRow(null)
    fetch(`/api/device/${encodeURIComponent(hostname)}/firewall-policies?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => setData(d))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading firewall policies...</div>
  if (!data) return <div className="p-4 text-xs text-gray-400">No firewall policy data for this device</div>

  const policies = data.policies || []
  const zones = data.zones || []

  // Build zone pair options from policies
  const zonePairs = new Set()
  policies.forEach(p => {
    const srcZones = p.srcintf.map(i => i.zone || i.name)
    const dstZones = p.dstintf.map(i => i.zone || i.name)
    srcZones.forEach(s => dstZones.forEach(d => zonePairs.add(`${s} → ${d}`)))
  })

  // Filter policies
  const filtered = policies.filter(p => {
    if (actionFilter !== 'all' && p.action !== actionFilter) return false
    if (zoneFilter) {
      const srcZones = p.srcintf.map(i => i.zone || i.name)
      const dstZones = p.dstintf.map(i => i.zone || i.name)
      const pairs = []
      srcZones.forEach(s => dstZones.forEach(d => pairs.push(`${s} → ${d}`)))
      if (!pairs.includes(zoneFilter)) return false
    }
    if (searchText) {
      const st = searchText.toLowerCase()
      const searchable = [
        p.name, p.comments,
        ...p.srcaddr.map(a => a.name), ...p.dstaddr.map(a => a.name),
        ...p.srcaddr.map(a => a.resolved), ...p.dstaddr.map(a => a.resolved),
        ...p.service.map(s => s.name), ...p.service.map(s => s.resolved || ''),
      ].join(' ').toLowerCase()
      if (!searchable.includes(st)) return false
    }
    return true
  })

  const enabledCount = policies.filter(p => p.status === 'enable').length
  const acceptCount = policies.filter(p => p.action === 'accept').length
  const denyCount = policies.filter(p => p.action === 'deny').length

  const fmtIntf = (list) => list.map(i => i.zone || i.name).join(', ')
  const fmtAddrInline = (list) => list.map(a => {
    if (a.resolved && a.resolved !== a.name) return `${a.name} [${a.resolved}]`
    return a.name
  })
  const fmtSvcInline = (list) => list.map(s => {
    if (s.resolved != null && s.resolved !== s.name) return `${s.name} [${s.resolved}]`
    if (s.resolved == null) return s.name
    return s.name
  })

  return (
    <div className="flex-1 overflow-y-auto">
      {/* Filter bar */}
      <div className="px-3 py-2 border-b flex flex-wrap items-center gap-2" style={{ borderColor: '#E5E7EB', background: '#F8FAFC' }}>
        <select value={zoneFilter} onChange={e => setZoneFilter(e.target.value)}
          className="text-xs border rounded px-1.5 py-1" style={{ borderColor: '#D1D5DB', maxWidth: 180 }}>
          <option value="">All zone pairs</option>
          {[...zonePairs].sort().map(zp => <option key={zp} value={zp}>{zp}</option>)}
        </select>
        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)}
          className="text-xs border rounded px-1.5 py-1" style={{ borderColor: '#D1D5DB' }}>
          <option value="all">All actions</option>
          <option value="accept">Accept</option>
          <option value="deny">Deny</option>
        </select>
        <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)}
          placeholder="Search..." className="text-xs border rounded px-1.5 py-1 flex-1"
          style={{ borderColor: '#D1D5DB', minWidth: 80, maxWidth: 160 }} />
      </div>

      {/* Summary badges */}
      <div className="px-3 py-1.5 flex flex-wrap gap-1.5 border-b" style={{ borderColor: '#E5E7EB' }}>
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: '#F3F4F6', color: '#374151' }}>
          {policies.length} total
        </span>
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: '#EFF6FF', color: '#2563EB' }}>
          {enabledCount} enabled
        </span>
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: '#ECFDF5', color: '#059669' }}>
          {acceptCount} accept
        </span>
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: '#FEF2F2', color: '#DC2626' }}>
          {denyCount} deny
        </span>
        {filtered.length !== policies.length && (
          <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: '#FFF7ED', color: '#C2410C' }}>
            showing {filtered.length}
          </span>
        )}
      </div>

      {/* Policy table */}
      <div className="px-2">
        <table className="w-full text-xs" style={{ borderCollapse: 'collapse' }}>
          <thead>
            <tr className="text-left" style={{ background: '#F8FAFC', color: '#64748B', fontSize: 10 }}>
              <th className="px-1 py-1">#</th>
              <th className="px-1 py-1">ID</th>
              <th className="px-1 py-1">Name</th>
              <th className="px-1 py-1">Source</th>
              <th className="px-1 py-1">Destination</th>
              <th className="px-1 py-1">Service</th>
              <th className="px-1 py-1">Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(p => {
              const isExpanded = expandedRow === p.policyid
              const isDisabled = p.status !== 'enable'
              const rowStyle = isDisabled ? { opacity: 0.5, background: '#F9FAFB' } : {}
              return (
                <Fragment key={p.policyid}>
                  <tr onClick={() => setExpandedRow(isExpanded ? null : p.policyid)}
                    className="border-b cursor-pointer hover:bg-blue-50"
                    style={{ borderColor: '#F3F4F6', ...rowStyle }}>
                    <td className="px-1 py-1 text-gray-400">{p.seq}</td>
                    <td className="px-1 py-1 font-mono">{p.policyid}</td>
                    <td className="px-1 py-1 font-medium truncate" style={{ maxWidth: 120 }}>{p.name || '—'}</td>
                    <td className="px-1 py-1" style={{ maxWidth: 180 }}>
                      {fmtAddrInline(p.srcaddr).map((t, i) => (
                        <div key={i} className="font-mono truncate" style={{ fontSize: 10 }}
                          title={p.srcaddr[i]?.resolved || p.srcaddr[i]?.name}>{t}</div>
                      ))}
                    </td>
                    <td className="px-1 py-1" style={{ maxWidth: 180 }}>
                      {fmtAddrInline(p.dstaddr).map((t, i) => (
                        <div key={i} className="font-mono truncate" style={{ fontSize: 10 }}
                          title={p.dstaddr[i]?.resolved || p.dstaddr[i]?.name}>{t}</div>
                      ))}
                    </td>
                    <td className="px-1 py-1" style={{ maxWidth: 120 }}>
                      {fmtSvcInline(p.service).map((t, i) => (
                        <div key={i} className="font-mono truncate" style={{ fontSize: 10 }}
                          title={p.service[i]?.resolved || p.service[i]?.name}>{t}</div>
                      ))}
                    </td>
                    <td className="px-1 py-1">
                      <span className="px-1.5 py-0.5 rounded text-white font-semibold" style={{
                        fontSize: 9,
                        background: p.action === 'accept' ? '#059669' : '#DC2626'
                      }}>{p.action}</span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr style={{ background: '#F8FAFC' }}>
                      <td colSpan={7} className="px-3 py-2">
                        {/* Expanded detail */}
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mb-2">
                          <div>
                            <span className="text-gray-400 font-semibold">Source Zone/Intf: </span>
                            <span className="font-mono">{p.srcintf.map(i => i.zone ? `${i.zone} (${i.name})` : i.name).join(', ')}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Dest Zone/Intf: </span>
                            <span className="font-mono">{p.dstintf.map(i => i.zone ? `${i.zone} (${i.name})` : i.name).join(', ')}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Source: </span>
                            <span className="font-mono">{p.srcaddr.map(a => a.resolved !== a.name ? `${a.name} → ${a.resolved}` : a.name).join(', ')}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Destination: </span>
                            <span className="font-mono">{p.dstaddr.map(a => a.resolved !== a.name ? `${a.name} → ${a.resolved}` : a.name).join(', ')}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Service: </span>
                            <span className="font-mono">{p.service.map(s => s.resolved != null ? (s.resolved !== s.name ? `${s.name} → ${s.resolved}` : s.name) : `${s.name} (ANY)`).join(', ')}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">NAT: </span>
                            <span className={p.nat === 'enable' ? 'text-green-700' : 'text-gray-400'}>{p.nat}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Schedule: </span>
                            <span>{p.schedule || 'always'}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-semibold">Log: </span>
                            <span>{p.logtraffic}</span>
                          </div>
                        </div>
                        {/* UTM profiles */}
                        {Object.keys(p.utm).length > 0 && (
                          <div className="mb-2">
                            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">UTM Profiles</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {Object.entries(p.utm).map(([k, v]) => (
                                <span key={k} className="text-xs px-1.5 py-0.5 rounded font-mono"
                                  style={{ background: '#EFF6FF', color: '#2563EB', fontSize: 10 }}>
                                  {k.replace(/-/g, ' ')}: {v}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        {/* Comments */}
                        {p.comments && (
                          <div>
                            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Comments</span>
                            <p className="text-xs text-gray-600 mt-0.5 whitespace-pre-line">{p.comments}</p>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// =============================================================================
// SecurityPoliciesTab — Cisco ACLs, Route Maps, Prefix Lists (S19D-5)
// =============================================================================
function SecurityPoliciesTab({ hostname, selectedRun }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedAcl, setExpandedAcl] = useState(null)
  const [expandedRm, setExpandedRm] = useState(null)
  const [expandedPl, setExpandedPl] = useState(null)
  const [searchText, setSearchText] = useState('')

  useEffect(() => {
    if (!hostname || !selectedRun) return
    setLoading(true)
    fetch(`/api/device/${encodeURIComponent(hostname)}/security-policies?run_id=${encodeURIComponent(selectedRun)}`)
      .then(r => r.ok ? r.json() : { acls: [], route_maps: [], prefix_lists: [] })
      .then(d => setData(d))
      .catch(() => setData({ acls: [], route_maps: [], prefix_lists: [] }))
      .finally(() => setLoading(false))
  }, [hostname, selectedRun])

  if (loading) return <div className="p-4 text-xs text-gray-400">Loading security data...</div>

  const acls = data?.acls || []
  const routeMaps = data?.route_maps || []
  const prefixLists = data?.prefix_lists || []

  if (acls.length === 0 && routeMaps.length === 0 && prefixLists.length === 0) {
    return <div className="p-4 text-xs text-gray-400">No security configuration data for this device</div>
  }

  const st = searchText.toLowerCase()
  const filteredAcls = st ? acls.filter(a => a.name.toLowerCase().includes(st)) : acls
  const filteredRm = st ? routeMaps.filter(r => r.name.toLowerCase().includes(st)) : routeMaps
  const filteredPl = st ? prefixLists.filter(p => p.name.toLowerCase().includes(st)) : prefixLists

  const actionBadge = (action) => (
    <span className="px-1.5 py-0.5 rounded text-white font-semibold" style={{
      fontSize: 9,
      background: action === 'permit' ? '#059669' : '#DC2626'
    }}>{action}</span>
  )

  return (
    <div className="flex-1 overflow-y-auto">
      {/* Search filter */}
      <div className="px-3 py-2 border-b" style={{ borderColor: '#E5E7EB', background: '#F8FAFC' }}>
        <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)}
          placeholder="Search by name..." className="text-xs border rounded px-1.5 py-1 w-full"
          style={{ borderColor: '#D1D5DB' }} />
      </div>

      {/* ACLs Section */}
      {filteredAcls.length > 0 && (
        <div className="border-b" style={{ borderColor: '#E5E7EB' }}>
          <div className="px-3 py-1.5" style={{ background: '#F1F5F9' }}>
            <span className="text-xs font-bold text-gray-700 uppercase tracking-wider">
              Access Control Lists ({filteredAcls.length})
            </span>
          </div>
          {filteredAcls.map(acl => {
            const isExpanded = expandedAcl === acl.name
            return (
              <div key={acl.name} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                <div onClick={() => setExpandedAcl(isExpanded ? null : acl.name)}
                  className="px-3 py-1.5 flex items-center justify-between cursor-pointer hover:bg-blue-50">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs">{isExpanded ? '▼' : '▶'}</span>
                    <span className="text-xs font-semibold text-gray-800">{acl.name}</span>
                    <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                      style={{ background: '#EFF6FF', color: '#2563EB', fontSize: 10 }}>{acl.type}</span>
                    {(acl.applied_to || []).map((b, bi) => (
                      <span key={bi} className="px-1.5 py-0.5 rounded font-medium" style={{
                        fontSize: 9,
                        background: b.direction === 'inbound' ? '#ECFDF5' : '#EFF6FF',
                        color: b.direction === 'inbound' ? '#065F46' : '#1E40AF',
                        border: `1px solid ${b.direction === 'inbound' ? '#A7F3D0' : '#BFDBFE'}`,
                      }}>
                        {b.interface} {b.direction === 'inbound' ? '(in)' : '(out)'}
                        {b.vrf && <span style={{ opacity: 0.7 }}> vrf {b.vrf}</span>}
                      </span>
                    ))}
                    {(acl.applied_to || []).length === 0 && (
                      <span className="px-1.5 py-0.5 rounded font-medium" style={{
                        fontSize: 9, background: '#FEF3C7', color: '#92400E'
                      }}>not applied</span>
                    )}
                  </div>
                  <span className="text-xs text-gray-400 shrink-0 ml-2">{acl.ace_count} ACEs</span>
                </div>
                {isExpanded && (
                  <div className="px-3 pb-2">
                    <table className="w-full text-xs" style={{ borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: '#F8FAFC', color: '#64748B', fontSize: 10 }}>
                          <th className="px-1 py-1 text-left">Seq</th>
                          <th className="px-1 py-1 text-left">Action</th>
                          <th className="px-1 py-1 text-left">Source</th>
                          <th className="px-1 py-1 text-left">Destination</th>
                          <th className="px-1 py-1 text-left">Proto</th>
                          <th className="px-1 py-1 text-left">Ports</th>
                          <th className="px-1 py-1 text-left">Log</th>
                        </tr>
                      </thead>
                      <tbody>
                        {acl.aces.map((ace, i) => (
                          <tr key={i} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                            <td className="px-1 py-1 font-mono text-gray-400">{ace.seq}</td>
                            <td className="px-1 py-1">{actionBadge(ace.action)}</td>
                            <td className="px-1 py-1 font-mono truncate" style={{ maxWidth: 120 }}>{ace.source}</td>
                            <td className="px-1 py-1 font-mono truncate" style={{ maxWidth: 120 }}>{ace.destination}</td>
                            <td className="px-1 py-1 text-gray-600">{ace.protocol || '—'}</td>
                            <td className="px-1 py-1 font-mono text-gray-600">{ace.l4_ports || '—'}</td>
                            <td className="px-1 py-1">{ace.log ? '✓' : ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Route Maps / Route Policies Section */}
      {filteredRm.length > 0 && (
        <div className="border-b" style={{ borderColor: '#E5E7EB' }}>
          <div className="px-3 py-1.5" style={{ background: '#F1F5F9' }}>
            <span className="text-xs font-bold text-gray-700 uppercase tracking-wider">
              {filteredRm.some(r => r.body) ? 'Route Policies' : 'Route Maps'} ({filteredRm.length})
            </span>
          </div>
          {filteredRm.map(rm => {
            const isExpanded = expandedRm === rm.name
            return (
              <div key={rm.name} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                <div onClick={() => setExpandedRm(isExpanded ? null : rm.name)}
                  className="px-3 py-1.5 flex items-center justify-between cursor-pointer hover:bg-blue-50">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs">{isExpanded ? '▼' : '▶'}</span>
                    <span className="text-xs font-semibold text-gray-800">{rm.name}</span>
                    {(rm.applied_to || []).map((b, bi) => (
                      <Fragment key={bi}>
                        <span className="px-1.5 py-0.5 rounded font-medium" style={{
                          fontSize: 9,
                          background: b.direction === 'inbound' ? '#ECFDF5' : '#EFF6FF',
                          color: b.direction === 'inbound' ? '#065F46' : '#1E40AF',
                          border: `1px solid ${b.direction === 'inbound' ? '#A7F3D0' : '#BFDBFE'}`,
                        }}>
                          {b.context} {b.direction === 'inbound' ? '(in)' : '(out)'}
                        </span>
                        {b.vrf && (
                          <span className="px-1.5 py-0.5 rounded font-medium" style={{
                            fontSize: 9, background: '#F1F5F9', color: '#475569', border: '1px solid #CBD5E1'
                          }}>vrf {b.vrf}</span>
                        )}
                      </Fragment>
                    ))}
                    {(rm.applied_to || []).length === 0 && (
                      <span className="px-1.5 py-0.5 rounded font-medium" style={{
                        fontSize: 9, background: '#FEF3C7', color: '#92400E'
                      }}>not referenced</span>
                    )}
                  </div>
                  <span className="text-xs text-gray-400 shrink-0 ml-2">
                    {rm.sequences ? `${rm.sequences.length} seq` : `${(rm.body || []).length} lines`}
                  </span>
                </div>
                {isExpanded && rm.sequences && (
                  <div className="px-3 pb-2">
                    <table className="w-full text-xs" style={{ borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: '#F8FAFC', color: '#64748B', fontSize: 10 }}>
                          <th className="px-1 py-1 text-left">Seq</th>
                          <th className="px-1 py-1 text-left">Action</th>
                          <th className="px-1 py-1 text-left">Match</th>
                          <th className="px-1 py-1 text-left">Set</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rm.sequences.map((s, i) => (
                          <tr key={i} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                            <td className="px-1 py-1 font-mono text-gray-400">{s.seq}</td>
                            <td className="px-1 py-1">{actionBadge(s.action)}</td>
                            <td className="px-1 py-1 font-mono text-gray-700">{s.match?.join(', ') || '—'}</td>
                            <td className="px-1 py-1 font-mono text-gray-700">{s.set?.join(', ') || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {isExpanded && rm.body && (
                  <div className="px-3 pb-2">
                    <pre className="text-xs font-mono bg-gray-50 rounded p-2 overflow-x-auto" style={{
                      color: '#334155', lineHeight: '1.5', whiteSpace: 'pre-wrap'
                    }}>
                      {rm.body.join('\n')}
                    </pre>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Prefix Lists / Prefix Sets Section */}
      {filteredPl.length > 0 && (
        <div className="border-b" style={{ borderColor: '#E5E7EB' }}>
          <div className="px-3 py-1.5" style={{ background: '#F1F5F9' }}>
            <span className="text-xs font-bold text-gray-700 uppercase tracking-wider">
              {filteredRm.some(r => r.body) ? 'Prefix Sets' : 'Prefix Lists'} ({filteredPl.length})
            </span>
          </div>
          {filteredPl.map(pl => {
            const isExpanded = expandedPl === pl.name
            return (
              <div key={pl.name} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                <div onClick={() => setExpandedPl(isExpanded ? null : pl.name)}
                  className="px-3 py-1.5 flex items-center justify-between cursor-pointer hover:bg-blue-50">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs">{isExpanded ? '▼' : '▶'}</span>
                    <span className="text-xs font-semibold text-gray-800">{pl.name}</span>
                    {(pl.referenced_by || []).map((rm, ri) => (
                      <span key={ri} className="px-1.5 py-0.5 rounded font-medium" style={{
                        fontSize: 9, background: '#F3E8FF', color: '#6B21A8', border: '1px solid #DDD6FE'
                      }}>
                        used by {rm}
                      </span>
                    ))}
                    {(pl.referenced_by || []).length === 0 && (
                      <span className="px-1.5 py-0.5 rounded font-medium" style={{
                        fontSize: 9, background: '#FEF3C7', color: '#92400E'
                      }}>not referenced</span>
                    )}
                  </div>
                  <span className="text-xs text-gray-400 shrink-0 ml-2">{pl.entries.length} entries</span>
                </div>
                {isExpanded && (
                  <div className="px-3 pb-2">
                    <table className="w-full text-xs" style={{ borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: '#F8FAFC', color: '#64748B', fontSize: 10 }}>
                          <th className="px-1 py-1 text-left">Seq</th>
                          <th className="px-1 py-1 text-left">Action</th>
                          <th className="px-1 py-1 text-left">Prefix</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pl.entries.map((e, i) => (
                          <tr key={i} className="border-b" style={{ borderColor: '#F3F4F6' }}>
                            <td className="px-1 py-1 font-mono text-gray-400">{e.seq}</td>
                            <td className="px-1 py-1">{actionBadge(e.action)}</td>
                            <td className="px-1 py-1 font-mono text-gray-700">{e.prefix}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// =============================================================================
// Tabbed Device Info (S19A-4)
// =============================================================================
const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'interfaces', label: 'Interfaces' },
  { id: 'vlans', label: 'VLANs' },
  { id: 'findings', label: 'Audit' },
  { id: 'routing', label: 'Routing' },
  { id: 'ospf', label: 'OSPF' },
  { id: 'bgp', label: 'BGP' },
  { id: 'policies', label: 'Policies' },
  { id: 'security', label: 'Security' },
]

function DeviceInfo({ deviceData, onClose, selectedMemberId, selectedRun }) {
  const [activeTab, setActiveTab] = useState('overview')
  const device = deviceData.device || {}
  const isCollected = device.collected !== false
  const isFortiGate = (device.os_type || '').toLowerCase() === 'fortios'

  // Parse hostname for routing tab
  const hostname = device.hostname || ''

  // Hide VLANs tab for FortiGate (merged into Interfaces) and IOS XR (no VLANs)
  const hideVlans = isFortiGate || (device.os_type || '').toLowerCase() === 'iosxr'
  // Show OSPF tab only when device has ospf_areas metadata
  const hasOspf = (device.ospf_areas && device.ospf_areas.length > 0) || false
  // Show BGP tab only when device has bgp_as metadata
  const hasBgp = !!device.bgp_as
  const tabs = TABS.filter(t => {
    if (t.id === 'vlans' && hideVlans) return false
    if (t.id === 'ospf' && !hasOspf) return false
    if (t.id === 'bgp' && !hasBgp) return false
    if (t.id === 'policies' && !isFortiGate) return false
    if (t.id === 'security' && isFortiGate) return false
    return true
  })

  return (
    <div className="flex flex-col h-full">
      {/* Header (always visible above tabs) */}
      <div className="p-3 border-b shrink-0" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <h2 style={{ fontSize: 15, fontWeight: 800, color: '#0F4F3A' }} className="truncate">
              {device.hostname}
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {device.role && <span>{formatRole(device.role)}</span>}
              {device.os_type && <span> &bull; {device.os_type}</span>}
            </p>
            {selectedMemberId !== null && selectedMemberId !== undefined && (
              <p className="text-xs font-medium mt-1 px-1.5 py-0.5 rounded inline-block"
                style={{ background: '#EFF6FF', color: '#2563EB' }}>
                Member {selectedMemberId}
              </p>
            )}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none ml-2 shrink-0">&times;</button>
        </div>
      </div>

      {/* Tab bar */}
      {isCollected && (
        <div className="flex border-b shrink-0" style={{ borderColor: '#E5E7EB' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="px-3 py-1.5 text-xs font-semibold transition-colors"
              style={activeTab === tab.id
                ? { color: '#2563EB', borderBottom: '2px solid #2563EB' }
                : { color: '#94A3B8', borderBottom: '2px solid transparent' }
              }
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {!isCollected ? (
          <div className="p-4 text-sm text-gray-500">
            <p className="font-medium text-gray-600">Uncollected device</p>
            <p className="text-xs text-gray-400 mt-1">Discovered as a neighbor but not directly collected.</p>
          </div>
        ) : activeTab === 'overview' ? (
          <OverviewTab deviceData={deviceData} selectedMemberId={selectedMemberId} />
        ) : activeTab === 'interfaces' ? (
          isFortiGate
            ? <FortiGateInterfacesTab hostname={hostname} selectedRun={selectedRun} />
            : <InterfacesTab deviceData={deviceData} />
        ) : activeTab === 'vlans' ? (
          <VlansTab hostname={hostname} selectedRun={selectedRun} />
        ) : activeTab === 'findings' ? (
          <FindingsTab deviceData={deviceData} selectedMemberId={selectedMemberId} />
        ) : activeTab === 'routing' ? (
          <RoutingTab hostname={hostname} selectedRun={selectedRun} />
        ) : activeTab === 'ospf' ? (
          <OspfTab hostname={hostname} selectedRun={selectedRun} />
        ) : activeTab === 'bgp' ? (
          <BgpTab hostname={hostname} selectedRun={selectedRun} />
        ) : activeTab === 'policies' ? (
          <FirewallPoliciesTab hostname={hostname} selectedRun={selectedRun} />
        ) : activeTab === 'security' ? (
          <SecurityPoliciesTab hostname={hostname} selectedRun={selectedRun} />
        ) : null}
      </div>
    </div>
  )
}

// =============================================================================
// Export: DeviceDetail — switches between NetworkSummary, LinkDetail, DeviceInfo
// =============================================================================
export default function DeviceDetail({
  deviceData,
  topologyData,
  networkSummary,
  findingsData,
  selectedDevice,
  selectedLink,
  selectedMemberId,
  selectedRun,
  onClose,
  onDeviceSelect,
}) {
  const { sevColors, severityOrder } = useLegend()
  // Link detail takes priority when an edge is selected
  if (selectedLink) {
    return <LinkDetail linkData={selectedLink} findingsData={findingsData} selectedRun={selectedRun} onClose={onClose} />
  }

  // External peer node click → minimal detail from adjacency data (S19C-10)
  if (selectedDevice && topologyData) {
    const extNode = (topologyData.nodes || []).find(
      n => n.data.id === selectedDevice && n.data.device_type === 'external'
    )
    if (extNode) {
      const nd = extNode.data
      // Find BGP adjacency(ies) involving this external peer
      const peerAdjs = (topologyData.adjacencies || []).filter(
        a => a.data.protocol === 'bgp' && (a.data.source === nd.id || a.data.target === nd.id)
      )
      const firstAdj = peerAdjs[0]?.data || {}
      // Determine which side is the external peer
      const isA = firstAdj.source === nd.id
      const prefix = isA ? 'a' : 'b'
      const collectedSide = isA ? 'b' : 'a'
      return (
        <div className="flex flex-col h-full">
          <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
            <div className="flex items-start justify-between">
              <div className="min-w-0">
                <h2 style={{ fontSize: 14, fontWeight: 800, color: '#0F4F3A' }} className="truncate">
                  {nd.peer_label || nd.id}
                </h2>
                <p className="text-xs text-gray-500 mt-0.5">External BGP Peer</p>
              </div>
              <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none ml-2 shrink-0">&times;</button>
            </div>
            <div className="flex items-center gap-2 mt-1.5">
              <span className="text-xs font-bold px-1.5 py-0.5 rounded" style={{ color: '#7C3AED', background: '#EDE9FE' }}>
                eBGP
              </span>
              {nd.remote_as && <span className="text-xs text-gray-500">AS {nd.remote_as}</span>}
            </div>
          </div>
          <div className="flex-1 overflow-y-auto min-h-0 p-3 space-y-3">
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Peer Information</p>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                <span className="text-gray-400">IP Address</span>
                <span className="font-mono">{nd.id}</span>
                {nd.remote_as && (<><span className="text-gray-400">AS Number</span><span>{nd.remote_as}</span></>)}
                {firstAdj[`description_${prefix}`] && (
                  <><span className="text-gray-400">Description</span><span>{firstAdj[`description_${prefix}`]}</span></>
                )}
                <span className="text-gray-400">Session State</span>
                <span className="font-bold" style={{ color: (firstAdj.state || '').toLowerCase() === 'established' ? '#059669' : '#DC2626' }}>
                  {(firstAdj.state || 'unknown').toUpperCase()}
                </span>
                {firstAdj[`prefixes_received_${collectedSide}`] != null && (
                  <><span className="text-gray-400">Prefixes Received (our side)</span>
                  <span>{firstAdj[`prefixes_received_${collectedSide}`].toLocaleString()}</span></>
                )}
                {firstAdj[`up_down_${collectedSide}`] && (
                  <><span className="text-gray-400">Uptime</span><span>{firstAdj[`up_down_${collectedSide}`]}</span></>
                )}
              </div>
            </div>
            {peerAdjs.length > 1 && (
              <div className="text-xs text-gray-400">
                {peerAdjs.length} BGP sessions with this peer
              </div>
            )}
          </div>
        </div>
      )
    }
  }

  // Device detail when a device is selected
  if (selectedDevice && deviceData) {
    return <DeviceInfo deviceData={deviceData} onClose={onClose} selectedMemberId={selectedMemberId} selectedRun={selectedRun} />
  }

  // Default: Network Summary
  return (
    <NetworkSummary
      topologyData={topologyData}
      networkSummary={networkSummary}
      findingsData={findingsData}
      onDeviceSelect={onDeviceSelect}
    />
  )
}
