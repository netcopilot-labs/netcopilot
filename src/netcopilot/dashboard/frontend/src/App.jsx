import { useState, useEffect, useCallback, useRef, Component, useMemo } from 'react'
import RunSelector from './components/RunSelector.jsx'
import DropdownPicker from './components/DropdownPicker.jsx'
import TopologyMap from './components/TopologyMap.jsx'
import DeviceDetail from './components/DeviceDetail.jsx'
import FindingsPage from './components/FindingsPage.jsx'
import DriftPanel from './components/DriftPanel.jsx'
import { extractDevices } from './components/FindingsPanel.jsx'
import ReportPanel from './components/ReportPanel.jsx'
import AgentChatPanel from './components/AgentChatPanel.jsx'
import { AgentProvider, useAgent } from './AgentContext.jsx'
import { TOPOLOGY_VIEWS } from './topologyUtils.js'
import { LegendProvider, useLegend } from './contexts/LegendContext.jsx'

// =============================================================================
// Per-tab Level-2 toolbar predicates (2026-05-18)
// =============================================================================
// `leftPanelMode` drives both the LEFT-panel content AND the Level-2 toolbar
// contents. Three tab modes — Topology / Audit (findings) / Report — each gets
// its own Level-2 controls. The 5 topology view buttons + device selector are
// SCOPED to Topology only; severity chips + device filter scoped to Audit;
// Send Email + Download PDF scoped to Report. Same shape as TopologyMap's
// COLLAPSED_VIEWS / EXPANDED_VIEWS predicate pattern.
const TOPOLOGY_MODES = new Set(['summary', 'device', 'link'])

// Tabs that force the center map to render the Physical view regardless of
// the user's last-chosen `selectedView`. The state is preserved — switching
// back to Topology restores the previous selection. Carlos's mental model:
// when auditing findings or reading a report, the Physical map is the
// representative reference; protocol overlays only matter on Topology.
const FORCE_PHYSICAL_MODES = new Set(['findings', 'report'])

// S01-5 — short label for a run in the "Compare to" drift dropdown.
function formatRunShort(run) {
  const date = run.timestamp
    ? new Date(run.timestamp).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
      })
    : run.run_id
  return `${date} — ${run.total_findings || 0} findings`
}

// Error boundary to catch React crashes and display them instead of blank page
class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }
  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo })
    console.error('React Error Boundary caught:', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, fontFamily: 'monospace', background: '#FEF2F2', minHeight: '100vh' }}>
          <h1 style={{ color: '#DC2626', fontSize: 20, marginBottom: 12 }}>Dashboard Error</h1>
          <pre style={{ background: '#FFF', border: '1px solid #FCA5A5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
            {this.state.error?.toString()}
            {'\n\n'}
            {this.state.errorInfo?.componentStack}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{ marginTop: 16, padding: '8px 16px', background: '#1D9E75', color: '#FFF', border: 'none', borderRadius: 6, cursor: 'pointer' }}
          >
            Reload Page
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// Bridge: Run Now button → pipeline progress SSE in agent chat
function PipelineProgressBridge({ runInProgress }) {
  const { startProgressStream, stopProgressStream } = useAgent()
  const prevRunning = useRef(false)

  useEffect(() => {
    // Start SSE when runInProgress transitions from false → true
    if (runInProgress && !prevRunning.current) {
      startProgressStream()
    }
    prevRunning.current = runInProgress
  }, [runInProgress, startProgressStream, stopProgressStream])

  return null
}

// Bridge: agent highlight events → topology map device selection (map only, no panel switch)
function AgentHighlightBridge({ onMapHighlight }) {
  const { highlightDevice, failedMember, highlightSeq } = useAgent()
  useEffect(() => {
    if (highlightSeq === 0) return
    if (!highlightDevice) {
      onMapHighlight(null)
      return
    }
    if (Array.isArray(highlightDevice)) {
      onMapHighlight(highlightDevice)
    } else if (failedMember != null) {
      onMapHighlight(`${highlightDevice}:${failedMember}`)
    } else {
      onMapHighlight(highlightDevice)
    }
  }, [highlightSeq, onMapHighlight])
  return null
}

// C1A2: Bridge — when the chat generates a report, surface it in the LEFT panel.
function ChatReportBridge({ onShowReport }) {
  const { chatReport } = useAgent()
  const lastSeen = useRef(null)
  useEffect(() => {
    if (chatReport?.reportId && chatReport.reportId !== lastSeen.current) {
      lastSeen.current = chatReport.reportId
      onShowReport()
    }
  }, [chatReport, onShowReport])
  return null
}

// ── Drag handle for resizable panels (S19A-1) ──
function DragHandle({ side, onDrag, raw }) {
  const handleMouseDown = useCallback((e) => {
    e.preventDefault()
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'

    const onMouseMove = (moveEvent) => {
      if (raw) {
        onDrag(moveEvent.clientX)
      } else {
        const pct = (moveEvent.clientX / window.innerWidth) * 100
        onDrag(pct)
      }
    }
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.userSelect = ''
      document.body.style.cursor = ''
    }
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [onDrag])

  return (
    <div
      onMouseDown={handleMouseDown}
      style={{
        width: 5,
        cursor: 'col-resize',
        background: 'transparent',
        zIndex: 10,
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      title={`Drag to resize ${side} panel`}
    >
      <div style={{ width: 3, height: 32, borderRadius: 2, background: '#CBD5E1' }} />
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
    <LegendProvider>
      <AppContent />
    </LegendProvider>
    </ErrorBoundary>
  )
}

function AppContent() {
  const { severityOrder, sevColors } = useLegend()
  const [selectedRun, setSelectedRun] = useState(null)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [selectedView, setSelectedView] = useState('physical')
  const [topologyData, setTopologyData] = useState(null)
  const [networkSummary, setNetworkSummary] = useState(null)
  const [findingsData, setFindingsData] = useState(null)
  const [deviceData, setDeviceData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  // C1S3: Left panel mode — replaces activePage (no more page navigation)
  // 'summary' = Network Summary, 'findings' = FindingsPage, 'device' / 'link' set by clicks
  const [leftPanelMode, setLeftPanelMode] = useState('summary')

  // 2026-05-18 — Audit-tab filter state hoisted out of FindingsPage so the
  // severity chips + device dropdown + lab-expected toggle can live in the
  // tab-aware Level-2 bar. FindingsPage receives them as props. `hideLabExpected`
  // moved up too so the Level-2 chip counts stay consistent with the list
  // (otherwise "Critical (12)" in Level-2 could mismatch a list filtered to 9).
  const [findingsSeverityFilter, setFindingsSeverityFilter] = useState('all')
  const [findingsDeviceFilter, setFindingsDeviceFilter] = useState('')
  const [hideLabExpected, setHideLabExpected] = useState(false)

  // 2026-05-18 — Report-tab action handlers exposed via ref. ReportPanel
  // populates `.current = { sendEmail, downloadPdf }` on every render; the
  // Level-2 bar's buttons call `.current.sendEmail?.()` etc. Keeps
  // ReportPanel's local state (email popover, recipient list, etc.)
  // encapsulated without bubbling it all the way up.
  const reportActionsRef = useRef({ sendEmail: null, downloadPdf: null })

  // S19A-1: Resizable detail panel (percentage of viewport width)
  const [rightPanelPct, setRightPanelPct] = useState(28)

  // C1S2: Agent panel width in pixels (persisted to localStorage)
  // C1A1: Default bumped 320 → 352 (+10%) for better readability.
  // localStorage migration: if a user had the old default (exactly 320),
  // auto-reset to 352. Custom widths preserved.
  const [agentPanelWidth, setAgentPanelWidth] = useState(() => {
    const saved = localStorage.getItem('netcopilot_agent_panel_width')
    if (saved) {
      const parsed = parseInt(saved, 10)
      if (parsed === 320) return 352  // migration from old default
      return parsed
    }
    return 352
  })

  // S19A-3: Severity filters (all active by default)
  const [severityFilters, setSeverityFilters] = useState(
    () => new Set(severityOrder)
  )
  // S19A-8: Selected link (mutual exclusion with selectedDevice)
  const [selectedLink, setSelectedLink] = useState(null)

  // S01-5: run-to-run drift ("Diff" mode within the Audit tab). diffMode toggles
  // the left panel from FindingsPage to DriftPanel; diffAgainst = the comparison
  // ("before") run (null = previous same-site run, auto); diffFocus scopes the
  // list + focuses the topology on a clicked element.
  const [diffMode, setDiffMode] = useState(false)
  const [diffAgainst, setDiffAgainst] = useState(null)
  const [diffData, setDiffData] = useState(null)
  const [diffLoading, setDiffLoading] = useState(false)
  const [diffError, setDiffError] = useState(null)
  const [diffFocus, setDiffFocus] = useState(null)
  const [allRuns, setAllRuns] = useState([])

  // S19B-3: VLAN data and selection for L2/L3 view
  const [selectedVlan, setSelectedVlan] = useState(null)
  const [vlanData, setVlanData] = useState(null)

  // ADR-217: OSPF VRF selector
  const [ospfVrf, setOspfVrf] = useState(null)

  // Layout positions saved to Neo4j via "Pin Layout" — separate for collapsed/expanded
  const [collapsedPositions, setCollapsedPositions] = useState({})
  const [expandedPositions, setExpandedPositions] = useState({})

  // S20-B8: Run trigger state
  const [runInProgress, setRunInProgress] = useState(false)
  const runPollRef = useRef(null)
  // Bumped when a run completes, to force a data reload even if the run_id is
  // unchanged (e.g. re-running the same demo) — otherwise the view stays stale.
  const [refreshSeq, setRefreshSeq] = useState(0)

  // Inventory picker for Run Now: the bundled demo (offline replay) + any
  // inventories the operator dropped in ./inventory.
  const [inventories, setInventories] = useState([])
  const [selectedInventory, setSelectedInventory] = useState('')

  const refreshInventories = useCallback(() => {
    return fetch('/api/inventories')
      .then((r) => r.json())
      .then((d) => {
        const invs = d.inventories || []
        setInventories(invs)
        setSelectedInventory((cur) => (invs.some((i) => i.id === cur) ? cur : (invs[0]?.id || '')))
        return invs
      })
      .catch(() => setInventories([{ id: 'campus', label: 'Demo — campus', kind: 'demo' }]))
  }, [])

  useEffect(() => { refreshInventories() }, [refreshInventories])

  const deleteInventory = useCallback(async (item) => {
    try {
      await fetch(`/api/inventories/${encodeURIComponent(item.id)}`, { method: 'DELETE' })
    } catch { /* surfaced via refresh */ }
    refreshInventories()
  }, [refreshInventories])

  // ── Data loading ──

  useEffect(() => {
    if (!selectedRun) return
    // Pre-warm vLLM prefix cache as soon as a run is selected — well before the
    // user opens AI Triage, so the KV cache is hot by the time the first chat
    // message arrives.
    fetch(`/api/chat/warmup/${encodeURIComponent(selectedRun)}`).catch(() => {})
    setSelectedDevice(null)
    setSelectedLink(null)
    setDeviceData(null)
    setSelectedVlan(null)
    setVlanData(null)
    setCollapsedPositions({})
    setExpandedPositions({})
    loadRunData(selectedRun, selectedView)
    if (selectedView === 'l2vlan') {
      loadVlanData(selectedRun)
    }
  }, [selectedRun, refreshSeq])

  useEffect(() => {
    if (!selectedRun) return
    setSelectedDevice(null)
    setSelectedLink(null)
    setDeviceData(null)
    setSelectedVlan(null)
    loadTopology(selectedRun, selectedView)
    // Fetch VLAN data when switching to L2/L3 view
    if (selectedView === 'l2vlan') {
      loadVlanData(selectedRun)
    }
  }, [selectedView])

  useEffect(() => {
    if (!selectedDevice || !selectedRun) {
      setDeviceData(null)
      return
    }
    loadDeviceData(selectedRun, selectedDevice)
  }, [selectedDevice, selectedRun])

  async function loadTopology(runId, view) {
    setLoading(true)
    setError(null)
    try {
      const [topoRes, posColRes, posExpRes] = await Promise.all([
        fetch(`/api/topology?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view)}`),
        fetch(`/api/topology/positions?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view)}`),
        fetch(`/api/topology/positions?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view + '_expanded')}`),
      ])
      if (!topoRes.ok) throw new Error(`Topology: HTTP ${topoRes.status}`)
      const [topo, posCol, posExp] = await Promise.all([topoRes.json(), posColRes.json(), posExpRes.json()])
      setTopologyData(topo)
      setCollapsedPositions(posCol.positions || {})
      setExpandedPositions(posExp.positions || {})
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function loadRunData(runId, view) {
    setLoading(true)
    setError(null)
    try {
      const [topoRes, findRes, posColRes, posExpRes] = await Promise.all([
        fetch(`/api/topology?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view)}`),
        fetch(`/api/findings/${encodeURIComponent(runId)}`),
        fetch(`/api/topology/positions?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view)}`),
        fetch(`/api/topology/positions?run_id=${encodeURIComponent(runId)}&view=${encodeURIComponent(view + '_expanded')}`),
      ])
      if (!topoRes.ok) throw new Error(`Topology: HTTP ${topoRes.status}`)
      if (!findRes.ok) throw new Error(`Findings: HTTP ${findRes.status}`)
      const [topo, find, posCol, posExp] = await Promise.all([topoRes.json(), findRes.json(), posColRes.json(), posExpRes.json()])
      setTopologyData(topo)
      setFindingsData(find)
      setCollapsedPositions(posCol.positions || {})
      setExpandedPositions(posExp.positions || {})
      // Capture stable summary — always from physical view data
      let physTopo = topo
      if (view !== 'physical') {
        try {
          const physRes = await fetch(`/api/topology?run_id=${encodeURIComponent(runId)}&view=physical`)
          if (physRes.ok) physTopo = await physRes.json()
        } catch (_) { /* fall back to current view data */ }
      }
      const physEdges = physTopo.edges || []
      const counts = { fiber: 0, rj45: 0, svl: 0, stack: 0, ha: 0, down: 0 }
      physEdges.forEach(e => {
        const d = e.data || {}
        if (d.status === 'down') { counts.down++; return }
        if (d.linkType === 'stack_interconnect') {
          const st = d.stackSubtype || 'svl'
          if (st === 'ha') counts.ha++
          else if (st === 'cable') counts.stack++
          else counts.svl++  // svl + dad = StackWise Virtual
          return
        }
        const ct = d.cable_type || 'unknown'
        if (ct === 'fiber') counts.fiber++
        else if (ct === 'rj45') counts.rj45++
      })
      // Fetch mgmt OOB count from mgmt view
      let mgmtOob = 0
      try {
        const mgmtRes = await fetch(`/api/topology?run_id=${encodeURIComponent(runId)}&view=mgmt`)
        if (mgmtRes.ok) {
          const mgmtTopo = await mgmtRes.json()
          mgmtOob = (mgmtTopo.edges || []).filter(e => e.data?.mgmt_type === 'oob').length
        }
      } catch (_) { /* non-blocking */ }
      setNetworkSummary({
        physicalDevices: physTopo.nodes?.filter(n => !n.data.isCompound && n.data.collected !== false).length || 0,
        clusters: physTopo.nodes?.filter(n => n.data.isCompound).length || 0,
        externalPeers: physTopo.external_peers?.length || 0,
        unreachable: physTopo.unreachable_devices?.length || 0,
        mgmtOob,
        ...counts,
      })
      // If current view is a protocol tab not available in this run, fall back
      const protos = topo.available_protocols || []
      if ((view === 'ospf' || view === 'bgp') && !protos.includes(view)) {
        setSelectedView('physical')
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function loadDeviceData(runId, deviceSpec) {
    const colonIdx = deviceSpec.indexOf(':')
    const hostname = colonIdx > 0 ? deviceSpec.substring(0, colonIdx) : deviceSpec
    try {
      const res = await fetch(
        `/api/device/${encodeURIComponent(hostname)}?run_id=${encodeURIComponent(runId)}`
      )
      if (!res.ok) throw new Error(`Device: HTTP ${res.status}`)
      const data = await res.json()
      setDeviceData(data)
    } catch (err) {
      console.error('Failed to load device:', err)
    }
  }

  async function loadVlanData(runId) {
    try {
      const res = await fetch(`/api/runs/${encodeURIComponent(runId)}/vlans`)
      if (res.ok) {
        setVlanData(await res.json())
      }
    } catch (err) {
      console.error('Failed to load VLAN data:', err)
    }
  }

  // ── Callbacks ──

  const handleDeviceSelect = useCallback((hostname) => {
    setSelectedDevice(hostname)
    setSelectedLink(null)
    if (hostname) setLeftPanelMode('device')
  }, [])

  // Map-only highlight — selects device on map without switching left panel
  const [highlightPath, setHighlightPath] = useState(null)

  const handleMapHighlight = useCallback((target) => {
    if (Array.isArray(target)) {
      setHighlightPath(target)
      setSelectedDevice(null)
      setSelectedLink(null)
    } else if (target) {
      setHighlightPath(null)
      setSelectedDevice(target)
      setSelectedLink(null)
      // 2026-05-18: agent-driven focus (e.g. get_device_detail tool fired by
      // the chat agent) snaps the topology to Physical view so the device
      // renders in the expanded, representative compound state. Per Carlos:
      // "get_device_detail tool → Physical expanded always." Without this,
      // the agent's focus would land on whatever protocol view the user was
      // on (OSPF/BGP/L2L3), where compounds are force-collapsed and the
      // selection effect's per-view dim-and-center is harder to read.
      setSelectedView('physical')
    } else {
      // Clear all highlights
      setHighlightPath(null)
      setSelectedDevice(null)
      setSelectedLink(null)
    }
  }, [])

  const handleLinkSelect = useCallback((linkData) => {
    setSelectedLink(linkData)
    setSelectedDevice(null)
    setDeviceData(null)
    if (linkData) setLeftPanelMode('link')
  }, [])

  const handleFindingClick = useCallback((deviceNames, opts = {}) => {
    // 2026-05-18: when called from within the Audit tab (opts.stayInFindings),
    // set `selectedDevice` only — keep FindingsPage visible in the LEFT panel
    // and let the center TopologyMap focus on the device. The earlier
    // behaviour (switching to DeviceDetail) is preserved for callers outside
    // the Audit tab (currently none, but kept for future call sites).
    if (deviceNames && deviceNames.length > 0) {
      setSelectedDevice(deviceNames[0])
      setSelectedLink(null)
      if (!opts.stayInFindings) {
        setLeftPanelMode('device')
      }
    }
  }, [])

  const handleViewChange = useCallback((view) => {
    setSelectedView(view)
  }, [])

  const toggleSeverityFilter = useCallback((severity) => {
    setSeverityFilters(prev => {
      const next = new Set(prev)
      if (next.has(severity)) next.delete(severity)
      else next.add(severity)
      return next
    })
  }, [])

  // S19A-1: Drag handler for left panel resize
  const handleRightDrag = useCallback((cursorPct) => {
    const pct = Math.max(15, Math.min(50, cursorPct - 0.5))
    setRightPanelPct(pct)
  }, [])

  // C1S2: Drag handler for agent panel resize (pixel-based, right edge)
  const handleAgentDrag = useCallback((cursorX) => {
    const width = Math.max(240, Math.min(420, window.innerWidth - cursorX))
    setAgentPanelWidth(width)
    localStorage.setItem('netcopilot_agent_panel_width', String(width))
  }, [])

  // ADR-174: Re-fetch findings (after acknowledge/unacknowledge)
  const refreshFindings = useCallback(async () => {
    if (!selectedRun) return
    try {
      const res = await fetch(`/api/findings/${encodeURIComponent(selectedRun)}`)
      if (res.ok) setFindingsData(await res.json())
    } catch { /* ignore */ }
  }, [selectedRun])

  // ADR-217: Extract OSPF VRFs from adjacencies and auto-select first
  const ospfVrfs = useMemo(() => {
    if (!topologyData?.adjacencies) return []
    const vrfSet = new Set()
    topologyData.adjacencies.forEach(a => {
      if (a.data.protocol === 'ospf' && a.data.vrf) vrfSet.add(a.data.vrf)
    })
    return [...vrfSet].sort()
  }, [topologyData])

  useEffect(() => {
    if (selectedView === 'ospf' && ospfVrfs.length > 0 && !ospfVrf) {
      setOspfVrf(ospfVrfs[0])
    }
    if (selectedView !== 'ospf') {
      setOspfVrf(null)
    }
  }, [selectedView, ospfVrfs])

  // S20-B8: Trigger a new run and poll for completion
  const handleRunNow = useCallback(async () => {
    if (runInProgress) return
    try {
      const res = await fetch('/api/runs/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inventory_id: selectedInventory }),
      })
      const body = await res.json()
      if (body.status === 'requested' || body.status === 'already_pending') {
        setRunInProgress(true)
        // Poll /api/runs/status every 10s until new_run_available OR a 5-min
        // safety timeout. Do NOT exit on !run_in_progress: the watcher removes
        // FLAG_REQUESTED at pipeline start (~5s in), but FLAG_COMPLETE is not
        // written until ~60s later — exiting early would mean the dashboard
        // misses real completion and leaves FLAG_COMPLETE stale for the next
        // session (which is what fed the "Topology HTTP 404" race).
        const startedAt = Date.now()
        const TIMEOUT_MS = 5 * 60 * 1000
        runPollRef.current = setInterval(async () => {
          if (Date.now() - startedAt > TIMEOUT_MS) {
            clearInterval(runPollRef.current)
            setRunInProgress(false)
            return
          }
          try {
            const statusRes = await fetch('/api/runs/status')
            const status = await statusRes.json()
            if (status.new_run_available) {
              clearInterval(runPollRef.current)
              setRunInProgress(false)
              if (status.latest_run_id) setSelectedRun(status.latest_run_id)
              // Force a reload even if the run_id didn't change (re-run demo).
              setRefreshSeq((s) => s + 1)
            }
          } catch { /* ignore poll errors */ }
        }, 3000)
      }
    } catch (err) {
      console.error('Run trigger failed:', err)
    }
  }, [runInProgress, selectedInventory])

  // S19A-2: Device list for Level 2 dropdown
  const deviceList = useMemo(() => {
    if (!topologyData?.nodes) return []
    return topologyData.nodes
      .filter(n => !n.data.parent)
      .map(n => n.data.id)
      .sort()
  }, [topologyData])

  // 2026-05-18 — per-tab Level-2 toolbar gating.
  const isTopologyTab = TOPOLOGY_MODES.has(leftPanelMode)
  const isFindingsTab = leftPanelMode === 'findings'
  const isReportTab = leftPanelMode === 'report'

  // 2026-05-18 — Audit + Report force the topology view to Physical via real
  // state mutation (equivalent to clicking the Physical view button on
  // Topology). Mutation, not a derived effective-prop, so the cy build effect
  // fires reliably AND the state stays 'physical' after a tab roundtrip —
  // matches Carlos's mental model "clicking Audit/Report = clicking Physical".
  useEffect(() => {
    if (FORCE_PHYSICAL_MODES.has(leftPanelMode) && selectedView !== 'physical') {
      setSelectedView('physical')
    }
  }, [leftPanelMode, selectedView])

  // S01-5 — leaving the Audit tab exits diff mode and drops any focus, so the
  // drift view never lingers under Topology/Report.
  useEffect(() => {
    if (leftPanelMode !== 'findings') {
      setDiffMode(false)
      setDiffFocus(null)
    }
  }, [leftPanelMode])

  // S01-5 — fetch the run list for the "Compare to" dropdown when diff mode opens.
  useEffect(() => {
    if (!diffMode) return
    fetch('/api/runs')
      .then((r) => (r.ok ? r.json() : { runs: [] }))
      .then((d) => setAllRuns(d.runs || []))
      .catch(() => setAllRuns([]))
  }, [diffMode])

  // S01-5 — fetch the diff for the current run vs its comparison run whenever
  // diff mode is on and the run / comparison changes.
  useEffect(() => {
    if (!diffMode || !selectedRun) return
    let cancelled = false
    setDiffLoading(true)
    setDiffError(null)
    setDiffFocus(null)
    const qs = diffAgainst ? `?against=${encodeURIComponent(diffAgainst)}` : ''
    fetch(`/api/diff/${encodeURIComponent(selectedRun)}${qs}`)
      .then((r) =>
        r.ok ? r.json() : r.json().then((e) => Promise.reject(new Error(e.detail || `HTTP ${r.status}`)))
      )
      .then((d) => {
        if (!cancelled) setDiffData(d)
      })
      .catch((e) => {
        if (!cancelled) {
          setDiffError(e.message)
          setDiffData(null)
        }
      })
      .finally(() => {
        if (!cancelled) setDiffLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [diffMode, selectedRun, diffAgainst])

  // S01-5 — click a drift row: toggle the list filter to that element, and focus
  // the topology node for device-scoped changes (without switching the panel).
  const handleDriftElementClick = useCallback((change) => {
    setDiffFocus((prev) => (prev && prev.key === change.key ? null : {
      key: change.key,
      element_type: change.element_type,
      element_id: change.element_id,
    }))
    if (change.element_type === 'device' && change.element_id) {
      setSelectedDevice(change.element_id)
      setSelectedLink(null)
    }
  }, [])

  // 2026-05-18 — Audit-tab chip counts. Mirrors FindingsPage's internal
  // derivation (kept in sync there too) so the Level-2 chip badges match the
  // filtered list. Applied filters: hideLabExpected + deviceFilter.
  const findingsChipCounts = useMemo(() => {
    const all = (findingsData?.findings) || []
    let pool = all
    if (hideLabExpected) pool = pool.filter(f => !(f.tags && f.tags.includes('lab_expected')))
    if (findingsDeviceFilter) pool = pool.filter(f => extractDevices(f).includes(findingsDeviceFilter))
    const unacked = pool.filter(f => !f.acknowledged)
    const acked = pool.filter(f => f.acknowledged)
    const bySev = {}
    unacked.forEach(f => {
      const s = f.severity || 'info'
      bySev[s] = (bySev[s] || 0) + 1
    })
    return {
      total: unacked.length,
      bySev,
      acked: acked.length,
      crossDevice: unacked.filter(f => f.is_cross_device).length,
      labExpectedAvailable: (findingsData?.summary?.lab_expected_count || 0) > 0,
    }
  }, [findingsData, hideLabExpected, findingsDeviceFilter])

  // S01-5 — "Compare to" dropdown options: same-site runs other than the current
  // one (newest first). The current run's site is looked up from the run list.
  const currentRunSite = allRuns.find((r) => r.run_id === selectedRun)?.site
  const compareRuns = allRuns
    .filter((r) => r.run_id !== selectedRun && (!currentRunSite || r.site === currentRunSite))
    .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))

  return (
    <AgentProvider selectedRun={selectedRun}>
    <PipelineProgressBridge runInProgress={runInProgress} />
    <AgentHighlightBridge onMapHighlight={handleMapHighlight} />
    <ChatReportBridge onShowReport={() => {
      setLeftPanelMode('report')
      setSelectedDevice(null)
      setSelectedLink(null)
    }} />
    <div className="h-screen flex flex-col" style={{ background: '#F1F5F9' }}>
      {/* ── Level 1: Header bar ── */}
      <header
        className="shrink-0 grid items-center px-4"
        style={{ background: '#FFFFFF', height: 48, borderBottom: '1px solid #E5E7EB', gridTemplateColumns: '1fr auto 1fr' }}
      >
        <div className="flex items-center gap-3">
          {/* Inline logo — network graph icon + wordmark */}
          <svg viewBox="55 8 390 94" width="192" height="43" style={{ display: 'block' }}>
            {/* N primary strokes */}
            <line x1="63" y1="24" x2="63" y2="76" stroke="#1D9E75" strokeWidth="2.2" strokeLinecap="round"/>
            <line x1="63" y1="24" x2="107" y2="76" stroke="#1D9E75" strokeWidth="2.2" strokeLinecap="round"/>
            <line x1="107" y1="24" x2="107" y2="76" stroke="#1D9E75" strokeWidth="2.2" strokeLinecap="round"/>
            {/* Arc connections */}
            <line x1="63" y1="24" x2="85" y2="14" stroke="#5DCAA5" strokeWidth="1.2" strokeLinecap="round" opacity="0.7"/>
            <line x1="107" y1="24" x2="85" y2="14" stroke="#5DCAA5" strokeWidth="1.2" strokeLinecap="round" opacity="0.7"/>
            <line x1="63" y1="76" x2="85" y2="86" stroke="#5DCAA5" strokeWidth="1.2" strokeLinecap="round" opacity="0.7"/>
            <line x1="107" y1="76" x2="85" y2="86" stroke="#5DCAA5" strokeWidth="1.2" strokeLinecap="round" opacity="0.7"/>
            {/* Primary N nodes */}
            <circle cx="63" cy="24" r="5.5" fill="#1D9E75"/>
            <circle cx="63" cy="76" r="5.5" fill="#1D9E75"/>
            <circle cx="107" cy="24" r="5.5" fill="#1D9E75"/>
            <circle cx="107" cy="76" r="5.5" fill="#1D9E75"/>
            {/* Diagonal midpoint */}
            <circle cx="85" cy="50" r="4" fill="#0F6E56"/>
            {/* Satellite nodes */}
            <circle cx="85" cy="14" r="3" fill="#5DCAA5"/>
            <circle cx="85" cy="86" r="3" fill="#5DCAA5"/>
            {/* Wordmark */}
            <text x="144" y="68" style={{ fontFamily: "'Helvetica Neue', Helvetica, Arial, sans-serif", fontWeight: 700, fontSize: 52, letterSpacing: '-1px', fill: '#1D9E75' }}>Net</text>
            <text x="225" y="68" style={{ fontFamily: "'Helvetica Neue', Helvetica, Arial, sans-serif", fontWeight: 300, fontSize: 52, letterSpacing: '-1px', fill: '#0F4F3A' }}>Copilot</text>
            {/* Divider */}
            <line x1="144" y1="80" x2="430" y2="80" stroke="#1D9E75" strokeWidth="0.75" opacity="0.4"/>
            {/* Tagline */}
            <text x="144" y="96" style={{ fontFamily: "'Helvetica Neue', Helvetica, Arial, sans-serif", fontWeight: 400, fontSize: 11, letterSpacing: '0.18em', fill: '#5DCAA5' }}>NETWORK CONTEXT INTELLIGENCE</text>
          </svg>
        </div>

        <nav className="flex items-center gap-1 justify-self-center">
          {/* C1A2: Topology / Audit / Report — all switch left panel mode.
              "Findings" was renamed to "Audit" in the top-bar label only;
              the internal mode name remains 'findings' to avoid churn. */}
          <button
            onClick={() => { setLeftPanelMode('summary'); setSelectedDevice(null); setSelectedLink(null) }}
            className="px-3 py-1.5 rounded text-sm font-medium transition-colors"
            style={
              leftPanelMode === 'summary' || leftPanelMode === 'device' || leftPanelMode === 'link'
                ? { background: '#1D9E75', color: '#FFFFFF' }
                : { background: 'transparent', color: '#64748B' }
            }
          >
            Topology
          </button>
          <button
            onClick={() => { setLeftPanelMode('findings'); setSelectedDevice(null); setSelectedLink(null) }}
            className="px-3 py-1.5 rounded text-sm font-medium transition-colors"
            style={
              leftPanelMode === 'findings'
                ? { background: '#1D9E75', color: '#FFFFFF' }
                : { background: 'transparent', color: '#64748B' }
            }
          >
            Audit
          </button>
          <button
            onClick={() => { setLeftPanelMode('report'); setSelectedDevice(null); setSelectedLink(null) }}
            className="px-3 py-1.5 rounded text-sm font-medium transition-colors"
            style={
              leftPanelMode === 'report'
                ? { background: '#1D9E75', color: '#FFFFFF' }
                : { background: 'transparent', color: '#64748B' }
            }
          >
            Report
          </button>
        </nav>

        <div className="flex items-center gap-2 justify-self-end">
          {/* Inventory picker — what Run Now collects (demo replay or a real inventory) */}
          <span className="text-xs text-gray-500 font-medium">Inventory:</span>
          <DropdownPicker
            items={inventories.map((inv) => ({ id: inv.id, label: inv.label, deletable: inv.kind === 'real' }))}
            selectedId={selectedInventory}
            onSelect={setSelectedInventory}
            onDelete={deleteInventory}
            disabled={runInProgress}
            placeholder="Select inventory…"
            deleteTitle={() => 'Delete inventory'}
            deleteMessage={(it) =>
              `Delete the inventory "${it.label}"? This removes the inventory file from ./inventory. Any data it loaded stays until you delete that run.`}
          />
          {/* S20-B8: Run Now button */}
          <button
            onClick={handleRunNow}
            disabled={runInProgress}
            className="px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5"
            style={
              runInProgress
                ? { background: '#334155', color: '#94A3B8', cursor: 'not-allowed' }
                : { background: '#1D9E75', color: '#FFFFFF' }
            }
            title={runInProgress ? 'Run in progress…' : 'Trigger a new pipeline run'}
          >
            {runInProgress ? (
              <>
                <span className="animate-spin" style={{ display: 'inline-block' }}>⟳</span>
                Running…
              </>
            ) : (
              '▶ Run Now'
            )}
          </button>
        </div>
      </header>

      {/* ── Level 2 (Topology tab): 5 view buttons + device selector ── */}
      {isTopologyTab && (
        <div
          className="shrink-0 flex items-center justify-between px-4"
          style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E8F0', height: 40 }}
        >
          <div className="flex items-center gap-1">
            {TOPOLOGY_VIEWS.map(view => {
              // Protocol views hidden when the run has no adjacencies for that protocol
              const protocols = topologyData?.available_protocols || []
              const isProtocolView = view.id === 'ospf' || view.id === 'bgp'
              const hasProtocol = !isProtocolView || protocols.includes(view.id)
              if (isProtocolView && !hasProtocol) return null
              const isActive = selectedView === view.id
              return (
                <button
                  key={view.id}
                  onClick={() => view.enabled && handleViewChange(view.id)}
                  disabled={!view.enabled}
                  className="px-3 py-1 rounded text-xs font-semibold transition-colors"
                  style={
                    isActive
                      ? { background: '#1D9E75', color: '#FFFFFF' }
                      : view.enabled
                        ? { background: 'transparent', color: '#64748B' }
                        : { background: 'transparent', color: '#94A3B8', opacity: 0.4, cursor: 'not-allowed' }
                  }
                  title={!view.enabled ? 'Coming soon' : undefined}
                >
                  {view.label}
                </button>
              )
            })}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 font-medium">Run:</span>
            <RunSelector selectedRun={selectedRun} onRunChange={setSelectedRun} refreshKey={refreshSeq} />
          </div>
        </div>
      )}

      {/* ── Level 2 (Audit tab): severity chips + device filter + lab-expected toggle ── */}
      {isFindingsTab && (
        <div
          className="shrink-0 flex items-center justify-between px-4 gap-2"
          style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E8F0', minHeight: 40 }}
        >
          <div className="flex items-center gap-1 flex-wrap">
          {/* S01-5: in diff mode the severity chips don't apply — show tier counts instead */}
          {diffMode && diffData && (
            <span className="text-xs text-gray-600">
              Drift:{' '}
              <b style={{ color: '#DC2626' }}>−{diffData.summary.removed}</b>{' '}
              <b style={{ color: '#059669' }}>+{diffData.summary.added}</b>{' '}
              <b style={{ color: '#D97706' }}>~{diffData.summary.changed}</b>{' '}
              <span className="text-gray-400">i {diffData.summary.info}</span>
            </span>
          )}
          {!diffMode && (<>
          {/* All */}
          <button
            onClick={() => setFindingsSeverityFilter('all')}
            className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
            style={
              findingsSeverityFilter === 'all'
                ? { background: '#1E3A5F', color: '#FFFFFF' }
                : { background: '#F1F5F9', color: '#64748B' }
            }
          >
            All ({findingsChipCounts.total})
          </button>
          {/* Severity chips */}
          {severityOrder.map(sev => {
            const count = findingsChipCounts.bySev[sev] || 0
            if (count === 0) return null
            const sc = sevColors[sev]
            const isActive = findingsSeverityFilter === sev
            return (
              <button
                key={sev}
                onClick={() => setFindingsSeverityFilter(sev)}
                className="px-2.5 py-1 rounded text-xs font-medium capitalize transition-colors"
                style={
                  isActive
                    ? { background: sc.color, color: '#FFFFFF' }
                    : { background: sc.bg, color: sc.color }
                }
              >
                {sev} ({count})
              </button>
            )
          })}
          {/* Acknowledged */}
          {findingsChipCounts.acked > 0 && (
            <button
              onClick={() => setFindingsSeverityFilter('acknowledged')}
              className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
              style={
                findingsSeverityFilter === 'acknowledged'
                  ? { background: '#6B7280', color: '#FFFFFF' }
                  : { background: '#F3F4F6', color: '#6B7280' }
              }
            >
              Acked ({findingsChipCounts.acked})
            </button>
          )}
          {/* Cross-Device */}
          {findingsChipCounts.crossDevice > 0 && (
            <button
              onClick={() => setFindingsSeverityFilter(findingsSeverityFilter === 'cross_device' ? 'all' : 'cross_device')}
              className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
              style={
                findingsSeverityFilter === 'cross_device'
                  ? { background: '#7C3AED', color: '#FFFFFF' }
                  : { background: '#F3E8FF', color: '#7C3AED' }
              }
            >
              Cross-Device ({findingsChipCounts.crossDevice})
            </button>
          )}
          {/* Device filter */}
          {deviceList.length > 0 && (
            <>
              <span className="text-gray-300 mx-1">|</span>
              <select
                value={findingsDeviceFilter}
                onChange={e => setFindingsDeviceFilter(e.target.value)}
                className="text-xs px-2 py-1 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
              >
                <option value="">All devices</option>
                {deviceList.map(d => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </>
          )}
          {/* Expected-findings toggle (only shown when a run tags expected findings) */}
          {findingsChipCounts.labExpectedAvailable && (
            <>
              <span className="text-gray-300 mx-1">|</span>
              <button
                onClick={() => setHideLabExpected(prev => !prev)}
                className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
                style={
                  hideLabExpected
                    ? { background: '#FEF3C7', color: '#92400E' }
                    : { background: '#F3F4F6', color: '#6B7280' }
                }
                title={hideLabExpected ? 'Showing only real issues' : 'Hide findings tagged as expected'}
              >
                {hideLabExpected ? '✓ Hide expected' : 'Hide expected'}
              </button>
            </>
          )}
          </>)}
          </div>

          {/* S01-5: right-aligned Diff toggle + "Compare to" run dropdown */}
          <div className="flex items-center gap-2 shrink-0">
            {diffMode && (
              <>
                <span className="text-xs text-gray-500">Compare to:</span>
                <select
                  value={diffAgainst || ''}
                  onChange={(e) => setDiffAgainst(e.target.value || null)}
                  className="text-xs px-2 py-1 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-emerald-400"
                >
                  <option value="">◀ Previous run (auto)</option>
                  {compareRuns.map((r) => (
                    <option key={r.run_id} value={r.run_id}>{formatRunShort(r)}</option>
                  ))}
                </select>
              </>
            )}
            <button
              onClick={() => setDiffMode((v) => !v)}
              className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
              style={diffMode ? { background: '#1D9E75', color: '#FFFFFF' } : { background: '#F1F5F9', color: '#475569' }}
              title={diffMode ? 'Exit diff mode' : 'Compare this run to another (drift)'}
            >
              {diffMode ? '✓ Diff' : '⇄ Diff'}
            </button>
          </div>
        </div>
      )}

      {/* ── Level 2 (Report tab): Send Email + Download PDF ── */}
      {isReportTab && (
        <div
          className="shrink-0 flex items-center px-4 gap-2"
          style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E8F0', height: 40 }}
        >
          <button
            onClick={() => reportActionsRef.current?.sendEmail?.()}
            className="px-3 py-1 rounded text-xs font-semibold"
            style={{ background: '#1D9E75', color: '#FFFFFF', border: 'none', cursor: 'pointer' }}
          >
            📧 Send by Email
          </button>
          <button
            onClick={() => reportActionsRef.current?.downloadPdf?.()}
            className="px-3 py-1 rounded text-xs font-semibold"
            style={{ background: '#FFFFFF', color: '#0F4F3A', border: '1.5px solid #1D9E75', cursor: 'pointer' }}
          >
            📥 Download PDF
          </button>
        </div>
      )}

      {/* ── Level 2b: VLAN selector (L2/L3 view only) ── */}
      {isTopologyTab && selectedView === 'l2vlan' && (
        <div
          className="shrink-0 flex items-center gap-3 px-4"
          style={{ background: '#EFF6FF', borderBottom: '1px solid #BFDBFE', height: 36 }}
        >
          <span className="text-xs font-medium text-gray-600">VLAN:</span>
          <select
            value={selectedVlan ?? ''}
            onChange={e => setSelectedVlan(e.target.value ? Number(e.target.value) : null)}
            className="text-xs px-2 py-1 rounded border border-blue-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
            style={{ minWidth: 260 }}
          >
            <option value="">ALL</option>
            {(vlanData?.vlans || []).map(v => (
              <option key={v.vlan_id} value={v.vlan_id}>
                {v.vlan_id} — {v.name || 'unnamed'}{v.subnet ? ` — ${v.subnet}` : ''}
              </option>
            ))}
          </select>
          {selectedVlan != null && (() => {
            const vlan = (vlanData?.vlans || []).find(v => v.vlan_id === selectedVlan)
            return vlan?.subnet ? (
              <span className="text-xs text-gray-500">Subnet: <span className="font-mono">{vlan.subnet}</span></span>
            ) : null
          })()}
        </div>
      )}

      {/* ── Level 2c: OSPF VRF selector (OSPF view only) ── */}
      {isTopologyTab && selectedView === 'ospf' && ospfVrfs.length > 0 && (
        <div
          className="shrink-0 flex items-center gap-3 px-4"
          style={{ background: '#ECFDF5', borderBottom: '1px solid #A7F3D0', height: 36 }}
        >
          <span className="text-xs font-medium text-gray-600">VRF:</span>
          <select
            value={ospfVrf ?? ''}
            onChange={e => setOspfVrf(e.target.value || null)}
            className="text-xs px-2 py-1 rounded border border-emerald-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-emerald-400"
            style={{ minWidth: 180 }}
          >
            {ospfVrfs.map(v => (
              <option key={v} value={v}>{v}</option>
            ))}
          </select>
          <span className="text-xs text-gray-500">
            {topologyData?.adjacencies?.filter(a => a.data.protocol === 'ospf' && a.data.vrf === ospfVrf).length || 0} adjacencies
          </span>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="bg-red-50 border-b border-red-200 px-4 py-2 text-red-700 text-sm shrink-0">
          {error}
          <button
            onClick={() => selectedRun && loadRunData(selectedRun, selectedView)}
            className="ml-2 underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {loading && (
        <div className="h-0.5 bg-blue-500 animate-pulse shrink-0" />
      )}

      {/* ── Main content ── */}
      {(
        <div
          className="flex-1 overflow-hidden flex"
          style={{ padding: 8, gap: 0 }}
        >
          {/* Left panel — content switches based on leftPanelMode */}
          <div
            className="overflow-hidden flex flex-col shrink-0"
            style={{
              width: `${rightPanelPct}%`,
              minWidth: 200,
              background: 'white',
              borderRadius: 8,
              border: '1px solid #E5E7EB',
            }}
          >
            {leftPanelMode === 'findings' && diffMode ? (
              <DriftPanel
                diffData={diffData}
                loading={diffLoading}
                error={diffError}
                focus={diffFocus}
                onElementClick={handleDriftElementClick}
                onClearFocus={() => setDiffFocus(null)}
              />
            ) : leftPanelMode === 'findings' ? (
              <FindingsPage
                findingsData={findingsData}
                topologyData={topologyData}
                selectedRun={selectedRun}
                onFindingClick={(devices) => {
                  // 2026-05-18: stayInFindings keeps FindingsPage visible in the LEFT
                  // panel while the click drives selectedDevice → TopologyMap focus
                  // in the CENTER. Was: switched LEFT to DeviceDetail.
                  handleFindingClick(devices, { stayInFindings: true })
                }}
                refreshFindings={refreshFindings}
                severityFilter={findingsSeverityFilter}
                setSeverityFilter={setFindingsSeverityFilter}
                deviceFilter={findingsDeviceFilter}
                setDeviceFilter={setFindingsDeviceFilter}
                hideLabExpected={hideLabExpected}
                setHideLabExpected={setHideLabExpected}
              />
            ) : leftPanelMode === 'report' ? (
              <ReportPanel selectedRun={selectedRun} actionsRef={reportActionsRef} />
            ) : (
              <DeviceDetail
                deviceData={deviceData}
                topologyData={topologyData}
                networkSummary={networkSummary}
                findingsData={findingsData}
                selectedDevice={selectedDevice}
                selectedLink={selectedLink}
                selectedMemberId={
                  selectedDevice?.includes(':')
                    ? parseInt(selectedDevice.split(':')[1], 10)
                    : null
                }
                selectedRun={selectedRun}
                onClose={() => {
                  handleDeviceSelect(null)
                  setSelectedLink(null)
                  setLeftPanelMode('summary')
                }}
                onDeviceSelect={handleDeviceSelect}
              />
            )}
          </div>

          <DragHandle side="left" onDrag={handleRightDrag} />

          {/* Center — Topology Map */}
          <div
            className="relative overflow-hidden flex-1"
            style={{
              background: 'white',
              borderRadius: 8,
              border: '1px solid #E5E7EB',
              minWidth: 200,
            }}
          >
            <TopologyMap
              topologyData={topologyData}
              findingsData={findingsData}
              selectedDevice={selectedDevice}
              onDeviceSelect={handleDeviceSelect}
              deviceList={deviceList}
              onLinkSelect={handleLinkSelect}
              selectedView={selectedView}
              severityFilters={severityFilters}
              onToggleSeverity={toggleSeverityFilter}
              selectedRun={selectedRun}
              collapsedPositions={collapsedPositions}
              expandedPositions={expandedPositions}
              onCollapsedPositionsChange={setCollapsedPositions}
              onExpandedPositionsChange={setExpandedPositions}
              selectedVlan={selectedVlan}
              vlanData={vlanData}
              ospfVrf={ospfVrf}
              highlightPath={highlightPath}
            />
          </div>

          <DragHandle side="right" onDrag={handleAgentDrag} raw />

          {/* Right panel — Agent Chat */}
          <div
            className="overflow-hidden flex flex-col shrink-0"
            style={{
              width: agentPanelWidth,
              minWidth: 260,
              maxWidth: 460,
              background: 'white',
              borderRadius: 8,
              border: '1px solid #E5E7EB',
            }}
          >
            <AgentChatPanel />
          </div>
        </div>
      )}
      {/* C1S3: FindingsPage moved to left panel — old full-page block removed */}
    </div>
    </AgentProvider>
  )
}
