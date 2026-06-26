import { useMemo, useState, useCallback } from 'react'
import { useLegend } from '../contexts/LegendContext.jsx'
import { extractDevices as _extractDevices } from './FindingsPanel.jsx'
import { useAgent } from '../AgentContext.jsx'

const extractDevices = _extractDevices

// ── Acknowledge reason dialog ──

function AckDialog({ count, onConfirm, onCancel }) {
  const [reason, setReason] = useState('')
  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(0,0,0,0.3)',
      }}
      onClick={onCancel}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'white', borderRadius: 8, padding: 20,
          width: 400, boxShadow: '0 4px 24px rgba(0,0,0,0.15)',
        }}
      >
        <p className="text-sm font-semibold text-gray-700 mb-2">
          Acknowledge {count} finding{count > 1 ? 's' : ''}
        </p>
        <p className="text-xs text-gray-500 mb-3">
          Acknowledged findings are grouped separately. This persists across pipeline runs.
        </p>
        <textarea
          className="w-full border border-gray-200 rounded p-2 text-xs text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
          rows={3}
          placeholder="Reason (e.g., accepted risk / scheduled maintenance)"
          value={reason}
          onChange={e => setReason(e.target.value)}
          autoFocus
        />
        <div className="flex justify-end gap-2 mt-3">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 rounded text-xs text-gray-500 hover:bg-gray-100"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(reason)}
            className="px-3 py-1.5 rounded text-xs font-medium text-white"
            style={{ background: '#1E3A5F' }}
          >
            Acknowledge
          </button>
        </div>
      </div>
    </div>
  )
}

export default function FindingsPage({
  findingsData,
  topologyData,
  selectedRun,
  onFindingClick,
  refreshFindings,
  // 2026-05-18: severityFilter / deviceFilter / hideLabExpected are now
  // owned by App.jsx so they can be rendered in the tab-aware Level-2 bar.
  // FindingsPage accepts them as controlled props.
  severityFilter,
  setSeverityFilter,
  deviceFilter,
  setDeviceFilter,
  hideLabExpected,
  setHideLabExpected,
}) {
  const { sevColors, severityOrder } = useLegend()
  const { sendMessage, isStreaming } = useAgent()
  const [expandedRules, setExpandedRules] = useState(new Set())
  const [ackDialog, setAckDialog] = useState(null) // {findingIds: [...]}
  const [unackAllDialog, setUnackAllDialog] = useState(false)
  // S20A4-5: Analyze panel (deterministic, no LLM)
  const [analyzeRuleId, setAnalyzeRuleId] = useState(null)
  // C1S8: Cross-device grouping toggle ('rule' | 'relationship')
  const [crossDeviceGrouping, setCrossDeviceGrouping] = useState('rule')

  // Device list from topology for the selector
  const deviceList = useMemo(() => {
    if (!topologyData?.nodes) return []
    return topologyData.nodes
      .filter(n => !n.data.parent && n.data.collected !== false)
      .map(n => n.data.id)
      .sort()
  }, [topologyData])

  const findings = findingsData?.findings || []
  const summary = findingsData?.summary || {}
  const labContext = findingsData?.lab_context || null
  const labExpectedCount = summary.lab_expected_count || 0
  const acknowledgedCount = summary.acknowledged_count || 0

  // ── Acknowledge / un-acknowledge API calls ──

  const doAcknowledge = useCallback(async (findingIds, reason) => {
    if (!selectedRun || !findingIds.length) return
    try {
      await fetch(`/api/findings/${encodeURIComponent(selectedRun)}/acknowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_ids: findingIds, reason }),
      })
      if (refreshFindings) await refreshFindings()
    } catch (err) {
      console.error('Acknowledge failed:', err)
    }
  }, [selectedRun, refreshFindings])

  const doUnacknowledge = useCallback(async (findingIds) => {
    if (!selectedRun || !findingIds.length) return
    try {
      await fetch(`/api/findings/${encodeURIComponent(selectedRun)}/acknowledge`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_ids: findingIds }),
      })
      if (refreshFindings) await refreshFindings()
    } catch (err) {
      console.error('Unacknowledge failed:', err)
    }
  }, [selectedRun, refreshFindings])

  const doUnacknowledgeAll = useCallback(async () => {
    if (!selectedRun) return
    try {
      await fetch(`/api/findings/${encodeURIComponent(selectedRun)}/acknowledgements`, {
        method: 'DELETE',
      })
      if (refreshFindings) await refreshFindings()
    } catch (err) {
      console.error('Unacknowledge all failed:', err)
    }
  }, [selectedRun, refreshFindings])

  // Split findings into unacknowledged and acknowledged
  const { unackedFindings, ackedFindings } = useMemo(() => {
    let pool = findings
    if (hideLabExpected) pool = pool.filter(f => !(f.tags && f.tags.includes('lab_expected')))
    if (deviceFilter) pool = pool.filter(f => extractDevices(f).includes(deviceFilter))
    return {
      unackedFindings: pool.filter(f => !f.acknowledged),
      ackedFindings: pool.filter(f => f.acknowledged),
    }
  }, [findings, hideLabExpected, deviceFilter])

  // Severity counts from unacknowledged findings only
  const bySeverity = useMemo(() => {
    const counts = {}
    unackedFindings.forEach(f => {
      const sev = f.severity || 'info'
      counts[sev] = (counts[sev] || 0) + 1
    })
    return counts
  }, [unackedFindings])

  // Cross-device count (C1S8)
  const crossDeviceCount = useMemo(() => {
    return unackedFindings.filter(f => f.is_cross_device).length
  }, [unackedFindings])

  // Filtered findings based on severity filter
  const filtered = useMemo(() => {
    if (severityFilter === 'acknowledged') return ackedFindings
    if (severityFilter === 'cross_device') return unackedFindings.filter(f => f.is_cross_device)
    let result = unackedFindings
    if (severityFilter !== 'all') {
      result = result.filter(f => f.severity === severityFilter)
    }
    return result
  }, [unackedFindings, ackedFindings, severityFilter])

  // Should we append the acked section at the bottom? (when viewing 'all' or a severity)
  const showAckedSection = severityFilter !== 'acknowledged' && ackedFindings.length > 0

  // Grouped by rule_id, sorted by severity then count
  function groupFindings(list) {
    const groups = {}
    list.forEach(f => {
      const ruleId = f.rule_id || 'unknown'
      const sev = f.severity || 'info'
      const key = `${ruleId}::${sev}`
      if (!groups[key]) {
        groups[key] = {
          ruleId,
          groupKey: key,
          severity: sev,
          findings: [],
          devices: new Set(),
        }
      }
      groups[key].findings.push(f)
      extractDevices(f).forEach(d => groups[key].devices.add(d))
    })

    return Object.values(groups).sort((a, b) => {
      const sevA = severityOrder.indexOf(a.severity)
      const sevB = severityOrder.indexOf(b.severity)
      if (sevA !== sevB) return (sevA === -1 ? 99 : sevA) - (sevB === -1 ? 99 : sevB)
      return b.findings.length - a.findings.length
    })
  }

  // Group by device relationship for cross-device view (C1S8)
  function groupByRelationship(list) {
    const groups = {}
    list.forEach(f => {
      const devs = extractDevices(f)
      const key = devs.length > 0 ? [...devs].sort().join(' + ') : 'unknown'
      if (!groups[key]) {
        groups[key] = {
          relationshipKey: key,
          devices: devs,
          findings: [],
          severities: new Set(),
        }
      }
      groups[key].findings.push(f)
      groups[key].severities.add(f.severity || 'info')
    })
    return Object.values(groups).sort((a, b) => {
      // Sort by worst severity, then by finding count
      const worstA = Math.min(...[...a.severities].map(s => severityOrder.indexOf(s)).filter(i => i >= 0), 99)
      const worstB = Math.min(...[...b.severities].map(s => severityOrder.indexOf(s)).filter(i => i >= 0), 99)
      if (worstA !== worstB) return worstA - worstB
      return b.findings.length - a.findings.length
    })
  }

  const grouped = useMemo(() => {
    if (severityFilter === 'cross_device' && crossDeviceGrouping === 'relationship') {
      return groupByRelationship(filtered)
    }
    return groupFindings(filtered)
  }, [filtered, severityFilter, crossDeviceGrouping])
  const ackedGrouped = useMemo(() => groupFindings(ackedFindings), [ackedFindings])

  function toggleRule(ruleId) {
    setExpandedRules(prev => {
      const next = new Set(prev)
      if (next.has(ruleId)) next.delete(ruleId)
      else next.add(ruleId)
      return next
    })
  }

  if (!selectedRun) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        Select a run to view findings
      </div>
    )
  }

  // ── Render a single group row ──

  function renderGroup(group, { isAckedSection = false } = {}) {
    const sc = sevColors[group.severity] || sevColors.info
    const toggleKey = (group.groupKey || group.ruleId) + (isAckedSection ? '_ack' : '')
    const isExpanded = expandedRules.has(toggleKey)
    const deviceNames = [...group.devices].slice(0, 5)
    const moreDevices = group.devices.size - 5

    const allLabExpected = group.findings.length > 0 &&
      group.findings.every(f => f.tags && f.tags.includes('lab_expected'))
    const allAcknowledged = group.findings.every(f => f.acknowledged)
    const unackedIds = group.findings.filter(f => !f.acknowledged).map(f => f.finding_id)

    return (
      <div
        key={toggleKey}
        className="border-b"
        style={{
          borderColor: '#E5E7EB',
          background: isAckedSection ? '#FAFAFA' : undefined,
        }}
      >
        {/* Group header */}
        <div className="flex items-start">
          <button
            onClick={() => {
              setExpandedRules(prev => {
                const next = new Set(prev)
                if (next.has(toggleKey)) next.delete(toggleKey)
                else next.add(toggleKey)
                return next
              })
            }}
            className="flex-1 text-left px-4 py-3 hover:bg-gray-50 transition-colors flex items-start gap-3"
          >
            <span className="text-gray-400 mt-0.5 shrink-0" style={{ fontSize: 10 }}>
              {isExpanded ? '\u25BC' : '\u25B6'}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  className="text-xs font-medium px-1.5 py-0.5 rounded capitalize"
                  style={
                    isAckedSection
                      ? { background: '#F3F4F6', color: '#6B7280', fontSize: 10 }
                      : { background: sc.bg, color: sc.color, fontSize: 10 }
                  }
                >
                  {isAckedSection ? `${group.severity} · ack` : group.severity}
                </span>
                <span className="text-sm font-semibold text-gray-700" style={isAckedSection ? { opacity: 0.6 } : undefined}>
                  {group.ruleId.replace(/_/g, ' ')}
                </span>
                <span className="text-xs text-gray-400">
                  ({group.findings.length})
                </span>
                {allLabExpected && (
                  <span
                    className="px-1.5 py-0.5 rounded font-medium"
                    style={{ background: '#ECFEFF', color: '#0891B2', fontSize: 9 }}
                  >
                    EXPECTED
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-500 mt-1 truncate">
                {isAckedSection && group.findings[0]?.acknowledged_reason
                  ? group.findings[0].acknowledged_reason
                  : deviceNames.join(', ') + (moreDevices > 0 ? ` +${moreDevices} more` : '')
                }
              </p>
            </div>
          </button>
          {/* Acknowledge / un-acknowledge button */}
          {!isAckedSection && unackedIds.length > 0 && (
            <div className="flex items-center gap-1 mr-3 mt-3 shrink-0">
              <button
                onClick={(e) => { e.stopPropagation(); setAckDialog({ findingIds: unackedIds }) }}
                className="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
                title={`Acknowledge all ${unackedIds.length} findings`}
              >
                Ack ({unackedIds.length})
              </button>
            </div>
          )}
          {isAckedSection && allAcknowledged && (
            <button
              onClick={(e) => {
                e.stopPropagation()
                doUnacknowledge(group.findings.map(f => f.finding_id))
              }}
              className="mr-3 mt-3 px-2 py-1 rounded text-xs text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors shrink-0"
              title="Remove acknowledgement"
            >
              Un-ack
            </button>
          )}
        </div>

        {/* Expanded findings */}
        {isExpanded && (
          <div className="pl-10 pr-4 pb-2">
            {group.findings.map((f, idx) => {
              const devices = extractDevices(f)
              const isLabExpected = f.tags && f.tags.includes('lab_expected')
              return (
                <div
                  key={f.finding_id || idx}
                  className="flex items-center border-t"
                  style={{ borderColor: '#F3F4F6' }}
                >
                  <button
                    onClick={() => {
                      onFindingClick(devices)
                      if (!isAckedSection && devices.length > 0) {
                        sendMessage(`Explain the ${group.ruleId} finding on ${devices[0]}`)
                      }
                    }}
                    className="flex-1 text-left py-1.5 text-xs hover:bg-gray-50 transition-colors"
                  >
                    <p className="text-gray-600" style={isAckedSection ? { opacity: 0.6 } : undefined}>
                      <span className="font-medium text-gray-500">
                        {devices.join(', ') || 'unknown'}
                      </span>
                      {isLabExpected && (
                        <span
                          className="ml-1.5 px-1 py-0.5 rounded font-medium"
                          style={{ background: '#ECFEFF', color: '#0891B2', fontSize: 9 }}
                        >
                          EXPECTED
                        </span>
                      )}
                      {f.message && (
                        <span className="text-gray-400 ml-1.5">
                          &mdash; {f.message}
                        </span>
                      )}
                    </p>
                  </button>
                  {/* Per-finding ack/un-ack */}
                  {!f.acknowledged ? (
                    <button
                      onClick={() => setAckDialog({ findingIds: [f.finding_id] })}
                      className="px-1.5 py-0.5 text-gray-300 hover:text-gray-500 transition-colors"
                      title="Acknowledge"
                      style={{ fontSize: 10 }}
                    >
                      ack
                    </button>
                  ) : (
                    <button
                      onClick={() => doUnacknowledge([f.finding_id])}
                      className="px-1.5 py-0.5 text-gray-300 hover:text-red-500 transition-colors"
                      title="Remove acknowledgement"
                      style={{ fontSize: 10 }}
                    >
                      un-ack
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  // ── Render a relationship group (C1S8 cross-device view) ──

  function renderRelationshipGroup(group) {
    const toggleKey = 'rel::' + group.relationshipKey
    const isExpanded = expandedRules.has(toggleKey)
    const deviceLabel = group.devices.length <= 3
      ? group.devices.join(' \u2194 ')
      : group.devices.slice(0, 2).join(' \u2194 ') + ` + ${group.devices.length - 2} more`
    const worstSev = severityOrder.find(s => group.severities.has(s)) || 'info'
    const sc = sevColors[worstSev] || sevColors.info

    return (
      <div key={toggleKey} className="border-b" style={{ borderColor: '#E5E7EB' }}>
        <button
          onClick={() => {
            setExpandedRules(prev => {
              const next = new Set(prev)
              if (next.has(toggleKey)) next.delete(toggleKey)
              else next.add(toggleKey)
              return next
            })
          }}
          className="w-full text-left px-4 py-3 hover:bg-gray-50 transition-colors flex items-start gap-3"
        >
          <span className="text-gray-400 mt-0.5 shrink-0" style={{ fontSize: 10 }}>
            {isExpanded ? '\u25BC' : '\u25B6'}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="px-1.5 py-0.5 rounded font-medium"
                style={{ background: '#F3E8FF', color: '#7C3AED', fontSize: 10 }}
              >
                cross-device
              </span>
              <span
                className="px-1.5 py-0.5 rounded capitalize"
                style={{ background: sc.bg, color: sc.color, fontSize: 10 }}
              >
                {worstSev}
              </span>
              <span className="text-sm font-semibold text-gray-700">{deviceLabel}</span>
              <span className="text-xs text-gray-400">({group.findings.length})</span>
            </div>
          </div>
        </button>
        {isExpanded && (
          <div className="bg-gray-50 px-4 py-2 space-y-1">
            {group.findings.map(f => {
              const fsc = sevColors[f.severity] || sevColors.info
              return (
                <div key={f.finding_id} className="flex items-start gap-2 py-1 text-xs text-gray-600">
                  <span
                    className="px-1 py-0.5 rounded capitalize shrink-0"
                    style={{ background: fsc.bg, color: fsc.color, fontSize: 9 }}
                  >
                    {f.severity}
                  </span>
                  <span className="font-medium text-gray-700">{f.rule_id.replace(/_/g, ' ')}</span>
                  {f.message && (
                    <span className="text-gray-500 truncate">{f.message.length > 120 ? f.message.slice(0, 117) + '...' : f.message}</span>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Acknowledge dialog */}
      {ackDialog && (
        <AckDialog
          count={ackDialog.findingIds.length}
          onCancel={() => setAckDialog(null)}
          onConfirm={async (reason) => {
            await doAcknowledge(ackDialog.findingIds, reason)
            setAckDialog(null)
          }}
        />
      )}

      {unackAllDialog && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'rgba(0,0,0,0.3)',
          }}
          onClick={() => setUnackAllDialog(false)}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'white', borderRadius: 8, padding: 20,
              width: 360, boxShadow: '0 4px 24px rgba(0,0,0,0.15)',
            }}
          >
            <p className="text-sm font-semibold text-gray-700 mb-2">
              Remove all {ackedFindings.length} acknowledgement{ackedFindings.length !== 1 ? 's' : ''}?
            </p>
            <p className="text-xs text-gray-500 mb-4">
              All acknowledged findings will return to the active list. This cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setUnackAllDialog(false)}
                className="px-3 py-1.5 rounded text-xs text-gray-500 hover:bg-gray-100"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  setUnackAllDialog(false)
                  await doUnacknowledgeAll()
                }}
                className="px-3 py-1.5 rounded text-xs font-medium text-white"
                style={{ background: '#DC2626' }}
              >
                Remove all
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filter bar moved to App.jsx Level-2 toolbar (2026-05-18 — tab-aware
          per-tab controls). Chip group + device dropdown + lab-expected
          toggle now render in the Level-2 slot when leftPanelMode==='findings'.
          What stays here: the unack-all dialog state + the dialog JSX itself
          (the dialog still renders below; the bulk-trigger button is no
          longer wired — re-add as a follow-up if needed).
          Original filter bar JSX (~120 lines) intentionally removed. */}
      {false && (
        <div className="p-3 border-b flex items-center justify-between gap-3 shrink-0" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-center gap-1 flex-wrap">
          {/* All button */}
          <button
            onClick={() => setSeverityFilter('all')}
            className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
            style={
              severityFilter === 'all'
                ? { background: '#1E3A5F', color: '#FFFFFF' }
                : { background: '#F1F5F9', color: '#64748B' }
            }
          >
            All ({unackedFindings.length})
          </button>
          {/* Severity buttons */}
          {severityOrder.map(sev => {
            const count = bySeverity[sev] || 0
            if (count === 0) return null
            const sc = sevColors[sev]
            const isActive = severityFilter === sev
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
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

          {/* Acknowledged button — like a severity category */}
          {ackedFindings.length > 0 && (
            <>
              <button
                onClick={() => setSeverityFilter('acknowledged')}
                className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
                style={
                  severityFilter === 'acknowledged'
                    ? { background: '#6B7280', color: '#FFFFFF' }
                    : { background: '#F3F4F6', color: '#6B7280' }
                }
              >
                Acked ({ackedFindings.length})
              </button>
              <button
                onClick={() => setUnackAllDialog(true)}
                className="px-2 py-1 rounded text-xs font-medium transition-colors"
                style={{ background: '#FEF2F2', color: '#DC2626' }}
                title="Remove all acknowledgements"
              >
                Un-ack all
              </button>
            </>
          )}

          {/* Cross-Device filter (C1S8) */}
          {crossDeviceCount > 0 && (
            <button
              onClick={() => setSeverityFilter(severityFilter === 'cross_device' ? 'all' : 'cross_device')}
              className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
              style={
                severityFilter === 'cross_device'
                  ? { background: '#7C3AED', color: '#FFFFFF' }
                  : { background: '#F3E8FF', color: '#7C3AED' }
              }
            >
              Cross-Device ({crossDeviceCount})
            </button>
          )}

          {/* Device filter */}
          {deviceList.length > 0 && (
            <>
              <span className="text-gray-300 mx-1">|</span>
              <select
                value={deviceFilter}
                onChange={e => setDeviceFilter(e.target.value)}
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
          {labExpectedCount > 0 && (
            <>
              <span className="text-gray-300 mx-1">|</span>
              <button
                onClick={() => setHideLabExpected(prev => !prev)}
                className="px-2.5 py-1 rounded text-xs font-medium transition-colors"
                style={
                  hideLabExpected
                    ? { background: '#0891B2', color: '#FFFFFF' }
                    : { background: '#ECFEFF', color: '#0891B2' }
                }
              >
                {hideLabExpected ? 'Lab hidden' : 'Lab'} ({labExpectedCount})
              </button>
            </>
          )}
        </div>

      </div>
      )}

      {/* Cross-device grouping toggle (C1S8) */}
      {severityFilter === 'cross_device' && (
        <div className="px-3 py-2 border-b flex items-center gap-2 shrink-0" style={{ borderColor: '#E5E7EB', background: '#FAFAFA' }}>
          <span className="text-xs text-gray-500">Group by:</span>
          <button
            onClick={() => setCrossDeviceGrouping('rule')}
            className="px-2 py-0.5 rounded text-xs font-medium transition-colors"
            style={
              crossDeviceGrouping === 'rule'
                ? { background: '#7C3AED', color: '#FFFFFF' }
                : { background: '#F3E8FF', color: '#7C3AED' }
            }
          >
            Rule
          </button>
          <button
            onClick={() => setCrossDeviceGrouping('relationship')}
            className="px-2 py-0.5 rounded text-xs font-medium transition-colors"
            style={
              crossDeviceGrouping === 'relationship'
                ? { background: '#7C3AED', color: '#FFFFFF' }
                : { background: '#F3E8FF', color: '#7C3AED' }
            }
          >
            Relationship
          </button>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        <div className="overflow-y-auto h-full">
            {grouped.map(group =>
              group.relationshipKey
                ? renderRelationshipGroup(group)
                : renderGroup(group)
            )}

            {showAckedSection && (
              <>
                <div
                  className="px-4 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider"
                  style={{ background: '#F9FAFB', borderBottom: '1px solid #E5E7EB' }}
                >
                  Acknowledged ({ackedFindings.length})
                </div>
                {ackedGrouped.map(group => renderGroup(group, { isAckedSection: true }))}
              </>
            )}
        </div>
      </div>
    </div>
  )
}
