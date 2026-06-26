import { useMemo } from 'react'
import { useLegend } from '../contexts/LegendContext.jsx'

// Section label style
const SECTION_LABEL = {
  fontSize: 10,
  fontWeight: 700,
  color: '#9CA3AF',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

// Severity badge abbreviations
const SEV_LABELS = {
  critical: 'Crit',
  high: 'High',
  low: 'Low',
  info: 'Info',
  cis: 'CIS',
}

export function extractDevices(finding) {
  const kf = finding.evidence?.key_facts
  if (Array.isArray(kf?.devices)) return kf.devices
  if (kf?.hostname) return [kf.hostname]

  let elementId = finding.evidence?.element_id || finding.finding_id || ''
  if (elementId.includes('::')) {
    elementId = elementId.split('::')[1]
  }
  if (elementId.includes('--')) {
    return elementId.split('--').map((p) => p.split(':')[0].split('/')[0]).filter(Boolean)
  }
  const dev = elementId.split(':')[0].split('/')[0]
  return dev ? [dev] : []
}

export default function FindingsPanel({
  findingsData,
  topologyData,
  onFindingClick,
  onDeviceSelect,
  selectedRun,
  selectedDevice,
  // S19A-3: Filter props from App
  severityFilters,
  onToggleSeverity,
  findingsDeviceFilter,
  onFindingsDeviceFilter,
}) {
  const { sevColors, severityOrder } = useLegend()
  const summary = findingsData?.summary || {}
  const bySeverity = summary.by_severity || {}

  // Unique device list from topology
  const deviceList = useMemo(() => {
    if (!topologyData?.nodes) return []
    return topologyData.nodes
      .filter(n => !n.data.parent)
      .map(n => n.data.id)
      .sort()
  }, [topologyData])

  // Filtered and sorted findings
  const filteredFindings = useMemo(() => {
    if (!findingsData?.findings) return []
    return [...findingsData.findings]
      .filter(f => {
        // Severity filter
        if (severityFilters && !severityFilters.has(f.severity)) return false
        // Device filter
        if (findingsDeviceFilter) {
          const devices = extractDevices(f)
          if (!devices.includes(findingsDeviceFilter)) return false
        }
        return true
      })
      .sort((a, b) => {
        const ai = severityOrder.indexOf(a.severity)
        const bi = severityOrder.indexOf(b.severity)
        if (ai !== bi) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
        // Secondary sort by device name
        const da = extractDevices(a)[0] || ''
        const db = extractDevices(b)[0] || ''
        return da.localeCompare(db)
      })
  }, [findingsData, severityFilters, findingsDeviceFilter])

  // Filtered count by severity
  const filteredBySeverity = useMemo(() => {
    const counts = {}
    filteredFindings.forEach(f => {
      counts[f.severity] = (counts[f.severity] || 0) + 1
    })
    return counts
  }, [filteredFindings])

  if (!findingsData || !selectedRun) {
    return (
      <div className="p-4 text-gray-400 text-sm">
        Select a run to view findings
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* ── Severity filter badges (S19A-3) ── */}
      <div className="p-3 border-b" style={{ borderColor: '#E5E7EB' }}>
        <div className="flex items-center justify-between mb-2">
          <p style={SECTION_LABEL}>Findings</p>
          <span className="text-xs font-semibold text-gray-600">
            {filteredFindings.length}
            {filteredFindings.length !== (findingsData?.findings?.length || 0) && (
              <span className="text-gray-400 font-normal">
                {' / '}{findingsData?.findings?.length || 0}
              </span>
            )}
          </span>
        </div>

        {/* Severity toggle badges */}
        <div className="flex flex-wrap gap-1 mb-2">
          {severityOrder.map(sev => {
            const count = bySeverity[sev] || 0
            const sc = sevColors[sev]
            const isActive = !severityFilters || severityFilters.has(sev)
            return (
              <button
                key={sev}
                onClick={() => onToggleSeverity?.(sev)}
                className="text-xs font-medium px-1.5 py-0.5 rounded transition-colors"
                style={
                  isActive
                    ? { background: sc.bg, color: sc.color, border: `1px solid ${sc.color}` }
                    : { background: '#F9FAFB', color: '#9CA3AF', border: '1px solid #E5E7EB' }
                }
                title={`${isActive ? 'Hide' : 'Show'} ${sev} findings`}
              >
                {SEV_LABELS[sev]} {count}
              </button>
            )
          })}
        </div>

        {/* Device filter dropdown */}
        <select
          value={findingsDeviceFilter || ''}
          onChange={e => onFindingsDeviceFilter?.(e.target.value || null)}
          className="w-full text-xs px-2 py-1.5 rounded border border-gray-200 bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
        >
          <option value="">All devices</option>
          {deviceList.map(d => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
      </div>

      {/* ── Findings list ── */}
      <div className="flex-1 overflow-y-auto">
        {filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-green-600">
            <span className="text-2xl mb-2">&#10003;</span>
            <p className="text-sm font-medium">No findings</p>
            {findingsData?.findings?.length > 0 && (
              <p className="text-xs text-gray-400 mt-1">Adjust filters to see findings</p>
            )}
          </div>
        ) : (
          filteredFindings.slice(0, 100).map((finding, idx) => {
            const sev = finding.severity || 'info'
            const sc = sevColors[sev] || sevColors.info
            const devices = extractDevices(finding)
            const deviceLabel = devices.length > 1
              ? `${devices[0]} \u2194 ${devices[1]}`
              : devices[0] || ''

            return (
              <button
                key={finding.finding_id || idx}
                onClick={() => onFindingClick(devices)}
                className="w-full text-left px-3 py-2 border-b hover:bg-gray-50 transition-colors"
                style={{ borderColor: '#F3F4F6' }}
              >
                <div className="flex items-start gap-2">
                  <span
                    className="w-2 h-2 rounded-full mt-1 shrink-0"
                    style={{ background: sc.color }}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium text-gray-700 truncate">
                      {finding.title || finding.rule_id?.replace(/_/g, ' ')}
                    </p>
                    {deviceLabel && (
                      <p className="text-xs text-gray-500 truncate mt-0.5">
                        {deviceLabel}
                      </p>
                    )}
                  </div>
                </div>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}
