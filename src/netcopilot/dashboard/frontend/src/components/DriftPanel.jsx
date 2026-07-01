import { useState } from 'react'

// S01-5: run-to-run drift change list. Groups added/removed/changed; the info
// tier is a collapsed, summarised section at the bottom (never itemised — it
// can be thousands of ARP/FDB rows). Clicking a row focuses that element and
// filters the list to it (handled by the parent via `focus`).

const TIER_META = {
  removed: { label: 'Removed', color: '#DC2626', bg: '#FEF2F2', sign: '−' },
  added: { label: 'Added', color: '#059669', bg: '#ECFDF5', sign: '+' },
  changed: { label: 'Changed', color: '#D97706', bg: '#FFFBEB', sign: '~' },
}

function fmt(v) {
  const s = v === null || v === undefined ? '∅' : typeof v === 'object' ? JSON.stringify(v) : String(v)
  return s.length > 40 ? s.slice(0, 39) + '…' : s
}

function ChangeRow({ change, meta, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-3 py-1.5 border-b border-gray-50 hover:bg-gray-50 transition-colors"
      style={active ? { background: '#EFF6FF' } : undefined}
    >
      <div className="flex items-start gap-2">
        <span
          className="text-[10px] font-mono px-1 rounded shrink-0 mt-0.5"
          style={{ background: meta.bg, color: meta.color }}
        >
          {change.entity_type}
        </span>
        <span className="text-xs text-gray-700 font-mono break-all">{change.key}</span>
      </div>
      {(change.changed_fields || []).slice(0, 6).map((f, i) => (
        <div key={i} className="text-[11px] text-gray-500 ml-1 font-mono truncate">
          {f.field}: {fmt(f.before)} → {fmt(f.after)}
        </div>
      ))}
      {(change.changed_fields || []).length > 6 && (
        <div className="text-[11px] text-gray-400 ml-1">
          +{change.changed_fields.length - 6} more field(s)
        </div>
      )}
    </button>
  )
}

function InfoSummary({ info }) {
  // Summarise by field name (counts), never itemise raw rows.
  const fieldCounts = {}
  for (const c of info) for (const f of c.changed_fields || []) fieldCounts[f.field] = (fieldCounts[f.field] || 0) + 1
  const entries = Object.entries(fieldCounts).sort((a, b) => b[1] - a[1])
  return (
    <div className="text-[11px] text-gray-500">
      {info.length} entit{info.length === 1 ? 'y' : 'ies'} with semi-volatile signal changes
      (prefix counts, ARP/FDB/MAC, DHCP, session uptime) — not configuration drift:
      <div className="mt-1 flex flex-wrap gap-1">
        {entries.map(([field, n]) => (
          <span key={field} className="px-1.5 py-0.5 rounded bg-gray-100 font-mono">
            {field} ×{n}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function DriftPanel({ diffData, loading, error, focus, onElementClick, onClearFocus }) {
  const [showInfo, setShowInfo] = useState(false)

  if (loading) return <div className="p-4 text-sm text-gray-500">Computing drift…</div>
  if (error) return <div className="p-4 text-sm text-red-600">Diff failed: {error}</div>
  if (!diffData) return <div className="p-4 text-sm text-gray-500">Select "⇄ Diff" to compare runs.</div>

  const { run_a, run_b, summary, changes, note } = diffData
  const drift = changes.filter((c) => c.tier !== 'info')
  const info = changes.filter((c) => c.tier === 'info')

  // Click-to-filter: scope the drift list to the focused element (by topology
  // element_id when present, else the exact change key).
  const scoped = focus
    ? drift.filter((c) => (focus.element_id ? c.element_id === focus.element_id : c.key === focus.key))
    : drift

  const byTier = { removed: [], added: [], changed: [] }
  for (const c of scoped) if (byTier[c.tier]) byTier[c.tier].push(c)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header — the two runs + tier counts */}
      <div className="px-3 py-2 border-b border-gray-200 shrink-0">
        <div className="text-sm font-semibold text-gray-800">Drift</div>
        <div className="text-xs text-gray-500 font-mono truncate" title={`${run_a || '—'} → ${run_b}`}>
          {run_a || '—'} → {run_b}
        </div>
        <div className="flex gap-3 mt-1 text-xs font-medium">
          <span style={{ color: TIER_META.removed.color }}>−{summary.removed}</span>
          <span style={{ color: TIER_META.added.color }}>+{summary.added}</span>
          <span style={{ color: TIER_META.changed.color }}>~{summary.changed}</span>
          <span className="text-gray-400">i {summary.info}</span>
        </div>
      </div>

      {note && <div className="px-3 py-2 text-xs text-gray-500">{note}</div>}

      {focus && (
        <div className="px-3 py-1.5 bg-blue-50 border-b border-blue-100 text-xs flex items-center justify-between shrink-0">
          <span className="text-blue-700 truncate">Filtered to {focus.element_id || focus.key}</span>
          <button onClick={onClearFocus} className="text-blue-600 hover:underline ml-2 shrink-0">
            clear
          </button>
        </div>
      )}

      {/* Body — grouped drift, then collapsed info */}
      <div className="flex-1 overflow-y-auto">
        {drift.length === 0 && !note && (
          <div className="p-4 text-sm text-gray-500">
            No configuration or state drift between these runs.
          </div>
        )}

        {['removed', 'added', 'changed'].map((tier) => {
          const items = byTier[tier]
          if (!items.length) return null
          const meta = TIER_META[tier]
          return (
            <div key={tier}>
              <div
                className="px-3 py-1 text-xs font-semibold sticky top-0 z-10"
                style={{ background: meta.bg, color: meta.color }}
              >
                {meta.label} ({items.length})
              </div>
              {items.map((c, i) => (
                <ChangeRow
                  key={c.key + ':' + i}
                  change={c}
                  meta={meta}
                  active={focus && (focus.element_id ? c.element_id === focus.element_id : c.key === focus.key)}
                  onClick={() => onElementClick(c)}
                />
              ))}
            </div>
          )
        })}

        {info.length > 0 && (
          <div className="border-t border-gray-100 mt-1">
            <button
              onClick={() => setShowInfo((v) => !v)}
              className="w-full px-3 py-1.5 text-left text-xs text-gray-500 hover:bg-gray-50 flex items-center justify-between"
            >
              <span>
                {showInfo ? '▾' : '▸'} Info signals ({info.length})
              </span>
              <span className="text-gray-400">volatile — not drift</span>
            </button>
            {showInfo && (
              <div className="px-3 pb-2">
                <InfoSummary info={info} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
