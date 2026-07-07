/**
 * ReconcilePage — Reconcile as an Audit sub-view (s14b, ADR-0017).
 *
 * Renders in the LEFT information panel (topology stays CENTER, assistant
 * RIGHT — the app-wide three-panel contract). Filters + actions live in the
 * Audit Level-2 toolbar in App.jsx: this component receives the filter values
 * as props, exposes its actions through `actionsRef` (the ReportPanel idiom),
 * and mirrors the reactive bits the toolbar needs (count / selection / busy)
 * up through `onUiState`. Clicking a pending row highlights its affected
 * device on the topology via `onDeviceClick`.
 *
 * The staged-approval workflow itself (Constitution Art. I: staged →
 * human-approved-per-write → audited → non-destructive) is unchanged from
 * s12 — same /api/reconcile/* calls, same modals, same gate banner.
 */
import { useEffect, useState, useCallback, Fragment } from 'react'

const PAGE_SIZE = 50

export default function ReconcilePage({
  selectedRun,
  source = '',
  objectType = '',
  minPriority = 0,
  dedupKey = '',
  actionsRef,
  onUiState,
  onDeviceClick,
}) {
  const [rows, setRows] = useState([])
  const [count, setCount] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [selectedIds, setSelectedIds] = useState(() => new Set())

  const [gateStatus, setGateStatus] = useState(null)
  const [bulkProgress, setBulkProgress] = useState(null)
  const [bulkToast, setBulkToast] = useState(null)

  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyRows, setHistoryRows] = useState([])
  const [historyTotal, setHistoryTotal] = useState(0)

  const [modifyTarget, setModifyTarget] = useState(null)
  const [confirmAction, setConfirmAction] = useState(null)
  const [bootstrapBusy, setBootstrapBusy] = useState(false)
  const [errorDetailId, setErrorDetailId] = useState(null)   // row whose last-write error is expanded

  // Reset to page 1 whenever the (toolbar-owned) filters change
  useEffect(() => { setPage(1) }, [source, objectType, minPriority, dedupKey])

  // Write-gate status once on mount
  useEffect(() => {
    fetch('/api/reconcile/status')
      .then(res => (res.ok ? res.json() : null))
      .then(body => setGateStatus(body))
      .catch(() => setGateStatus(null))
  }, [])

  const fetchPending = useCallback(async () => {
    setLoading(true)
    try {
      const qs = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
      if (source) qs.set('source', source)
      if (objectType) qs.set('object_type', objectType)
      if (minPriority > 0) qs.set('min_priority', String(minPriority))
      if (dedupKey) qs.set('dedup_key', dedupKey)
      const res = await fetch(`/api/reconcile/pending?${qs.toString()}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      setRows(body.results || [])
      setCount(body.count || 0)
      setSelectedIds(new Set())
    } catch (e) {
      setBulkToast({ kind: 'error', message: `Failed to load pending: ${e.message}` })
    } finally {
      setLoading(false)
    }
  }, [source, objectType, minPriority, dedupKey, page])

  useEffect(() => { fetchPending() }, [fetchPending])

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/reconcile/history?page=1&page_size=20')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      setHistoryRows(body.results || [])
      setHistoryTotal(body.count || 0)
    } catch {
      setHistoryRows([]); setHistoryTotal(0)
    }
  }, [])

  useEffect(() => { if (historyOpen) fetchHistory() }, [historyOpen, fetchHistory])

  const handleBootstrap = useCallback(async () => {
    if (bootstrapBusy || !selectedRun) return
    setBootstrapBusy(true)
    setBulkToast(null)
    try {
      const res = await fetch('/api/reconcile/bootstrap', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: selectedRun }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail?.error?.message || `HTTP ${res.status}`)
      }
      const body = await res.json()
      setBulkToast({ kind: 'success', message: body.summary || 'Bootstrap complete.' })
      await fetchPending()
    } catch (e) {
      setBulkToast({ kind: 'error', message: `Bootstrap failed: ${e.message}` })
    } finally {
      setTimeout(() => setBootstrapBusy(false), 5000)
    }
  }, [bootstrapBusy, selectedRun, fetchPending])

  const handleApprove = async (id) => {
    try {
      const res = await fetch(`/api/reconcile/approve/${encodeURIComponent(id)}`, { method: 'POST' })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail?.error?.message || `HTTP ${res.status}`)
      }
      const body = await res.json()
      setBulkToast({
        kind: body.outcome === 'failed' ? 'warning' : 'success',
        message: `${body.outcome}: netbox_id=${body.netbox_object_id}, http=${body.api_response_status}`,
      })
      await fetchPending()
    } catch (e) { setBulkToast({ kind: 'error', message: e.message }) }
  }

  const handleReject = async (id) => {
    try {
      const res = await fetch(`/api/reconcile/reject/${encodeURIComponent(id)}`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setBulkToast({ kind: 'success', message: `Rejected ${id}` })
      await fetchPending()
    } catch (e) { setBulkToast({ kind: 'error', message: e.message }) }
  }

  const startBulkApprove = useCallback((ids = null) => {
    setBulkProgress({ position: 0, total: ids?.length || count })
    const qs = new URLSearchParams()
    if (ids) qs.set('ids', ids.join(','))
    else {
      if (source) qs.set('source', source)
      if (objectType) qs.set('object_type', objectType)
      if (minPriority > 0) qs.set('min_priority', String(minPriority))
    }
    const es = new EventSource(`/api/reconcile/approve_bulk/stream?${qs.toString()}`, { withCredentials: true })
    es.addEventListener('progress', (e) => {
      const data = JSON.parse(e.data)
      if (data.status !== 'writing') {
        setBulkProgress(prev => prev ? { ...prev, position: data.position, total: data.total } : null)
      }
    })
    es.addEventListener('complete', (e) => {
      const s = JSON.parse(e.data); es.close(); setBulkProgress(null)
      setBulkToast({
        kind: s.failed > 0 ? 'warning' : 'success',
        message: `Written: ${s.written}, Failed: ${s.failed}, Auto-resolved: ${s.auto_resolved}, Duration: ${Math.round(s.duration_ms / 100) / 10}s`,
      })
      fetchPending()
    })
    es.addEventListener('aborted', (e) => {
      const data = JSON.parse(e.data); es.close(); setBulkProgress(null)
      setBulkToast({ kind: 'error', message: `Bulk aborted: ${data.reason}` })
      fetchPending()
    })
    es.onerror = () => {
      es.close(); setBulkProgress(null)
      setBulkToast({ kind: 'error', message: 'SSE connection lost — refresh to verify state' })
      fetchPending()
    }
  }, [count, source, objectType, minPriority, fetchPending])

  const startBulkReject = useCallback(async (ids) => {
    try {
      const res = await fetch('/api/reconcile/reject_bulk', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      setBulkToast({ kind: 'success', message: `Rejected: ${body.rejected}, Not found: ${body.not_found}` })
      fetchPending()
    } catch (e) { setBulkToast({ kind: 'error', message: e.message }) }
  }, [fetchPending])

  const saveModify = async (newPayload) => {
    try {
      const res = await fetch(`/api/reconcile/modify/${encodeURIComponent(modifyTarget.id)}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: newPayload }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail?.error?.message || `HTTP ${res.status}`)
      }
      setBulkToast({ kind: 'success', message: `Modified ${modifyTarget.id}` })
      setModifyTarget(null); fetchPending()
    } catch (e) { setBulkToast({ kind: 'error', message: e.message }) }
  }

  // Selection helpers
  const toggleSelected = (id) => {
    const next = new Set(selectedIds)
    next.has(id) ? next.delete(id) : next.add(id)
    setSelectedIds(next)
  }
  const allOnPageSelected = rows.length > 0 && rows.every(r => selectedIds.has(r.id))
  const toggleSelectAll = () => {
    const next = new Set(selectedIds)
    if (allOnPageSelected) rows.forEach(r => next.delete(r.id))
    else rows.forEach(r => next.add(r.id))
    setSelectedIds(next)
  }

  const totalPages = Math.max(1, Math.ceil(count / PAGE_SIZE))
  const writesDisabled = gateStatus !== null && gateStatus.write_enabled === false

  // Expose actions to the Level-2 toolbar (ReportPanel idiom)
  useEffect(() => {
    if (!actionsRef) return
    actionsRef.current = {
      bootstrap: () => setConfirmAction({
        label: selectedRun
          ? `Stage NetBox candidates from run ${selectedRun} (idempotent — already staged/written objects are skipped)`
          : 'Select a run first',
        count: null,
        onConfirm: handleBootstrap,
      }),
      approveAllMatching: () => setConfirmAction({
        label: `Approve all ${count} candidates matching the current filters → write to NetBox`,
        count, onConfirm: () => startBulkApprove(null),
      }),
      approveSelected: () => setConfirmAction({
        label: `Approve ${selectedIds.size} selected candidates → write to NetBox`,
        count: selectedIds.size, onConfirm: () => startBulkApprove(Array.from(selectedIds)),
      }),
      rejectSelected: () => setConfirmAction({
        label: `Reject ${selectedIds.size} selected candidates → audit row + delete pending`,
        count: selectedIds.size, onConfirm: () => startBulkReject(Array.from(selectedIds)),
      }),
    }
  }, [actionsRef, selectedRun, count, selectedIds, handleBootstrap, startBulkApprove, startBulkReject])

  // Mirror reactive UI state up to the toolbar
  useEffect(() => {
    onUiState?.({
      count,
      selectedCount: selectedIds.size,
      bootstrapBusy,
      bulkActive: !!bulkProgress,
    })
  }, [onUiState, count, selectedIds, bootstrapBusy, bulkProgress])

  return (
    <div className="flex flex-1 min-h-0 flex-col">
      {writesDisabled && (
        <div className="shrink-0 px-3 py-2 text-xs"
          style={{ background: '#FFFBEB', borderBottom: '1px solid #FDE68A', color: '#92400E' }}>
          ⚠ NetBox writes are disabled (<code>NETBOX_WRITE_ENABLED=false</code>). You can review,
          modify and reject candidates; approvals will be refused until the deployment opts in.
          {gateStatus.netbox_configured === false && (
            <> NetBox is also unconfigured (<code>NETBOX_URL</code> / <code>NETBOX_API_TOKEN</code>).</>
          )}
        </div>
      )}

      {bulkProgress && (
        <div className="shrink-0 px-3 py-2 bg-blue-50 border-b border-blue-200">
          <div className="text-xs text-blue-900 mb-1">Approving… {bulkProgress.position}/{bulkProgress.total}</div>
          <div className="w-full bg-blue-200 rounded h-2">
            <div className="bg-blue-600 h-2 rounded transition-all duration-200"
              style={{ width: `${(bulkProgress.position / Math.max(1, bulkProgress.total)) * 100}%` }} />
          </div>
        </div>
      )}

      {bulkToast && (
        <div className="shrink-0 px-3 py-2 text-xs flex items-center justify-between"
          style={{
            background: bulkToast.kind === 'error' ? '#FEF2F2' : bulkToast.kind === 'warning' ? '#FFFBEB' : '#F0FDF4',
            borderBottom: '1px solid #E5E7EB',
            color: bulkToast.kind === 'error' ? '#991B1B' : bulkToast.kind === 'warning' ? '#92400E' : '#166534',
          }}>
          <span>{bulkToast.message}</span>
          <button onClick={() => setBulkToast(null)} className="text-xs underline ml-2">dismiss</button>
        </div>
      )}

      {/* Pending table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-100 border-b border-slate-200">
            <tr>
              <th className="px-2 py-1.5 text-left w-6">
                <input type="checkbox" checked={allOnPageSelected} onChange={toggleSelectAll} />
              </th>
              <th className="px-1 py-1.5 text-left w-8">Pri</th>
              <th className="px-1 py-1.5 text-left w-20">Type</th>
              <th className="px-2 py-1.5 text-left">Target</th>
              <th className="px-1 py-1.5 text-center w-20">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (<tr><td colSpan={5} className="px-2 py-4 text-center text-slate-500">Loading…</td></tr>)}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={5} className="px-2 py-4 text-center text-slate-500">
                No pending candidates. Use <strong>↻ Bootstrap</strong> in the toolbar to stage from the selected run.
              </td></tr>
            )}
            {!loading && rows.map(r => {
              const dk = dedupKeyForRow(r)
              const device = deviceForRow(r)
              const failed = Boolean(r.last_write_error)
              const expanded = errorDetailId === r.id
              return (
                <Fragment key={r.id}>
                <tr className={`border-b border-slate-100 hover:bg-slate-50 group ${failed ? 'bg-amber-50' : ''}`}>
                  <td className="px-2 py-1">
                    <input type="checkbox" checked={selectedIds.has(r.id)} onChange={() => toggleSelected(r.id)} />
                  </td>
                  <td className="px-1 py-1 font-mono text-slate-500">{r.priority}</td>
                  <td className="px-1 py-1">
                    <span className="px-1 py-0.5 rounded" style={{ background: '#F3E8FF', color: '#6B21A8', fontSize: 10 }}>{r.netbox_object_type}</span>
                  </td>
                  <td className="px-2 py-1 font-mono truncate" title={`${dk}${r.created_at ? ` · ${relativeTime(r.created_at)}` : ''}`}
                    style={device ? { cursor: 'pointer' } : undefined}
                    onClick={device ? () => onDeviceClick?.(device) : undefined}>
                    {failed && (
                      <button onClick={(e) => { e.stopPropagation(); setErrorDetailId(expanded ? null : r.id) }}
                        title="Last write failed — click to see the NetBox error"
                        className="mr-1 align-middle" style={{ fontSize: 12 }}>🔍</button>
                    )}
                    {device ? <span className="text-emerald-700 hover:underline">{dk}</span> : dk}
                  </td>
                  <td className="px-1 py-1 text-center whitespace-nowrap">
                    <button onClick={() => handleApprove(r.id)} title="Approve"
                      className="px-1 mx-0.5 rounded text-white" style={{ background: '#1D9E75', fontSize: 11 }}>✓</button>
                    <button onClick={() => setModifyTarget(r)} title="Modify"
                      className="px-1 mx-0.5 rounded text-white" style={{ background: '#6366F1', fontSize: 11 }}>✎</button>
                    <button onClick={() => handleReject(r.id)} title="Reject"
                      className="px-1 mx-0.5 rounded text-white" style={{ background: '#DC2626', fontSize: 11 }}>✕</button>
                  </td>
                </tr>
                {expanded && (
                  <tr className="bg-amber-50 border-b border-amber-200">
                    <td colSpan={5} className="px-3 py-2">
                      <div className="text-xs text-amber-900">
                        <span className="font-semibold">Last write failed</span>
                        {r.last_attempt_at ? <span className="text-amber-700"> · {relativeTime(r.last_attempt_at)}</span> : null}
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-amber-800 whitespace-pre-wrap break-words">
                        {r.last_write_error}
                      </div>
                      <div className="mt-1 text-[11px] text-amber-700">
                        Fix the cause (or ✎ Modify the payload) and re-approve, or ✕ Reject if this candidate shouldn't exist.
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

      {totalPages > 1 && (
        <div className="shrink-0 border-t border-slate-200 px-3 py-1.5 flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            className="text-xs px-2 py-0.5 border rounded disabled:opacity-50">‹ Prev</button>
          <span className="text-xs text-slate-600">Page {page} of {totalPages} · {count} pending</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
            className="text-xs px-2 py-0.5 border rounded disabled:opacity-50">Next ›</button>
        </div>
      )}

      {/* Write-history panel (collapsible) */}
      <div className="shrink-0 border-t border-slate-300">
        <button onClick={() => setHistoryOpen(o => !o)}
          className="w-full px-3 py-2 text-left text-xs font-medium hover:bg-slate-50" style={{ background: '#F1F5F9' }}>
          {historyOpen ? '▼' : '▶'} Write history ({historyTotal} audit rows)
        </button>
        {historyOpen && (
          <div className="max-h-56 overflow-auto">
            <table className="w-full text-xs">
              <thead className="bg-slate-100 sticky top-0">
                <tr>
                  <th className="px-2 py-1 text-left w-16">Status</th>
                  <th className="px-2 py-1 text-left w-20">Type</th>
                  <th className="px-2 py-1 text-left">Target</th>
                  <th className="px-2 py-1 text-left w-16">id</th>
                </tr>
              </thead>
              <tbody>
                {historyRows.map((w, i) => (
                  <tr key={w.id || i} className="border-b border-slate-100">
                    <td className="px-2 py-1 font-mono">{statusBadge(w)}</td>
                    <td className="px-2 py-1">{w.netbox_object_type}</td>
                    <td className="px-2 py-1 font-mono truncate" title={`${w.dedup_key} · ${(w.timestamp || '').slice(0, 19)} · ${w.source}`}>{w.dedup_key}</td>
                    <td className="px-2 py-1">{w.netbox_object_id || '—'}</td>
                  </tr>
                ))}
                {historyRows.length === 0 && (
                  <tr><td colSpan={4} className="px-2 py-3 text-center text-slate-500">No writes yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {confirmAction && (
        <ConfirmModal label={confirmAction.label} count={confirmAction.count}
          onCancel={() => setConfirmAction(null)}
          onConfirm={() => { confirmAction.onConfirm(); setConfirmAction(null) }} />
      )}
      {modifyTarget && (
        <ModifyModal candidate={modifyTarget} onCancel={() => setModifyTarget(null)} onSave={saveModify} />
      )}
    </div>
  )
}

// ── Sub-components ───────────────────────────────────────────────────────────

function ConfirmModal({ label, count, onCancel, onConfirm }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onCancel}>
      <div className="bg-white rounded p-4 max-w-md mx-4" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold mb-2">Confirm</h3>
        <p className="text-sm text-slate-700 mb-4">{label}</p>
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1 text-sm border border-slate-300 rounded">Cancel</button>
          <button onClick={onConfirm} className="px-3 py-1 text-sm rounded" style={{ background: '#1D4ED8', color: '#FFF' }}>
            {count != null ? `Confirm (${count})` : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

function ModifyModal({ candidate, onCancel, onSave }) {
  const [text, setText] = useState(() => JSON.stringify(candidate.payload, null, 2))
  const [error, setError] = useState(null)
  const handleSave = () => {
    try {
      const parsed = JSON.parse(text)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('Payload must be a JSON object')
      }
      onSave(parsed)
    } catch (e) { setError(e.message) }
  }
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onCancel}>
      <div className="bg-white rounded p-4 w-full max-w-3xl mx-4" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold mb-1">Modify candidate</h3>
        <p className="text-xs text-slate-600 mb-3">{candidate.netbox_object_type} • {dedupKeyForRow(candidate)}</p>
        <textarea value={text} onChange={e => { setText(e.target.value); setError(null) }}
          className="w-full font-mono text-xs border border-slate-300 rounded p-2" rows={20} spellCheck={false} />
        {error && (<div className="mt-2 text-xs text-red-700">⚠ {error}</div>)}
        <div className="mt-3 flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1 text-sm border border-slate-300 rounded">Cancel</button>
          <button onClick={handleSave} className="px-3 py-1 text-sm rounded" style={{ background: '#1D4ED8', color: '#FFF' }}>Save</button>
        </div>
      </div>
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function dedupKeyForRow(r) {
  const t = r.netbox_object_type
  const p = r.payload || {}
  if (t === 'site' || t === 'platform') return p.slug || ''
  if (t === 'manufacturer' || t === 'vrf') return p.name || ''
  if (t === 'device' || t === 'cluster' || t === 'virtual_chassis') return p.name || ''
  if (t === 'vlan') return `${p.vid ?? ''} ${p.name || ''}`.trim()
  if (t === 'prefix') return p.prefix || p.dedup_key || ''
  if (t === 'ipaddress') return p.address || ''
  if (t === 'cable') return p.dedup_key || ''
  if (t === 'interface' || t === 'inventory_item') {
    return p.dedup_key || `${p.device?.name || p.device}::${p.name}`
  }
  return JSON.stringify(p)
}

// The device a candidate touches — for highlighting it on the topology.
// Non-device candidates (site / manufacturer / platform / vlan / prefix /
// vrf) have no single device and simply don't highlight.
function deviceForRow(r) {
  const t = r.netbox_object_type
  const p = r.payload || {}
  if (t === 'device' || t === 'cluster' || t === 'virtual_chassis') return p.name || null
  if (t === 'interface' || t === 'inventory_item') {
    return p._resolve_device_name || p.device?.name || (typeof p.device === 'string' ? p.device : null)
  }
  if (t === 'ipaddress') return p._resolve_device_name || null
  if (t === 'cable') return p._resolve_a_device || null
  return null
}

function relativeTime(iso) {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (!t) return iso.slice(0, 19)
  const mins = Math.round((Date.now() - t) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}

function statusBadge(w) {
  const s = w.api_response_status
  if (w.source === 'manual_reject') return '[REJECT]'
  if (s === null || s === undefined) return '[NULL]'
  if (s >= 200 && s < 300) {
    if ((w.reason || '').toLowerCase().includes('auto-resolved')) return `[409→${s}]`
    return `[${s}]`
  }
  return `[${s}] FAIL`
}
