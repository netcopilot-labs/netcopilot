/**
 * ReconcilePage — Reconcile dashboard tab (s12, ADR-0014).
 *
 * Operator-facing surface for the NetBox staged-approval workflow
 * (Constitution Art. I: staged, human-approved-per-write, audited,
 * non-destructive):
 *   - Write-gate banner (NETBOX_WRITE_ENABLED off → approvals will be refused)
 *   - Filter sidebar (source / object_type / min_priority / target search)
 *   - Pending writes table (50/page, per-row + bulk actions, sticky toolbar)
 *   - SSE-driven progress bar during bulk approve
 *   - Confirmation modals on bulk actions
 *   - Modify modal (textarea-based JSON editor; client-side parse validation)
 *   - Collapsible write-history panel
 *
 * Self-contained for simplicity (sub-components live as inline functions).
 * Calls into the /api/reconcile/* routes.
 */
import { useEffect, useState, useCallback } from 'react'

const PAGE_SIZE = 50

const SOURCES = ['bootstrap', 'drift', 'manual']
const OBJECT_TYPES = [
  'site', 'manufacturer', 'platform', 'cluster', 'virtual_chassis',
  'device', 'interface', 'inventory_item',
]

export default function ReconcilePage({ selectedRun }) {
  // Filters — URL-driven so refresh preserves state
  const [source, setSource] = useState(() => getQueryParam('source') || '')
  const [objectType, setObjectType] = useState(() => getQueryParam('object_type') || '')
  const [minPriority, setMinPriority] = useState(() => parseInt(getQueryParam('min_priority') || '0', 10))
  const [dedupKey, setDedupKey] = useState(() => getQueryParam('dedup_key') || '')
  const [page, setPage] = useState(() => parseInt(getQueryParam('page') || '1', 10))

  // Table state
  const [rows, setRows] = useState([])
  const [count, setCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [selectedIds, setSelectedIds] = useState(() => new Set())

  // Write-gate state (s12: surface the Constitution Art. I gate honestly —
  // a standing banner beats an opaque 403 on every Approve click)
  const [gateStatus, setGateStatus] = useState(null) // {write_enabled, netbox_configured}

  // Bulk-progress state
  const [bulkProgress, setBulkProgress] = useState(null) // {position, total}
  const [bulkToast, setBulkToast] = useState(null)

  // History panel state
  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyRows, setHistoryRows] = useState([])
  const [historyTotal, setHistoryTotal] = useState(0)

  // Modals
  const [modifyTarget, setModifyTarget] = useState(null) // candidate row being edited
  const [confirmAction, setConfirmAction] = useState(null) // {label, count, onConfirm}

  // Bootstrap button state
  const [bootstrapBusy, setBootstrapBusy] = useState(false)

  // Fetch the write-gate status once on mount
  useEffect(() => {
    fetch('/api/reconcile/status')
      .then(res => (res.ok ? res.json() : null))
      .then(body => setGateStatus(body))
      .catch(() => setGateStatus(null))
  }, [])

  // Push filter state into URL whenever it changes
  useEffect(() => {
    const params = new URLSearchParams()
    if (source) params.set('source', source)
    if (objectType) params.set('object_type', objectType)
    if (minPriority > 0) params.set('min_priority', String(minPriority))
    if (dedupKey) params.set('dedup_key', dedupKey)
    if (page > 1) params.set('page', String(page))
    const url = new URL(window.location.href)
    url.search = params.toString()
    window.history.replaceState(null, '', url.toString())
  }, [source, objectType, minPriority, dedupKey, page])

  // Fetch pending candidates whenever filters/page change
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
      setSelectedIds(new Set()) // clear selection on data change
    } catch (e) {
      setBulkToast({ kind: 'error', message: `Failed to load pending: ${e.message}` })
    } finally {
      setLoading(false)
    }
  }, [source, objectType, minPriority, dedupKey, page])

  useEffect(() => {
    fetchPending()
  }, [fetchPending])

  const fetchHistory = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ page: '1', page_size: '20' })
      const res = await fetch(`/api/reconcile/history?${qs.toString()}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      setHistoryRows(body.results || [])
      setHistoryTotal(body.count || 0)
    } catch (e) {
      setHistoryRows([])
      setHistoryTotal(0)
    }
  }, [])

  useEffect(() => {
    if (historyOpen) fetchHistory()
  }, [historyOpen, fetchHistory])

  // Bootstrap button — stages candidates from the currently selected run
  const handleBootstrap = async () => {
    if (bootstrapBusy || !selectedRun) return
    setBootstrapBusy(true)
    setBulkToast(null)
    try {
      const res = await fetch('/api/reconcile/bootstrap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      // 5s cooldown so the button can't be spammed
      setTimeout(() => setBootstrapBusy(false), 5000)
    }
  }

  // Per-row actions
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
    } catch (e) {
      setBulkToast({ kind: 'error', message: e.message })
    }
  }

  const handleReject = async (id) => {
    try {
      const res = await fetch(`/api/reconcile/reject/${encodeURIComponent(id)}`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setBulkToast({ kind: 'success', message: `Rejected ${id}` })
      await fetchPending()
    } catch (e) {
      setBulkToast({ kind: 'error', message: e.message })
    }
  }

  // Bulk approve via SSE stream
  const startBulkApprove = (ids = null) => {
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
        // Terminal status for this candidate
        setBulkProgress(prev => prev ? { ...prev, position: data.position, total: data.total } : null)
      }
    })

    es.addEventListener('complete', (e) => {
      const summary = JSON.parse(e.data)
      es.close()
      setBulkProgress(null)
      setBulkToast({
        kind: summary.failed > 0 ? 'warning' : 'success',
        message: `Written: ${summary.written}, Failed: ${summary.failed}, Auto-resolved: ${summary.auto_resolved}, Duration: ${Math.round(summary.duration_ms / 100) / 10}s`,
      })
      fetchPending()
    })

    es.addEventListener('aborted', (e) => {
      const data = JSON.parse(e.data)
      es.close()
      setBulkProgress(null)
      setBulkToast({ kind: 'error', message: `Bulk aborted: ${data.reason}` })
      fetchPending()
    })

    es.onerror = () => {
      es.close()
      setBulkProgress(null)
      setBulkToast({ kind: 'error', message: 'SSE connection lost — refresh to verify state' })
      fetchPending()
    }
  }

  const startBulkReject = async (ids) => {
    try {
      const res = await fetch('/api/reconcile/reject_bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      setBulkToast({
        kind: 'success',
        message: `Rejected: ${body.rejected}, Not found: ${body.not_found}`,
      })
      fetchPending()
    } catch (e) {
      setBulkToast({ kind: 'error', message: e.message })
    }
  }

  // Modify modal — save handler
  const saveModify = async (newPayload) => {
    try {
      const res = await fetch(`/api/reconcile/modify/${encodeURIComponent(modifyTarget.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: newPayload }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail?.error?.message || `HTTP ${res.status}`)
      }
      setBulkToast({ kind: 'success', message: `Modified ${modifyTarget.id}` })
      setModifyTarget(null)
      fetchPending()
    } catch (e) {
      setBulkToast({ kind: 'error', message: e.message })
    }
  }

  // Selection helpers
  const toggleSelected = (id) => {
    const next = new Set(selectedIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedIds(next)
  }
  const allOnPageSelected = rows.length > 0 && rows.every(r => selectedIds.has(r.id))
  const toggleSelectAll = () => {
    if (allOnPageSelected) {
      const next = new Set(selectedIds)
      rows.forEach(r => next.delete(r.id))
      setSelectedIds(next)
    } else {
      const next = new Set(selectedIds)
      rows.forEach(r => next.add(r.id))
      setSelectedIds(next)
    }
  }

  const totalPages = Math.max(1, Math.ceil(count / PAGE_SIZE))
  const writesDisabled = gateStatus !== null && gateStatus.write_enabled === false

  return (
    <div className="flex flex-1 min-h-0 flex-col">
      {/* Write-gate banner — Constitution Art. I surfaced up front */}
      {writesDisabled && (
        <div
          className="shrink-0 px-3 py-2 text-sm"
          style={{ background: '#FFFBEB', borderBottom: '1px solid #FDE68A', color: '#92400E' }}
        >
          ⚠ NetBox writes are disabled (<code>NETBOX_WRITE_ENABLED=false</code>).
          You can review, modify and reject candidates; approvals will be refused
          until the deployment opts in.
          {gateStatus.netbox_configured === false && (
            <> NetBox is also unconfigured (<code>NETBOX_URL</code> / <code>NETBOX_API_TOKEN</code>).</>
          )}
        </div>
      )}

      <div className="flex flex-1 min-h-0">
      {/* ── Left filter sidebar ────────────────────────────────────── */}
      <aside className="shrink-0 border-r border-slate-200 bg-slate-50 p-3" style={{ width: 240, overflowY: 'auto' }}>
        <button
          onClick={() => setConfirmAction({
            label: selectedRun
              ? `Stage NetBox candidates from run ${selectedRun} (idempotent — already staged/written objects are skipped)`
              : 'Select a run first',
            count: null,
            onConfirm: handleBootstrap,
          })}
          disabled={bootstrapBusy || !selectedRun}
          title={selectedRun ? `Stage candidates from ${selectedRun}` : 'Select a run in the top bar first'}
          className="w-full px-3 py-2 mb-4 rounded text-sm font-medium"
          style={{
            background: bootstrapBusy || !selectedRun ? '#94A3B8' : '#1D9E75',
            color: '#FFFFFF',
            cursor: bootstrapBusy || !selectedRun ? 'not-allowed' : 'pointer',
          }}
        >
          {bootstrapBusy ? '⏳ Cooldown…' : '↻ Bootstrap from run'}
        </button>

        <FilterField label="Source">
          <select value={source} onChange={e => { setSource(e.target.value); setPage(1) }} className="w-full p-1 text-sm border border-slate-300 rounded">
            <option value="">all</option>
            {SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </FilterField>

        <FilterField label="Object type">
          <select value={objectType} onChange={e => { setObjectType(e.target.value); setPage(1) }} className="w-full p-1 text-sm border border-slate-300 rounded">
            <option value="">all</option>
            {OBJECT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </FilterField>

        <FilterField label={`Min priority: ${minPriority}`}>
          <input
            type="range" min="0" max="100" value={minPriority}
            onChange={e => { setMinPriority(parseInt(e.target.value, 10)); setPage(1) }}
            className="w-full"
          />
        </FilterField>

        <FilterField label="Search target">
          <input
            type="text" placeholder="e.g. acc-sw-01" value={dedupKey}
            onChange={e => { setDedupKey(e.target.value); setPage(1) }}
            className="w-full p-1 text-sm border border-slate-300 rounded"
          />
        </FilterField>

        <div className="mt-4 text-xs text-slate-500">
          {count} pending<br/>
          Page {page} of {totalPages}
        </div>
      </aside>

      {/* ── Center: pending table + history panel ─────────────────── */}
      <main className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {/* Sticky toolbar (selection actions + always-on bulk-all) */}
        <div className="shrink-0 border-b border-slate-200 bg-white px-3 py-2 flex items-center justify-between" style={{ minHeight: 44 }}>
          <div className="text-sm text-slate-700">
            {selectedIds.size > 0 ? (
              <span><strong>{selectedIds.size}</strong> selected on this page</span>
            ) : (
              <span className="text-slate-500">No selection</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {selectedIds.size > 0 && (
              <>
                <button
                  onClick={() => setConfirmAction({
                    label: `Approve ${selectedIds.size} selected candidates → write to NetBox`,
                    count: selectedIds.size,
                    onConfirm: () => startBulkApprove(Array.from(selectedIds)),
                  })}
                  className="px-3 py-1 rounded text-xs font-medium"
                  style={{ background: '#1D9E75', color: '#FFFFFF' }}
                >
                  Approve selected
                </button>
                <button
                  onClick={() => setConfirmAction({
                    label: `Reject ${selectedIds.size} selected candidates → audit row + delete pending`,
                    count: selectedIds.size,
                    onConfirm: () => startBulkReject(Array.from(selectedIds)),
                  })}
                  className="px-3 py-1 rounded text-xs font-medium"
                  style={{ background: '#DC2626', color: '#FFFFFF' }}
                >
                  Reject selected
                </button>
              </>
            )}
            <button
              onClick={() => setConfirmAction({
                label: `Approve all ${count} candidates matching the current filters → write to NetBox`,
                count,
                onConfirm: () => startBulkApprove(null),
              })}
              disabled={count === 0 || !!bulkProgress}
              className="px-3 py-1 rounded text-xs font-medium"
              style={{
                background: count === 0 || bulkProgress ? '#94A3B8' : '#1D4ED8',
                color: '#FFFFFF',
                cursor: count === 0 || bulkProgress ? 'not-allowed' : 'pointer',
              }}
            >
              Approve all matching filters
            </button>
          </div>
        </div>

        {/* Bulk progress bar */}
        {bulkProgress && (
          <div className="shrink-0 px-3 py-2 bg-blue-50 border-b border-blue-200">
            <div className="text-xs text-blue-900 mb-1">
              Approving… {bulkProgress.position}/{bulkProgress.total}
            </div>
            <div className="w-full bg-blue-200 rounded h-2">
              <div
                className="bg-blue-600 h-2 rounded transition-all duration-200"
                style={{ width: `${(bulkProgress.position / Math.max(1, bulkProgress.total)) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Toast */}
        {bulkToast && (
          <div
            className="shrink-0 px-3 py-2 text-sm flex items-center justify-between"
            style={{
              background: bulkToast.kind === 'error' ? '#FEF2F2' : bulkToast.kind === 'warning' ? '#FFFBEB' : '#F0FDF4',
              borderBottom: '1px solid #E5E7EB',
              color: bulkToast.kind === 'error' ? '#991B1B' : bulkToast.kind === 'warning' ? '#92400E' : '#166534',
            }}
          >
            <span>{bulkToast.message}</span>
            <button onClick={() => setBulkToast(null)} className="text-xs underline">dismiss</button>
          </div>
        )}

        {/* Table */}
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-100 border-b border-slate-200">
              <tr>
                <th className="px-2 py-1.5 text-left w-8">
                  <input type="checkbox" checked={allOnPageSelected} onChange={toggleSelectAll} />
                </th>
                <th className="px-2 py-1.5 text-left w-16">Pri</th>
                <th className="px-2 py-1.5 text-left w-28">Source</th>
                <th className="px-2 py-1.5 text-left w-32">Type</th>
                <th className="px-2 py-1.5 text-left">Target</th>
                <th className="px-2 py-1.5 text-left w-32">Created</th>
                <th className="px-2 py-1.5 text-right w-44">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} className="px-2 py-4 text-center text-slate-500">Loading…</td></tr>
              )}
              {!loading && rows.length === 0 && (
                <tr><td colSpan={7} className="px-2 py-4 text-center text-slate-500">
                  No pending candidates. Click <strong>↻ Bootstrap from run</strong> to stage from the selected run.
                </td></tr>
              )}
              {!loading && rows.map(r => {
                const dk = dedupKeyForRow(r)
                return (
                  <tr key={r.id} className="border-b border-slate-100 hover:bg-slate-50">
                    <td className="px-2 py-1">
                      <input type="checkbox" checked={selectedIds.has(r.id)} onChange={() => toggleSelected(r.id)} />
                    </td>
                    <td className="px-2 py-1 font-mono text-xs">{r.priority}</td>
                    <td className="px-2 py-1">
                      <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#E0F2FE', color: '#075985' }}>{r.source}</span>
                    </td>
                    <td className="px-2 py-1">
                      <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#F3E8FF', color: '#6B21A8' }}>{r.netbox_object_type}</span>
                    </td>
                    <td className="px-2 py-1 font-mono text-xs">{dk}</td>
                    <td className="px-2 py-1 text-xs text-slate-600">{relativeTime(r.created_at)}</td>
                    <td className="px-2 py-1 text-right">
                      <button onClick={() => handleApprove(r.id)} className="px-2 py-0.5 mx-0.5 text-xs rounded" style={{ background: '#1D9E75', color: '#FFF' }}>Approve</button>
                      <button onClick={() => handleReject(r.id)} className="px-2 py-0.5 mx-0.5 text-xs rounded" style={{ background: '#DC2626', color: '#FFF' }}>Reject</button>
                      <button onClick={() => setModifyTarget(r)} className="px-2 py-0.5 mx-0.5 text-xs rounded" style={{ background: '#6366F1', color: '#FFF' }}>Modify</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="shrink-0 border-t border-slate-200 px-3 py-2 flex items-center justify-center gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="text-xs px-2 py-1 border rounded disabled:opacity-50">‹ Prev</button>
            <span className="text-xs text-slate-600">Page {page} of {totalPages}</span>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="text-xs px-2 py-1 border rounded disabled:opacity-50">Next ›</button>
          </div>
        )}

        {/* History panel (collapsible) */}
        <div className="shrink-0 border-t border-slate-300">
          <button
            onClick={() => setHistoryOpen(o => !o)}
            className="w-full px-3 py-2 text-left text-sm font-medium hover:bg-slate-50"
            style={{ background: '#F1F5F9' }}
          >
            {historyOpen ? '▼' : '▶'} Write history ({historyTotal} audit rows)
          </button>
          {historyOpen && (
            <div className="max-h-64 overflow-auto">
              <table className="w-full text-xs">
                <thead className="bg-slate-100 sticky top-0">
                  <tr>
                    <th className="px-2 py-1 text-left w-20">Status</th>
                    <th className="px-2 py-1 text-left w-32">Time</th>
                    <th className="px-2 py-1 text-left w-24">Type</th>
                    <th className="px-2 py-1 text-left">Target</th>
                    <th className="px-2 py-1 text-left w-20">NetBox id</th>
                    <th className="px-2 py-1 text-left w-24">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {historyRows.map((w, i) => (
                    <tr key={w.id || i} className="border-b border-slate-100">
                      <td className="px-2 py-1 font-mono">{statusBadge(w)}</td>
                      <td className="px-2 py-1 text-slate-600">{(w.timestamp || '').slice(0, 19)}</td>
                      <td className="px-2 py-1">{w.netbox_object_type}</td>
                      <td className="px-2 py-1 font-mono">{w.dedup_key}</td>
                      <td className="px-2 py-1">{w.netbox_object_id || '—'}</td>
                      <td className="px-2 py-1 text-slate-600">{w.source}</td>
                    </tr>
                  ))}
                  {historyRows.length === 0 && (
                    <tr><td colSpan={6} className="px-2 py-3 text-center text-slate-500">No writes yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Modals */}
        {confirmAction && (
          <ConfirmModal
            label={confirmAction.label}
            count={confirmAction.count}
            onCancel={() => setConfirmAction(null)}
            onConfirm={() => { confirmAction.onConfirm(); setConfirmAction(null) }}
          />
        )}
        {modifyTarget && (
          <ModifyModal
            candidate={modifyTarget}
            onCancel={() => setModifyTarget(null)}
            onSave={saveModify}
          />
        )}
      </main>
      </div>
    </div>
  )
}

// ── Sub-components ───────────────────────────────────────────────────────────

function FilterField({ label, children }) {
  return (
    <label className="block mb-3">
      <div className="text-xs font-medium text-slate-700 mb-1">{label}</div>
      {children}
    </label>
  )
}

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
    } catch (e) {
      setError(e.message)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onCancel}>
      <div className="bg-white rounded p-4 w-full max-w-3xl mx-4" onClick={e => e.stopPropagation()}>
        <h3 className="text-base font-semibold mb-1">Modify candidate</h3>
        <p className="text-xs text-slate-600 mb-3">
          {candidate.netbox_object_type} • {dedupKeyForRow(candidate)}
        </p>
        <textarea
          value={text}
          onChange={e => { setText(e.target.value); setError(null) }}
          className="w-full font-mono text-xs border border-slate-300 rounded p-2"
          rows={20}
          spellCheck={false}
        />
        {error && (
          <div className="mt-2 text-xs text-red-700">⚠ {error}</div>
        )}
        <div className="mt-3 flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1 text-sm border border-slate-300 rounded">Cancel</button>
          <button onClick={handleSave} className="px-3 py-1 text-sm rounded" style={{ background: '#1D4ED8', color: '#FFF' }}>
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getQueryParam(name) {
  const url = new URL(window.location.href)
  return url.searchParams.get(name)
}

function dedupKeyForRow(r) {
  const t = r.netbox_object_type
  const p = r.payload || {}
  if (t === 'site' || t === 'platform') return p.slug || ''
  if (t === 'manufacturer') return p.name || ''
  if (t === 'device' || t === 'cluster' || t === 'virtual_chassis') return p.name || ''
  if (t === 'interface' || t === 'inventory_item') {
    return p.dedup_key || `${p.device?.name || p.device}::${p.name}`
  }
  return JSON.stringify(p)
}

function relativeTime(iso) {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (!t) return iso.slice(0, 19)
  const dt = Date.now() - t
  const mins = Math.round(dt / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}

function statusBadge(w) {
  const s = w.api_response_status
  const src = w.source
  if (src === 'manual_reject') return '[REJECT]'
  if (s === null || s === undefined) return '[NULL]'
  if (s >= 200 && s < 300) {
    if ((w.reason || '').toLowerCase().includes('auto-resolved')) return `[409→${s}]`
    return `[${s}]`
  }
  return `[${s}] FAIL`
}
