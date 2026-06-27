import { useEffect, useState } from 'react'
import DropdownPicker from './DropdownPicker.jsx'

export default function RunSelector({ selectedRun, onRunChange, refreshKey }) {
  const [runs, setRuns] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchRuns()
  }, [])

  // Refetch when a run completes (new run / updated finding counts).
  useEffect(() => {
    if (refreshKey) fetchRuns()
  }, [refreshKey])

  // When App.jsx sets selectedRun to a run we don't yet have (post Run Now),
  // refetch so the list stays consistent with the selection.
  useEffect(() => {
    if (selectedRun && runs.length > 0 && !runs.some((r) => r.run_id === selectedRun)) {
      fetchRuns()
    }
  }, [selectedRun, runs])

  async function fetchRuns() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/runs')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const list = data.runs || []
      setRuns(list)
      if (!selectedRun && list.length > 0) {
        const sorted = [...list].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
        onRunChange(sorted[0].run_id)
      }
      return list
    } catch (err) {
      setError(err.message)
      return []
    } finally {
      setLoading(false)
    }
  }

  function formatRunLabel(run) {
    const date = run.timestamp
      ? new Date(run.timestamp).toLocaleDateString('en-GB', {
          day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
        })
      : run.run_id
    const count = run.total_findings || 0
    return `${date} — ${count} findings`
  }

  async function deleteRun(item) {
    try {
      await fetch(`/api/runs/${encodeURIComponent(item.site)}/${encodeURIComponent(item.id)}`, { method: 'DELETE' })
    } catch { /* surfaced via refetch */ }
    const list = await fetchRuns()
    if (item.id === selectedRun) {
      const next = list.find((r) => r.run_id !== item.id)
      onRunChange(next ? next.run_id : '')
    }
  }

  if (error) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-red-400 text-sm">Cannot connect to API</span>
        <button
          onClick={fetchRuns}
          className="text-xs hover:opacity-80 text-white px-2 py-1 rounded"
          style={{ background: '#475569' }}
        >
          Retry
        </button>
      </div>
    )
  }

  if (loading) {
    return <span style={{ color: '#94A3B8' }} className="text-sm">Loading runs...</span>
  }

  const items = [...runs]
    .sort(
      (a, b) =>
        (a.site || '').localeCompare(b.site || '') ||
        (b.timestamp || '').localeCompare(a.timestamp || '')
    )
    .map((r) => ({
      id: r.run_id,
      label: formatRunLabel(r),
      group: (r.site || 'unknown').toUpperCase(),
      deletable: true,
      site: r.site,
    }))

  return (
    <DropdownPicker
      items={items}
      selectedId={selectedRun || ''}
      onSelect={onRunChange}
      onDelete={deleteRun}
      placeholder={items.length ? 'Select a run…' : 'No runs yet'}
      minWidth={220}
      deleteTitle={() => 'Delete run'}
      deleteMessage={(it) =>
        `Delete the loaded run "${it.label}" (site ${it.site})? This removes its topology, findings, and all graph data, and cannot be undone.`}
    />
  )
}
