import { useEffect, useState } from 'react'

export default function RunSelector({ selectedRun, onRunChange }) {
  const [runs, setRuns] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchRuns()
  }, [])

  // When App.jsx sets selectedRun to a run we don't yet have in our list
  // (post Run Now), refetch so the dropdown's <option> list stays consistent
  // with the <select>'s value. Without this, the <select> renders blank-ish
  // for the new run because none of its <option>s match.
  useEffect(() => {
    if (selectedRun && runs.length > 0 && !runs.some(r => r.run_id === selectedRun)) {
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
      setRuns(data.runs || [])
      // Auto-pick the most recent run by timestamp (run date), not API order
      // (which is loaded_at / Neo4j ingest time).
      if (!selectedRun && data.runs?.length > 0) {
        const sorted = [...data.runs].sort(
          (a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')
        )
        onRunChange(sorted[0].run_id)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function formatRunLabel(run) {
    const site = run.site !== 'unknown' ? run.site.toUpperCase() : ''
    const date = run.timestamp
      ? new Date(run.timestamp).toLocaleDateString('en-GB', {
          day: '2-digit', month: 'short', year: 'numeric',
          hour: '2-digit', minute: '2-digit'
        })
      : run.run_id
    const count = run.total_findings || 0
    const parts = [site, date, `${count} findings`].filter(Boolean)
    return parts.join(' \u2014 ')
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

  // Group runs by site, sorted newest-first within each group
  const grouped = {}
  for (const run of runs) {
    const site = (run.site || 'unknown').toUpperCase()
    if (!grouped[site]) grouped[site] = []
    grouped[site].push(run)
  }
  // Sort runs within each group by timestamp descending
  for (const site of Object.keys(grouped)) {
    grouped[site].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
  }
  // Sort groups alphabetically; show all sites.
  const sortedSites = Object.keys(grouped).sort()

  return (
    <select
      value={selectedRun || ''}
      onChange={(e) => onRunChange(e.target.value)}
      className="text-sm rounded px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-500 max-w-md"
      style={{
        background: '#334155',
        color: '#E2E8F0',
        border: '1px solid #475569',
      }}
    >
      {sortedSites.map((site) => (
        <optgroup key={site} label={site}>
          {grouped[site].map((run) => (
            <option key={run.run_id} value={run.run_id}>
              {formatRunLabel(run)}
            </option>
          ))}
        </optgroup>
      ))}
    </select>
  )
}
