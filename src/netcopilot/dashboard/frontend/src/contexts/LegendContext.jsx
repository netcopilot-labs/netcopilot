/**
 * LegendContext — C9S8.
 *
 * Fetches severity and role styling metadata from GET /api/legend on
 * app mount.  Every consumer component uses the useLegend() hook
 * instead of importing static constants from topologyUtils.js.
 *
 * The backend is the single source of truth — adding a new severity
 * or role means editing routes/legend.py, not a JS file.
 *
 * ADR-312.
 */

import { createContext, useContext, useState, useEffect } from 'react'

const LegendContext = createContext(null)

/**
 * Wrap the app tree in <LegendProvider> to make legend data available
 * to all descendants via useLegend().
 *
 * While loading, renders a centered spinner.
 * On error, renders a retry button.
 */
export function LegendProvider({ children }) {
  const [legend, setLegend] = useState(null)
  const [error, setError] = useState(null)

  const fetchLegend = () => {
    setError(null)
    fetch('/api/legend')
      .then(res => {
        if (!res.ok) throw new Error(`Legend fetch failed: ${res.status}`)
        return res.json()
      })
      .then(data => {
        // Transform arrays into the object shapes components expect
        const severityOrder = data.severities.map(s => s.id)

        const sevColors = {}
        data.severities.forEach(s => {
          sevColors[s.id] = { color: s.color, bg: s.bg }
        })

        const roleTiers = {}
        const roleColors = {}
        data.roles.forEach(r => {
          roleTiers[r.id] = r.tier
          roleColors[r.id] = r.color
        })

        setLegend({
          severityOrder,
          sevColors,
          roleTiers,
          roleColors,
          defaultRole: data.default_role,
        })
      })
      .catch(err => {
        console.error('LegendContext: fetch failed', err)
        setError(err.message)
      })
  }

  useEffect(() => { fetchLegend() }, [])

  // Loading state — brief spinner blocks rendering until legend is ready
  if (!legend && !error) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', fontFamily: 'system-ui',
      }}>
        <div style={{ textAlign: 'center', color: '#6b7280' }}>
          <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>⟳</div>
          <div>Loading NetCopilot…</div>
        </div>
      </div>
    )
  }

  // Error state — show message + retry
  if (error) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', fontFamily: 'system-ui',
      }}>
        <div style={{ textAlign: 'center', color: '#dc2626' }}>
          <div style={{ fontSize: '1.2rem', marginBottom: '0.5rem' }}>
            Failed to load legend metadata
          </div>
          <div style={{ fontSize: '0.9rem', color: '#6b7280', marginBottom: '1rem' }}>
            {error}
          </div>
          <button
            onClick={fetchLegend}
            style={{
              padding: '0.5rem 1rem', cursor: 'pointer',
              border: '1px solid #d1d5db', borderRadius: '0.375rem',
              background: '#fff',
            }}
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <LegendContext.Provider value={legend}>
      {children}
    </LegendContext.Provider>
  )
}

/**
 * Hook to access legend data from any component inside <LegendProvider>.
 *
 * Returns: { severityOrder, sevColors, roleTiers, roleColors, defaultRole }
 */
export function useLegend() {
  const ctx = useContext(LegendContext)
  if (!ctx) {
    throw new Error('useLegend() must be used inside <LegendProvider>')
  }
  return ctx
}
