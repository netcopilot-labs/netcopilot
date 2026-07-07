// ServicesPanel — the Services lens (s16, ADR-0019).
//
// Lives in the LEFT panel while the Service topology view is active: the
// run's operator-named services (NetBox × observed), searchable, with the
// join trigger. Located rows click through to their owning device on the
// map (highlight only — the lens stays, s14b convention); unlocated rows
// are listed honestly (nothing to attach to on the map).
import { useCallback, useEffect, useState } from 'react'

const METHOD_LABEL = {
  'arp+fdb': { text: 'port-precise', color: '#1D9E75' },
  arp: { text: 'gateway', color: '#0EA5E9' },
  subnet: { text: 'approximate', color: '#F59E0B' },
  colocated: { text: 'VLAN-placed', color: '#F59E0B' },
  gateway: { text: 'gateway', color: '#2563EB' },
  'gateway-containing': { text: 'aggregate', color: '#F59E0B' },
  none: { text: 'never seen', color: '#9CA3AF' },
}

export default function ServicesPanel({ selectedRun, onServiceClick }) {
  const [services, setServices] = useState([])
  const [joined, setJoined] = useState(true)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [joining, setJoining] = useState(false)
  const [error, setError] = useState(null)

  const refresh = useCallback(async () => {
    if (!selectedRun) return
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/services?run_id=${encodeURIComponent(selectedRun)}`)
      if (!res.ok) throw new Error((await res.json()).detail || `HTTP ${res.status}`)
      const d = await res.json()
      setServices(d.services || [])
      setJoined(Boolean(d.joined))
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }, [selectedRun])

  useEffect(() => { refresh() }, [refresh])

  const runJoin = useCallback(async () => {
    setJoining(true)
    setError(null)
    try {
      const res = await fetch('/api/services/join', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: selectedRun }),
      })
      if (!res.ok) throw new Error((await res.json()).detail || `HTTP ${res.status}`)
      await refresh()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setJoining(false)
    }
  }, [selectedRun, refresh])

  const q = search.trim().toLowerCase()
  const filtered = services.filter(s =>
    !q
    || (s.name || '').toLowerCase().includes(q)
    || (s.ip || '').includes(q)
    || (s.description || '').toLowerCase().includes(q))
  const networks = filtered.filter(s => s.kind === 'network')
  const hostsOnly = filtered.filter(s => s.kind !== 'network')
  const located = hostsOnly.filter(s => s.device)
  const unlocated = hostsOnly.filter(s => !s.device)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-3 py-2 border-b border-gray-200 flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold text-gray-800">Services</div>
          <div className="text-[11px] text-gray-500">
            NetBox-named IPs × what the network observes
          </div>
        </div>
        <button
          onClick={runJoin}
          disabled={joining || !selectedRun}
          className="px-2 py-1 rounded text-[11px] font-medium"
          style={{ background: '#1D9E75', color: 'white', opacity: joining ? 0.6 : 1 }}
          title="Re-read NetBox and re-join against this run's observations"
        >
          {joining ? 'Joining…' : joined ? '↻ Re-join' : '▶ Run join'}
        </button>
      </div>

      <div className="px-3 py-2 border-b border-gray-100">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search name / IP / description…"
          className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded"
        />
      </div>

      <div className="flex-1 overflow-y-auto">
        {error && (
          <div className="m-3 p-2 rounded text-[11px]" style={{ background: '#FEF2F2', color: '#B91C1C' }}>
            {error}
          </div>
        )}
        {loading && <div className="p-3 text-xs text-gray-400">Loading…</div>}
        {!loading && !joined && !error && (
          <div className="m-3 p-3 rounded text-xs text-gray-600" style={{ background: '#F0FDF4' }}>
            The service layer has not been joined for this run — that is
            <b> unknown, not empty</b>. Name device IPs in NetBox
            (dns_name/description), then run the join.
          </div>
        )}
        {!loading && joined && filtered.length === 0 && !error && (
          <div className="p-3 text-xs text-gray-400">No services match.</div>
        )}

        {networks.length > 0 && (
          <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wide text-blue-500">
            Client networks
          </div>
        )}
        {networks.map(s => {
          const m = METHOD_LABEL[s.location_method] || METHOD_LABEL.none
          const gws = s.gateways || []
          return (
            <button
              key={s.ip}
              onClick={() => s.device && onServiceClick?.(s.device)}
              className="w-full text-left px-3 py-2 border-b border-gray-50 hover:bg-blue-50"
              title={s.device ? `Highlight ${s.device} on the map` : 'Not located'}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-blue-900 truncate">{s.name}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full shrink-0"
                      style={{ background: `${m.color}18`, color: m.color }}>
                  {m.text}
                </span>
              </div>
              <div className="text-[11px] text-gray-500">
                {s.ip}{gws.length ? ` → ${gws.join(', ')}` : ' — no gateway found'}
              </div>
            </button>
          )
        })}

        {networks.length > 0 && (located.length > 0 || unlocated.length > 0) && (
          <div className="px-3 pt-3 pb-1 text-[10px] uppercase tracking-wide text-gray-400">
            Hosts
          </div>
        )}
        {located.map(s => {
          const m = METHOD_LABEL[s.location_method] || METHOD_LABEL.none
          return (
            <button
              key={s.ip}
              onClick={() => onServiceClick?.(s.device)}
              className="w-full text-left px-3 py-2 border-b border-gray-50 hover:bg-gray-50"
              title={`Highlight ${s.device} on the map`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-gray-800 truncate">{s.name}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full shrink-0"
                      style={{ background: `${m.color}18`, color: m.color }}>
                  {m.text}
                </span>
              </div>
              <div className="text-[11px] text-gray-500">
                {s.ip} → {s.device}{s.location_method === 'arp+fdb' && s.interface ? ` · ${s.interface}` : ''}
              </div>
            </button>
          )
        })}

        {unlocated.length > 0 && (
          <div className="px-3 pt-3 pb-1 text-[10px] uppercase tracking-wide text-gray-400">
            Never seen by the network
          </div>
        )}
        {unlocated.map(s => (
          <div key={s.ip} className="px-3 py-2 border-b border-gray-50">
            <div className="text-xs text-gray-500">{s.name}</div>
            <div className="text-[11px] text-gray-400">
              {s.ip} — documented in NetBox, no observation (offline? stale record?)
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
