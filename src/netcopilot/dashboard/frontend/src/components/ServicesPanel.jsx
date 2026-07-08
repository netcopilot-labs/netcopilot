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

const METHOD_WORDING = {
  'arp+fdb': 'Port-precise — the switch learned this MAC on that physical port.',
  arp: 'Gateway-resolved via ARP — the exact access port wasn\'t derivable.',
  subnet: 'Approximate — no ARP seen; placed by the switch\'s VLAN subnet.',
  colocated: 'Approximate — the host itself wasn\'t observed; placed on the switch its VLAN neighbours were seen on.',
  gateway: 'An interface serves exactly this network.',
  'gateway-containing': 'Approximate — a gateway serves part of this range (the declared prefix is an aggregate).',
  none: 'NEVER SEEN by the network — documented in NetBox, no observation.',
}

// Left-panel detail for a clicked service or client-network node.
function ServiceDetail({ svc, onBack, onDevice }) {
  const isNet = svc.kind === 'network'
  const m = METHOD_LABEL[svc.location_method] || METHOD_LABEL.none
  const gws = svc.gateways || (svc.device ? [`${svc.device}${svc.interface ? '/' + svc.interface : ''}`] : [])
  const Row = ({ k, v }) => v ? (
    <div className="flex gap-2 py-0.5">
      <span className="text-[11px] text-gray-400 w-24 shrink-0">{k}</span>
      <span className="text-[11px] text-gray-800 break-all">{v}</span>
    </div>
  ) : null
  return (
    <div className="p-3">
      <button onClick={onBack} className="text-[11px] text-emerald-700 hover:underline mb-2">← back to list</button>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-semibold text-gray-800 break-all">{svc.name}</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded-full shrink-0"
              style={{ background: isNet ? '#DBEAFE' : '#DCFCE7', color: isNet ? '#1E3A8A' : '#166534' }}>
          {isNet ? 'client network' : 'service'}
        </span>
      </div>
      <Row k={isNet ? 'Prefix' : 'IP'} v={svc.address || svc.ip} />
      <Row k="DNS name" v={svc.dns_name} />
      <Row k="Description" v={svc.description} />
      <Row k="Tenant" v={svc.tenant} />
      <Row k="Role" v={svc.role} />
      <Row k="VRF" v={svc.vrf} />
      <Row k="Tags" v={(svc.tags || []).join(', ') || null} />
      <div className="mt-2 pt-2 border-t border-gray-100">
        {svc.located ? (
          <>
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-gray-400">{isNet ? 'Connected at' : 'Located on'}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full"
                    style={{ background: `${m.color}18`, color: m.color }}>{m.text}</span>
            </div>
            {gws.map(g => {
              const dev = g.split('/')[0]
              return (
                <button key={g} onClick={() => onDevice?.(dev)}
                  className="block text-[11px] text-emerald-700 hover:underline py-0.5">{g}</button>
              )
            })}
            <div className="text-[11px] text-gray-500 mt-1">{METHOD_WORDING[svc.location_method]}</div>
          </>
        ) : (
          <div className="text-[11px] text-gray-500">{METHOD_WORDING.none}</div>
        )}
        {svc.mac && <Row k="MAC" v={svc.mac} />}
        {svc.joined_at && <div className="text-[10px] text-gray-400 mt-2">joined {svc.joined_at}</div>}
      </div>
    </div>
  )
}

// Detail for a clicked virtualization-host box (s18): its port, hypervisor,
// endpoint count, and the named VMs behind it.
function VhostDetail({ vhost, vms, onBack, onDevice }) {
  return (
    <div className="p-3">
      <button onClick={onBack} className="text-[11px] text-emerald-700 hover:underline mb-2">← back to list</button>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-semibold text-orange-900">{vhost.hypervisor} host</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ background: '#FFEDD5', color: '#9A3412' }}>
          virtualization
        </span>
      </div>
      <div className="text-[11px] text-gray-500 mb-2">
        <button onClick={() => onDevice?.(String(vhost.host_port).split('/')[0])}
          className="text-emerald-700 hover:underline">{vhost.host_port}</button>
        {' · '}{vhost.endpoint_count} endpoint MAC(s) — {vhost.named_vms} named
      </div>
      <div className="text-[10px] text-gray-400 mb-1">Determined from the FDB: multiple MACs / a hypervisor OUI on one physical port.</div>
      <div className="text-[10px] uppercase tracking-wide text-gray-400 mt-2 mb-1">Named VMs</div>
      {vms.map(s => (
        <div key={s.ip} className="text-[11px] text-gray-800 py-0.5">{s.name} <span className="text-gray-400">{s.ip}</span></div>
      ))}
      {vhost.endpoint_count - vms.length > 0 && (
        <div className="text-[11px] text-gray-400 py-0.5">+ {vhost.endpoint_count - vms.length} VM(s) with no NetBox name</div>
      )}
    </div>
  )
}

export default function ServicesPanel({ selectedRun, onServiceClick, selectedIp, onSelectIp, selectedVhost, onClearVhost }) {
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

  const selected = selectedIp ? services.find(s => s.ip === selectedIp) : null

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

      {!selected && !selectedVhost && (
        <div className="px-3 py-2 border-b border-gray-100">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search name / IP / description…"
            className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded"
          />
        </div>
      )}

      {selectedVhost && (
        <div className="flex-1 overflow-y-auto">
          <VhostDetail vhost={selectedVhost} onBack={onClearVhost} onDevice={onServiceClick}
            vms={services.filter(s => s.server && `vhost:${s.server}` === selectedVhost.id)} />
        </div>
      )}
      {selected && !selectedVhost && (
        <div className="flex-1 overflow-y-auto">
          <ServiceDetail svc={selected} onBack={() => onSelectIp?.(null)} onDevice={onServiceClick} />
        </div>
      )}

      <div className="flex-1 overflow-y-auto" style={(selected || selectedVhost) ? { display: 'none' } : undefined}>
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
              onClick={() => { onSelectIp?.(s.ip); if (s.device) onServiceClick?.(s.device) }}
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
              onClick={() => { onSelectIp?.(s.ip); onServiceClick?.(s.device) }}
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
