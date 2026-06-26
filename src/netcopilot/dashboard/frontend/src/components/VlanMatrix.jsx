import { useMemo } from 'react'
import { useLegend } from '../contexts/LegendContext.jsx'

const MODE_DISPLAY = {
  trunk:  { letter: 'T', color: '#059669', bg: '#ECFDF5' },
  access: { letter: 'A', color: '#2563EB', bg: '#EFF6FF' },
  native: { letter: 'N', color: '#D97706', bg: '#FFFBEB' },
}

export default function VlanMatrix({ vlanData, selectedVlan, onVlanSelect, topologyData }) {
  const { roleTiers } = useLegend()
  // Build matrix data: rows = devices sorted by role tier, columns = VLANs sorted numerically
  const { devices, vlans, matrix } = useMemo(() => {
    if (!vlanData?.vlans?.length) return { devices: [], vlans: [], matrix: {} }

    // Collect all devices from VLAN members, with role from topology
    const deviceRoles = {}
    if (topologyData?.nodes) {
      topologyData.nodes.forEach(n => {
        if (!n.data.isCompound) deviceRoles[n.data.id] = n.data.role || 'external'
      })
    }

    // Build hostname→{vlan_id→mode} lookup
    const mat = {}
    const deviceSet = new Set()
    vlanData.vlans.forEach(v => {
      v.members.forEach(m => {
        deviceSet.add(m.hostname)
        if (!mat[m.hostname]) mat[m.hostname] = {}
        mat[m.hostname][v.vlan_id] = m.mode || 'trunk'
      })
    })

    // Sort devices by role tier then alphabetically
    const devs = [...deviceSet].sort((a, b) => {
      const tierA = roleTiers[deviceRoles[a]] ?? 5
      const tierB = roleTiers[deviceRoles[b]] ?? 5
      if (tierA !== tierB) return tierA - tierB
      return a.localeCompare(b)
    })

    // Sort VLANs numerically
    const vls = vlanData.vlans
      .map(v => ({ id: v.vlan_id, name: v.name }))
      .sort((a, b) => a.id - b.id)

    return { devices: devs, vlans: vls, matrix: mat }
  }, [vlanData, topologyData])

  if (!vlans.length) {
    return (
      <div className="p-4 text-sm text-gray-400 text-center">
        No VLAN data available
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-700">VLAN Matrix</h3>
        <p className="text-xs text-gray-400 mt-0.5">
          {vlans.length} VLANs &middot; {devices.length} devices
        </p>
      </div>
      <div className="flex-1 overflow-auto">
        <table className="text-xs border-collapse w-full">
          <thead className="sticky top-0 z-10">
            <tr>
              <th className="bg-gray-50 border border-gray-200 px-2 py-1 text-left text-gray-600 font-semibold sticky left-0 z-20">
                Device
              </th>
              {vlans.map(v => (
                <th
                  key={v.id}
                  className="border border-gray-200 px-1 py-1 text-center font-medium cursor-pointer hover:bg-blue-50 transition-colors"
                  style={{
                    background: selectedVlan === v.id ? '#DBEAFE' : '#F9FAFB',
                    color: selectedVlan === v.id ? '#1D4ED8' : '#4B5563',
                    minWidth: 36,
                  }}
                  onClick={() => onVlanSelect(selectedVlan === v.id ? null : v.id)}
                  title={`VLAN ${v.id}${v.name ? ` — ${v.name}` : ''}`}
                >
                  {v.id}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {devices.map(hostname => (
              <tr key={hostname} className="hover:bg-gray-50">
                <td className="bg-white border border-gray-200 px-2 py-1 text-gray-700 font-medium whitespace-nowrap sticky left-0 z-10">
                  {hostname}
                </td>
                {vlans.map(v => {
                  const mode = matrix[hostname]?.[v.id]
                  const display = mode ? MODE_DISPLAY[mode] : null
                  return (
                    <td
                      key={v.id}
                      className="border border-gray-200 text-center"
                      style={{
                        background: selectedVlan === v.id
                          ? '#DBEAFE'
                          : display ? display.bg : undefined,
                      }}
                      title={display ? `VLAN ${v.id}${v.name ? ` (${v.name})` : ''} — ${mode} — ${hostname}` : undefined}
                    >
                      {display && (
                        <span style={{ color: display.color, fontWeight: 700 }}>
                          {display.letter}
                        </span>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
