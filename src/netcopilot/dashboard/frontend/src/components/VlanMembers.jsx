import { useLegend } from '../contexts/LegendContext.jsx'

const MODE_BADGE = {
  trunk:   { label: 'Trunk',  color: '#059669', bg: '#ECFDF5' },
  access:  { label: 'Access', color: '#2563EB', bg: '#EFF6FF' },
  native:  { label: 'Native', color: '#D97706', bg: '#FFFBEB' },
  unknown: { label: '—',      color: '#6B7280', bg: '#F3F4F6' },
}

export default function VlanMembers({ vlanData, selectedVlan, topologyData, onDeviceSelect }) {
  const { roleTiers } = useLegend()
  if (!selectedVlan || !vlanData?.vlans) {
    return (
      <div className="p-4 text-sm text-gray-400 text-center">
        Select a VLAN from the dropdown above
      </div>
    )
  }

  const vlan = vlanData.vlans.find(v => v.vlan_id === selectedVlan)
  if (!vlan) return null

  // Sort members by role tier then alphabetically
  const deviceRoles = {}
  if (topologyData?.nodes) {
    topologyData.nodes.forEach(n => {
      if (!n.data.isCompound) deviceRoles[n.data.id] = n.data.role || 'external'
    })
  }
  const members = [...vlan.members].sort((a, b) => {
    const tierA = roleTiers[deviceRoles[a.hostname]] ?? 5
    const tierB = roleTiers[deviceRoles[b.hostname]] ?? 5
    if (tierA !== tierB) return tierA - tierB
    return a.hostname.localeCompare(b.hostname)
  })

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-700">
          VLAN {vlan.vlan_id} {vlan.name && `— ${vlan.name}`}
        </h3>
        <p className="text-xs text-gray-400 mt-0.5">
          {members.length} device{members.length !== 1 ? 's' : ''}
          {vlan.subnet && <span> &middot; {vlan.subnet}</span>}
        </p>
      </div>
      <div className="flex-1 overflow-auto">
        {members.map(m => {
          const badge = MODE_BADGE[m.mode] || MODE_BADGE.unknown
          return (
            <div
              key={m.hostname}
              className="px-3 py-2 border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
              onClick={() => onDeviceSelect(m.hostname)}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-gray-700 truncate">{m.hostname}</span>
                <span
                  className="text-[10px] font-semibold px-1.5 py-0.5 rounded shrink-0"
                  style={{ color: badge.color, background: badge.bg }}
                >
                  {badge.label}
                </span>
              </div>
              {m.interfaces.length > 0 && (
                <div className="text-[10px] text-gray-400 mt-0.5 truncate">
                  {m.interfaces.length <= 3
                    ? m.interfaces.join(', ')
                    : `${m.interfaces.slice(0, 3).join(', ')} +${m.interfaces.length - 3} more`}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
