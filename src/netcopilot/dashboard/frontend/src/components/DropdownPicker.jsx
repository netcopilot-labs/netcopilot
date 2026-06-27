import { useState, useRef, useEffect } from 'react'
import ConfirmModal from './ConfirmModal.jsx'

// A compact custom dropdown (styled like the native "Device:" select) whose rows
// can carry a per-line trashcan — which a native <select> can't. Each item:
// { id, label, group?, deletable? }. Selecting a row calls onSelect(id); the
// trashcan opens a mandatory confirm, then onDelete(item).
export default function DropdownPicker({
  items, selectedId, onSelect, onDelete,
  placeholder = 'Select…', disabled = false, maxWidth = 220,
  deleteTitle, deleteMessage,
}) {
  const [open, setOpen] = useState(false)
  const [confirming, setConfirming] = useState(null)
  const ref = useRef(null)

  useEffect(() => {
    function onDocClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    return () => document.removeEventListener('mousedown', onDocClick)
  }, [])

  const selected = items.find((i) => i.id === selectedId)

  // Preserve item order but group by `group`.
  const groups = []
  const byGroup = {}
  for (const it of items) {
    const g = it.group || ''
    if (!(g in byGroup)) { byGroup[g] = []; groups.push(g) }
    byGroup[g].push(it)
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => !disabled && setOpen((o) => !o)}
        disabled={disabled}
        className="text-xs rounded border bg-white hover:bg-gray-50 focus:outline-none focus:ring-1 focus:ring-blue-400"
        style={{
          borderColor: '#D1D5DB', color: '#374151', padding: '4px 8px', maxWidth,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6,
          cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.6 : 1,
        }}
      >
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {selected ? selected.label : placeholder}
        </span>
        <span style={{ opacity: 0.5, fontSize: 9 }}>▾</span>
      </button>

      {open && (
        <div
          style={{
            position: 'absolute', right: 0, marginTop: 4, background: '#fff',
            border: '1px solid #E5E7EB', borderRadius: 6, minWidth: 220, maxHeight: 340,
            overflowY: 'auto', zIndex: 50, boxShadow: '0 6px 20px rgba(0,0,0,0.12)',
          }}
        >
          {items.length === 0 && (
            <div style={{ padding: '8px 12px', color: '#9CA3AF', fontSize: 12 }}>None</div>
          )}
          {groups.map((g) => (
            <div key={g || '_'}>
              {g && (
                <div style={{ padding: '4px 10px', fontSize: 10, color: '#9CA3AF', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{g}</div>
              )}
              {byGroup[g].map((it) => (
                <div
                  key={it.id}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                    padding: '5px 10px', background: it.id === selectedId ? '#ECFDF5' : 'transparent',
                  }}
                  onMouseEnter={(e) => { if (it.id !== selectedId) e.currentTarget.style.background = '#F3F4F6' }}
                  onMouseLeave={(e) => { if (it.id !== selectedId) e.currentTarget.style.background = 'transparent' }}
                >
                  <span
                    onClick={() => { onSelect(it.id); setOpen(false) }}
                    style={{ flex: 1, fontSize: 12, color: '#374151', cursor: 'pointer', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  >
                    {it.label}
                  </span>
                  {it.deletable && (
                    <button
                      title="Delete"
                      onClick={(e) => { e.stopPropagation(); setConfirming(it) }}
                      style={{ color: '#DC2626', background: 'transparent', fontSize: 13, padding: '0 2px', cursor: 'pointer' }}
                    >
                      🗑
                    </button>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {confirming && (
        <ConfirmModal
          title={deleteTitle ? deleteTitle(confirming) : 'Delete?'}
          message={deleteMessage ? deleteMessage(confirming) : `Delete "${confirming.label}"? This cannot be undone.`}
          onCancel={() => setConfirming(null)}
          onConfirm={() => { const it = confirming; setConfirming(null); setOpen(false); onDelete(it) }}
        />
      )}
    </div>
  )
}
