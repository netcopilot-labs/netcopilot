// Mandatory-confirmation floating dialog (used for delete actions).
export default function ConfirmModal({ title, message, confirmLabel = 'Delete', onConfirm, onCancel }) {
  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#1E293B', color: '#E2E8F0', borderRadius: 8, padding: 20,
          width: 380, border: '1px solid #334155', boxShadow: '0 10px 40px rgba(0,0,0,0.5)',
        }}
      >
        <div style={{ fontWeight: 600, marginBottom: 8 }}>{title}</div>
        <div style={{ fontSize: 13, color: '#CBD5E1', marginBottom: 18, lineHeight: 1.4 }}>{message}</div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button
            onClick={onCancel}
            style={{ padding: '6px 14px', borderRadius: 4, background: '#334155', color: '#E2E8F0', fontSize: 13 }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            style={{ padding: '6px 14px', borderRadius: 4, background: '#DC2626', color: '#fff', fontSize: 13, fontWeight: 600 }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
