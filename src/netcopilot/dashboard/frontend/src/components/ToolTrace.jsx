export default function ToolTrace({ tools }) {
  if (!tools || tools.length === 0) return null

  return (
    <div style={{ fontFamily: 'monospace', fontSize: 12, padding: '6px 0', color: '#64748B' }}>
      {tools.map((tool, i) => (
        <div key={i} className="flex items-center gap-2" style={{ padding: '2px 0' }}>
          <span style={{ width: 14, textAlign: 'center' }}>
            {tool.status === 'running' ? (
              <span className="animate-spin inline-block" style={{ color: '#1D9E75' }}>&#x27F3;</span>
            ) : tool.status === 'error' ? (
              <span style={{ color: '#DC2626' }}>&#x2717;</span>
            ) : (
              <span style={{ color: '#1D9E75' }}>&#x2713;</span>
            )}
          </span>
          <span style={{ flex: 1 }}>{tool.name}</span>
          <span style={{ color: '#94A3B8', minWidth: 40, textAlign: 'right' }}>
            {tool.status === 'running' ? '' : `${tool.duration || '0.0'}s`}
          </span>
        </div>
      ))}
    </div>
  )
}
