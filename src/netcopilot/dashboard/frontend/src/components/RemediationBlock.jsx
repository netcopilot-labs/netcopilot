import { useState } from 'react'

export default function RemediationBlock({ code, language }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (_) {
      // Fallback for HTTP context (no clipboard API)
      const textarea = document.createElement('textarea')
      textarea.value = code
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div
      style={{
        position: 'relative',
        borderLeft: '3px solid #1D9E75',
        background: '#F1F5F9',
        borderRadius: 4,
        margin: '8px 0',
        padding: '10px 12px',
        fontFamily: 'monospace',
        fontSize: 12,
        lineHeight: 1.5,
        whiteSpace: 'pre-wrap',
        overflowX: 'auto',
      }}
    >
      <button
        onClick={handleCopy}
        style={{
          position: 'absolute',
          top: 4,
          right: 4,
          padding: '2px 8px',
          fontSize: 10,
          borderRadius: 3,
          border: '1px solid #CBD5E1',
          background: copied ? '#D1FAE5' : '#FFFFFF',
          color: copied ? '#065F46' : '#64748B',
          cursor: 'pointer',
        }}
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
      {language && (
        <span style={{ position: 'absolute', top: 4, left: 12, fontSize: 9, color: '#94A3B8', textTransform: 'uppercase' }}>
          {language}
        </span>
      )}
      <code>{code}</code>
    </div>
  )
}
