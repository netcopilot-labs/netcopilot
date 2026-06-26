import { useState, useEffect, useRef } from 'react'

/**
 * EmailRecipientPopover — floating modal overlay for entering recipients
 * before sending a report by email. Used by:
 *
 *   - ReportPanel.jsx ("Send by Email" button on the Report panel)
 *   - AgentChatPanel.jsx (chat-initiated reports waiting for confirmation)
 *
 * Wire-up:
 *   <EmailRecipientPopover
 *     defaultRecipient="someone@example.com"
 *     status="idle" | "sending" | "sent" | "error"
 *     errorMessage={null}
 *     onSend={(recipientsString) => Promise<void>}
 *     onClose={() => void}
 *   />
 *
 * Recipients are entered as a comma-separated string. Validation/parsing
 * happens server-side in reports.smtp_client.parse_recipients(). The
 * popover only enforces non-emptiness.
 */
export default function EmailRecipientPopover({
  defaultRecipient = '',
  status = 'idle',
  errorMessage = null,
  onSend,
  onClose,
}) {
  const [recipients, setRecipients] = useState(defaultRecipient)
  const inputRef = useRef(null)

  useEffect(() => {
    // Focus the input on mount and select all so the user can
    // overtype the default with a single keystroke
    if (inputRef.current) {
      inputRef.current.focus()
      inputRef.current.select()
    }
  }, [])

  const isBusy = status === 'sending'
  const isSent = status === 'sent'

  const handleSubmit = (e) => {
    e?.preventDefault?.()
    if (isBusy || isSent) return
    if (!recipients.trim()) return
    onSend(recipients)
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(15, 23, 42, 0.35)',
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'white',
          borderRadius: 10,
          padding: 20,
          width: 420,
          boxShadow: '0 10px 32px rgba(0,0,0,0.18)',
          border: '1px solid #E5E7EB',
        }}
      >
        <p style={{
          fontSize: 14,
          fontWeight: 600,
          color: '#0F4F3A',
          marginBottom: 4,
        }}>
          📧 Send report by email
        </p>
        <p style={{
          fontSize: 12,
          color: '#64748B',
          marginBottom: 12,
        }}>
          Enter one or more email addresses, separated by commas.
        </p>

        <form onSubmit={handleSubmit}>
          <input
            ref={inputRef}
            type="text"
            value={recipients}
            onChange={(e) => setRecipients(e.target.value)}
            disabled={isBusy || isSent}
            placeholder="alice@example.com, bob@example.com"
            style={{
              width: '100%',
              padding: '8px 10px',
              fontSize: 13,
              border: '1px solid #CBD5E1',
              borderRadius: 6,
              outline: 'none',
              background: (isBusy || isSent) ? '#F1F5F9' : 'white',
              color: '#0F172A',
            }}
            onFocus={(e) => { e.target.style.borderColor = '#1D9E75' }}
            onBlur={(e) => { e.target.style.borderColor = '#CBD5E1' }}
          />

          {/* Status / error line */}
          {status === 'error' && errorMessage && (
            <p style={{
              marginTop: 8,
              fontSize: 12,
              color: '#DC2626',
              background: '#FEF2F2',
              border: '1px solid #FECACA',
              borderRadius: 6,
              padding: '6px 8px',
            }}>
              {errorMessage}
            </p>
          )}
          {isSent && (
            <p style={{
              marginTop: 8,
              fontSize: 12,
              color: '#0F4F3A',
              background: '#F0FDF4',
              border: '1px solid #BBF7D0',
              borderRadius: 6,
              padding: '6px 8px',
            }}>
              ✓ Report sent.
            </p>
          )}

          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 8,
            marginTop: 14,
          }}>
            <button
              type="button"
              onClick={onClose}
              disabled={isBusy}
              style={{
                padding: '7px 14px',
                fontSize: 12,
                color: '#475569',
                background: 'white',
                border: '1px solid #CBD5E1',
                borderRadius: 6,
                cursor: isBusy ? 'not-allowed' : 'pointer',
              }}
            >
              {isSent ? 'Close' : 'Cancel'}
            </button>
            {!isSent && (
              <button
                type="submit"
                disabled={isBusy || !recipients.trim()}
                style={{
                  padding: '7px 14px',
                  fontSize: 12,
                  fontWeight: 600,
                  color: 'white',
                  background: (isBusy || !recipients.trim()) ? '#94A3B8' : '#1D9E75',
                  border: 'none',
                  borderRadius: 6,
                  cursor: (isBusy || !recipients.trim()) ? 'not-allowed' : 'pointer',
                }}
              >
                {isBusy ? 'Sending…' : 'Send'}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
