import { useState, useRef, useEffect } from 'react'
import { useAgent } from '../AgentContext'
import AgentMessage from './AgentMessage'
import EmailRecipientPopover from './EmailRecipientPopover'

export default function AgentChatPanel() {
  const {
    messages, pipelineMessages, isStreaming, contextReady, sendMessage, showHelp,
    pendingReportEmail, confirmReportEmail, cancelReportEmail,
  } = useAgent()
  // C1A2: Email send status for the chat-initiated report popover
  const [emailStatus, setEmailStatus] = useState('idle')
  const [emailError, setEmailError] = useState(null)

  // Reset send-status when a new pendingReportEmail arrives
  useEffect(() => {
    if (pendingReportEmail) {
      setEmailStatus('idle')
      setEmailError(null)
    }
  }, [pendingReportEmail])

  const handleSendReportEmail = async (recipientsString) => {
    setEmailStatus('sending')
    setEmailError(null)
    const result = await confirmReportEmail(recipientsString)
    if (result.sent) {
      setEmailStatus('sent')
    } else {
      setEmailStatus('error')
      setEmailError(result.error || 'Send failed')
    }
  }
  const [input, setInput] = useState('')
  const [models, setModels] = useState([])
  const [activeModel, setActiveModel] = useState('')
  const messagesEndRef = useRef(null)

  // C1A1: Empty state has the 3 onboarding buttons visible already.
  // Disable the header Help button while empty so the user doesn't get
  // a redundant duplicate. Help becomes useful after the first message,
  // when the empty state is gone.
  const isChatEmpty = messages.length === 0 && pipelineMessages.length === 0

  // Load available models
  useEffect(() => {
    fetch('/api/agent/models')
      .then(r => r.json())
      .then(data => {
        setModels(data.models || [])
        setActiveModel(data.active || '')
      })
      .catch(() => {})
  }, [])

  const handleModelChange = async (modelId) => {
    try {
      await fetch(`/api/agent/models/${modelId}`, { method: 'POST' })
      setActiveModel(modelId)
    } catch (_) {}
  }

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = () => {
    if (!input.trim() || isStreaming) return
    sendMessage(input.trim())
    setInput('')
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="flex flex-col h-full" style={{ background: '#FFFFFF' }}>
      {/* Header */}
      <div
        className="shrink-0 flex items-center gap-2 px-3"
        style={{ height: 40, borderBottom: '1px solid #E5E7EB' }}
      >
        <span style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: contextReady ? '#1D9E75' : '#F59E0B',
          display: 'inline-block',
          flexShrink: 0,
        }} />
        <span style={{ fontSize: 14, fontWeight: 700, color: '#0F172A', flexShrink: 0 }}>
          Context Agent
        </span>
        <div style={{ flex: 1 }} />
        {/* C1A1: Help button — re-summons the 3 onboarding options as a
            help_card in the chat stream. Disabled while the chat is empty
            (the buttons are already visible in the empty state) and while
            a streaming response is in progress. */}
        <button
          onClick={() => !isStreaming && !isChatEmpty && showHelp()}
          disabled={isStreaming || isChatEmpty}
          title={
            isChatEmpty
              ? 'Help options are already shown below'
              : isStreaming
              ? 'Wait for the current response'
              : 'Show onboarding options again'
          }
          style={{
            fontSize: 11,
            fontWeight: 600,
            padding: '3px 10px',
            border: '1px solid #1D9E75',
            borderRadius: 4,
            color: isStreaming || isChatEmpty ? '#94A3B8' : '#1D9E75',
            background: '#FFFFFF',
            borderColor: isStreaming || isChatEmpty ? '#E5E7EB' : '#1D9E75',
            cursor: isStreaming || isChatEmpty ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
          }}
          onMouseEnter={e => {
            if (!isStreaming && !isChatEmpty) {
              e.target.style.background = '#1D9E75'
              e.target.style.color = '#FFFFFF'
            }
          }}
          onMouseLeave={e => {
            if (!isStreaming && !isChatEmpty) {
              e.target.style.background = '#FFFFFF'
              e.target.style.color = '#1D9E75'
            }
          }}
        >
          Help
        </button>
        <select
          value={activeModel}
          onChange={e => handleModelChange(e.target.value)}
          style={{
            fontSize: 11,
            padding: '2px 4px',
            border: '1px solid #E5E7EB',
            borderRadius: 4,
            color: '#64748B',
            background: '#F8FAFC',
            cursor: 'pointer',
            maxWidth: 130,
          }}
        >
          {models.map(m => (
            <option key={m.id} value={m.id}>{m.label}</option>
          ))}
        </select>
      </div>

      {/* Messages */}
      <div
        className="flex-1 overflow-y-auto flex flex-col"
        style={{ padding: '8px 10px' }}
      >
        {pipelineMessages.length > 0 && (
          <div style={{
            margin: '6px 0', padding: '8px 10px', background: '#F0FDF4',
            borderRadius: 8, border: '1px solid #BBF7D0', fontSize: 13
          }}>
            <div style={{ fontWeight: 600, color: '#166534', marginBottom: 4, fontSize: 12 }}>
              Pipeline Progress
            </div>
            {pipelineMessages.map((evt, i) => {
              const isLast = i === pipelineMessages.length - 1
              const isError = evt.stage === 'error' || evt.stage === 'collection_error'
              const isWarning = evt.stage === 'warning'
              const isDone = evt.stage === 'done'
              const isRunning = isLast && !isDone && !isError
              return (
                <div key={`${evt.stage}-${i}`} style={{
                  padding: '2px 0',
                  fontFamily: 'monospace',
                  color: isError ? '#DC2626' : isWarning ? '#D97706' : isDone ? '#166534' : '#374151',
                }}>
                  {isError ? '✗ ' : isDone ? '✓ ' : isRunning ? '⟳ ' : '✓ '}
                  {evt.message}
                </div>
              )
            })}
          </div>
        )}
        {messages.length === 0 && pipelineMessages.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-end" style={{ paddingBottom: 40 }}>
            <div style={{ color: '#94A3B8', fontSize: 28, marginBottom: 8 }}>&#x1F50D;</div>
            <p style={{ color: '#64748B', fontSize: 13, textAlign: 'center', lineHeight: 1.5 }}>
              Ask anything about your network
            </p>
            {/* C1A1: First-touch onboarding buttons. Replace the previous example
                questions with three meta-question buttons that route to the new
                onboarding tools (about_netcopilot, dashboard_guide, list_capabilities).
                The buttons disappear after the first message. The same questions
                also work in plain text — see system prompt routing rules. */}
            <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { label: '💡 What is NetCopilot?',          prompt: 'What is NetCopilot?' },
                { label: '🖥 How does this dashboard work?', prompt: 'How does this dashboard work?' },
                { label: '📋 What can NetCopilot do for me?', prompt: 'What can NetCopilot do for me?' },
              ].map((item, i) => (
                <button
                  key={i}
                  onClick={() => sendMessage(item.prompt)}
                  style={{
                    fontSize: 12,
                    color: '#475569',
                    background: '#F8FAFC',
                    border: '1px solid #E2E8F0',
                    borderRadius: 6,
                    cursor: 'pointer',
                    padding: '6px 12px',
                    textAlign: 'left',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => {
                    e.target.style.color = '#1D9E75'
                    e.target.style.borderColor = '#1D9E75'
                    e.target.style.background = '#F0FDF4'
                  }}
                  onMouseLeave={e => {
                    e.target.style.color = '#475569'
                    e.target.style.borderColor = '#E2E8F0'
                    e.target.style.background = '#F8FAFC'
                  }}
                >
                  {item.label}
                </button>
              ))}
            </div>
            {/* C1A1: Hint about the Help button in the header — visible only
                in the empty state, where the user is being introduced to
                the dashboard. After the first message, this hint is no
                longer needed because the Help button is already discoverable. */}
            <p style={{
              marginTop: 12,
              color: '#94A3B8',
              fontSize: 11,
              fontStyle: 'italic',
              textAlign: 'center',
              lineHeight: 1.4,
              maxWidth: 240,
            }}>
              Click <strong style={{ color: '#1D9E75', fontStyle: 'normal' }}>Help</strong> in the header above to bring these options back anytime.
            </p>
          </div>
        ) : (
          messages.map((msg, i) => <AgentMessage key={i} message={msg} />)
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div
        className="shrink-0 flex items-center gap-2"
        style={{ padding: '8px 10px', borderTop: '1px solid #E5E7EB' }}
      >
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isStreaming || !contextReady}
          placeholder={!contextReady ? 'Loading network context...' : isStreaming ? 'Waiting for response...' : 'Ask about your network...'}
          style={{
            flex: 1,
            padding: '8px 12px',
            fontSize: 14,
            border: '1px solid #E5E7EB',
            borderRadius: 6,
            outline: 'none',
            background: isStreaming ? '#F8FAFC' : '#FFFFFF',
          }}
          onFocus={e => e.target.style.borderColor = '#1D9E75'}
          onBlur={e => e.target.style.borderColor = '#E5E7EB'}
        />
        <button
          onClick={handleSend}
          disabled={isStreaming || !input.trim() || !contextReady}
          style={{
            padding: '8px 14px',
            fontSize: 14,
            fontWeight: 600,
            borderRadius: 6,
            border: 'none',
            background: isStreaming || !input.trim() || !contextReady ? '#E2E8F0' : '#1D9E75',
            color: isStreaming || !input.trim() || !contextReady ? '#94A3B8' : '#FFFFFF',
            cursor: isStreaming || !input.trim() || !contextReady ? 'not-allowed' : 'pointer',
          }}
        >
          Send
        </button>
      </div>

      {/* C1A2: Email recipient popover for chat-initiated reports.
          Shown when generate_report fires and emits a report_ready highlight. */}
      {pendingReportEmail && (
        <EmailRecipientPopover
          defaultRecipient={pendingReportEmail.suggestedRecipients}
          status={emailStatus}
          errorMessage={emailError}
          onSend={handleSendReportEmail}
          onClose={cancelReportEmail}
        />
      )}
    </div>
  )
}
