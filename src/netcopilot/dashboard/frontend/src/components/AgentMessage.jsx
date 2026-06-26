import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import RemediationBlock from './RemediationBlock'
import ToolTrace from './ToolTrace'
import { useAgent } from '../AgentContext'

// C1A1: Tools whose output is pre-formatted, deterministic text that the
// LLM is required to quote verbatim (per the system prompt rules in
// agent_system.txt). For these tools, the message content is rendered
// as pre-wrapped text instead of through ReactMarkdown — this preserves
// line breaks, indentation, and bullet characters exactly as the tool
// returned them. ReactMarkdown is the wrong renderer for plain text
// because CommonMark collapses single newlines into spaces.
//
// Adding a tool name here makes any message that called that tool
// render verbatim. The list is tiny on purpose — most tools should
// produce markdown-friendly output.
const VERBATIM_TOOLS = new Set([
  'about_netcopilot',
  'dashboard_guide',
  'list_capabilities',
])

function messageIsVerbatim(message) {
  if (!message.tools || message.tools.length === 0) return false
  return message.tools.some(t => VERBATIM_TOOLS.has(t.name))
}

// C1A1: HelpCard — rendered when the user clicks the Help button in the
// chat panel header. Displays the same 3 onboarding buttons as the
// empty state, inside the message stream, so the conversation history
// is preserved while the user re-summons the welcome experience.
//
// This is NOT a real chat message — it's a UI element with role
// 'help_card' that gets pushed into the messages array by AgentContext's
// showHelp(). The history builder filters it out (only user/assistant
// roles are sent to the LLM), so it never reaches the model.
function HelpCard() {
  const { sendMessage, isStreaming } = useAgent()

  const items = [
    { label: '💡 What is NetCopilot?',          prompt: 'What is NetCopilot?' },
    { label: '🖥 How does this dashboard work?', prompt: 'How does this dashboard work?' },
    { label: '📋 What can NetCopilot do for me?', prompt: 'What can NetCopilot do for me?' },
  ]

  return (
    <div style={{
      padding: '12px',
      margin: '8px 0',
      background: '#F0FDF4',
      border: '1px solid #BBF7D0',
      borderRadius: 8,
    }}>
      <p style={{
        color: '#166534',
        fontSize: 12,
        fontWeight: 600,
        marginBottom: 8,
        textAlign: 'center',
      }}>
        How can I help?
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {items.map((item, i) => (
          <button
            key={i}
            onClick={() => !isStreaming && sendMessage(item.prompt)}
            disabled={isStreaming}
            style={{
              fontSize: 12,
              color: '#475569',
              background: '#FFFFFF',
              border: '1px solid #E2E8F0',
              borderRadius: 6,
              cursor: isStreaming ? 'not-allowed' : 'pointer',
              padding: '6px 12px',
              textAlign: 'left',
              transition: 'all 0.15s',
              opacity: isStreaming ? 0.6 : 1,
            }}
            onMouseEnter={e => {
              if (!isStreaming) {
                e.target.style.color = '#1D9E75'
                e.target.style.borderColor = '#1D9E75'
                e.target.style.background = '#F0FDF4'
              }
            }}
            onMouseLeave={e => {
              e.target.style.color = '#475569'
              e.target.style.borderColor = '#E2E8F0'
              e.target.style.background = '#FFFFFF'
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
    </div>
  )
}

export default function AgentMessage({ message }) {
  // C1A1: help_card is a synthetic message that renders the 3 onboarding
  // buttons inside the chat stream when the user clicks the Help button.
  if (message.role === 'help_card') {
    return <HelpCard />
  }

  if (message.role === 'user') {
    return (
      <div style={{ padding: '8px 12px', margin: '4px 0', maxWidth: '85%', alignSelf: 'flex-end' }}>
        <p style={{ color: '#1D9E75', fontSize: 14, fontWeight: 500 }}>{message.content}</p>
      </div>
    )
  }

  // Assistant message
  return (
    <div style={{ padding: '4px 0', margin: '4px 0', width: '100%' }}>
      {message.tools && message.tools.length > 0 ? (
        <div style={{
          background: '#F8FAFC',
          borderRadius: 6,
          padding: '4px 10px',
          marginBottom: 6,
          border: '1px solid #E2E8F0',
        }}>
          <ToolTrace tools={message.tools} />
        </div>
      ) : null}

      {message.error ? (
        <div style={{
          color: '#DC2626',
          fontSize: 14,
          padding: '8px 12px',
          background: '#FEF2F2',
          borderRadius: 6,
          border: '1px solid #FECACA',
        }}>
          {message.error}
        </div>
      ) : message.content && messageIsVerbatim(message) ? (
        // C1A1: verbatim rendering — the tool produced pre-formatted plain
        // text that must be displayed exactly as returned. ReactMarkdown
        // would collapse single newlines into spaces, destroying the
        // category structure of list_capabilities and the bullet layout
        // of dashboard_guide. <pre> with white-space: pre-wrap preserves
        // every newline and every space while still wrapping long lines
        // at the panel edge. font-family: inherit keeps the friendly
        // sans-serif look (we want a menu, not command output).
        <pre style={{
          fontSize: 14,
          lineHeight: 1.6,
          color: '#334155',
          fontFamily: 'inherit',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          margin: 0,
        }}>
          {message.content}
        </pre>
      ) : message.content ? (
        <div style={{ fontSize: 14, lineHeight: 1.6, color: '#334155' }}>
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              code({ inline, className, children, ...props }) {
                const match = /language-(\w+)/.exec(className || '')
                const codeStr = String(children).replace(/\n$/, '')
                if (!inline && (match || codeStr.includes('\n') || codeStr.length > 60)) {
                  return <RemediationBlock code={codeStr} language={match?.[1]} />
                }
                return (
                  <code
                    style={{
                      background: '#F1F5F9',
                      padding: '1px 4px',
                      borderRadius: 3,
                      fontSize: 13,
                      fontFamily: 'monospace',
                    }}
                    {...props}
                  >
                    {children}
                  </code>
                )
              },
              p({ children }) {
                return <p style={{ margin: '6px 0' }}>{children}</p>
              },
              ul({ children }) {
                return <ul style={{ margin: '6px 0', paddingLeft: 20 }}>{children}</ul>
              },
              ol({ children }) {
                return <ol style={{ margin: '6px 0', paddingLeft: 20 }}>{children}</ol>
              },
              li({ children }) {
                return <li style={{ margin: '2px 0' }}>{children}</li>
              },
              a({ href, children }) {
                return <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: '#1D9E75', textDecoration: 'underline' }}>{children}</a>
              },
              strong({ children }) {
                return <strong style={{ fontWeight: 600, color: '#0F172A' }}>{children}</strong>
              },
              blockquote({ children }) {
                return (
                  <blockquote style={{
                    borderLeft: '3px solid #CBD5E1',
                    margin: '8px 0',
                    padding: '4px 12px',
                    color: '#64748B',
                  }}>
                    {children}
                  </blockquote>
                )
              },
              table({ children }) {
                return (
                  <div style={{ overflowX: 'auto', margin: '8px 0' }}>
                    <table style={{
                      borderCollapse: 'collapse',
                      fontSize: 13,
                      width: '100%',
                    }}>
                      {children}
                    </table>
                  </div>
                )
              },
              th({ children }) {
                return (
                  <th style={{
                    borderBottom: '2px solid #E2E8F0',
                    padding: '6px 10px',
                    textAlign: 'left',
                    fontWeight: 600,
                    color: '#374151',
                    background: '#F8FAFC',
                    whiteSpace: 'nowrap',
                  }}>
                    {children}
                  </th>
                )
              },
              td({ children }) {
                return (
                  <td style={{
                    borderBottom: '1px solid #F1F5F9',
                    padding: '5px 10px',
                    color: '#475569',
                  }}>
                    {children}
                  </td>
                )
              },
            }}
          >
            {message.content}
          </ReactMarkdown>
        </div>
      ) : !message.done ? (
        <div style={{ color: '#94A3B8', fontSize: 14, fontStyle: 'italic' }}>Thinking...</div>
      ) : null}

      {message.usage && (
        <div style={{
          fontSize: 11,
          color: '#94A3B8',
          marginTop: 6,
          padding: '4px 8px',
          background: '#F8FAFC',
          borderRadius: 4,
          fontFamily: 'monospace',
        }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <span>{message.usage.model?.split('-').slice(0,2).join(' ')}</span>
            <span>{message.usage.api_calls} call{message.usage.api_calls !== 1 ? 's' : ''}</span>
            <span>In: {message.usage.input_tokens?.toLocaleString()}</span>
            <span>Out: {message.usage.output_tokens?.toLocaleString()}</span>
            <span style={{ color: message.usage.cost_usd > 0.01 ? '#F59E0B' : '#94A3B8' }}>
              ${message.usage.cost_usd?.toFixed(4)}
            </span>
          </div>
          {message.usage.anonymization && (
            <div style={{ marginTop: 3, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ color: '#1D9E75' }}>&#x1F512;</span>
              <span>
                {message.usage.anonymization.devices_anonymized} devices,{' '}
                {message.usage.anonymization.ips_anonymized} IPs,{' '}
                {message.usage.anonymization.sites_anonymized} sites anonymized
              </span>
              {message.usage.anonymization.sample_mappings?.length > 0 && (
                <span style={{ color: '#CBD5E1' }}>
                  ({message.usage.anonymization.sample_mappings.join(', ')})
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
