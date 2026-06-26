import { useState, useEffect, useCallback } from 'react'
import EmailRecipientPopover from './EmailRecipientPopover.jsx'
import { useAgent } from '../AgentContext.jsx'

/**
 * ReportPanel — left-panel live preview of a NetCopilot report (C1A2).
 *
 * Two display modes:
 *
 * 1. **General report (default)**. On mount and whenever the selected
 *    run changes, fetches POST /api/reports/general/{run_id} and renders
 *    the canonical 7-section operational handover document.
 *
 * 2. **Chat-scoped report**. When the agent calls generate_report from
 *    the chat panel, AgentContext stores the new report_id in
 *    `chatReport`. ReportPanel detects that and switches to fetching
 *    GET /api/reports/cached/{report_id} instead — the chat tool already
 *    cached the rendered report, no regeneration needed. Works for both
 *    `general` and `conversation` scopes. A "Show general report" pill
 *    lets the operator drop back to the canonical report at any time.
 *
 * The two action buttons (📧 Send by Email, 📥 Download PDF) always use
 * whichever report_id is currently displayed, so the preview is byte-
 * identical to the PDF and the email.
 */

const SEV_COLORS = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#0EA5E9',
  info: '#64748B',
}

function SeverityBadge({ severity }) {
  const sev = (severity || 'info').toLowerCase()
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 6px',
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 700,
      color: 'white',
      background: SEV_COLORS[sev] || SEV_COLORS.info,
      textTransform: 'uppercase',
      letterSpacing: 0.3,
    }}>{sev}</span>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <h3 style={{
        fontSize: 11,
        fontWeight: 700,
        color: '#0F4F3A',
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        marginBottom: 6,
        borderBottom: '1px solid #D1FAE5',
        paddingBottom: 3,
      }}>{title}</h3>
      {children}
    </div>
  )
}

export default function ReportPanel({ selectedRun, actionsRef }) {
  const { chatReport, clearChatReport } = useAgent()

  const [report, setReport] = useState(null)
  const [loadStatus, setLoadStatus] = useState('idle') // idle | loading | error
  const [loadError, setLoadError] = useState(null)
  const [defaultRecipient, setDefaultRecipient] = useState('')

  // Email popover state
  const [popoverOpen, setPopoverOpen] = useState(false)
  const [emailStatus, setEmailStatus] = useState('idle')
  const [emailError, setEmailError] = useState(null)

  // Fetch the default recipient once on mount
  useEffect(() => {
    fetch('/api/reports/default-recipient')
      .then((r) => r.ok ? r.json() : { default_recipient: '' })
      .then((data) => setDefaultRecipient(data.default_recipient || ''))
      .catch(() => { /* non-blocking */ })
  }, [])

  // Load the report:
  //   - If chat just generated one, fetch the cached version by report_id
  //   - Otherwise fetch (or refresh) the canonical general report for the run
  const loadReport = useCallback(async () => {
    if (chatReport?.reportId) {
      setLoadStatus('loading')
      setLoadError(null)
      try {
        const res = await fetch(
          `/api/reports/cached/${encodeURIComponent(chatReport.reportId)}`
        )
        if (!res.ok) {
          if (res.status === 404) {
            // Cached report expired — fall back to a fresh general report
            clearChatReport()
            return
          }
          throw new Error(`HTTP ${res.status}`)
        }
        const data = await res.json()
        setReport(data)
        setLoadStatus('idle')
        return
      } catch (err) {
        setLoadStatus('error')
        setLoadError(err.message || 'Failed to load chat report')
        return
      }
    }

    if (!selectedRun) {
      setReport(null)
      return
    }
    setLoadStatus('loading')
    setLoadError(null)
    try {
      const res = await fetch(
        `/api/reports/general/${encodeURIComponent(selectedRun)}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' } }
      )
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text || res.statusText}`)
      }
      const data = await res.json()
      setReport(data)
      setLoadStatus('idle')
    } catch (err) {
      setLoadStatus('error')
      setLoadError(err.message || 'Failed to load report')
    }
  }, [selectedRun, chatReport, clearChatReport])

  useEffect(() => { loadReport() }, [loadReport])

  const handleSendEmail = () => {
    if (!report?.report_id) return
    setEmailStatus('idle')
    setEmailError(null)
    setPopoverOpen(true)
  }

  const handleDownloadPdf = () => {
    if (!report?.report_id) return
    const url = `/api/reports/pdf/${encodeURIComponent(report.report_id)}`
    const a = document.createElement('a')
    a.href = url
    a.download = ''
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }

  // 2026-05-18 — expose action handlers to the parent so the Level-2 toolbar
  // (rendered in App.jsx for the Report tab) can drive Send Email + Download
  // PDF without bubbling all of ReportPanel's local state up. Updated every
  // render so the closures capture the latest `report.report_id`.
  if (actionsRef) {
    actionsRef.current = {
      sendEmail: handleSendEmail,
      downloadPdf: handleDownloadPdf,
    }
  }

  const handleSendFromPopover = async (recipientsString) => {
    if (!report?.report_id) return
    setEmailStatus('sending')
    setEmailError(null)
    try {
      const recipients = recipientsString
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      const targetRunId = report.run_id || selectedRun
      const res = await fetch(
        `/api/reports/email/${encodeURIComponent(targetRunId)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ report_id: report.report_id, recipients }),
        }
      )
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text || res.statusText}`)
      }
      const data = await res.json()
      if (!data.sent) {
        throw new Error(data.error || 'Email send failed')
      }
      setEmailStatus('sent')
    } catch (err) {
      setEmailStatus('error')
      setEmailError(err.message || 'Failed to send email')
    }
  }

  const handleClosePopover = () => {
    setPopoverOpen(false)
    setEmailStatus('idle')
    setEmailError(null)
  }

  // ── Render ──

  if (!selectedRun && !chatReport) {
    return (
      <div style={{ padding: 16 }}>
        <p style={{ fontSize: 12, color: '#94A3B8', fontStyle: 'italic' }}>
          Select a run to generate a report.
        </p>
      </div>
    )
  }

  if (loadStatus === 'loading' && !report) {
    return (
      <div style={{ padding: 16 }}>
        <p style={{ fontSize: 12, color: '#64748B' }}>Generating report…</p>
      </div>
    )
  }

  if (loadStatus === 'error') {
    return (
      <div style={{ padding: 16 }}>
        <div style={{
          fontSize: 12,
          color: '#DC2626',
          background: '#FEF2F2',
          border: '1px solid #FECACA',
          borderRadius: 6,
          padding: '8px 10px',
          marginBottom: 10,
        }}>
          {loadError}
        </div>
        <button
          onClick={loadReport}
          style={{
            padding: '6px 12px',
            fontSize: 12,
            background: '#1D9E75',
            color: 'white',
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
          }}
        >
          Retry
        </button>
      </div>
    )
  }

  if (!report) return null

  const isConversation = report.scope === 'conversation'

  return (
    <div style={{
      padding: 14,
      height: '100%',
      overflowY: 'auto',
      background: 'white',
    }}>
      {/* Header */}
      <div style={{ marginBottom: 12 }}>
        <h2 style={{
          fontSize: 15,
          fontWeight: 700,
          color: '#0F4F3A',
          marginBottom: 2,
        }}>
          {isConversation ? '📝 ' : '📊 '}
          {isConversation
            ? (report.title || 'Investigation Report')
            : 'Network Status Report'}
        </h2>
        <p style={{ fontSize: 11, color: '#64748B' }}>
          {report.site || 'network'} · {report.generated_at}
          {isConversation && ' · investigation snapshot'}
        </p>
        {chatReport && (
          <button
            onClick={clearChatReport}
            style={{
              marginTop: 6,
              padding: '3px 8px',
              fontSize: 10,
              fontWeight: 600,
              color: '#0F4F3A',
              background: '#F0FDF4',
              border: '1px solid #BBF7D0',
              borderRadius: 4,
              cursor: 'pointer',
            }}
            title="Switch back to the canonical general report for this run"
          >
            ← Show general report
          </button>
        )}
      </div>

      {/* Action buttons (Send Email + Download PDF) relocated 2026-05-18 to
          the App.jsx Level-2 toolbar — see actionsRef wiring above. */}

      {isConversation
        ? <ConversationBody report={report} />
        : <GeneralBody report={report} />}

      {popoverOpen && (
        <EmailRecipientPopover
          defaultRecipient={defaultRecipient}
          status={emailStatus}
          errorMessage={emailError}
          onSend={handleSendFromPopover}
          onClose={handleClosePopover}
        />
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────
//  General report body
// ─────────────────────────────────────────────────────────────────────

function GeneralBody({ report }) {
  const health = report.health || {}
  const delta = report.delta || {}
  const topCriticals = report.top_criticals || []
  const topRecommendations = report.top_recommendations || []
  const cdPatterns = report.cross_device_patterns || []

  return (
    <>
      {report.prose_summary && (
        <div style={{
          background: '#F0FDF4',
          border: '1px solid #BBF7D0',
          borderRadius: 6,
          padding: '10px 12px',
          marginBottom: 14,
          fontSize: 12,
          lineHeight: 1.5,
          color: '#0F4F3A',
          fontStyle: 'italic',
        }}>
          {report.prose_summary}
        </div>
      )}

      <Section title="Network Health">
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 6,
          fontSize: 11,
        }}>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: '#0F172A' }}>{health.devices_total || 0}</span> devices
          </div>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: health.devices_unreachable ? '#DC2626' : '#0F172A' }}>
              {health.devices_unreachable || 0}
            </span> unreachable
          </div>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: '#0F172A' }}>{health.physical_links || 0}</span> physical links
          </div>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: '#0F172A' }}>{health.stack_links || 0}</span> stack
          </div>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: '#0F172A' }}>{health.infrastructure_links || 0}</span> HA / infra
          </div>
          <div style={{ color: '#475569' }}>
            <span style={{ fontWeight: 700, color: '#0F172A' }}>{health.routing_adjacencies || 0}</span> adjacencies
          </div>
        </div>
      </Section>

      <Section title="Finding Delta">
        {delta.previous_run_id ? (
          <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.6 }}>
            <div>vs <code style={{ fontSize: 10, color: '#64748B' }}>{delta.previous_run_id}</code></div>
            <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
              <span><strong style={{ color: '#DC2626' }}>+{delta.new_count || 0}</strong> new</span>
              <span><strong style={{ color: '#0F4F3A' }}>−{delta.resolved_count || 0}</strong> resolved</span>
              <span><strong style={{ color: '#64748B' }}>={delta.unchanged_count || 0}</strong> unchanged</span>
            </div>
          </div>
        ) : (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No previous run to compare against.
          </div>
        )}
      </Section>

      <Section title={`Top Critical Findings (${topCriticals.length})`}>
        {topCriticals.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No unacknowledged critical/high findings.
          </div>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {topCriticals.map((f, i) => (
              <li key={i} style={{
                fontSize: 11,
                marginBottom: 6,
                paddingBottom: 6,
                borderBottom: i < topCriticals.length - 1 ? '1px dotted #E2E8F0' : 'none',
              }}>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                  <SeverityBadge severity={f.severity} />
                  <code style={{ fontSize: 10, color: '#64748B' }}>{f.rule_id}</code>
                </div>
                <div style={{ color: '#0F172A', fontWeight: 500, lineHeight: 1.4 }}>{f.title}</div>
                {f.affected_devices?.length > 0 && (
                  <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>
                    {f.affected_devices.join(', ')}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Top Recommendations (${topRecommendations.length})`}>
        {topRecommendations.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No actionable recommendations.
          </div>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {topRecommendations.map((r, i) => (
              <li key={i} style={{
                fontSize: 11,
                marginBottom: 6,
                paddingBottom: 6,
                borderBottom: i < topRecommendations.length - 1 ? '1px dotted #E2E8F0' : 'none',
              }}>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                  <SeverityBadge severity={r.severity} />
                  <code style={{ fontSize: 10, color: '#64748B' }}>{r.rule_id}</code>
                </div>
                <div style={{ color: '#0F172A', lineHeight: 1.4 }}>{r.headline}</div>
                {r.affected_count > 0 && (
                  <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>
                    {r.affected_count} affected
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Cross-Device Patterns (${report.cross_device_count || 0})`}>
        {cdPatterns.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No cross-device patterns detected.
          </div>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {cdPatterns.map((p, i) => (
              <li key={i} style={{ fontSize: 11, marginBottom: 4, color: '#475569' }}>
                <code style={{ fontSize: 10, color: '#0F4F3A' }}>{p.rule_id}</code>
                {' · '}<strong>{p.count}</strong> findings
                {p.sample_devices?.length > 0 && (
                  <span style={{ color: '#64748B' }}> · {p.sample_devices.slice(0, 3).join(', ')}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </>
  )
}

// ─────────────────────────────────────────────────────────────────────
//  Conversation report body
// ─────────────────────────────────────────────────────────────────────

function ConversationBody({ report }) {
  const facts = report.key_facts || []
  const devices = report.devices_touched || []
  const tools = report.tools_used || []
  const findings = report.findings_referenced || []
  const metadata = report.metadata || {}

  return (
    <>
      {report.question && (
        <div style={{
          background: '#F0FDF4',
          border: '1px solid #BBF7D0',
          borderRadius: 6,
          padding: '10px 12px',
          marginBottom: 14,
          fontSize: 12,
          lineHeight: 1.5,
          color: '#0F4F3A',
          fontStyle: 'italic',
        }}>
          “{report.question}”
        </div>
      )}

      <Section title={`Key Facts (${facts.length})`}>
        {facts.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No key facts captured.
          </div>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {facts.map((f, i) => (
              <li key={i} style={{
                fontSize: 11,
                marginBottom: 5,
                color: '#0F172A',
                lineHeight: 1.4,
                paddingLeft: 14,
                position: 'relative',
              }}>
                <span style={{ position: 'absolute', left: 0 }}>•</span>
                {f.text}
                {f.grounded && (
                  <span style={{
                    marginLeft: 6,
                    fontSize: 9,
                    color: '#0F4F3A',
                    background: '#D1FAE5',
                    padding: '0 4px',
                    borderRadius: 3,
                  }}>verified</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Devices Touched (${devices.length})`}>
        {devices.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No devices referenced.
          </div>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {devices.map((d, i) => (
              <li key={i} style={{
                fontSize: 11,
                marginBottom: 4,
                color: '#0F172A',
              }}>
                <strong>{d.name}</strong>
                {d.role && <span style={{ color: '#64748B' }}> · {d.role}</span>}
                {d.os && <span style={{ color: '#64748B' }}> · {d.os}</span>}
                {d.reachable === false && (
                  <span style={{ color: '#DC2626', marginLeft: 6 }}>unreachable</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Tools Used (${tools.length})`}>
        {tools.length === 0 ? (
          <div style={{ fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>
            No tools recorded.
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {tools.map((t, i) => (
              <code key={i} style={{
                fontSize: 10,
                background: '#F1F5F9',
                color: '#0F4F3A',
                padding: '2px 6px',
                borderRadius: 3,
              }}>{t}</code>
            ))}
          </div>
        )}
      </Section>

      {findings.length > 0 && (
        <Section title={`Findings Referenced (${findings.length})`}>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {findings.map((f, i) => (
              <li key={i} style={{
                fontSize: 11,
                marginBottom: 6,
                paddingBottom: 6,
                borderBottom: i < findings.length - 1 ? '1px dotted #E2E8F0' : 'none',
              }}>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                  <SeverityBadge severity={f.severity} />
                  <code style={{ fontSize: 10, color: '#64748B' }}>{f.rule_id}</code>
                </div>
                <div style={{ color: '#0F172A', fontWeight: 500, lineHeight: 1.4 }}>{f.title}</div>
                {f.affected_devices?.length > 0 && (
                  <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>
                    {f.affected_devices.join(', ')}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {report.conclusions && (
        <Section title="Conclusions">
          <div style={{
            background: '#FFFBEB',
            border: '1px solid #FDE68A',
            borderRadius: 6,
            padding: '8px 10px',
            fontSize: 12,
            color: '#78350F',
            lineHeight: 1.5,
          }}>
            {report.conclusions}
          </div>
        </Section>
      )}

      {(metadata.invalid_devices_dropped || metadata.invalid_finding_ids_dropped) && (
        <div style={{
          fontSize: 10,
          color: '#94A3B8',
          fontStyle: 'italic',
          marginTop: 8,
        }}>
          Grounding dropped {metadata.invalid_devices_dropped || 0} device(s) and {' '}
          {metadata.invalid_finding_ids_dropped || 0} finding ID(s) the LLM referenced
          but Neo4j has no record of.
        </div>
      )}
    </>
  )
}
