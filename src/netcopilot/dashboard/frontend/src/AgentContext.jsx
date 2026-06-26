import { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'

const AgentContext = createContext(null)

export function AgentProvider({ children, selectedRun }) {
  const [messages, setMessages] = useState([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [contextReady, setContextReady] = useState(false)
  const [highlightDevice, setHighlightDevice] = useState(null)
  const [failedMember, setFailedMember] = useState(null)
  const [highlightSeq, setHighlightSeq] = useState(0)
  // C1A2: pending report waiting for the user to confirm "yes send by email".
  // Set when the agent emits a report_ready highlight event from generate_report.
  // Cleared when the user dismisses or completes the email send flow.
  // Shape: { reportId, scope, suggestedRecipients, site, runId } | null
  const [pendingReportEmail, setPendingReportEmail] = useState(null)
  // C1A2: the latest report generated from chat. Persists across popover
  // open/close so the LEFT ReportPanel keeps showing the conversation
  // report after the user dismisses the email dialog. Cleared by the
  // user via "Show general report" or by selecting a different run.
  // Shape: { reportId, scope } | null
  const [chatReport, setChatReport] = useState(null)
  const [sessionId] = useState(() => crypto.randomUUID?.() || `s-${Date.now()}`)
  const abortRef = useRef(null)

  // Warm up the enriched context when run changes (prefix cache priming)
  useEffect(() => {
    if (!selectedRun) {
      setContextReady(false)
      return
    }
    setContextReady(false)
    setMessages([])
    // C1A2: any chat-scoped report belongs to the previous run — clear it.
    setChatReport(null)
    // Warm up by sending a minimal request that forces context build
    fetch(`/api/chat/warmup/${encodeURIComponent(selectedRun)}`)
      .then(() => setContextReady(true))
      .catch(() => setContextReady(true))  // Don't block on warmup failure
  }, [selectedRun])

  const sendMessage = useCallback(async (text) => {
    if (!text.trim() || !selectedRun || isStreaming) return

    // Abort any in-flight request
    if (abortRef.current) abortRef.current.abort()
    const controller = new AbortController()
    abortRef.current = controller

    // Clear previous highlight state
    setHighlightDevice(null)
    setFailedMember(null)
    setHighlightSeq(s => s + 1)

    // Add user message
    const userMsg = { role: 'user', content: text }
    const agentMsg = { role: 'assistant', content: '', tools: [], done: false, error: null }
    setMessages(prev => [...prev, userMsg, agentMsg])
    setIsStreaming(true)

    try {
      // Build history with tool context for conversation continuity
      const history = []
      for (const m of messages) {
        if (m.role === 'user') {
          history.push({ role: 'user', content: m.content })
        } else if (m.role === 'assistant' && m.content) {
          // Include tool names in assistant context so model knows what was already queried
          let content = m.content
          if (m.tools && m.tools.length > 0) {
            const toolNames = m.tools.map(t => t.name).join(', ')
            content = `[Tools used: ${toolNames}]\n${content}`
          }
          history.push({ role: 'assistant', content })
        }
      }

      const res = await fetch(`/api/agent/chat/${encodeURIComponent(selectedRun)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, session_id: sessionId, history }),
        signal: controller.signal,
      })

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const event = JSON.parse(line.slice(6))

            if (event.type === 'tool_status') {
              setMessages(prev => {
                const updated = [...prev]
                const last = { ...updated[updated.length - 1] }
                const toolName = event.data.replace('Querying ', '').replace('...', '')
                last.tools = [...last.tools, { name: toolName, startTime: Date.now(), status: 'running' }]
                updated[updated.length - 1] = last
                return updated
              })
            } else if (event.type === 'content') {
              setMessages(prev => {
                const updated = [...prev]
                const last = { ...updated[updated.length - 1] }
                last.content += event.data
                // Mark the last running tool as complete
                if (last.tools.length > 0) {
                  const tools = [...last.tools]
                  const runningIdx = tools.findIndex(t => t.status === 'running')
                  if (runningIdx >= 0 && runningIdx < tools.length) {
                    // Mark all running tools as complete when content starts
                    for (let i = 0; i < tools.length; i++) {
                      if (tools[i].status === 'running') {
                        tools[i] = { ...tools[i], status: 'done', duration: ((Date.now() - tools[i].startTime) / 1000).toFixed(1) }
                      }
                    }
                  }
                  last.tools = tools
                }
                updated[updated.length - 1] = last
                return updated
              })
            } else if (event.type === 'usage') {
              setMessages(prev => {
                const updated = [...prev]
                const last = { ...updated[updated.length - 1] }
                last.usage = typeof event.data === 'string' ? JSON.parse(event.data) : event.data
                updated[updated.length - 1] = last
                return updated
              })
            } else if (event.type === 'done') {
              setMessages(prev => {
                const updated = [...prev]
                const last = { ...updated[updated.length - 1] }
                last.done = true
                // Finalize any remaining running tools
                last.tools = last.tools.map(t =>
                  t.status === 'running'
                    ? { ...t, status: 'done', duration: ((Date.now() - t.startTime) / 1000).toFixed(1) }
                    : t
                )
                updated[updated.length - 1] = last
                return updated
              })
            } else if (event.type === 'highlight') {
              try {
                const data = JSON.parse(event.data)
                if (data.type === 'report_ready') {
                  // C1A2: generate_report tool fired and produced a report_id.
                  // Surface the email-confirm popover; the user can also choose
                  // to ignore it and the report stays cached for 30 minutes.
                  // suggested_recipients arrives as an array from the tool;
                  // join into a comma-separated string for the popover input.
                  const suggested = Array.isArray(data.suggested_recipients)
                    ? data.suggested_recipients.join(', ')
                    : (data.suggested_recipients || '')
                  setPendingReportEmail({
                    reportId: data.report_id,
                    scope: data.scope,
                    suggestedRecipients: suggested,
                    site: data.site,
                    runId: data.run_id,
                  })
                  // Also persist for the LEFT panel — survives popover close.
                  setChatReport({
                    reportId: data.report_id,
                    scope: data.scope,
                  })
                } else if (data.devices) {
                  // Multi-device path highlight
                  setHighlightDevice(data.devices)
                  setFailedMember(null)
                  setHighlightSeq(s => s + 1)
                } else if (data.device) {
                  setHighlightDevice(data.device)
                  setFailedMember(data.failedMember ?? null)
                  setHighlightSeq(s => s + 1)
                }
              } catch (_) {}
            } else if (event.type === 'error') {
              setMessages(prev => {
                const updated = [...prev]
                const last = { ...updated[updated.length - 1] }
                last.error = event.data
                last.done = true
                updated[updated.length - 1] = last
                return updated
              })
            }
          } catch (_) {
            // Ignore malformed SSE lines
          }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setMessages(prev => {
          const updated = [...prev]
          const last = { ...updated[updated.length - 1] }
          last.error = err.message
          last.done = true
          updated[updated.length - 1] = last
          return updated
        })
      }
    } finally {
      setIsStreaming(false)
      abortRef.current = null
    }
  }, [selectedRun, sessionId, isStreaming, messages])

  const clearMessages = useCallback(() => {
    setMessages([])
  }, [])

  // C1A1: Show the onboarding help card. Pushes a synthetic message into
  // the conversation that AgentMessage.jsx renders as the 3 onboarding
  // buttons. The help_card role is filtered out by the history builder
  // above (only user/assistant are sent to the LLM), so it's a pure
  // visual scroll-stream entry.
  //
  // Don't duplicate adjacent help cards: if the last message is already
  // a help_card, do nothing. Prevents accidental spam.
  const showHelp = useCallback(() => {
    setMessages(prev => {
      if (prev.length > 0 && prev[prev.length - 1].role === 'help_card') {
        return prev
      }
      return [...prev, { role: 'help_card', done: true }]
    })
  }, [])

  // ── C1S4-US7: Pipeline progress SSE ──────────────────────────────
  const [pipelineMessages, setPipelineMessages] = useState([])
  const progressRef = useRef(null)

  const startProgressStream = useCallback(() => {
    if (progressRef.current) progressRef.current.close()
    setPipelineMessages([])

    const es = new EventSource('/api/runs/progress')
    progressRef.current = es

    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data)
        setPipelineMessages(prev => {
          // Deduplicate by stage (each stage at most once, except collection_error)
          if (event.stage !== 'collection_error' && prev.some(m => m.stage === event.stage)) return prev
          return [...prev, event]
        })
        if (event.stage === 'done' || event.stage === 'error') {
          es.close()
          progressRef.current = null
        }
      } catch (_) {}
    }

    es.onerror = () => {
      es.close()
      progressRef.current = null
    }
  }, [])

  // C1A2: Confirm send-by-email for a chat-initiated report.
  // POSTs to /api/reports/email/{run_id} with the cached report_id and
  // user-supplied recipients. Resolves to {sent, error?} so the caller
  // (the popover) can render success/error inline.
  const confirmReportEmail = useCallback(async (recipientsString) => {
    if (!pendingReportEmail) return { sent: false, error: 'No pending report' }
    const { reportId, runId } = pendingReportEmail
    try {
      const recipients = recipientsString
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      const res = await fetch(
        `/api/reports/email/${encodeURIComponent(runId)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ report_id: reportId, recipients }),
        }
      )
      if (!res.ok) {
        const text = await res.text()
        return { sent: false, error: `HTTP ${res.status}: ${text || res.statusText}` }
      }
      const data = await res.json()
      if (!data.sent) {
        return { sent: false, error: data.error || 'Email send failed' }
      }
      return { sent: true }
    } catch (err) {
      return { sent: false, error: err.message || 'Send failed' }
    }
  }, [pendingReportEmail])

  const cancelReportEmail = useCallback(() => {
    setPendingReportEmail(null)
  }, [])

  // C1A2: clear the chat-scoped report so the LEFT ReportPanel falls back
  // to showing the canonical general report for the current run.
  const clearChatReport = useCallback(() => {
    setChatReport(null)
  }, [])

  const stopProgressStream = useCallback(() => {
    if (progressRef.current) {
      progressRef.current.close()
      progressRef.current = null
    }
  }, [])

  // Cleanup on unmount
  useEffect(() => () => { if (progressRef.current) progressRef.current.close() }, [])

  return (
    <AgentContext.Provider value={{ messages, pipelineMessages, isStreaming, contextReady, sendMessage, clearMessages, showHelp, startProgressStream, stopProgressStream, sessionId, highlightDevice, failedMember, highlightSeq, pendingReportEmail, confirmReportEmail, cancelReportEmail, chatReport, clearChatReport }}>
      {children}
    </AgentContext.Provider>
  )
}

export function useAgent() {
  const ctx = useContext(AgentContext)
  if (!ctx) throw new Error('useAgent must be inside AgentProvider')
  return ctx
}
