"""generate_report — MCP tool for the  Report feature.

The LLM calls this when the user asks for a report. Two scopes:

  scope="general"        — the canonical 7-section operational report.
                           Same content the dashboard's Report button shows.

  scope="conversation"   — a case-file snapshot of the recent investigation
                           in the chat. The LLM is the context analyzer:
                           it picks the topic, the key facts, the devices
                           mentioned, and the conclusions, then passes them
                           to the tool. The tool grounds the facts against
                           Neo4j (invalid devices/findings dropped silently)
                           and returns a structured report.

The tool calls the same FastAPI routes the dashboard button uses
(/api/reports/general/{run_id}, /api/reports/conversation/{run_id}) so
there is a single source of truth — chat and dashboard always produce
identical reports.

Two-phase confirmation flow: the tool ALWAYS shows the report in the
LEFT panel and pre-fills the email recipient. It NEVER sends the email
in the same call. The user confirms via the Send button OR by replying
"yes" / "send" / "confirm" in the chat afterwards. This avoids
accidental email sends from ambiguous user input.

The tool returns a formatted text summary AS its result (so the LLM can
echo it in the chat), and yields a `report_ready` highlight event that
the AgentContext frontend handler picks up to switch the LEFT panel to
Report mode and open the EmailRecipientPopover.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)


# Where the local FastAPI lives. The dashboard container talks to itself
# via 127.0.0.1:8080 (uvicorn). For tests we override this.
_INTERNAL_API_BASE = os.environ.get(
    "NETCOPILOT_INTERNAL_API", "http://127.0.0.1:8080"
)


async def generate_report(
    *,
    scope: str = "general",
    title: str | None = None,
    question: str | None = None,
    facts: list[str] | None = None,
    devices_mentioned: list[str] | None = None,
    finding_ids_mentioned: list[str] | None = None,
    tools_used: list[str] | None = None,
    conclusions: str | None = None,
    context: dict,
) -> str:
    """Generate a NetCopilot report (general or conversation-scoped).

    For scope="general", no other parameters are needed — the tool reads
    the current run from context and assembles the canonical report.

    For scope="conversation", the LLM MUST supply:
      - title: 1-sentence summary of the conversation topic
      - facts: list of key facts the operator should know
      - devices_mentioned: list of device names referenced in the chat
      - finding_ids_mentioned: list of finding_ids referenced (optional)
      - tools_used: list of MCP tool names called during the conversation
      - conclusions: action items / next steps

    Returns a formatted text summary the LLM should echo in chat. The
    actual report data is rendered in the LEFT panel via a side-channel
    (the report_ready highlight event).
    """
    # Validate scope
    if scope not in ("general", "conversation"):
        return (
            f"generate_report: invalid scope {scope!r}. "
            f"Must be 'general' or 'conversation'."
        )

    run_id = (context or {}).get("run_id", "")
    if not run_id:
        return (
            "generate_report: no run_id in context. "
            "A network run must be selected before generating a report."
        )

    # Build the request locally rather than going through HTTP — the report
    # generator is in-process and we don't need the HTTP round-trip. We
    # also avoid auth complications (the global FastAPI auth dependency
    # would block an in-process call without credentials).
    try:
        if scope == "general":
            from netcopilot.dashboard.backend.reports.generator import build_general_report

            report = build_general_report(run_id)
            report_dict = report.to_dict()
        else:
            from netcopilot.dashboard.backend.reports.generator import build_conversation_report

            if not title:
                return (
                    "generate_report (conversation scope): the LLM must supply a "
                    "non-empty `title` summarizing the conversation topic."
                )
            report = build_conversation_report(
                run_id,
                title=title,
                question=question,
                facts=facts or [],
                devices_mentioned=devices_mentioned or [],
                finding_ids_mentioned=finding_ids_mentioned or [],
                tools_used=tools_used or [],
                conclusions=conclusions,
            )
            report_dict = report.to_dict()
    except Exception as exc:
        log.exception("generate_report failed for run_id=%s scope=%s", run_id, scope)
        return f"generate_report failed: {type(exc).__name__}: {exc}"

    # Format a chat-friendly summary the LLM should echo to the operator.
    # The LLM is instructed (in the system prompt) to print this verbatim
    # and remind the user that the full report is shown in the LEFT panel.
    if scope == "general":
        summary = _format_general_summary(report_dict)
    else:
        summary = _format_conversation_summary(report_dict)

    # Emit a side-channel signal that AgentContext picks up to switch
    # the LEFT panel to Report mode and open the email popover. This
    # uses the existing `highlight` event channel that already flows from
    # the orchestrator → SSE → frontend.
    default_recipient = os.environ.get("REPORT_DEFAULT_RECIPIENT", "")
    highlight_payload = {
        "type": "report_ready",
        "scope": scope,
        "report_id": report_dict["report_id"],
        "suggested_recipients": [default_recipient] if default_recipient else [],
        "site": report_dict.get("site", ""),
        "run_id": run_id,
    }

    # The orchestrator looks for `__highlight__:<json>` markers in the tool
    # result and emits them as `highlight` SSE events. (See
    # agent/orchestrator.py and agent/shared.py for the existing pattern.)
    # We append the marker to the end of the result string.
    return summary + f"\n\n__highlight__:{json.dumps(highlight_payload)}"


# ─────────────────────────────────────────────────────────────────────────────
#  Chat summary formatters
# ─────────────────────────────────────────────────────────────────────────────


def _format_general_summary(r: dict) -> str:
    """Plain text summary the LLM echoes for a general report."""
    health = r.get("health", {})
    delta = r.get("delta", {})
    top_critical_count = len(r.get("top_criticals", []))
    cd_count = r.get("cross_device_count", 0)

    lines = [
        f"📋 General Report — {r.get('site', '?')} — {r.get('generated_at', '?')}",
        "",
        r.get("prose_summary", ""),
        "",
        f"• Devices: {health.get('devices_total', 0)} total, "
        f"{health.get('devices_unreachable', 0)} unreachable",
        f"• Top critical/high findings: {top_critical_count}",
        f"• Cross-device findings: {cd_count}",
    ]
    if delta.get("previous_run_id"):
        lines.append(
            f"• Delta vs previous run: +{delta.get('new_count', 0)} new, "
            f"-{delta.get('resolved_count', 0)} resolved"
        )
    lines.append("")
    lines.append("The full report is now shown in the left panel.")
    lines.append(
        "Click 📧 Send by Email to send it, or 📥 Download PDF to save it."
    )
    return "\n".join(lines)


def _format_conversation_summary(r: dict) -> str:
    """Plain text summary the LLM echoes for a conversation report."""
    lines = [
        f"📝 Investigation Report — {r.get('title', '?')}",
        "",
        f"• Devices touched: {len(r.get('devices_touched', []))}",
        f"• Tools used: {', '.join(r.get('tools_used', []) or ['—'])}",
        f"• Key facts: {len(r.get('key_facts', []))}",
        f"• Findings referenced: {len(r.get('findings_referenced', []))}",
    ]
    metadata = r.get("metadata", {}) or {}
    dropped_d = metadata.get("invalid_devices_dropped", 0)
    dropped_f = metadata.get("invalid_finding_ids_dropped", 0)
    if dropped_d or dropped_f:
        lines.append(
            f"• (Dropped {dropped_d} invalid device(s) and {dropped_f} "
            f"invalid finding ID(s) during grounding.)"
        )
    lines.append("")
    lines.append("The investigation snapshot is now shown in the left panel.")
    lines.append(
        "Click 📧 Send by Email to share it, or 📥 Download PDF to save it."
    )
    return "\n".join(lines)
