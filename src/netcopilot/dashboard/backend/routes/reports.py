"""Reports endpoint — .

Four routes:

    POST /api/reports/general/{run_id}        → Generate the general report
    POST /api/reports/conversation/{run_id}   → Generate a conversation-scoped report
    GET  /api/reports/pdf/{report_id}         → Download the PDF for a previously generated report
    POST /api/reports/email/{run_id}          → Send a previously generated report by email

The general report is built from Neo4j + the existing data layer. The
conversation report is built from LLM-supplied topic + facts (see the
generate_report MCP tool in agent/tools/report.py — the LLM is the
context analyzer, this route just validates and renders).

All routes require dashboard auth (HTTP Basic) via the global FastAPI
dependency in main.py.

.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..data_loader import run_exists
from netcopilot.dashboard.backend.reports.generator import (
    build_conversation_report,
    build_general_report,
    get_cached_report,
)
from netcopilot.dashboard.backend.reports.pdf_renderer import is_pdf_rendering_available, render_pdf
from netcopilot.dashboard.backend.reports.smtp_client import SendResult, parse_recipients, send_report

log = logging.getLogger(__name__)
router = APIRouter()


# ── Pydantic models ──────────────────────────────────────────────────────────


class ConversationReportRequest(BaseModel):
    """Body for POST /api/reports/conversation/{run_id}.

    The LLM (or the dashboard) supplies the topic and facts. The route
    grounds them against Neo4j and returns the rendered report data.
    """

    title: str = Field(..., min_length=1, max_length=200)
    question: str | None = None
    facts: list[str] = Field(default_factory=list)
    devices_mentioned: list[str] = Field(default_factory=list)
    finding_ids_mentioned: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    conclusions: str | None = None


class EmailReportRequest(BaseModel):
    """Body for POST /api/reports/email/{run_id}."""

    report_id: str
    recipients: list[str] = Field(default_factory=list)


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/api/reports/general/{run_id}")
def generate_general_report(run_id: str):
    """Generate the canonical 7-section general report for a run.

    Returns the report data as JSON. The same data can be downloaded as
    PDF via /api/reports/pdf/{report_id} or emailed via
    /api/reports/email/{run_id}.
    """
    if not run_exists(run_id):
        raise HTTPException(
            status_code=404,
            detail=f"Run '{run_id}' not found or missing required files",
        )
    try:
        report = build_general_report(run_id)
    except Exception as exc:
        log.exception("Failed to build general report for %s", run_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {exc}",
        )
    return report.to_dict()


@router.post("/api/reports/conversation/{run_id}")
def generate_conversation_report(
    run_id: str,
    body: ConversationReportRequest,
):
    """Generate a conversation-scoped report from LLM-supplied facts.

    The LLM is the context analyzer — it picks the topic and the facts
    to include based on the recent chat. This route validates that any
    mentioned devices/findings actually exist in Neo4j (invalid entries
    are dropped silently with a count in metadata).
    """
    if not run_exists(run_id):
        raise HTTPException(
            status_code=404,
            detail=f"Run '{run_id}' not found",
        )
    try:
        report = build_conversation_report(
            run_id,
            title=body.title,
            question=body.question,
            facts=body.facts,
            devices_mentioned=body.devices_mentioned,
            finding_ids_mentioned=body.finding_ids_mentioned,
            tools_used=body.tools_used,
            conclusions=body.conclusions,
        )
    except Exception as exc:
        log.exception("Failed to build conversation report for %s", run_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {exc}",
        )
    return report.to_dict()


@router.get("/api/reports/cached/{report_id}")
def get_cached_report_by_id(report_id: str):
    """Return a previously generated report from the in-memory cache.

    Used by the LEFT panel ReportPanel to display a chat-initiated
    conversation report — the chat tool already generated the report
    and cached it under report_id, so the panel just looks it up
    instead of regenerating from scratch.

    404 if expired or never generated.
    """
    report_dict = get_cached_report(report_id)
    if report_dict is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found in cache. "
                   "It may have expired (30-minute TTL).",
        )
    return report_dict


@router.get("/api/reports/pdf/{report_id}")
def download_report_pdf(report_id: str):
    """Download a previously generated report as a PDF.

    Looks up the report in the in-memory cache (30-min TTL). Returns
    application/pdf with a Content-Disposition header so the browser
    triggers a download.
    """
    report_dict = get_cached_report(report_id)
    if report_dict is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found in cache. "
                   "It may have expired (30-minute TTL) — regenerate it.",
        )

    if not is_pdf_rendering_available():
        raise HTTPException(
            status_code=503,
            detail="PDF rendering is unavailable in this environment "
                   "(weasyprint not installed). The report data is still "
                   "available as JSON.",
        )

    try:
        pdf_bytes = render_pdf(report_dict["scope"], report_dict)
    except Exception as exc:
        log.exception("PDF rendering failed for %s", report_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to render PDF: {exc}",
        )

    site = report_dict.get("site") or "network"
    run_id = report_dict.get("run_id") or "report"
    scope = report_dict.get("scope") or "general"
    filename = f"netcopilot-{scope}-report-{site}-{run_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.post("/api/reports/email/{run_id}")
def email_report(run_id: str, body: EmailReportRequest):
    """Send a previously generated report by email.

    Looks up the report in the cache, renders it to PDF, attaches it,
    and sends via Gmail SMTP (configured via env vars). Returns
    {sent: bool, message_id, recipients_count, error?}.

    If recipients is empty, falls back to REPORT_DEFAULT_RECIPIENT.
    """
    if not run_exists(run_id):
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    report_dict = get_cached_report(body.report_id)
    if report_dict is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{body.report_id}' not found in cache. Regenerate it first.",
        )

    if not is_pdf_rendering_available():
        raise HTTPException(
            status_code=503,
            detail="PDF rendering is unavailable in this environment.",
        )

    # Resolve recipients: use body if provided, otherwise the default from .env
    recipients_input: list[str] | str
    if body.recipients:
        recipients_input = body.recipients
    else:
        default = os.environ.get("REPORT_DEFAULT_RECIPIENT", "")
        if not default:
            raise HTTPException(
                status_code=400,
                detail="No recipients provided and REPORT_DEFAULT_RECIPIENT is not set.",
            )
        recipients_input = default

    try:
        validated_recipients = parse_recipients(recipients_input)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Render PDF
    try:
        pdf_bytes = render_pdf(report_dict["scope"], report_dict)
    except Exception as exc:
        log.exception("PDF rendering failed for %s", body.report_id)
        raise HTTPException(status_code=500, detail=f"PDF rendering failed: {exc}")

    # Build subject + body
    scope = report_dict.get("scope", "general")
    site = report_dict.get("site") or "network"
    generated_at = report_dict.get("generated_at", "")
    if scope == "general":
        subject = f"[NetCopilot] Shift handover — {site} — {generated_at}"
        body_text = (
            "NetCopilot shift handover report attached.\n"
            "\n"
            f"Site: {site}\n"
            f"Generated: {generated_at}\n"
            f"Run: {report_dict.get('run_id', '?')}\n"
            "\n"
            f"Summary: {report_dict.get('prose_summary', '')}\n"
            "\n"
            "See the attached PDF for the full report.\n"
            "\n"
            "— NetCopilot · Network Context Intelligence\n"
        )
    else:
        subject = f"[NetCopilot] Investigation — {report_dict.get('title', 'Report')} — {site}"
        body_text = (
            "NetCopilot investigation report attached.\n"
            "\n"
            f"Topic: {report_dict.get('title', '')}\n"
            f"Site: {site}\n"
            f"Generated: {generated_at}\n"
            "\n"
            "See the attached PDF for the full investigation snapshot.\n"
            "\n"
            "— NetCopilot · Network Context Intelligence\n"
        )

    pdf_filename = f"netcopilot-{scope}-report-{site}-{report_dict.get('run_id', 'report')}.pdf"

    # Send
    result: SendResult = send_report(
        recipients=validated_recipients,
        subject=subject,
        body_text=body_text,
        pdf_bytes=pdf_bytes,
        pdf_filename=pdf_filename,
    )

    if not result.sent:
        log.warning("Email send failed: %s", result.error)
        return {
            "sent": False,
            "error": result.error or "Unknown error",
            "recipients": validated_recipients,
        }

    return {
        "sent": True,
        "message_id": result.message_id,
        "recipients": result.recipients,
        "recipients_count": len(result.recipients or []),
    }


@router.get("/api/reports/default-recipient")
def get_default_recipient():
    """Return the default email recipient from REPORT_DEFAULT_RECIPIENT.

    Used by the frontend to pre-fill the EmailRecipientPopover input.
    """
    return {
        "default_recipient": os.environ.get("REPORT_DEFAULT_RECIPIENT", ""),
    }
