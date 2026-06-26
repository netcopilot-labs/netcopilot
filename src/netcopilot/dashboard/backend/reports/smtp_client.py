"""SMTP client for the report email feature.

Synchronous send via the standard-library `smtplib`. Works with any RFC 5321
SMTP server (e.g. Gmail at smtp.gmail.com:587, STARTTLS, app password).
Configuration comes entirely from environment variables — see .env.example.

Used by `routes/reports.py` and exercised by the report MCP tool via the route.
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from email.message import EmailMessage

log = logging.getLogger(__name__)

# Simple RFC-5321 ish email regex. Not a full RFC 5322 parser — we let
# Gmail be the source of truth for "is this address actually deliverable".
# We just want to catch obvious typos like missing "@" or no domain.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class SendResult:
    """Outcome of an SMTP send attempt."""

    sent: bool
    message_id: str | None = None
    recipients: list[str] | None = None
    error: str | None = None


def parse_recipients(raw: str | list[str]) -> list[str]:
    """Parse a recipient list from a string OR a list of strings.

    Accepts:
        "alice@example.com"
        "alice@example.com, bob@example.com"
        ["alice@example.com", "bob@example.com"]
        ["alice@example.com,bob@example.com"]   (split + flatten)

    Returns a de-duplicated, ordered list of trimmed addresses.
    Raises ValueError on the first invalid address found.
    """
    if isinstance(raw, str):
        items = [raw]
    else:
        items = list(raw)

    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        for addr in str(item).split(","):
            addr = addr.strip()
            if not addr:
                continue
            if not _EMAIL_RE.match(addr):
                raise ValueError(f"Invalid email address: {addr!r}")
            if addr.lower() in seen:
                continue
            seen.add(addr.lower())
            out.append(addr)
    if not out:
        raise ValueError("No recipients provided")
    return out


def _build_message(
    *,
    subject: str,
    body_text: str,
    from_name: str,
    from_addr: str,
    recipients: list[str],
    pdf_bytes: bytes,
    pdf_filename: str,
) -> tuple[EmailMessage, str]:
    """Assemble an EmailMessage with the PDF attachment.

    Returns (msg, message_id) — message_id is generated locally and set
    on the message header so the caller can log/return it.
    """
    msg = EmailMessage()
    message_id = f"<{uuid.uuid4().hex}@netcopilot.local>"
    msg["Message-ID"] = message_id
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(body_text)
    msg.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=pdf_filename,
    )
    return msg, message_id


def send_report(
    *,
    recipients: str | list[str],
    subject: str,
    body_text: str,
    pdf_bytes: bytes,
    pdf_filename: str,
    smtp_host: str | None = None,
    smtp_port: int | None = None,
    smtp_user: str | None = None,
    smtp_password: str | None = None,
    smtp_use_tls: bool | None = None,
    smtp_from_addr: str | None = None,
    smtp_from_name: str | None = None,
    timeout: int = 30,
) -> SendResult:
    """Send a report PDF as an email attachment.

    All SMTP parameters default to environment variables (SMTP_HOST,
    SMTP_PORT, etc.) — pass them explicitly only when overriding for
    tests. The function is synchronous and blocks until the SMTP server
    accepts the message (typically 1-3 sec for Gmail).

    Returns a SendResult dataclass — never raises. Caller checks .sent.
    """
    # Resolve config from env if not explicitly provided
    smtp_host = smtp_host or os.environ.get("SMTP_HOST", "")
    smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = smtp_user or os.environ.get("SMTP_USER", "")
    smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD", "")
    if smtp_use_tls is None:
        smtp_use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in (
            "true",
            "1",
            "yes",
            "on",
        )
    smtp_from_addr = smtp_from_addr or os.environ.get(
        "SMTP_FROM_ADDRESS", smtp_user
    )
    smtp_from_name = smtp_from_name or os.environ.get(
        "SMTP_FROM_NAME", "NetCopilot"
    )

    if not smtp_host:
        return SendResult(
            sent=False,
            error="SMTP_HOST is not configured. Set it in .env to enable email.",
        )
    if not smtp_user or not smtp_password:
        return SendResult(
            sent=False,
            error="SMTP_USER and SMTP_PASSWORD must both be set in .env.",
        )

    # Parse + validate recipients
    try:
        parsed_recipients = parse_recipients(recipients)
    except ValueError as exc:
        return SendResult(sent=False, error=str(exc))

    # Build the message
    msg, message_id = _build_message(
        subject=subject,
        body_text=body_text,
        from_name=smtp_from_name,
        from_addr=smtp_from_addr,
        recipients=parsed_recipients,
        pdf_bytes=pdf_bytes,
        pdf_filename=pdf_filename,
    )

    # Connect + send
    try:
        log.info(
            "SMTP send: host=%s:%d user=%s recipients=%d",
            smtp_host,
            smtp_port,
            smtp_user,
            len(parsed_recipients),
        )
        with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as s:
            s.ehlo()
            if smtp_use_tls:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            s.login(smtp_user, smtp_password)
            s.send_message(msg)
        log.info("SMTP send OK message_id=%s", message_id)
        return SendResult(
            sent=True,
            message_id=message_id,
            recipients=parsed_recipients,
        )
    except smtplib.SMTPAuthenticationError as exc:
        # Most common: bad app password, 2FA not enabled, account locked
        err = (
            f"SMTP authentication failed (code {exc.smtp_code}). "
            f"Check that 2-Step Verification is enabled on the Gmail account "
            f"and that SMTP_PASSWORD is a valid app password without spaces. "
            f"Server message: {_decode(exc.smtp_error)}"
        )
        log.warning("SMTP auth error: %s", err)
        return SendResult(sent=False, error=err)
    except smtplib.SMTPRecipientsRefused as exc:
        rejected = ", ".join(sorted(exc.recipients.keys()))
        err = f"All recipients refused by the SMTP server: {rejected}"
        log.warning("SMTP recipients refused: %s", err)
        return SendResult(sent=False, error=err)
    except smtplib.SMTPSenderRefused as exc:
        err = (
            f"SMTP sender refused (code {exc.smtp_code}). The From address "
            f"{smtp_from_addr!r} must match the authenticated user "
            f"{smtp_user!r} for Gmail. Server message: {_decode(exc.smtp_error)}"
        )
        log.warning("SMTP sender refused: %s", err)
        return SendResult(sent=False, error=err)
    except smtplib.SMTPException as exc:
        err = f"SMTP error: {type(exc).__name__}: {exc}"
        log.warning("SMTP exception: %s", err)
        return SendResult(sent=False, error=err)
    except Exception as exc:
        err = f"Unexpected error during SMTP send: {type(exc).__name__}: {exc}"
        log.exception("Unexpected SMTP send error")
        return SendResult(sent=False, error=err)


def _decode(value) -> str:
    """Best-effort decode of an smtplib error blob to a readable string."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return str(value)
    return str(value)
