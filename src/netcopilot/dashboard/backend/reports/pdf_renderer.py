"""PDF rendering for the  Report feature.

Renders general or conversation reports to PDF bytes via WeasyPrint +
Jinja2. WeasyPrint is in `requirements.txt` and installed inside the
Docker image; the local dev venv may not have it (which is fine — the
unit tests skip the renderer step when WeasyPrint is unavailable).

The HTML templates live in `reports/templates/`:
    general_report.html       — single-page operational status report
    conversation_report.html  — case-file style investigation snapshot

Both are branded with the NetCopilot green palette
(#1D9E75 / #0F4F3A / #5DCAA5) and use system fonts only (no external
font files — known WeasyPrint Docker quirk).
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(scope: str, report_dict: dict) -> str:
    """Render the report dict to HTML using the appropriate Jinja2 template.

    Returns the rendered HTML string. Useful as a separate step from PDF
    rendering — easier to test, easier to debug.
    """
    if scope == "general":
        template = _jinja_env.get_template("general_report.html")
    elif scope == "conversation":
        template = _jinja_env.get_template("conversation_report.html")
    else:
        raise ValueError(f"Unknown report scope: {scope}")

    return template.render(report=report_dict)


def render_pdf(scope: str, report_dict: dict) -> bytes:
    """Render the report dict to PDF bytes via WeasyPrint.

    Raises RuntimeError if WeasyPrint is not importable (e.g., the local
    dev venv missing the system dependencies). Inside the Docker container
    WeasyPrint is always available — see Dockerfile stage 2.
    """
    try:
        import weasyprint
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is not installed in this environment. "
            "PDF rendering requires the dashboard Docker image where "
            "weasyprint is in requirements.txt and the system libraries "
            "(libpango, libcairo, etc.) are installed via apt-get."
        ) from exc

    html_str = render_html(scope, report_dict)
    pdf_bytes = weasyprint.HTML(string=html_str).write_pdf()
    log.info(
        "Rendered %s report to PDF (%d bytes, report_id=%s)",
        scope,
        len(pdf_bytes),
        report_dict.get("report_id", "?"),
    )
    return pdf_bytes


def is_pdf_rendering_available() -> bool:
    """Cheap probe — used by routes/tests to decide whether to attempt PDF."""
    try:
        import weasyprint  # noqa: F401
        return True
    except ImportError:
        return False
