"""Reports package — .

Modules:
    generator     — assembles general + conversation report data from Neo4j
    pdf_renderer  — renders ReportData → PDF bytes via WeasyPrint + Jinja2
    smtp_client   — synchronous email send via Gmail SMTP, STARTTLS, app password

The MCP tool `agent.tools.report.generate_report` calls into the FastAPI
routes in `routes/reports.py` (single source of truth — both the chat
agent and the dashboard UI use the same backend endpoints).

Locked architectural decisions ():

- Reports are generated on demand from current Neo4j state (no caching
  beyond a 30-minute in-memory dict keyed by report_id for the case
  where the user clicks Download then Email a few seconds later).
- General reports have 7 sections: prose summary, metadata, scorecard,
  finding delta, top criticals, top recommendations, cross-device patterns.
- Conversation reports follow a different "case file" template: title,
  question, key facts, devices touched, tools used, findings referenced,
  conclusions / action items.
- Email goes via Gmail SMTP (smtp.gmail.com:587, STARTTLS, app password).
  Plan B is the always-available Download PDF button.
- Sender identity is fixed at SMTP_FROM_ADDRESS = SMTP_USER per Gmail's
  policy. Display name is SMTP_FROM_NAME.
- Comma-separated multi-recipient parsing in the email endpoint.
"""
