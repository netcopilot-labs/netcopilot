"""F4f: shared agent-runtime helpers + Telegram bot pure helpers.

The Telegram bot is a long-polling service that can't be exercised without a bot
token, so the committed tests cover the pure pieces (context build, chunking,
token redaction) and skip the bot import when python-telegram-bot is absent.
"""

import pytest

from netcopilot import agent_runtime
from netcopilot.anonymizer import SessionAnonymizer


# ── agent_runtime (shared by the dashboard SSE route + the Telegram bot) ──────

def test_build_tool_context_derives_site_from_run_id(monkeypatch):
    monkeypatch.setattr(agent_runtime, "is_available", lambda: False)
    ctx = agent_runtime.build_tool_context("hq_2026-01-15_10-00-00")
    assert ctx["run_id"] == "hq_2026-01-15_10-00-00"
    assert ctx["site"] == "hq"            # prefix fallback when Neo4j is down
    assert ctx["data_dir"].endswith("hq_2026-01-15_10-00-00")


def test_build_tool_context_unknown_site_without_prefix(monkeypatch):
    monkeypatch.setattr(agent_runtime, "is_available", lambda: False)
    assert agent_runtime.build_tool_context("plainrun")["site"] == "unknown"


def test_seed_anonymizer_noop_without_neo4j(monkeypatch):
    monkeypatch.setattr(agent_runtime, "is_available", lambda: False)
    anon = SessionAnonymizer()
    agent_runtime.seed_anonymizer(anon, "r1")  # must not raise
    assert anon.get_summary()["devices_anonymized"] == 0


# ── Telegram bot pure helpers (skip if the [telegram] extra isn't installed) ──

def _bot():
    pytest.importorskip("telegram")
    from netcopilot import telegram_bot
    return telegram_bot


def test_chunk_message_splits_long_text():
    tb = _bot()
    chunks = tb._chunk_message("x" * 9000)
    assert len(chunks) >= 2 and all(len(c) <= 4000 for c in chunks)


def test_chunk_message_short_text_single_chunk():
    tb = _bot()
    assert tb._chunk_message("short") == ["short"]


def test_token_redaction():
    tb = _bot()
    out = tb._TOKEN_REDACT_RE.sub(
        "bot<REDACTED>", "POST https://api.telegram.org/bot12345:AbC-dEf_9/getUpdates"
    )
    assert "12345:AbC-dEf_9" not in out and "bot<REDACTED>" in out


def test_access_dev_mode_allows_all(monkeypatch):
    tb = _bot()
    monkeypatch.setattr(tb, "_allowed_users", set())  # empty whitelist = dev mode
    assert tb._check_access(999, "anyone") is True
