"""Telegram bot client for NetCopilot.

@NetCopilotBot: second client for the MCP tools, proving the
MCP server's client-agnostic architecture. Operators query the
network from their phone.

Uses python-telegram-bot v21+ with async long polling.
"""

import logging
import os
import re
import time
from pathlib import Path

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from netcopilot.orchestrator import run_tool_loop, SYSTEM_PROMPT
from netcopilot.llm import build_provider, get_provider
from netcopilot.llm.registry import load_registry
from netcopilot.agent_runtime import build_tool_context, seed_anonymizer
from netcopilot.anonymizer import SessionAnonymizer
from netcopilot.mcp.registry import TOOL_SCHEMAS

log = logging.getLogger(__name__)

# ── Bot-token redaction filter ──
#
# python-telegram-bot's httpx adapter logs full request URLs at INFO level on
# every getUpdates call (~10s polling cadence). The URL contains the bot token:
#   POST https://api.telegram.org/bot<DIGITS>:<ALNUM_-+>/getUpdates ...
# Pre-fix, ~2 weeks of VM logs + ~41 hours of XPS logs accumulated thousands
# of token impressions in plaintext. This filter regex-redacts the token from
# record.msg + record.args BEFORE the formatter renders the line.

_TOKEN_REDACT_RE = re.compile(r"bot\d+:[A-Za-z0-9_-]+")


class _RedactTokenFilter(logging.Filter):
    """Redact Telegram bot tokens from log records before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _TOKEN_REDACT_RE.sub("bot<REDACTED>", record.msg)
        if record.args:
            record.args = tuple(
                _TOKEN_REDACT_RE.sub("bot<REDACTED>", a) if isinstance(a, str) else a
                for a in record.args
            )
        return True


# ── Configuration ──

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ALLOWED_USERS = os.environ.get("TELEGRAM_ALLOWED_USERS", "")
TELEGRAM_MAX_RESULT_CHARS = int(os.environ.get("TELEGRAM_MAX_RESULT_CHARS", "32000"))
RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

# Parse allowed users whitelist
_allowed_users: set[int] = set()
if TELEGRAM_ALLOWED_USERS:
    for uid in TELEGRAM_ALLOWED_USERS.split(","):
        uid = uid.strip()
        if uid.isdigit():
            _allowed_users.add(int(uid))

# ── Conversation History ──

# chat_id → (messages, last_access_timestamp)
_conversations: dict[int, tuple[list[dict], float]] = {}
_CONVERSATION_TTL = 1800  # 30 minutes
_MAX_PAIRS = 10  # Max message pairs per conversation

# Per-chat active run override (chat_id → run_id)
_active_runs: dict[int, str] = {}


def _check_access(user_id: int, username: str | None) -> bool:
    """Check if user is authorized. Empty whitelist = dev mode (allow all)."""
    if not _allowed_users:
        return True
    if user_id in _allowed_users:
        return True
    log.warning("Access denied: user_id=%d username=%s", user_id, username or "?")
    return False


def _get_history(chat_id: int) -> list[dict]:
    """Get conversation history, cleaning expired sessions."""
    now = time.time()
    expired = [cid for cid, (_, ts) in _conversations.items() if now - ts > _CONVERSATION_TTL]
    for cid in expired:
        del _conversations[cid]

    if chat_id not in _conversations:
        return []
    msgs, ts = _conversations[chat_id]
    if now - ts > _CONVERSATION_TTL:
        del _conversations[chat_id]
        return []
    return msgs


def _save_history(chat_id: int, messages: list[dict]):
    """Save conversation history, enforcing pair cap."""
    if len(messages) > _MAX_PAIRS * 2:
        messages = messages[-_MAX_PAIRS * 2:]
    _conversations[chat_id] = (messages, time.time())


def _list_runs() -> list[str]:
    """List all available run_ids, newest first."""
    if not RUNS_DIR.is_dir():
        return []
    return sorted(
        [d.name for d in RUNS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")],
        reverse=True,
    )


def _resolve_run(chat_id: int) -> str | None:
    """Resolve the active run for this chat. Per-chat override > latest."""
    if chat_id in _active_runs:
        return _active_runs[chat_id]
    runs = _list_runs()
    return runs[0] if runs else None


def _chunk_message(text: str, max_len: int = 4000) -> list[str]:
    """Split text into chunks for Telegram's 4096-char limit.

    Splits at double newlines first, then single newlines, then word boundaries.
    Max 5 chunks — remainder truncated with notice.
    """
    if not text:
        return ["No response generated."]
    if len(text) <= max_len:
        return [text]

    chunks: list[str] = []
    remaining = text

    while remaining and len(chunks) < 5:
        if len(remaining) <= max_len:
            chunks.append(remaining)
            remaining = ""
            break

        # Try double newline
        split_pos = remaining.rfind("\n\n", 0, max_len)
        if split_pos > max_len // 4:
            chunks.append(remaining[:split_pos])
            remaining = remaining[split_pos + 2:]
            continue

        # Try single newline
        split_pos = remaining.rfind("\n", 0, max_len)
        if split_pos > max_len // 4:
            chunks.append(remaining[:split_pos])
            remaining = remaining[split_pos + 1:]
            continue

        # Try word boundary
        split_pos = remaining.rfind(" ", 0, max_len)
        if split_pos > max_len // 4:
            chunks.append(remaining[:split_pos])
            remaining = remaining[split_pos + 1:]
            continue

        # Hard split
        chunks.append(remaining[:max_len])
        remaining = remaining[max_len:]

    if remaining:
        chunks.append("[Response truncated. Use filters to narrow.]")

    return chunks


async def _send_chunked(update: Update, text: str):
    """Send text as one or more messages, with Markdown fallback to plain text."""
    for chunk in _chunk_message(text):
        try:
            await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)
        except BadRequest:
            await update.message.reply_text(chunk)


# ── Command Handlers ──


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Welcome message with bot capabilities."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    await update.message.reply_text(
        "*NetCopilot* \u2014 Network Intelligence Bot\n\n"
        "Ask me anything about your network. I have access to the MCP tools "
        "for topology, findings, routing, security, and more.\n\n"
        "*Examples:*\n"
        "\u2022 How many devices are in the network?\n"
        "\u2022 What are the critical findings?\n"
        "\u2022 What happens if core-rtr-01 fails?\n"
        "\u2022 How does customer-A traffic reach the internet?\n\n"
        "Type /help for more commands.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Usage tips and example questions."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    await update.message.reply_text(
        "*Commands:*\n"
        "/start \u2014 Welcome message\n"
        "/help \u2014 This help text\n"
        "/tools \u2014 List all 16 available tools\n"
        "/run \u2014 Show or switch data run (`/run <substring>`)\n"
        "/clear \u2014 Reset conversation history\n"
        "/model \u2014 Show active LLM\n"
        "/collect \u2014 Trigger fresh data collection\n\n"
        "*Tips:*\n"
        "\u2022 Ask follow-up questions \u2014 I remember context for 30 minutes\n"
        "\u2022 Be specific: \"findings on fw-01\" is better than \"all findings\"\n"
        "\u2022 Long responses are split across messages automatically\n"
        "\u2022 Use /clear to start a fresh conversation",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_tools(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List all available MCP tools."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    lines = [f"*Available Tools ({len(TOOL_SCHEMAS)}):*\n"]
    for ts in TOOL_SCHEMAS:
        desc = ts["description"].split(".")[0] + "."
        lines.append(f"\u2022 `{ts['name']}` \u2014 {desc}")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


async def cmd_run(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show current run or switch: /run shows active, /run <filter> switches."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    chat_id = update.effective_chat.id
    args = context.args  # words after /run

    runs = _list_runs()
    if not runs:
        await update.message.reply_text("No data runs found.")
        return

    # /run <filter> — switch to matching run
    if args:
        query = args[0].lower()
        matches = [r for r in runs if query in r.lower()]
        if not matches:
            await update.message.reply_text(
                f"No run matching \"{args[0]}\".\n\n"
                f"*Available:*\n" + "\n".join(f"  `{r}`" for r in runs),
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        if len(matches) > 1:
            await update.message.reply_text(
                f"Multiple matches:\n" + "\n".join(f"  `{r}`" for r in matches)
                + "\n\nBe more specific.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        _active_runs[chat_id] = matches[0]
        # Clear conversation history when switching runs
        if chat_id in _conversations:
            del _conversations[chat_id]
        await update.message.reply_text(
            f"Switched to `{matches[0]}`. Conversation cleared.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # /run — show current
    run_id = _resolve_run(chat_id)
    site = build_tool_context(run_id)["site"]

    parts = run_id.split("_", 1)
    timestamp = parts[1] if len(parts) > 1 else "unknown"

    override = " (selected)" if chat_id in _active_runs else " (latest)"

    await update.message.reply_text(
        f"*Current Run:* `{run_id}`{override}\n"
        f"*Site:* {site or 'unknown'}\n"
        f"*Timestamp:* {timestamp}\n\n"
        f"Switch runs with `/run <substring>`",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reset conversation history for this chat."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    chat_id = update.effective_chat.id
    if chat_id in _conversations:
        del _conversations[chat_id]
    await update.message.reply_text("Conversation cleared. Fresh start!")


async def cmd_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show the active LLM provider."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    models, default_id = load_registry()
    cfg = next((m for m in models if m.id == default_id), None)
    label = cfg.label if cfg else default_id
    await update.message.reply_text(
        f"*Active model:* {label}\n"
        f"Configured in `models.yaml` (default: `{default_id}`).",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_collect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Trigger a fresh pipeline collection run."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    import httpx

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("http://netcopilot-dashboard:8080/api/runs/trigger")
            if resp.status_code == 200:
                await update.message.reply_text(
                    "Collection started. Ask me again in ~90 seconds."
                )
            else:
                await update.message.reply_text(
                    f"Failed to trigger collection: HTTP {resp.status_code}"
                )
    except Exception as exc:
        await update.message.reply_text(f"Could not reach dashboard: {exc}")


# ── Text Message Handler ──


async def _process_query(update: Update, user_text: str):
    """Shared query logic for text and voice messages."""
    chat_id = update.effective_chat.id

    # Resolve active run for this chat
    run_id = _resolve_run(chat_id)
    if not run_id:
        await update.message.reply_text("No data runs available. Run /collect first.")
        return

    # Build tool context + select the default registry model
    tool_context = build_tool_context(run_id)
    models, default_id = load_registry()
    cfg = next((m for m in models if m.id == default_id), None)
    try:
        provider = build_provider(cfg) if cfg else get_provider()
    except Exception as exc:  # e.g. a commercial model without its API key
        await update.message.reply_text(f"LLM model unavailable: {exc}")
        return

    # Anonymize per the model's flag (cloud models scrub; local stays on-host).
    anonymizer = None
    if (cfg.anonymize if cfg else provider.name == "claude"):
        anonymizer = SessionAnonymizer()
        seed_anonymizer(anonymizer, run_id)

    # Build normalized history (system is passed separately to the loop)
    raw_history = _get_history(chat_id)
    history = [*raw_history, {"role": "user", "content": user_text}]
    if anonymizer:
        history = [{**m, "content": anonymizer.anonymize(m["content"])} for m in history]

    # Typing indicator + status message
    await update.effective_chat.send_action(ChatAction.TYPING)
    status_msg = await update.message.reply_text("Thinking...")

    # Run the orchestrator tool loop
    content_parts = []
    try:
        async for event in run_tool_loop(
            history, tool_context, provider=provider, system=SYSTEM_PROMPT,
            anonymizer=anonymizer, max_result_chars=TELEGRAM_MAX_RESULT_CHARS,
        ):
            if event["type"] == "tool_status":
                try:
                    await status_msg.edit_text(event["data"])
                except BadRequest:
                    pass  # message unchanged or already deleted
            elif event["type"] == "content":
                content_parts.append(event["data"])
            elif event["type"] == "error":
                content_parts.append(f"Error: {event['data']}")
            # tool_call / tool_result / highlight / usage events: ignored by Telegram
    except Exception as exc:
        log.exception("Tool loop failed for chat %d", chat_id)
        content_parts.append(f"Something went wrong: {exc}")

    # Remove status message
    try:
        await status_msg.delete()
    except BadRequest:
        pass

    # Send final answer
    final_text = "".join(content_parts) or "No response generated."
    await _send_chunked(update, final_text)

    # Update conversation history
    history.append({"role": "user", "content": user_text})
    history.append({"role": "assistant", "content": final_text})
    _save_history(chat_id, history)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return
    await _process_query(update, update.message.text)


# ── Voice Message Handler ──

# Lazy-loaded Whisper model (downloaded on first voice message, ~150MB)
_whisper_model = None


def _get_whisper_model():
    """Load faster-whisper model on first use."""
    global _whisper_model
    if _whisper_model is None:
        from faster_whisper import WhisperModel

        log.info("Loading Whisper 'base' model (first voice message)...")
        _whisper_model = WhisperModel("base", device="cpu", compute_type="int8")
        log.info("Whisper model loaded.")
    return _whisper_model


async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle voice messages: download -> transcribe -> query."""
    if not _check_access(update.effective_user.id, update.effective_user.username):
        await update.message.reply_text("Access denied. Contact your admin.")
        return

    import tempfile

    # Download voice file
    voice = update.message.voice or update.message.audio
    if not voice:
        await update.message.reply_text("Could not read audio.")
        return

    status_msg = await update.message.reply_text("Transcribing audio...")

    try:
        voice_file = await context.bot.get_file(voice.file_id)
        with tempfile.NamedTemporaryFile(suffix=".ogg", delete=False) as tmp:
            tmp_path = tmp.name
            await voice_file.download_to_drive(tmp_path)

        # Transcribe
        model = _get_whisper_model()
        segments, info = model.transcribe(tmp_path, beam_size=5)
        transcript = " ".join(seg.text.strip() for seg in segments).strip()

        # Clean up temp file
        Path(tmp_path).unlink(missing_ok=True)

        if not transcript:
            await status_msg.edit_text("Could not understand the audio. Try again or type your question.")
            return

        log.info("Voice transcription (%s, %.1fs): %s", info.language, info.duration, transcript)
        await status_msg.edit_text(f"Heard: \"{transcript}\"\n\nProcessing...")

    except Exception as exc:
        log.exception("Voice transcription failed")
        try:
            await status_msg.edit_text(f"Transcription failed: {exc}")
        except BadRequest:
            pass
        return

    # Delete status and process as normal query
    try:
        await status_msg.delete()
    except BadRequest:
        pass

    await _process_query(update, transcript)


# ── Main Entry Point ──


def main():
    """Start the Telegram bot with long polling."""
    if not TELEGRAM_BOT_TOKEN:
        log.error("TELEGRAM_BOT_TOKEN not set. Exiting.")
        return

    if not _allowed_users:
        log.warning(
            "TELEGRAM_ALLOWED_USERS not set — bot is in dev mode (all users allowed)"
        )
    else:
        log.info(
            "Access restricted to %d user(s): %s", len(_allowed_users), _allowed_users
        )

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("tools", cmd_tools))
    app.add_handler(CommandHandler("run", cmd_run))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(CommandHandler("model", cmd_model))
    app.add_handler(CommandHandler("collect", cmd_collect))

    # Text and voice messages (must be last)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.VOICE | filters.AUDIO, handle_voice))

    log.info("NetCopilot Telegram bot starting (polling)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # Redact the bot token from logs. python-telegram-bot's
    # httpx adapter logs full request URLs (including bot token) at INFO. Two
    # layered defences:
    #
    #   1. Bump httpx logger to WARNING — suppresses the "HTTP Request:" INFO
    #      line entirely. This is the bulletproof primary fix; the leaking
    #      log line never gets emitted. WARNING/ERROR-level httpx events
    #      (network errors, timeouts) are NOT suppressed.
    #
    #   2. Defence-in-depth: install _RedactTokenFilter on httpx logger AND
    #      root logger. If anything else (now or future) ever emits a token
    #      in a log record, the regex catches it before the formatter renders.
    #
    # The initial filter-only attempt (commit attempt during this audit, not
    # landed) didn't actually redact in-container despite working in isolation
    # — root cause unidentified, possibly logger-propagation order with
    # python-telegram-bot's Application init. Belt + suspenders.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpx").addFilter(_RedactTokenFilter())
    logging.getLogger().addFilter(_RedactTokenFilter())
    main()
