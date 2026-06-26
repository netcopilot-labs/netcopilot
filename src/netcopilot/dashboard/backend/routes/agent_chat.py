"""Agent chat — multi-turn tool-calling orchestrator, streamed as SSE.

POST /api/agent/chat/{run_id}
  → system prompt (behavioral rules + tool schemas)
  → the LLM provider calls MCP tools in a loop
  → events stream back as Server-Sent Events

The frontend sends one message + prior history and receives one SSE stream of
tool_status / tool_call / tool_result / content / highlight / usage / done /
error events.

Provider-agnostic: the F4a orchestrator drives any LLMProvider (Claude or
Ollama), selected via /api/agent/models. When the Claude (cloud) provider is
active, a per-session SessionAnonymizer scrubs network identifiers before they
leave the host; the local Ollama provider needs no anonymization.
"""

import json
import logging
import os
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from netcopilot.anonymizer import SessionAnonymizer
from netcopilot.graph.client import get_driver, get_site_for_run, is_available
from netcopilot.llm import get_provider
from netcopilot.llm.registry import get_model, is_configured, load_registry
from netcopilot.orchestrator import SYSTEM_PROMPT, run_tool_loop

log = logging.getLogger(__name__)
router = APIRouter()

RUNS_DIR = os.environ.get("RUNS_DIR", "runs")
MAX_TOOL_TURNS = 15

# The selectable models come from the registry (models.yaml, or the legacy env
# pair). Selection persists in-process. The model's own `anonymize` flag — not the
# provider name — decides whether identifiers are scrubbed before sending.
_active = {"id": None}  # resolved lazily to the registry default on first read

# Per-session anonymizers (Claude path only), with TTL cleanup.
_anonymizers: dict[str, tuple[SessionAnonymizer, float]] = {}
_ANON_TTL_SECONDS = 3600


class AgentChatRequest(BaseModel):
    message: str
    session_id: str
    history: list[dict] = []


@router.get("/api/agent/models")
def get_models():
    """Return the *configured* models (key/endpoint present) and the selection.

    Models declared in the registry but missing their API key or endpoint are
    hidden, so the selector only offers models that will actually answer. If
    nothing is configured, fall back to showing all (so the user sees the list
    and the 'needs a key' error rather than an empty dropdown).
    """
    models, default_id = load_registry()
    available = [m for m in models if is_configured(m)] or models
    ids = {m.id for m in available}
    if _active["id"] not in ids:
        _active["id"] = default_id if default_id in ids else available[0].id
    return {
        "models": [
            {"id": m.id, "label": m.label, "anonymize": m.anonymize, "type": m.type}
            for m in available
        ],
        "active": _active["id"],
    }


@router.post("/api/agent/models/{model_id}")
def set_model(model_id: str):
    """Switch the active model."""
    valid = {m.id for m in load_registry()[0]}
    if model_id not in valid:
        raise HTTPException(400, f"Unknown model: {model_id}. Valid: {sorted(valid)}")
    _active["id"] = model_id
    log.info("Agent model switched to: %s", model_id)
    return {"active": model_id}


@router.post("/api/agent/chat/{run_id}")
async def agent_chat(run_id: str, request: AgentChatRequest):
    """SSE endpoint for agent chat with multi-turn tool calling."""
    return StreamingResponse(
        _stream(run_id, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _build_context(run_id: str) -> dict:
    """Build the tool context (run_id, site, data_dir) from a run_id."""
    site = get_site_for_run(run_id) if is_available() else None
    if not site and "_" in run_id:
        site = run_id.split("_")[0]
    return {
        "run_id": run_id,
        "site": site or "unknown",
        "data_dir": f"{RUNS_DIR}/{run_id}",
    }


def _sse(event_type: str, data) -> str:
    """Format one Server-Sent Event as `data: {"type", "data"}`."""
    return f"data: {json.dumps({'type': event_type, 'data': data})}\n\n"


async def _stream(run_id: str, req: AgentChatRequest):
    """Drive the orchestrator and translate its events into SSE frames."""
    context = _build_context(run_id)

    model_id = _active["id"] or load_registry()[1]
    cfg = get_model(model_id)
    try:
        provider = get_provider(model_id)
    except Exception as exc:  # e.g. a commercial model selected without its API key
        yield _sse("error", f"Model '{model_id}' unavailable: {exc}")
        yield _sse("done", "")
        return

    # Anonymize per the model's own flag (cloud models scrub; local keeps data on-host).
    anonymizer = None
    if (cfg.anonymize if cfg else provider.name == "claude"):
        anonymizer = _get_anonymizer(req.session_id)
        _seed_anonymizer(anonymizer, run_id)

    history: list[dict] = []
    for m in req.history:
        if m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str):
            history.append({"role": m["role"], "content": m["content"]})
    history.append({"role": "user", "content": req.message})

    if anonymizer:
        # The caller anonymizes the initial history; run_tool_loop anonymizes the
        # tool results it feeds back.
        history = [{**m, "content": anonymizer.anonymize(m["content"])} for m in history]

    try:
        async for event in run_tool_loop(
            history, context, provider=provider, system=SYSTEM_PROMPT,
            anonymizer=anonymizer, max_turns=MAX_TOOL_TURNS,
        ):
            etype = event["type"]
            if etype == "done":
                yield _sse("done", "")
            elif etype == "usage":
                # Add per-model cost from the registry's pricing (USD per 1M tokens).
                data = event["data"]
                if cfg:
                    data["cost_usd"] = round(
                        data.get("input_tokens", 0) * cfg.price_in / 1_000_000
                        + data.get("output_tokens", 0) * cfg.price_out / 1_000_000,
                        6,
                    )
                yield _sse("usage", data)
            else:
                # content/tool_status/error carry str data; tool_call/tool_result/
                # highlight carry dicts — _sse json-encodes either.
                yield _sse(etype, event["data"])
    except Exception as exc:  # noqa: BLE001 — last-resort SSE error frame
        log.exception("agent chat stream failed")
        yield _sse("error", f"chat failed: {exc}")
        yield _sse("done", "")


def _get_anonymizer(session_id: str) -> SessionAnonymizer:
    """Get or create a per-session anonymizer, cleaning up expired sessions."""
    now = time.time()
    for sid in [s for s, (_, ts) in _anonymizers.items() if now - ts > _ANON_TTL_SECONDS]:
        del _anonymizers[sid]
    anon = _anonymizers.get(session_id, (SessionAnonymizer(), now))[0]
    _anonymizers[session_id] = (anon, now)
    return anon


def _seed_anonymizer(anon: SessionAnonymizer, run_id: str) -> None:
    """Register a run's identifiers (devices, sites, VRFs, AS numbers) so they
    are scrubbed before any content reaches the cloud provider."""
    if not is_available():
        return
    try:
        with get_driver().session() as sess:
            for rec in sess.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "RETURN d.name AS name, d.site AS site, d.role AS role, d.platform AS platform",
                run_id=run_id,
            ):
                if rec["name"] and rec["role"]:
                    anon.register_device(rec["name"])
                elif rec["name"]:
                    anon.register_isp(rec["name"])  # external peer
                if rec["site"]:
                    anon.register_site(rec["site"])
                if rec["platform"] and rec["role"]:
                    anon.register_platform(rec["platform"])

            for rec in sess.run(
                "MATCH (s:SharedService {run_id: $run_id, service_type: 'ospf_area'}) "
                "WHERE s.vrf IS NOT NULL RETURN DISTINCT s.vrf AS vrf",
                run_id=run_id,
            ):
                if rec["vrf"]:
                    anon.register_vrf(rec["vrf"])

            for rec in sess.run(
                "MATCH (:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]->(:Device {run_id: $run_id}) "
                "WHERE r.protocol = 'bgp' RETURN DISTINCT r.local_as AS las, r.remote_as AS ras",
                run_id=run_id,
            ):
                if rec["las"]:
                    anon.register_asn(str(rec["las"]))
                if rec["ras"]:
                    anon.register_asn(str(rec["ras"]))
    except Exception:  # noqa: BLE001 — seeding is best-effort
        log.debug("anonymizer seeding failed for %s", run_id, exc_info=True)
