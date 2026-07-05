"""Reconcile API — NetBox staging + approve + audit history (s12, ADR-0014).

HTTP surface for the operator-supervised NetBox write workflow. Layered on
top of :mod:`netcopilot.declared_state.staging` (approve + reject + audit)
and :mod:`netcopilot.declared_state.bootstrap` (inventory + collected run →
:NetBoxPendingWrite).

Endpoints:
    GET   /api/reconcile/status                      — write gate + config state
    GET   /api/reconcile/pending                     — paginated pending list
    POST  /api/reconcile/approve/{id}                — single approve
    POST  /api/reconcile/reject/{id}                 — single reject (audit row)
    PATCH /api/reconcile/modify/{id}                 — update payload_json
    POST  /api/reconcile/approve_bulk                — synchronous bulk approve
    GET   /api/reconcile/approve_bulk/stream         — SSE per-candidate progress
    POST  /api/reconcile/reject_bulk                 — bulk reject (all audit rows)
    POST  /api/reconcile/bootstrap                   — stage candidates from a run
    GET   /api/reconcile/history                     — paginated :NetBoxWrite log

Approve paths are write-gated (Constitution Art. I): with
``NETBOX_WRITE_ENABLED`` off, single approve returns 403 and the SSE stream
emits an ``aborted`` event — never a silent failure. Reject / modify /
bootstrap make no NetBox API call and are not gated.

The SSE stream uses the event-typed form ("event: progress\\ndata: {...}")
so the frontend EventSource can branch on event type cleanly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import StreamingResponse

log = logging.getLogger(__name__)
router = APIRouter()


# ── GET /api/reconcile/status ───────────────────────────────────────────────


@router.get("/api/reconcile/status")
async def status_endpoint() -> dict[str, Any]:
    """Write-gate + configuration state for the Reconcile UI banner.

    Read-only env inspection — no NetBox API call is made.
    """
    from netcopilot.declared_state.gate import write_enabled

    return {
        "write_enabled": write_enabled(),
        "netbox_configured": bool(
            os.environ.get("NETBOX_URL") and os.environ.get("NETBOX_API_TOKEN")
        ),
    }


# ── GET /api/reconcile/pending ──────────────────────────────────────────────


@router.get("/api/reconcile/pending")
async def list_pending_endpoint(
    source: Optional[str] = Query(None),
    object_type: Optional[str] = Query(None),
    min_priority: Optional[int] = Query(None, ge=1, le=100),
    dedup_key: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """Paginated list of :NetBoxPendingWrite candidates.

    Filters mirror the MCP tool + the Reconcile UI sidebar.
    """
    from netcopilot.declared_state.staging import list_pending

    try:
        rows = list_pending(
            source=source,
            object_type=object_type,
            min_priority=min_priority,
        )
    except Exception as exc:
        log.error("list_pending failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if dedup_key:
        # In-memory filter — dedup_key isn't a top-level :NetBoxPendingWrite
        # property; it lives inside the payload. Cheap at pending-queue scale.
        from netcopilot.declared_state.staging import _dedup_key_for_audit
        rows = [
            r for r in rows
            if dedup_key.lower() in _dedup_key_for_audit(
                r["netbox_object_type"], r.get("payload") or {}
            ).lower()
        ]

    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "count": total,
        "page": page,
        "page_size": page_size,
        "results": rows[start:end],
    }


# ── POST /api/reconcile/approve/{id} ────────────────────────────────────────


@router.post("/api/reconcile/approve/{candidate_id}")
async def approve_endpoint(candidate_id: str) -> dict[str, Any]:
    """Approve one pending candidate → NetBox API write + :NetBoxWrite audit row.

    Returns the outcome dict from :func:`staging.approve` on success, 403 when
    the write gate is off, 502 on NetBox auth abort, or 404 if the candidate
    is gone.
    """
    from netcopilot.declared_state.gate import WritesDisabled
    from netcopilot.declared_state.staging import AuthAbortError, approve

    try:
        result = await asyncio.to_thread(approve, candidate_id)
    except WritesDisabled as exc:
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "writes_disabled", "message": str(exc)}},
        ) from exc
    except AuthAbortError as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": {"code": "netbox_auth_abort", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        log.error("approve(%r) failed: %s", candidate_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_pending", "message": f"No pending candidate with id={candidate_id}"}},
        )
    return result


# ── POST /api/reconcile/reject/{id} ─────────────────────────────────────────


@router.post("/api/reconcile/reject/{candidate_id}")
async def reject_endpoint(candidate_id: str) -> dict[str, Any]:
    """Reject one pending candidate → :NetBoxWrite audit row + delete pending.

    Not write-gated — no NetBox API call is made.
    """
    from netcopilot.declared_state.staging import reject

    try:
        rejected = await asyncio.to_thread(reject, candidate_id)
    except Exception as exc:
        log.error("reject(%r) failed: %s", candidate_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not rejected:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_pending", "message": f"No pending candidate with id={candidate_id}"}},
        )
    return {"rejected": True, "candidate_id": candidate_id}


# ── PATCH /api/reconcile/modify/{id} ────────────────────────────────────────


@router.patch("/api/reconcile/modify/{candidate_id}")
async def modify_endpoint(
    candidate_id: str,
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Replace a candidate's payload_json with the given payload.

    The new payload is validated at write time (when approve is called);
    we don't validate against NetBox's per-object_type schema here because
    the schema is fluid across NetBox versions and we want operators to be
    able to set fields NetCopilot doesn't know about.
    """
    from netcopilot.declared_state.staging import modify

    new_payload = payload.get("payload") if "payload" in payload else payload
    if not isinstance(new_payload, dict):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "invalid_payload",
                              "message": "Body must include a JSON object 'payload', or be the payload itself."}},
        )

    try:
        updated = await asyncio.to_thread(modify, candidate_id, new_payload)
    except Exception as exc:
        log.error("modify(%r) failed: %s", candidate_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not updated:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_pending", "message": f"No pending candidate with id={candidate_id}"}},
        )
    return {"modified": True, "candidate_id": candidate_id}


# ── POST /api/reconcile/approve_bulk (synchronous) ──────────────────────────


@router.post("/api/reconcile/approve_bulk")
async def approve_bulk_endpoint(
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Synchronous bulk approve.

    Body:
        {
            "source": "bootstrap" | ...,        # optional filter
            "object_type": "device" | ...,      # optional filter
            "min_priority": 1..100,             # optional filter
            "ids": ["uuid-...", ...]            # optional explicit list; overrides filters
        }

    For long-running bulks (>30 s), prefer the SSE endpoint:
        GET /api/reconcile/approve_bulk/stream?...

    Returns the full summary from :func:`staging.approve_bulk`.
    """
    from netcopilot.declared_state.gate import WritesDisabled
    from netcopilot.declared_state.staging import approve_bulk

    try:
        # Run the synchronous approve_bulk off the event loop to avoid
        # blocking other requests.
        summary = await asyncio.to_thread(
            approve_bulk,
            source=body.get("source"),
            object_type=body.get("object_type"),
            min_priority=body.get("min_priority"),
            ids=body.get("ids"),
        )
    except WritesDisabled as exc:
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "writes_disabled", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        log.error("approve_bulk failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return summary


# ── GET /api/reconcile/approve_bulk/stream (SSE) ────────────────────────────


@router.get("/api/reconcile/approve_bulk/stream")
async def approve_bulk_stream_endpoint(
    source: Optional[str] = Query(None),
    object_type: Optional[str] = Query(None),
    min_priority: Optional[int] = Query(None, ge=1, le=100),
    ids: Optional[str] = Query(None, description="Comma-separated pending ids"),
) -> StreamingResponse:
    """SSE per-candidate progress for bulk approve.

    Event format:
        event: progress
        data: {candidate_id, dedup_key, object_type, status, position, total, ...}

        event: complete
        data: {written, auto_resolved, failed, failed_ids, duration_ms, ...}

        event: aborted
        data: {reason, ...}

    With the write gate off, the stream emits a single ``aborted`` event
    (reason ``writes_disabled: ...``) — an EventSource cannot read a 403 body,
    so the refusal travels in-band. Frontend EventSource branches on event type.
    """
    id_list = [s for s in (ids.split(",") if ids else []) if s.strip()] or None

    async def _stream():
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        SENTINEL = object()

        def progress_callback(event: dict[str, Any]) -> None:
            # Called from the worker thread; marshal back to event loop.
            asyncio.run_coroutine_threadsafe(queue.put(event), loop)

        def run_bulk():
            from netcopilot.declared_state.gate import WritesDisabled
            from netcopilot.declared_state.staging import approve_bulk
            try:
                summary = approve_bulk(
                    source=source,
                    object_type=object_type,
                    min_priority=min_priority,
                    ids=id_list,
                    progress_callback=progress_callback,
                )
                return summary
            except WritesDisabled as exc:
                asyncio.run_coroutine_threadsafe(
                    queue.put({
                        "event": "aborted",
                        "data": {"reason": f"writes_disabled: {exc}"},
                    }),
                    loop,
                )
                return None
            except Exception as exc:  # noqa: BLE001
                log.error("approve_bulk (SSE) crashed: %s", exc)
                asyncio.run_coroutine_threadsafe(
                    queue.put({
                        "event": "aborted",
                        "data": {"reason": f"internal_error: {exc}"},
                    }),
                    loop,
                )
                return None
            finally:
                asyncio.run_coroutine_threadsafe(queue.put(SENTINEL), loop)

        # Run the bulk in a background thread; drain the queue here.
        bulk_task = asyncio.create_task(asyncio.to_thread(run_bulk))

        try:
            while True:
                event = await queue.get()
                if event is SENTINEL:
                    break
                evt_type = event.get("event", "progress")
                data = json.dumps(event.get("data", {}), default=str)
                yield f"event: {evt_type}\ndata: {data}\n\n"
        finally:
            await bulk_task

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── POST /api/reconcile/reject_bulk ─────────────────────────────────────────


@router.post("/api/reconcile/reject_bulk")
async def reject_bulk_endpoint(
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Bulk reject candidates (each writes a :NetBoxWrite audit row)."""
    from netcopilot.declared_state.staging import reject_bulk

    try:
        summary = await asyncio.to_thread(
            reject_bulk,
            source=body.get("source"),
            object_type=body.get("object_type"),
            min_priority=body.get("min_priority"),
            ids=body.get("ids"),
        )
    except Exception as exc:
        log.error("reject_bulk failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return summary


# ── POST /api/reconcile/bootstrap ───────────────────────────────────────────


@router.post("/api/reconcile/bootstrap")
async def bootstrap_endpoint(
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Stage NetBox candidates from a collected run + inventory.

    Body:
        {
            "run_id": "2026-...",             # required (the UI's selected run)
            "inventory_path": "/path/lab.yaml" # optional → NETBOX_BOOTSTRAP_INVENTORY
        }

    Bootstrap needs the inventory YAML the run was collected from. The UI
    sends only run_id; the deployment provides the inventory via the
    ``NETBOX_BOOTSTRAP_INVENTORY`` env var. Without either, this degrades
    honestly to a 400 pointing at the CLI — no guessed default.
    """
    run_id = body.get("run_id")
    if not run_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "run_id_required",
                              "message": "Body must include run_id (select a run in the dashboard first)."}},
        )

    inventory_path = body.get("inventory_path") or os.environ.get("NETBOX_BOOTSTRAP_INVENTORY")
    if not inventory_path:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "inventory_unconfigured",
                    "message": (
                        "No inventory configured for bootstrap. Set "
                        "NETBOX_BOOTSTRAP_INVENTORY to the inventory YAML path, or run "
                        "from the CLI: `netcopilot netbox bootstrap <run_id> "
                        "--inventory <path>` (idempotent; re-staging is safe), "
                        "then refresh this tab."
                    ),
                }
            },
        )

    from netcopilot.declared_state.bootstrap import run as bootstrap_run

    try:
        result = await asyncio.to_thread(bootstrap_run, run_id, inventory_path)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "inventory_not_found", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        log.error("bootstrap failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "bootstrap_failed", "message": str(exc)}},
        ) from exc

    return {
        "new": result.new,
        "skipped": result.skipped,
        "warnings": result.warnings,
        "summary": result.format_summary(),
    }


# ── POST /api/reconcile/stage_from_finding ──────────────────────────────────


@router.post("/api/reconcile/stage_from_finding")
async def stage_from_finding_endpoint(
    body: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Stage the NetBox correction(s) for one INTENT_* drift finding (s13).

    Body: ``{"finding_id": "INTENT_...::device", "run_id": "..."}``

    Staging writes only Neo4j (a :NetBoxPendingWrite + FROM_FINDING edge) —
    no NetBox API write happens here, so this is not write-gated; the write
    happens later via the gated approve flow.
    """
    finding_id = body.get("finding_id")
    run_id = body.get("run_id")
    if not finding_id or not run_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "missing_params",
                              "message": "Body must include finding_id and run_id."}},
        )

    from netcopilot.declared_state.drift import (
        DriftSourceUnavailable,
        NotCorrectable,
        stage_correction,
    )

    try:
        result = await asyncio.to_thread(stage_correction, finding_id, run_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "finding_not_found", "message": str(exc)}},
        ) from exc
    except NotCorrectable as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_correctable", "message": str(exc)}},
        ) from exc
    except DriftSourceUnavailable as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": {"code": "netbox_unreachable", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        log.error("stage_from_finding(%r) failed: %s", finding_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return result


# ── GET /api/reconcile/history ──────────────────────────────────────────────


@router.get("/api/reconcile/history")
async def history_endpoint(
    source: Optional[str] = Query(None),
    object_type: Optional[str] = Query(None),
    success_only: Optional[bool] = Query(None),
    since: Optional[str] = Query(None, description="ISO timestamp"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """Paginated :NetBoxWrite history.

    Filters:
        * source         — bootstrap / drift / manual / manual_reject
        * object_type    — site / cluster / device / interface / ...
        * success_only   — True → 2xx only; False → 4xx+5xx; None → all
        * since          — ISO timestamp; only writes after this
    """
    from netcopilot.graph.client import get_driver, is_available

    if not is_available():
        raise HTTPException(
            status_code=503,
            detail={"error": {"code": "neo4j_unavailable",
                              "message": "Neo4j not reachable; cannot read audit history."}},
        )

    where_clauses: list[str] = []
    params: dict[str, Any] = {}
    if source:
        where_clauses.append("w.source = $source")
        params["source"] = source
    if object_type:
        where_clauses.append("w.netbox_object_type = $object_type")
        params["object_type"] = object_type
    if success_only is True:
        where_clauses.append("w.api_response_status >= 200 AND w.api_response_status < 300")
    elif success_only is False:
        where_clauses.append("(w.api_response_status IS NOT NULL AND w.api_response_status >= 400)")
    if since:
        where_clauses.append("w.timestamp >= $since")
        params["since"] = since

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    skip = (page - 1) * page_size

    count_cypher = f"MATCH (w:NetBoxWrite) {where} RETURN count(w) AS n"
    list_cypher = (
        f"MATCH (w:NetBoxWrite) {where} "
        "RETURN w ORDER BY w.timestamp DESC "
        f"SKIP {skip} LIMIT {page_size}"
    )

    try:
        with get_driver().session() as session:
            total = (session.run(count_cypher, **params).single() or {}).get("n", 0)
            rows = [dict(record["w"]) for record in session.run(list_cypher, **params)]
    except Exception as exc:
        log.error("history endpoint Cypher failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "count": total,
        "page": page,
        "page_size": page_size,
        "results": rows,
    }
