"""Run trigger + progress + delta endpoints.

Flag-file pattern (decouples the dashboard from the collector — the dashboard
never runs the collection itself). The dashboard writes/reads flag files under
``runs/.trigger/`` on the shared ``runs/`` volume; a separate watcher process
polls for the request flag and executes ``netcopilot run`` wherever it has
network reach to the devices. This keeps the dashboard free of collection
dependencies (e.g. pyATS) and matches the "collector is not co-located"
deployment model.

Progress: writers append JSON lines to ``runs/.trigger/.progress.jsonl``:
  T=0   trigger_run() OVERWRITES with a "triggered" event
  T>0   the watcher APPENDS a "watcher_start" event
  T>0   ``netcopilot run`` APPENDS stage events (collect, parse, model, rules, load, done)
The dashboard tails the file over SSE → the frontend EventSource consumes it.

POST /api/runs/trigger   — create request flag + initial progress
GET  /api/runs/status    — run-in-progress state + latest run_id
GET  /api/runs/progress  — SSE stream tailing .progress.jsonl
GET  /api/runs/delta     — compare findings between two runs
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

log = logging.getLogger(__name__)
router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

# Flag files live inside the existing runs/ volume (shared with the watcher)
_TRIGGER_DIR = RUNS_DIR / ".trigger"
_FLAG_REQUESTED = _TRIGGER_DIR / "run_requested"
_FLAG_COMPLETE = _TRIGGER_DIR / "run_complete"
_FLAG_TRIGGERED_AT = _TRIGGER_DIR / "triggered_at"
_PROGRESS_FILE = _TRIGGER_DIR / ".progress.jsonl"


def _ensure_trigger_dir() -> None:
    _TRIGGER_DIR.mkdir(parents=True, exist_ok=True)


def _latest_run_id() -> str | None:
    """Return the most recently modified run directory name, or None."""
    try:
        run_dirs = [
            d for d in RUNS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
        if not run_dirs:
            return None
        latest = max(run_dirs, key=lambda d: d.stat().st_mtime)
        return latest.name
    except OSError:
        return None


@router.post("/api/runs/trigger")
def trigger_run():
    """Create the run-requested flag file.

    A separate watcher process polls for this file and executes
    ``netcopilot run``. Returns immediately — does not wait for completion.

    Returns 409-equivalent ``already_pending`` if a run is already pending.
    """
    _ensure_trigger_dir()

    # Clear a stale FLAG_COMPLETE from any earlier run whose completion was
    # never consumed by /api/runs/status (e.g. browser closed mid-poll).
    # Without this, the next status poll after this trigger would read the
    # stale flag, set new_run_available=true, and the frontend would
    # setSelectedRun to the in-progress run dir — which exists on disk
    # before the Neo4j load completes, producing a "Topology: HTTP 404" banner.
    if _FLAG_COMPLETE.exists():
        try:
            _FLAG_COMPLETE.unlink()
        except OSError:
            pass

    if _FLAG_REQUESTED.exists():
        return {"status": "already_pending"}

    now = datetime.now(timezone.utc).isoformat()
    _FLAG_REQUESTED.write_text(now)
    _FLAG_TRIGGERED_AT.write_text(now)

    # Overwrite progress file with initial event (T=0, immediate feedback)
    _PROGRESS_FILE.write_text(
        json.dumps({"ts": now, "stage": "triggered",
                    "message": "Run triggered, waiting for the collector..."}) + "\n"
    )

    log.info("Run requested at %s", now)
    return {"status": "requested", "triggered_at": now}


@router.get("/api/runs/status")
def run_status():
    """Return current run status and latest run_id.

    Checks for the completion flag written by the watcher after a successful
    run. Clears the completion flag on read (one-shot notification).
    """
    run_in_progress = _FLAG_REQUESTED.exists()

    last_triggered = None
    try:
        last_triggered = _FLAG_TRIGGERED_AT.read_text().strip() or None
    except OSError:
        pass

    # Read and clear the completion flag (one-shot notification)
    new_run_available = False
    if _FLAG_COMPLETE.exists():
        try:
            _FLAG_COMPLETE.unlink()
            new_run_available = True
        except OSError:
            pass

    return {
        "run_in_progress": run_in_progress,
        "last_triggered": last_triggered,
        "latest_run_id": _latest_run_id(),
        "new_run_available": new_run_available,
    }


# ── Pipeline progress SSE ───────────────────────────────────────────────────────


@router.get("/api/runs/progress")
async def run_progress():
    """SSE stream tailing .progress.jsonl for real-time pipeline status.

    Writers append to the file: trigger_run() (T=0), the watcher
    (watcher_start), and ``netcopilot run`` (stage events). This endpoint
    tails it and streams events until 'done'/'error'.
    """
    return StreamingResponse(
        _stream_progress(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _stream_progress():
    """Tail .progress.jsonl, yield SSE events. Close on 'done'/'error'."""
    lines_sent = 0
    start = time.monotonic()
    saw_watcher = False
    max_wait = 300  # 5 minutes

    while time.monotonic() - start < max_wait:
        # Read current file contents
        if _PROGRESS_FILE.exists():
            try:
                all_lines = _PROGRESS_FILE.read_text().strip().split("\n")
            except OSError:
                all_lines = []

            # Send new lines
            for line in all_lines[lines_sent:]:
                if not line.strip():
                    continue
                yield f"data: {line.strip()}\n\n"
                try:
                    parsed = json.loads(line.strip())
                    if parsed.get("stage") == "watcher_start":
                        saw_watcher = True
                    if parsed.get("stage") in ("done", "error"):
                        return
                except json.JSONDecodeError:
                    pass
            lines_sent = len(all_lines)

        # Dead-zone warning: 60s with no watcher_start
        elapsed = time.monotonic() - start
        if elapsed > 60 and not saw_watcher:
            warning = json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "warning",
                "message": "Pipeline has not started after 60s. Is the run watcher running?",
            })
            yield f"data: {warning}\n\n"
            saw_watcher = True  # don't warn again

        await asyncio.sleep(1)

    yield f'data: {json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "stage": "error", "message": "Progress timeout (5 min)"})}\n\n'


# ── Delta analysis ──────────────────────────────────────────────────────────────


@router.get("/api/runs/delta")
def get_delta(
    current: str = Query(..., description="Current run_id"),
    previous: Optional[str] = Query(None, description="Previous run_id — auto-selected if omitted"),
):
    """Compare findings between two runs.

    If previous is not specified, auto-selects the run immediately before
    current in chronological order.

    Returns:
        200: Delta dict with new/resolved/persistent findings and counts.
        404: current run not found, or no previous run available.
    """
    from netcopilot.dashboard.backend.delta_analyzer import build_delta, find_previous_run

    if not (RUNS_DIR / current).is_dir():
        raise HTTPException(status_code=404, detail=f"Run '{current}' not found")

    prev_run = previous or find_previous_run(current)
    if not prev_run:
        raise HTTPException(
            status_code=404,
            detail=f"No previous run found for '{current}'",
        )
    if not (RUNS_DIR / prev_run).is_dir():
        raise HTTPException(status_code=404, detail=f"Previous run '{prev_run}' not found")

    return build_delta(current, prev_run)
