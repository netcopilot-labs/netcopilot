"""Change-validation endpoint — the diff payload plus its verdict.

    GET /api/validate/{run_id}
        Validate ``run_id`` (the "after") against the previous same-site run.
        ``?against=<run_id>`` overrides the comparison ("before") run;
        ``?scope=dev1,dev2`` declares the intended change scope (the dashboard
        sends no scope — its banner is the threshold-only verdict; scoped
        validation is the CLI/MCP flow).

The payload is a superset of ``GET /api/diff/{run_id}``: ``DiffResult.to_dict()``
plus a ``verdict`` key (:meth:`ChangeVerdict.to_dict`, or ``null`` when there is
no comparison run). Disk-based, no Neo4j — same as the diff route.

S05-4 (change-validation verdict).
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from netcopilot.diff.engine import compute_diff, load_run, previous_run
from netcopilot.diff.verdict import evaluate_change

log = logging.getLogger(__name__)
router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


@router.get("/api/validate/{run_id}")
def get_validation(run_id: str, against: str | None = None, scope: str | None = None):
    """Return the tiered diff of ``run_id`` vs its comparison run, judged.

    Same error semantics as ``/api/diff``: 404 unknown run, 400 cross-site,
    200 + ``note`` (and ``verdict: null``) when the run has nothing before it.
    """
    try:
        after = load_run(run_id, RUNS_DIR)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    before_id = against or previous_run(run_id, RUNS_DIR)
    if not before_id:
        return {
            "run_a": None,
            "run_b": run_id,
            "site": after.site,
            "summary": {"added": 0, "removed": 0, "changed": 0, "info": 0},
            "changes": [],
            "verdict": None,
            "note": "No previous same-site run to compare — this is the earliest run of the site.",
        }

    try:
        before = load_run(before_id, RUNS_DIR)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Comparison run '{before_id}' not found")

    try:
        result = compute_diff(before, after)
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        raise HTTPException(status_code=400, detail=str(exc))

    scope_devices = (
        frozenset(s.strip() for s in scope.split(",") if s.strip()) if scope else None
    )
    verdict = evaluate_change(result, before, after, scope_devices)
    return {**result.to_dict(), "verdict": verdict.to_dict()}
