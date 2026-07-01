"""Run-to-run diff endpoint — the tiered drift between two runs of a site.

    GET /api/diff/{run_id}
        Diff ``run_id`` (the "after") against the previous same-site run (the
        "before"). ``?against=<run_id>`` overrides the comparison ("before") run.

Disk-based (``RUNS_DIR``): each run's persisted model + findings are the
authoritative diff inputs, so this endpoint does not require Neo4j. The payload
is :meth:`DiffResult.to_dict` — the shape the Audit-tab drift UI renders.

S01-4 (run-to-run drift).
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from netcopilot.diff.engine import compute_diff, load_run, previous_run

log = logging.getLogger(__name__)
router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


@router.get("/api/diff/{run_id}")
def get_diff(run_id: str, against: str | None = None):
    """Return the tiered diff of ``run_id`` vs its previous same-site run.

    ``?against=<run_id>`` overrides the comparison run. 404 if either run is
    unknown; 400 on a cross-site pair. When ``run_id`` has no earlier same-site
    run, returns a 200 empty diff carrying a ``note`` (not an error — the run
    exists, there is simply nothing before it).
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

    return result.to_dict()
