"""Filesystem helpers for run artifacts the dashboard reads off disk.

Findings detail comes from Neo4j; these helpers cover the small on-disk pieces
(the per-run findings summary and a run-exists check). RUNS_DIR is the runs
directory (env-overridable).
"""

import json
import os
from pathlib import Path

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


def load_summary(run_id: str) -> dict | None:
    """Load a run's findings/summary.json (None if absent or unreadable)."""
    path = RUNS_DIR / run_id / "findings" / "summary.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def run_exists(run_id: str) -> bool:
    """True if the run directory exists and has a findings.json."""
    run_dir = RUNS_DIR / run_id
    return run_dir.is_dir() and (run_dir / "findings" / "findings.json").exists()
