"""Runs endpoint — list pipeline runs from Neo4j.

The run list comes from Neo4j Run nodes only; runs not loaded into Neo4j do not
appear. Returns HTTP 503 if Neo4j is unavailable. Findings counts are enriched
from each run's findings/summary.json on disk.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from netcopilot.graph.client import get_driver, is_available

logger = logging.getLogger(__name__)

router = APIRouter()

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


def _parse_timestamp(run_id: str) -> str | None:
    """Derive an ISO timestamp from a run_id.

    Patterns:
        mysite_2026-02-25_10-30-00 -> 2026-02-25T10:30:00
        2026-02-25_10-30-00        -> 2026-02-25T10:30:00
    """
    parts = run_id.split("_")
    date_idx = None
    for i, part in enumerate(parts):
        if len(part) == 10 and part[4:5] == "-" and part[7:8] == "-":
            date_idx = i
            break
    if date_idx is None:
        return None

    date_str = parts[date_idx]
    time_str = parts[date_idx + 1] if date_idx + 1 < len(parts) else "00-00-00"
    time_str = time_str.replace("-", ":")
    try:
        return datetime.fromisoformat(f"{date_str}T{time_str}").isoformat()
    except ValueError:
        return None


def _enrich_findings_count(run_id: str) -> int:
    """Read total_findings from the run's findings/summary.json (0 if absent)."""
    summary_path = RUNS_DIR / run_id / "findings" / "summary.json"
    if not summary_path.exists():
        return 0
    try:
        return json.loads(summary_path.read_text()).get("total_findings", 0)
    except (json.JSONDecodeError, OSError):
        return 0


@router.get("/api/runs")
def get_runs():
    """List pipeline runs from Neo4j Run nodes.

    Sorted by pinned (first) then loaded_at descending; enriched with
    total_findings from disk. Returns HTTP 503 if Neo4j is unavailable.
    """
    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"error": "Neo4j unavailable. Start with: docker compose up -d"},
        )

    try:
        with get_driver().session() as session:
            result = session.run(
                "MATCH (r:Run) "
                "RETURN r.run_id AS run_id, r.site AS site, "
                "r.loaded_at AS loaded_at, r.pinned AS pinned, "
                "r.label AS label, r.devices_count AS devices, "
                "r.links_count AS links "
                "ORDER BY r.pinned DESC, r.loaded_at DESC"
            )
            runs = []
            for record in result:
                run_id = record["run_id"]
                runs.append({
                    "run_id": run_id,
                    "site": record["site"] or "unknown",
                    "timestamp": _parse_timestamp(run_id),
                    "loaded_at": record["loaded_at"],
                    "pinned": record["pinned"] or False,
                    "label": record["label"],
                    "devices": record["devices"] or 0,
                    "links": record["links"] or 0,
                    "total_findings": _enrich_findings_count(run_id),
                })
        return {"runs": runs}
    except Exception as e:
        logger.error("Failed to query Neo4j for runs: %s", e)
        return JSONResponse(
            status_code=503,
            content={"error": f"Neo4j query failed: {type(e).__name__}: {e}"},
        )
