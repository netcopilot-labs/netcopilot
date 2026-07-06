"""Service-layer endpoints (s16).

GET  /api/services       — the run's :Service rows (feeds the Service view + lens)
POST /api/services/join  — (re-)run the NetBox×observation join for a run

The join is the s13-drift twin: on-demand, site+run-scoped, deletes and
reloads only its own rows. NetBox unreachable → 503 (unknown, not empty).
"""
import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/services")
def list_services(run_id: str = Query(...), site: str | None = Query(None)):
    """The run's Service rows. An empty list is ambiguous by itself, so the
    response says whether the join has ever run for this run (joined=false →
    the UI can offer the join instead of claiming 'no services')."""
    from netcopilot.graph.client import get_driver, get_site_for_run

    site = site or get_site_for_run(run_id)
    if site is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} is not loaded")

    with get_driver().session() as session:
        rows = [
            dict(r["s"])
            for r in session.run(
                "MATCH (s:Service {site: $site, run_id: $run_id}) "
                "RETURN s ORDER BY s.name",
                site=site, run_id=run_id,
            )
        ]
    return {"run_id": run_id, "site": site, "joined": bool(rows),
            "services": rows}


class JoinRequest(BaseModel):
    run_id: str


@router.post("/api/services/join")
async def run_join(req: JoinRequest):
    from netcopilot.declared_state.services import (
        ServiceSourceUnavailable,
        run_service_join,
    )

    try:
        # Blocking NetBox + Neo4j work off the event loop (s12 convention).
        report = await asyncio.to_thread(run_service_join, req.run_id)
    except ServiceSourceUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "run_id": report.run_id,
        "site": report.site,
        "services": len(report.services),
        "by_method": report.counts_by_method(),
        "skipped_infrastructure": len(report.skipped_infrastructure),
        "summary": report.format_summary(),
        "warnings": report.warnings,
    }
