"""Findings endpoint — findings array + pre-computed summary.

 Acknowledgement system — operators can acknowledge expected findings
with a reason. Acknowledgements persist in Neo4j keyed by (site, finding_id),
surviving across pipeline runs. finding_id is deterministic (rule_id::element_id).
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from netcopilot.findings import load_findings_enriched
from ..data_loader import load_summary, run_exists
from netcopilot.graph.client import get_driver, get_site_for_run, is_available

log = logging.getLogger(__name__)
router = APIRouter()


# ── Pydantic models for acknowledge endpoints ──


class AcknowledgeRequest(BaseModel):
    finding_ids: list[str]
    reason: str = ""


class UnacknowledgeRequest(BaseModel):
    finding_ids: list[str]


class AnnotateRequest(BaseModel):
    finding_id: str
    text: str


# ── Helpers ──


def _load_annotations(run_id: str) -> dict[str, list[dict]]:
    """Load all annotations for a run from Neo4j.

    Returns {finding_id: [{text, created_at}, ...]} (multiple notes per finding).
    Returns empty dict if Neo4j is unavailable.
    """
    try:
        if not is_available():
            return {}
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                "MATCH (a:Annotation {run_id: $run_id}) "
                "RETURN a.finding_id AS fid, a.text AS text, a.created_at AS created_at "
                "ORDER BY a.created_at",
                run_id=run_id,
            )
            ann: dict[str, list] = {}
            for r in result:
                fid = r["fid"]
                if fid:
                    ann.setdefault(fid, []).append({
                        "text": r["text"] or "",
                        "created_at": r["created_at"] or "",
                    })
            return ann
    except Exception:
        log.debug("Could not load annotations for run %s", run_id, exc_info=True)
        return {}


def _load_acknowledgements(site: str) -> dict[str, dict]:
    """Load all acknowledgements for a site from Neo4j.

    Returns {finding_id: {reason, acknowledged_at, acknowledged_by}}.
    """
    try:
        if not is_available():
            return {}
        driver = get_driver()
        with driver.session() as session:
            result = session.run(
                "MATCH (a:Acknowledgement {site: $site}) "
                "RETURN a.finding_id AS fid, a.reason AS reason, "
                "       a.acknowledged_at AS ack_at, a.acknowledged_by AS ack_by",
                site=site,
            )
            return {
                r["fid"]: {
                    "reason": r["reason"] or "",
                    "acknowledged_at": r["ack_at"] or "",
                    "acknowledged_by": r["ack_by"] or "operator",
                }
                for r in result
            }
    except Exception:
        log.debug("Could not load acknowledgements", exc_info=True)
        return {}


# ── Endpoints ──


@router.get("/api/findings/{run_id}")
def get_findings(run_id: str):
    """Return findings array and summary for a given run.

    Reads findings.json and summary.json, injects synthetic unreachable
    findings, enriches with acknowledgement status from Neo4j.
    """
    if not run_exists(run_id):
        raise HTTPException(
            status_code=404,
            detail=f"Run '{run_id}' not found or missing required files",
        )

    # Audit note: findings now load via the canonical
    # Neo4j-first helper in agent/shared.py — same path as the agent
    # MCP tool. Aligns with 's "Neo4j is source of truth, JSON
    # is backup" framing. The helper handles DEVICE_UNREACHABLE
    # synthesis + basic acknowledgement enrichment internally.
    findings = load_findings_enriched(run_id)
    if findings is None:
        raise HTTPException(
            status_code=404,
            detail=f"findings.json not found for run '{run_id}'",
        )

    # Enrich with full acknowledgement details (timestamp + by). The
    # canonical loader already set `acknowledged` + `acknowledged_reason`
    # via the Cypher OPTIONAL MATCH; this loop adds the timestamp /
    # author fields the dashboard renders alongside.
    ack_count = 0
    site = get_site_for_run(run_id) if is_available() else None
    if site:
        acks = _load_acknowledgements(site)
        if acks:
            for f in findings:
                fid = f.get("finding_id", "")
                if fid in acks:
                    f["acknowledged"] = True
                    f["acknowledged_reason"] = acks[fid]["reason"]
                    f["acknowledged_at"] = acks[fid]["acknowledged_at"]
                    ack_count += 1

    # Enrich with annotation notes (S20-B13)
    annotations = _load_annotations(run_id)
    if annotations:
        for f in findings:
            fid = f.get("finding_id", "")
            if fid in annotations:
                f["annotations"] = annotations[fid]

    # Tag cross-device findings 
    cross_device_count = 0
    for f in findings:
        eid = f.get("evidence", {}).get("element_id", "")
        is_cd = (
            "--" in eid
            or eid.startswith(("ntp::", "stp_", "fdb_mgmt_"))
            or f.get("cross_device", False)
        )
        f["is_cross_device"] = is_cd
        if is_cd:
            cross_device_count += 1

    summary = load_summary(run_id)

    response = {
        "summary": summary or {},
        "findings": findings,
    }
    if ack_count > 0:
        response["summary"]["acknowledged_count"] = ack_count
    response["summary"]["cross_device_count"] = cross_device_count

    return response


@router.get("/api/findings/{run_id}/acknowledgements")
def get_acknowledgements(run_id: str):
    """Return all acknowledgements for the site of this run."""
    site = get_site_for_run(run_id) if is_available() else None
    if not site:
        return {"acknowledgements": {}}
    return {"acknowledgements": _load_acknowledgements(site)}


@router.post("/api/findings/{run_id}/acknowledge")
def acknowledge_findings(run_id: str, body: AcknowledgeRequest):
    """Acknowledge one or more findings by finding_id."""
    if not body.finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids required")

    site = get_site_for_run(run_id) if is_available() else None
    if not site:
        raise HTTPException(status_code=404, detail="Run not found in Neo4j")

    now = datetime.now(timezone.utc).isoformat()
    driver = get_driver()
    # Audit note: batch via UNWIND so all acks land in one
    # transaction. Previous N+1 loop allowed partial-state on Neo4j blip.
    with driver.session() as session:
        session.run(
            "UNWIND $fids AS fid "
            "MERGE (a:Acknowledgement {site: $site, finding_id: fid}) "
            "SET a.reason = $reason, a.acknowledged_at = $now, "
            "    a.acknowledged_by = 'operator'",
            site=site,
            fids=body.finding_ids,
            reason=body.reason,
            now=now,
        )
    return {"acknowledged_count": len(body.finding_ids)}


@router.delete("/api/findings/{run_id}/acknowledgements")
def unacknowledge_all(run_id: str):
    """Remove all acknowledgements for the site of this run."""
    site = get_site_for_run(run_id) if is_available() else None
    if not site:
        raise HTTPException(status_code=404, detail="Run not found in Neo4j")

    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (a:Acknowledgement {site: $site}) DELETE a RETURN count(*) AS removed",
            site=site,
        )
        removed = result.single()["removed"]
    return {"removed_count": removed}


@router.delete("/api/findings/{run_id}/acknowledge")
def unacknowledge_findings(run_id: str, body: UnacknowledgeRequest):
    """Remove acknowledgements for one or more findings."""
    if not body.finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids required")

    site = get_site_for_run(run_id) if is_available() else None
    if not site:
        raise HTTPException(status_code=404, detail="Run not found in Neo4j")

    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (a:Acknowledgement {site: $site}) "
            "WHERE a.finding_id IN $fids "
            "DELETE a "
            "RETURN count(*) AS removed",
            site=site,
            fids=body.finding_ids,
        )
        removed = result.single()["removed"]
    return {"removed_count": removed}


# ── S20-B13: Finding Annotations ──────────────────────────────────────────────


@router.post("/api/findings/{run_id}/annotate")
def annotate_finding(run_id: str, body: AnnotateRequest):
    """Add an annotation note to a finding.

    Annotations stack (multiple notes per finding are allowed) and are
    distinct from acknowledgements — they do not affect finding status.

    Returns:
        200: {annotated: True, finding_id}
        400: finding_id or text missing
        503: Neo4j unavailable
    """
    if not body.finding_id or not body.text.strip():
        raise HTTPException(status_code=400, detail="finding_id and text required")

    if not is_available():
        raise HTTPException(status_code=503, detail="Neo4j unavailable")

    now = datetime.now(timezone.utc).isoformat()
    driver = get_driver()
    with driver.session() as session:
        session.run(
            "CREATE (a:Annotation {"
            "  finding_id: $finding_id, run_id: $run_id,"
            "  text: $text, created_at: $created_at"
            "})",
            finding_id=body.finding_id,
            run_id=run_id,
            text=body.text.strip(),
            created_at=now,
        )
    return {"annotated": True, "finding_id": body.finding_id}


@router.get("/api/findings/{run_id}/annotations")
def get_annotations(run_id: str):
    """Return all annotation notes for a run, grouped by finding_id.

    Returns:
        200: {annotations: {finding_id: [{text, created_at}, ...]}}
    """
    return {"annotations": _load_annotations(run_id)}
