"""Resolve the run context (run_id + site) that a tool call needs.

Shared by the MCP server and the CLI/orchestrator so run resolution lives in one place.
"""

from __future__ import annotations

from .graph.client import get_driver, get_site_for_run, is_available


def resolve_run_id(site: str | None = None) -> str | None:
    """Latest run_id (optionally for a site), from Neo4j. None if unavailable/empty."""
    if not is_available():
        return None
    with get_driver().session() as session:
        if site:
            rec = session.run(
                "MATCH (r:Run {site: $site}) "
                "RETURN r.run_id AS run_id ORDER BY r.loaded_at DESC LIMIT 1",
                site=site,
            ).single()
        else:
            rec = session.run(
                "MATCH (r:Run) RETURN r.run_id AS run_id ORDER BY r.loaded_at DESC LIMIT 1"
            ).single()
        return rec["run_id"] if rec else None


def build_context(site: str | None = None, run_id: str | None = None) -> dict:
    """Build the {run_id, site} context a tool needs, resolving the latest run if unset."""
    if not run_id:
        run_id = resolve_run_id(site)
    if not run_id:
        return {"run_id": "", "site": site or "unknown"}
    resolved = site
    if not resolved:
        resolved = (get_site_for_run(run_id) if is_available() else None) or (
            run_id.split("_")[0] if "_" in run_id else None
        )
    return {"run_id": run_id, "site": resolved or "unknown"}
