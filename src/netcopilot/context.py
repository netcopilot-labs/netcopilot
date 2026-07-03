"""Resolve the run context (run_id + site + data_dir) that a tool call needs.

Shared by the MCP server, the CLI/orchestrator, and the chat clients (via
``agent_runtime.build_tool_context``) so run resolution lives in one place.
"""

from __future__ import annotations

import os

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
    """Build the {run_id, site, data_dir} context a tool needs, resolving the latest run if unset.

    ``data_dir`` points at the run's collected files (``$RUNS_DIR/<run_id>``) —
    the file-reading tools (trace_path, get_ospf_detail, ...) silently degrade
    to no_data without it, so every context built here must carry it.
    """
    if not run_id:
        run_id = resolve_run_id(site)
    if not run_id:
        return {"run_id": "", "site": site or "unknown", "data_dir": ""}
    resolved = site
    if not resolved:
        resolved = (get_site_for_run(run_id) if is_available() else None) or (
            run_id.split("_")[0] if "_" in run_id else None
        )
    runs_dir = os.environ.get("RUNS_DIR", "runs")
    return {
        "run_id": run_id,
        "site": resolved or "unknown",
        "data_dir": f"{runs_dir}/{run_id}",
    }
