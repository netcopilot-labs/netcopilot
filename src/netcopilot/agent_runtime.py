"""Shared chat-client runtime helpers (used by the dashboard SSE route and the
Telegram bot): build the tool context for a run, and seed a SessionAnonymizer
from a run's Neo4j identifiers before any content reaches a cloud provider.
"""

from __future__ import annotations

import logging
import os

from netcopilot.anonymizer import SessionAnonymizer
from netcopilot.graph.client import get_driver, get_site_for_run, is_available

log = logging.getLogger(__name__)

RUNS_DIR = os.environ.get("RUNS_DIR", "runs")


def build_tool_context(run_id: str) -> dict:
    """Build the MCP tool context (run_id, site, data_dir) for a run."""
    site = get_site_for_run(run_id) if is_available() else None
    if not site and "_" in run_id:
        site = run_id.split("_")[0]
    return {
        "run_id": run_id,
        "site": site or "unknown",
        "data_dir": f"{RUNS_DIR}/{run_id}",
    }


def seed_anonymizer(anon: SessionAnonymizer, run_id: str) -> None:
    """Register a run's identifiers (devices, sites, VRFs, AS numbers) so they
    are scrubbed before content reaches a cloud provider. Best-effort."""
    if not is_available():
        return
    try:
        with get_driver().session() as sess:
            for rec in sess.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "RETURN d.name AS name, d.site AS site, d.role AS role, d.platform AS platform",
                run_id=run_id,
            ):
                if rec["name"] and rec["role"]:
                    anon.register_device(rec["name"])
                elif rec["name"]:
                    anon.register_isp(rec["name"])  # external peer
                if rec["site"]:
                    anon.register_site(rec["site"])
                if rec["platform"] and rec["role"]:
                    anon.register_platform(rec["platform"])

            for rec in sess.run(
                "MATCH (s:SharedService {run_id: $run_id, service_type: 'ospf_area'}) "
                "WHERE s.vrf IS NOT NULL RETURN DISTINCT s.vrf AS vrf",
                run_id=run_id,
            ):
                if rec["vrf"]:
                    anon.register_vrf(rec["vrf"])

            for rec in sess.run(
                "MATCH (:Device {run_id: $run_id})-[r:ROUTING_ADJACENCY]->(:Device {run_id: $run_id}) "
                "WHERE r.protocol = 'bgp' RETURN DISTINCT r.local_as AS las, r.remote_as AS ras",
                run_id=run_id,
            ):
                if rec["las"]:
                    anon.register_asn(str(rec["las"]))
                if rec["ras"]:
                    anon.register_asn(str(rec["ras"]))
    except Exception:  # noqa: BLE001 — seeding is best-effort
        log.debug("anonymizer seeding failed for %s", run_id, exc_info=True)
