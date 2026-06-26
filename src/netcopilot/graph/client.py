"""Neo4j driver — process-wide singleton + helpers.

Connection details come from environment variables:
    NEO4J_URI      → bolt://localhost:7687
    NEO4J_USER     → neo4j
    NEO4J_PASSWORD → neo4j   (set your own)

``get_driver()`` always returns a driver instance and does NOT verify connectivity;
check reachability separately with ``is_available()``. One driver per process, created
lazily; reset via ``reset()`` (tests) or ``close()`` (shutdown).
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_driver = None


def get_driver():
    """Return the singleton Neo4j driver, creating it on first call."""
    global _driver
    if _driver is None:
        from neo4j import GraphDatabase

        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "neo4j")
        _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def get_session(database: str = "neo4j"):
    """Return a new session from the singleton driver (use as a context manager)."""
    return get_driver().session(database=database)


def is_available() -> bool:
    """Whether Neo4j is reachable. Never raises — returns False on any error."""
    try:
        get_driver().verify_connectivity()
        return True
    except Exception as exc:
        log.warning("Neo4j unavailable: %s", exc)
        return False


def get_site_for_run(run_id: str) -> str | None:
    """Return the site for a run by reading any Device node, or None."""
    with get_driver().session() as session:
        record = session.run(
            "MATCH (d:Device {run_id: $run_id}) RETURN d.site AS site LIMIT 1",
            run_id=run_id,
        ).single()
        return record["site"] if record else None


def close():
    """Close the singleton driver. Safe to call repeatedly."""
    global _driver
    if _driver is not None:
        try:
            _driver.close()
        except Exception:
            pass
        _driver = None


def reset():
    """Reset the singleton (for tests): close and clear so the next call reconnects."""
    close()
