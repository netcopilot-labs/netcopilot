"""diff_runs — run-to-run drift: what changed between two runs of a site.

Reads the two runs' persisted model + findings from disk (``RUNS_DIR``) and
returns the tiered diff: **added / removed / changed** (drift) plus an
**info** tier for semi-volatile signals (BGP prefix counts, ARP/FDB/MAC,
DHCP leases, session uptime/flap). No Neo4j needed — the per-run artifacts on
disk are the authoritative diff inputs.

The agent surface returns readable, tiered text (the LLM synthesises from it);
the canonical machine shape is :meth:`DiffResult.to_dict`, which the dashboard
endpoint serves to the frontend (S01-4).

S01-3 (run-to-run drift).
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict

from netcopilot.diff.engine import compute_diff, load_run, previous_run

log = logging.getLogger(__name__)

#: Cap the itemised list per tier so a large drift never blows the result size;
#: the per-tier counts in the header are always reported in full.
_MAX_ITEMS_PER_TIER = 40
_MAX_FIELDS_PER_ITEM = 6


def _short(value: object, width: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _render(result) -> str:
    d = result.to_dict()
    s = d["summary"]
    lines = [
        f"Drift {d['run_a']} → {d['run_b']}  (site: {d['site']})",
        f"added: {s['added']}   removed: {s['removed']}   changed: {s['changed']}   info: {s['info']}",
    ]
    if not d["changes"]:
        lines.append("")
        lines.append("No drift — the two runs are identical in configuration and state.")
        return "\n".join(lines)

    by_tier: dict[str, list] = defaultdict(list)
    for c in d["changes"]:
        by_tier[c["tier"]].append(c)

    for tier in ("removed", "added", "changed", "info"):
        items = by_tier.get(tier, [])
        if not items:
            continue
        lines.append("")
        lines.append(f"{tier.upper()} ({len(items)}):")
        for c in items[:_MAX_ITEMS_PER_TIER]:
            lines.append(f"  [{c['entity_type']}] {c['key']}")
            for f in c.get("changed_fields", [])[:_MAX_FIELDS_PER_ITEM]:
                lines.append(f"      {f['field']}: {_short(f['before'])} → {_short(f['after'])}")
        if len(items) > _MAX_ITEMS_PER_TIER:
            lines.append(f"  … and {len(items) - _MAX_ITEMS_PER_TIER} more {tier}")
    return "\n".join(lines)


async def diff_runs(
    *,
    run_a: str | None = None,
    run_b: str | None = None,
    context: dict,
) -> str:
    """Diff two runs of a site. ``run_b`` = newer ("after"), ``run_a`` = older
    ("before"). Both default sensibly: ``run_b`` to the current loaded run,
    ``run_a`` to the previous same-site run of ``run_b``."""
    runs_dir = os.environ.get("RUNS_DIR", "runs")

    after = run_b or context.get("run_id") or None
    if not after:
        return (
            "diff_runs: no run to compare. Pass run_b (the newer run) or load a "
            "current run first."
        )

    try:
        before = run_a or previous_run(after, runs_dir)
    except FileNotFoundError as exc:
        return f"diff_runs: {exc}"
    if not before:
        return (
            f"diff_runs: no previous same-site run found for '{after}'. Pass "
            f"run_a to compare against a specific earlier run."
        )

    try:
        result = compute_diff(load_run(before, runs_dir), load_run(after, runs_dir))
    except FileNotFoundError as exc:
        return f"diff_runs: {exc}"
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        return f"diff_runs: {exc}"

    return _render(result)
