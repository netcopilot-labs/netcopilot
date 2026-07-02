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

import re
from datetime import datetime

from netcopilot.diff.engine import available_runs, compute_diff, load_run, previous_run

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


def _human_ts(run_id: str) -> str:
    """Best-effort ``YYYY-MM-DD_HH-MM-SS`` → ``02 Jul 2026 05:36``; else the raw id.

    Lets the model map a human date reference ("the run from 02 Jul 05:36") back
    to the exact run_id it must pass. Deterministic (parses fixed values, no now()).
    """
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})$", run_id)
    if not m:
        return run_id
    try:
        return datetime(*(int(x) for x in m.groups())).strftime("%d %b %Y %H:%M")
    except ValueError:
        return run_id


def _runs_hint(runs_dir: str, site: str | None, missing: str) -> str:
    """A not-found message that lists the available runs so the agent can retry
    with a real run_id (turns a dead-end into a self-correcting turn)."""
    runs = available_runs(runs_dir, site)
    scope = f" for site '{site}'" if site else ""
    if not runs:
        return f"diff_runs: run '{missing}' not found and no runs are available{scope}."
    listed = "\n".join(f"  • {r}  ({_human_ts(r)})" for r in runs)
    return (
        f"diff_runs: run '{missing}' not found{scope}. Retry with an exact run_id "
        f"from the available runs (oldest first, newest last):\n{listed}"
    )


async def diff_runs(
    *,
    run_a: str | None = None,
    run_b: str | None = None,
    runs_back: int | None = None,
    context: dict,
) -> str:
    """Diff two runs of a site. ``run_b`` = newer ("after"), ``run_a`` = older
    ("before"). Both default sensibly: ``run_b`` to the current loaded run,
    ``run_a`` to the previous same-site run of ``run_b``. ``runs_back=N`` resolves
    ``run_a`` deterministically to the Nth chronological predecessor ("N runs ago").
    When a requested run cannot be resolved, the available run_ids are listed so
    the caller can retry."""
    runs_dir = os.environ.get("RUNS_DIR", "runs")
    if runs_back is not None:  # providers may hand it over as a string
        try:
            runs_back = int(runs_back)
        except (TypeError, ValueError):
            runs_back = None

    after = run_b or context.get("run_id") or None
    if not after:
        return (
            "diff_runs: no run to compare. Pass run_b (the newer run) or load a "
            "current run first."
        )

    # Resolve/validate the newer run; if it's a bad reference, list what exists.
    try:
        after_data = load_run(after, runs_dir)
    except FileNotFoundError:
        return _runs_hint(runs_dir, None, after)
    site = after_data.site

    # Resolve the older run.
    if run_a:
        try:
            before_data = load_run(run_a, runs_dir)
        except FileNotFoundError:
            return _runs_hint(runs_dir, site, run_a)
    elif runs_back and runs_back >= 1:
        # "N runs ago" → the Nth same-site run chronologically before `after`.
        # Timestamp run_ids sort chronologically; non-timestamp ids (e.g. a demo
        # seed run) sort after them, so they aren't miscounted as predecessors.
        preds = sorted(r for r in available_runs(runs_dir, site) if r < after)
        if runs_back > len(preds):
            listed = "\n".join(f"  • {r}  ({_human_ts(r)})" for r in preds) or "  (none)"
            return (
                f"diff_runs: only {len(preds)} run(s) precede '{after}' for site "
                f"'{site}' — cannot go {runs_back} back. Earlier runs:\n{listed}"
            )
        before_data = load_run(preds[-runs_back], runs_dir)
    else:
        before = previous_run(after, runs_dir)
        if not before:
            msg = f"diff_runs: '{after}' is the earliest run"
            msg += f" for site '{site}'." if site else "."
            others = [r for r in available_runs(runs_dir, site) if r != after]
            if others:
                listed = "\n".join(f"  • {r}  ({_human_ts(r)})" for r in others)
                msg += f" Other available runs:\n{listed}"
            return msg
        before_data = load_run(before, runs_dir)

    try:
        result = compute_diff(before_data, after_data)
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        return f"diff_runs: {exc}"

    rendered = _render(result)
    # Always surface the rest of the run inventory so the model can resolve a
    # relative reference ("2 runs ago") or offer choices — without it, a caller
    # that used the default only ever sees the one previous run and can't tell
    # what else exists (it would guess or wrongly conclude none exist).
    others = [r for r in available_runs(runs_dir, site) if r not in (after, before_data.run_id)]
    if others:
        listed = "\n".join(f"  • {r}  ({_human_ts(r)})" for r in others)
        rendered += (
            f"\n\nOther runs on record for site '{site}' — to compare a different "
            f"pair, pass run_a (older) and/or run_b (newer):\n{listed}"
        )
    return rendered
