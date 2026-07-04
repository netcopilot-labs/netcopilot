"""validate_change — deterministic pass/warn/fail verdict on a network change.

Composes the pieces that already exist: two run snapshots → the diff engine →
the verdict engine (``diff/verdict.py``, ADR-0006). The operator (or an agent
pipeline) declares which devices were *supposed* to change; the verdict fails
on out-of-scope drift or new critical/high findings. Non-actuating: judges
collected runs, never touches devices.
"""

from __future__ import annotations

import logging
import os

from netcopilot.diff.engine import compute_diff, load_run, previous_run
from netcopilot.diff.verdict import ChangeVerdict, evaluate_change

from ..result import ToolResult
from .run_diff import _human_ts, _runs_hint

log = logging.getLogger(__name__)

_BANNER = {"pass": "✅ PASS", "warn": "⚠️ WARN", "fail": "❌ FAIL"}


def _render(verdict: ChangeVerdict, before: str, after: str,
            scope: frozenset[str] | None, unknown_scope: list[str]) -> str:
    lines = [
        f"Change validation — {before} → {after}",
        f"Declared scope: {', '.join(sorted(scope)) if scope else '(none — verdict is threshold-only; declare scope_devices for intent checking)'}",
        "",
        f"Verdict: {_BANNER[verdict.result]}",
    ]
    if unknown_scope:
        lines.append(
            f"⚠ Scope device(s) not present in either run: {', '.join(unknown_scope)} "
            "— check for typos; drift on other devices will fail the verdict."
        )
    if verdict.reasons:
        lines.append("")
        lines.append("Reasons:")
        lines.extend(f"  • {r['detail']}" for r in verdict.reasons)
    c = verdict.counts
    nf = ", ".join(f"{k}: {v}" for k, v in sorted(c["new_findings"].items())) or "none"
    lines += [
        "",
        "Summary:",
        f"  Drift changes: {c['drift_total']}"
        + (f" (in scope: {c['in_scope']}, out of scope: {c['out_of_scope']}, "
           f"unattributed: {c['unattributed']})" if scope else
           f" (unattributed: {c['unattributed']})"),
        f"  New findings: {nf}",
        f"  Resolved findings: {c['resolved_findings']}",
        f"  Info-tier (operational noise, ignored): {c['info']}",
        "",
        "For the full change list call diff_runs with the same two runs.",
    ]
    return "\n".join(lines)


async def validate_change(
    *,
    run_before: str | None = None,
    run_after: str | None = None,
    scope_devices: list[str] | None = None,
    context: dict,
) -> ToolResult:
    """Judge the drift between two runs against a declared change scope.

    ``run_after`` defaults to the current loaded run, ``run_before`` to its
    previous same-site run (same defaults as ``diff_runs``). ``scope_devices``
    is the list of devices that were supposed to change; omit it for a
    threshold-only verdict (new-findings / honesty checks, no intent check).
    """
    runs_dir = os.environ.get("RUNS_DIR", "runs")

    after = run_after or context.get("run_id") or None
    if not after:
        return ToolResult("error", (
            "validate_change: no run to validate. Pass run_after (the post-change "
            "run) or load a current run first."
        ))
    try:
        after_data = load_run(after, runs_dir)
    except FileNotFoundError:
        return ToolResult("not_found", _runs_hint(runs_dir, None, after))
    site = after_data.site

    if run_before:
        try:
            before_data = load_run(run_before, runs_dir)
        except FileNotFoundError:
            return ToolResult("not_found", _runs_hint(runs_dir, site, run_before))
    else:
        before = previous_run(after, runs_dir)
        if not before:
            msg = f"validate_change: '{after}' is the earliest run"
            msg += f" for site '{site}'." if site else "."
            msg += " A validation needs a pre-change run to compare against."
            return ToolResult("no_data", msg)
        before_data = load_run(before, runs_dir)

    scope = frozenset(str(d) for d in scope_devices) if scope_devices else None
    known_devices = {
        str(d.get("device_id"))
        for data in (before_data, after_data)
        for d in data.model.get("devices", [])
    }
    unknown_scope = sorted(scope - known_devices) if scope else []

    try:
        diff = compute_diff(before_data, after_data)
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        return ToolResult("error", f"validate_change: {exc}")

    verdict = evaluate_change(diff, before_data, after_data, scope)
    text = _render(verdict, before_data.run_id, after_data.run_id, scope, unknown_scope)
    return ToolResult("ok", text, verdict=verdict.to_dict())
