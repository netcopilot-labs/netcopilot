"""Delta analyzer — compare findings between two pipeline runs (S20-B9, ADR-226).

build_delta(current_run_id, previous_run_id) compares findings.json files:
  - new_findings:        in current, not in previous  (keyed by finding_id)
  - resolved_findings:   in previous, not in current
  - persistent_findings: in both

Findings are keyed by finding_id (deterministic: rule_id::element_id).
"""

import json
import os
from pathlib import Path

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


def _load_findings(run_id: str) -> dict[str, dict]:
    """Load findings.json for a run, return {finding_id: finding} dict.

    Returns empty dict if file not found or unreadable.
    """
    fp = RUNS_DIR / run_id / "findings" / "findings.json"
    try:
        raw = json.loads(fp.read_text())
        findings = raw.get("findings", []) if isinstance(raw, dict) else raw
        return {
            f["finding_id"]: f
            for f in findings
            if isinstance(f, dict) and f.get("finding_id")
        }
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def _delta_summary(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity") or "info"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_delta(current_run_id: str, previous_run_id: str) -> dict:
    """Compare findings between two runs.

    Returns:
        {
            current_run_id, previous_run_id,
            new_findings:        [...],
            resolved_findings:   [...],
            persistent_findings: [...],
            delta_summary: {
                new:        {critical, high, low, cis, info},
                resolved:   {...},
                persistent: {...},
            },
            counts: {new, resolved, persistent},
        }
    """
    current = _load_findings(current_run_id)
    previous = _load_findings(previous_run_id)

    current_ids = set(current)
    previous_ids = set(previous)

    new = [current[fid] for fid in current_ids - previous_ids]
    resolved = [previous[fid] for fid in previous_ids - current_ids]
    persistent = [current[fid] for fid in current_ids & previous_ids]

    return {
        "current_run_id": current_run_id,
        "previous_run_id": previous_run_id,
        "new_findings": new,
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "delta_summary": {
            "new": _delta_summary(new),
            "resolved": _delta_summary(resolved),
            "persistent": _delta_summary(persistent),
        },
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "persistent": len(persistent),
        },
    }


def find_previous_run(current_run_id: str) -> str | None:
    """Return the run_id immediately before current in chronological order.

    Run directories are sorted lexicographically — the timestamp format
    (YYYY-MM-DD_HH-MM-SS) sorts correctly as strings.

    Returns None if there is no previous run.
    """
    try:
        all_runs = sorted(
            d.name
            for d in RUNS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )
        idx = all_runs.index(current_run_id)
        return all_runs[idx - 1] if idx > 0 else None
    except (ValueError, OSError):
        return None
