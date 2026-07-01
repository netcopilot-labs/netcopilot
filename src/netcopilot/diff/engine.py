"""Run-to-run diff engine.

Two layers:

- :func:`load_run` — disk → :class:`RunData` (reads a run's
  ``model/network_model.json`` + ``findings/findings.json``). The model +
  findings on disk are the authoritative per-run artifacts (same ones the
  golden master and the graph loader consume).

- :func:`compute_diff` — a **pure** function of two :class:`RunData` values →
  :class:`DiffResult`. No I/O, so it is unit-tested directly on synthetic
  model/findings dicts. Given the same inputs it always produces the same
  output (entity types iterated in a fixed order, keys sorted, changed fields
  sorted).

:func:`diff_run_ids` is the convenience wrapper (load both, then compute).

The classification contract (stable keys + drift/info/volatile fields) lives in
:mod:`netcopilot.diff.field_policy`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcopilot.diff import field_policy as fp

#: Tier ordering for deterministic, human-sensible output grouping.
_TIER_ORDER = {"removed": 0, "added": 1, "changed": 2, "info": 3}


@dataclass(frozen=True)
class RunData:
    """A single run's diffable content.

    ``site`` is derived from the run's devices (each device carries ``site``);
    it is ``None`` only when no device declares one. ``model`` is the full
    ``network_model.json`` dict; ``findings`` is the list under the
    ``findings`` key of ``findings.json``.
    """

    run_id: str
    site: str | None
    model: dict[str, Any]
    findings: list[dict[str, Any]]


@dataclass(frozen=True)
class DiffResult:
    """The tiered diff of two runs.

    ``changes`` is a flat, deterministically-ordered list of entry dicts; the
    UI/tool re-group by ``tier``. ``summary`` holds per-tier counts.
    """

    run_a: str
    run_b: str
    site: str | None
    changes: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable payload (for the MCP tool + backend endpoint)."""
        return {
            "run_a": self.run_a,
            "run_b": self.run_b,
            "site": self.site,
            "summary": self.summary,
            "changes": self.changes,
        }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _run_site(model: dict[str, Any]) -> str | None:
    """Derive a run's site from its devices (site is not in model_metadata).

    A run is single-site by construction. Returns the one distinct site, or
    ``None`` if no device declares one. Raises if devices disagree — a genuinely
    malformed run we should not silently average over.
    """
    sites = {d.get("site") for d in model.get("devices", []) if d.get("site")}
    if not sites:
        return None
    if len(sites) > 1:
        raise ValueError(f"run spans multiple sites {sorted(sites)} — malformed run")
    return next(iter(sites))


def load_run(run_id: str, runs_dir: str | Path = "runs") -> RunData:
    """Load a run's model + findings from disk into a :class:`RunData`.

    Both ``model/network_model.json`` and ``findings/findings.json`` are
    required — they are standard ``process_run`` outputs. A missing file raises
    ``FileNotFoundError`` naming it, rather than diffing against a silent empty.
    """
    run_dir = Path(runs_dir) / str(run_id)
    model_path = run_dir / "model" / "network_model.json"
    findings_path = run_dir / "findings" / "findings.json"

    if not model_path.is_file():
        raise FileNotFoundError(f"run '{run_id}': model not found at {model_path}")
    if not findings_path.is_file():
        raise FileNotFoundError(f"run '{run_id}': findings not found at {findings_path}")

    model = json.loads(model_path.read_text(encoding="utf-8"))
    findings_doc = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = findings_doc.get("findings", []) if isinstance(findings_doc, dict) else findings_doc

    return RunData(run_id=str(run_id), site=_run_site(model), model=model, findings=findings)


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------
def _index(items: list[dict[str, Any]], key_fn) -> dict[str, dict[str, Any]]:
    """Index a list of entities by their stable key.

    Duplicate keys are a data defect (two entities claiming the same identity);
    we surface it rather than silently letting one shadow the other.
    """
    out: dict[str, dict[str, Any]] = {}
    for it in items:
        k = key_fn(it)
        if k in out:
            raise ValueError(f"duplicate stable key {k!r} in entity list")
        out[k] = it
    return out


def _entry(
    entity_type: str,
    key: str,
    tier: str,
    *,
    element_type: str | None = None,
    element_id: str | None = None,
    changed_fields: list[dict[str, Any]] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "entity_type": entity_type,
        "key": key,
        "tier": tier,
        "element_type": element_type,
        "element_id": element_id,
    }
    if changed_fields is not None:
        entry["changed_fields"] = changed_fields
    # Removed entities carry their full prior data so the topology can ghost
    # them (endpoints, etc.); added entities carry their new data.
    if before is not None:
        entry["before"] = before
    if after is not None:
        entry["after"] = after
    return entry


def _diff_collection(
    entity_type: str,
    old: list[dict[str, Any]],
    new: list[dict[str, Any]],
    key_fn,
    element_ref_fn,
) -> list[dict[str, Any]]:
    """Diff one entity collection; return its change entries (key-sorted)."""
    old_idx = _index(old, key_fn)
    new_idx = _index(new, key_fn)
    entries: list[dict[str, Any]] = []

    for key in sorted(set(old_idx) | set(new_idx)):
        in_old = key in old_idx
        in_new = key in new_idx

        if in_new and not in_old:
            et, eid = element_ref_fn(new_idx[key])
            entries.append(
                _entry(entity_type, key, "added", element_type=et, element_id=eid, after=new_idx[key])
            )
        elif in_old and not in_new:
            et, eid = element_ref_fn(old_idx[key])
            entries.append(
                _entry(entity_type, key, "removed", element_type=et, element_id=eid, before=old_idx[key])
            )
        else:
            drift, info = fp.classify_field_changes(old_idx[key], new_idx[key])
            if not drift and not info:
                continue  # only volatile fields differed → no change
            tier = "changed" if drift else "info"
            fields = drift if drift else info
            et, eid = element_ref_fn(new_idx[key])
            entries.append(
                _entry(entity_type, key, tier, element_type=et, element_id=eid, changed_fields=fields)
            )
    return entries


def _finding_element_ref(f: dict[str, Any]) -> tuple[str | None, str | None]:
    """Topology reference for a finding, taken from its evidence block."""
    ev = f.get("evidence", {}) or {}
    et = ev.get("element_type")
    eid = ev.get("element_id")
    if et in {"device", "interface", "link"} and eid:
        # interfaces halo their owning node; the finding's element_id is the
        # interface_id, but the topology element is still the interface's node.
        return (et, str(eid))
    return (None, None)


def compute_diff(run_a: RunData, run_b: RunData) -> DiffResult:
    """Pure diff of two runs (``run_a`` = before, ``run_b`` = after).

    Raises ``ValueError`` if the two runs are from different sites (when both
    sites are known).
    """
    if run_a.site and run_b.site and run_a.site != run_b.site:
        raise ValueError(
            f"cross-site diff not supported: run '{run_a.run_id}' is site "
            f"'{run_a.site}', run '{run_b.run_id}' is site '{run_b.site}'"
        )

    changes: list[dict[str, Any]] = []

    for entity_type in fp.ENTITY_TYPES:
        changes.extend(
            _diff_collection(
                entity_type,
                run_a.model.get(entity_type, []),
                run_b.model.get(entity_type, []),
                fp.STABLE_KEYS[entity_type],
                lambda e, _t=entity_type: fp.element_ref(_t, e),
            )
        )

    # Findings last — same add/remove/change machinery, keyed by finding_id.
    changes.extend(
        _diff_collection(
            "findings",
            run_a.findings,
            run_b.findings,
            fp.finding_key,
            _finding_element_ref,
        )
    )

    summary = {"added": 0, "removed": 0, "changed": 0, "info": 0}
    for c in changes:
        summary[c["tier"]] += 1

    return DiffResult(
        run_a=run_a.run_id,
        run_b=run_b.run_id,
        site=run_a.site or run_b.site,
        changes=changes,
        summary=summary,
    )


def diff_run_ids(run_a: str, run_b: str, runs_dir: str | Path = "runs") -> DiffResult:
    """Convenience: load both runs from disk and diff them."""
    return compute_diff(load_run(run_a, runs_dir), load_run(run_b, runs_dir))


def previous_run(run_id: str, runs_dir: str | Path = "runs") -> str | None:
    """Return the newest same-site run on disk that precedes ``run_id``.

    Run folders are timestamp-named (``YYYY-MM-DD_HH-MM-SS``), which sorts
    chronologically as plain strings, so "previous" = the greatest folder name
    that is lexicographically less than ``run_id`` and shares its site. Returns
    ``None`` when there is no earlier same-site run (e.g. the first run of a
    site, or a non-timestamp run_id with no predecessor). Used by the CLI/backend
    to default the comparison run.
    """
    base = Path(runs_dir)
    target_model = base / str(run_id) / "model" / "network_model.json"
    if not target_model.is_file():
        raise FileNotFoundError(f"run '{run_id}': model not found at {target_model}")
    target_site = _run_site(json.loads(target_model.read_text(encoding="utf-8")))

    candidates: list[str] = []
    for d in base.iterdir():
        if not d.is_dir() or d.name >= str(run_id):
            continue
        model_path = d / "model" / "network_model.json"
        if not model_path.is_file():
            continue
        try:
            site = _run_site(json.loads(model_path.read_text(encoding="utf-8")))
        except (ValueError, json.JSONDecodeError):
            continue
        if target_site is not None and site != target_site:
            continue
        candidates.append(d.name)

    return max(candidates) if candidates else None
