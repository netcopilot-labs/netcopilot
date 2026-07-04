"""Change-validation verdict — the deterministic judgment layer over a run diff.

``evaluate_change`` answers the operator's question after a change: *did the
network change the way I intended, and nothing else?* It is a pure function of
the two run artifacts (via :class:`~netcopilot.diff.engine.DiffResult` plus the
loaded runs for device attribution) and an optional declared scope — no LLM, no
Neo4j, no clock. The policy below IS the spec; changing it is an ADR-level
decision, not a tweak.

Verdict policy (ADR-0006):

- **fail**
  - a new finding of severity ``critical`` or ``high`` appeared (regardless of
    scope — a change that introduces a severe problem is never a pass), or
  - a scope was declared and a drift-tier change touches **no** in-scope device
    (out-of-scope drift is exactly the false-OK trap this feature exists to
    catch; removals are included — a device/link that vanished outside the
    declared scope is drift, not cleanup).
- **warn**
  - new findings below the fail threshold (``medium`` / ``low`` / ``cis`` — a
    new compliance finding is a regression worth flagging),
  - an existing finding's content changed,
  - drift with no declared scope (without an expectation NetCopilot cannot
    judge intent — it reports honestly instead of guessing; Constitution
    Art. III),
  - drift that cannot be attributed to any device (``ospf_lsdb`` entries, and
    aggregate entities whose membership is unknown) — surfaced, never silently
    dropped and never escalated to a false fail.
- **pass** — no drift, or every drift-tier change touches the declared scope,
  with no new findings at or above the warn threshold.

Info-tier entries (the field-policy noise contract) and new ``info``-severity
findings never affect the verdict — they appear in ``counts`` only. Resolved
findings (present before, gone after) are a positive signal in ``counts``,
never a reason.

Scope rule: a change is in-scope iff **any** attributed device is in the
declared scope — a link or adjacency touching a changed device is expected to
change with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import DiffResult, RunData
from . import field_policy as fp

#: New-finding severities that force a fail / warn. Everything else (``info``)
#: is counted but never drives the verdict.
FAIL_SEVERITIES = frozenset({"critical", "high"})
WARN_SEVERITIES = frozenset({"medium", "low", "cis"})

#: Per-entity-type extraction of the device names a raw model entity touches.
#: Empty list → the entity type has no reliable device attribution
#: (``ospf_lsdb``: ``adv_router`` is a router-id, not a hostname).
_DEVICE_FIELDS: dict[str, Any] = {
    "devices": lambda e: [e.get("device_id")],
    "interfaces": lambda e: [e.get("device_id")],
    "links": lambda e: [e.get("local_device_id"), e.get("remote_device_id")],
    "adjacencies": lambda e: [e.get("device_a"), e.get("device_b")],
    "shared_services": lambda e: list(e.get("members") or []),
    "l2_domains": lambda e: list(e.get("member_devices") or []),
    "ospf_lsdb": lambda e: [],
    "firewall_policies": lambda e: [e.get("device")],  # a policy is owned by one device
}

VERDICT_LEVELS = ("pass", "warn", "fail")


@dataclass(frozen=True)
class ChangeVerdict:
    """The judgment: ``result`` + machine-readable ``reasons`` + ``counts``.

    ``reasons`` entries are dicts with a stable ``code`` plus context
    (``detail`` always; ``entity_type``/``key``/``severity``/``count`` where
    they apply). The dict shape is a frozen contract — external MCP clients
    consume it via structuredContent.
    """

    result: str
    reasons: tuple[dict[str, Any], ...] = ()
    counts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "reasons": [dict(r) for r in self.reasons],
            "counts": dict(self.counts),
        }


def _attribution_index(*runs: RunData) -> dict[tuple[str, str], frozenset[str]]:
    """(entity_type, stable_key) → devices the entity touches, across both runs.

    Built from the raw models because ``changed``-tier diff entries carry only
    field deltas, not the entity — parsing composite keys back into device
    names would couple the verdict to key formats. Union across runs so an
    entity whose membership itself changed attributes to both sides.
    """
    index: dict[tuple[str, str], set[str]] = {}
    for run in runs:
        for entity_type in fp.ENTITY_TYPES:
            key_fn = fp.STABLE_KEYS[entity_type]
            extract = _DEVICE_FIELDS[entity_type]
            for entity in run.model.get(entity_type, []):
                devices = {str(d) for d in extract(entity) if d}
                index.setdefault((entity_type, key_fn(entity)), set()).update(devices)
    return {k: frozenset(v) for k, v in index.items()}


def _entry_ref(entry: dict[str, Any]) -> str:
    """Human-oriented reference for a reason detail."""
    return f"{entry['entity_type']}:{entry['key']}"


def evaluate_change(
    diff: DiffResult,
    run_before: RunData,
    run_after: RunData,
    scope_devices: frozenset[str] | None = None,
) -> ChangeVerdict:
    """Judge ``diff`` (before → after) against an optional declared scope.

    ``run_before`` / ``run_after`` must be the same runs the diff was computed
    from — they provide device attribution for the drift entries.
    """
    index = _attribution_index(run_before, run_after)

    fails: list[dict[str, Any]] = []
    warns: list[dict[str, Any]] = []
    counts: dict[str, Any] = {
        "drift_total": 0,
        "in_scope": 0,
        "out_of_scope": 0,
        "unattributed": 0,
        "info": 0,
        "new_findings": {},
        "changed_findings": 0,
        "resolved_findings": 0,
    }

    minor_findings = 0
    unattributed: dict[str, int] = {}
    unscoped_drift = 0

    for entry in diff.changes:
        entity_type, tier = entry["entity_type"], entry["tier"]

        if entity_type == "findings":
            if tier == "added":
                severity = str((entry.get("after") or {}).get("severity", "")).lower()
                counts["new_findings"][severity] = counts["new_findings"].get(severity, 0) + 1
                title = (entry.get("after") or {}).get("title", "")
                if severity in FAIL_SEVERITIES:
                    fails.append({
                        "code": "new_finding",
                        "severity": severity,
                        "key": entry["key"],
                        "detail": f"new {severity} finding: {title or entry['key']}",
                    })
                elif severity in WARN_SEVERITIES:
                    minor_findings += 1
            elif tier == "removed":
                counts["resolved_findings"] += 1
            else:  # changed / info — a finding whose content shifted
                counts["changed_findings"] += 1
            continue

        if tier == "info":
            counts["info"] += 1
            continue

        # Drift-tier model entry (added / removed / changed).
        counts["drift_total"] += 1
        devices = index.get((entity_type, entry["key"]), frozenset())

        if not devices:
            counts["unattributed"] += 1
            unattributed[entity_type] = unattributed.get(entity_type, 0) + 1
            continue

        if scope_devices is None:
            unscoped_drift += 1
            continue

        if devices & scope_devices:
            counts["in_scope"] += 1
        else:
            counts["out_of_scope"] += 1
            fails.append({
                "code": "out_of_scope_change",
                "entity_type": entity_type,
                "key": entry["key"],
                "detail": (
                    f"{tier} {_entry_ref(entry)} touches only "
                    f"{sorted(devices)} — outside declared scope"
                ),
            })

    if minor_findings:
        warns.append({
            "code": "new_minor_findings",
            "count": minor_findings,
            "detail": f"{minor_findings} new finding(s) below the fail threshold",
        })
    if counts["changed_findings"]:
        warns.append({
            "code": "changed_findings",
            "count": counts["changed_findings"],
            "detail": f"{counts['changed_findings']} existing finding(s) changed content",
        })
    if scope_devices is None and unscoped_drift:
        warns.append({
            "code": "unscoped_drift",
            "count": unscoped_drift,
            "detail": (
                f"{unscoped_drift} drift change(s) with no declared scope — "
                "cannot judge intent, review the diff"
            ),
        })
    for entity_type in sorted(unattributed):
        warns.append({
            "code": "unattributed_change",
            "entity_type": entity_type,
            "count": unattributed[entity_type],
            "detail": (
                f"{unattributed[entity_type]} {entity_type} change(s) not "
                "attributable to a device"
            ),
        })

    result = "fail" if fails else ("warn" if warns else "pass")
    return ChangeVerdict(result=result, reasons=tuple(fails + warns), counts=counts)
