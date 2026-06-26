"""R1 Phase 1.1 — the model is a deterministic function of the facts.

``build_model`` must produce identical output regardless of the filesystem
iteration order of the ``facts/`` directory. Without the ``sorted(...)`` guard in
``model_builder`` the device-processing order leaks into collision winners
(IP / router-id -> hostname), link side-assignment, and the OSPF-area
``spf_runs`` member pick — so the same facts could yield a different graph on a
different machine.

This reverses the ``facts/`` iteration order and asserts the model is identical.
It needs a topology that actually *exhibits* order-dependence (multiple devices,
ARP-subnet links, a multi-member OSPF area) — the trivial 2-device CDP fixture
does not, so a synthetic such fixture is tracked as Phase-1.1b follow-up. Until
then this runs against the local demo run when present (it provably exhibits the
behaviour; the negative control — removing the sort — fails on it), and skips in
CI where that gitignored run is absent.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcopilot.model import build_model

#: Local, gitignored demo run that exhibits order-dependence (see ledger).
_DEMO_RUNS_BASE = Path(__file__).resolve().parent.parent / "runs"
_DEMO_RUN_ID = "2026-06-23_09-16-04"

_REAL_ITERDIR = Path.iterdir

#: Structural model collections — same set the golden master snapshots. Excludes
#: ``model_metadata`` (wall-clock ``generated_at``, volatile by design).
_STRUCTURAL_KEYS = ("devices", "interfaces", "links", "adjacencies", "shared_services")


def _structural(model: dict) -> str:
    return json.dumps({k: model.get(k, []) for k in _STRUCTURAL_KEYS}, sort_keys=True)


def _build_with_facts_order(monkeypatch, runs_base: str, run_id: str, *, reverse: bool) -> dict:
    """build_model with the ``facts/`` dir forced to iterate in a chosen order."""
    def fake_iterdir(self: Path):
        entries = list(_REAL_ITERDIR(self))
        if self.name == "facts":
            entries = sorted(entries, key=lambda p: p.name, reverse=reverse)
        return iter(entries)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    try:
        return build_model(run_id, runs_base=runs_base)
    finally:
        monkeypatch.setattr(Path, "iterdir", _REAL_ITERDIR)


@pytest.mark.skipif(
    not (_DEMO_RUNS_BASE / _DEMO_RUN_ID / "facts").is_dir(),
    reason="local demo run absent (gitignored); CI-grade synthetic fixture is Phase-1.1b",
)
def test_model_independent_of_facts_iteration_order_demo(monkeypatch):
    forward = _build_with_facts_order(monkeypatch, str(_DEMO_RUNS_BASE), _DEMO_RUN_ID, reverse=False)
    reverse = _build_with_facts_order(monkeypatch, str(_DEMO_RUNS_BASE), _DEMO_RUN_ID, reverse=True)

    assert _structural(forward) == _structural(reverse), (
        "model differs under reversed facts/ iteration order — the "
        "sorted(facts_base.iterdir()) determinism guard is missing or broken"
    )
