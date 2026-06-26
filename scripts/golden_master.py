#!/usr/bin/env python3
"""Golden-master harness for the BGP + OSPF determinism refactor (R1).

Captures a canonical, sorted snapshot of the pure ``facts -> (model, findings)``
function so the refactor can prove it changed **nothing it didn't mean to**
(Phase 1) and **exactly what it meant to** (Phase 2).

What it is, precisely:
  * A REGRESSION NET, not a correctness oracle. It freezes the CURRENT output,
    known bugs included. ``fixtures/golden/LEDGER.md`` records which frozen
    outputs are known-wrong Phase-2 targets. It is blind to *unknown*-wrong
    output by design — that gap is covered by the audits + review, not by this.
  * Neo4j-free. It snapshots the model dict (``build_model``) + findings
    (``run_rules``), both pure functions of the collected facts, so it runs in
    CI with no database. (The loader/graph layer has its own test suite.)

Mirrors ``pipeline.process_run`` exactly: ``build_model`` (which persists
``network_model.json`` via ``_write_model``) then ``run_rules`` (which reads it
back). No live devices, no DB.

Usage:
    # capture the expected snapshot for a run
    python scripts/golden_master.py capture \
        --runs-base fixtures/golden --run demo --out fixtures/golden/demo/snapshot.json

    # check a (possibly refactored) build against the frozen snapshot
    python scripts/golden_master.py check \
        --runs-base fixtures/golden --run demo --against fixtures/golden/demo/snapshot.json

    # prove the build is stable run-to-run on this machine (cheap determinism check)
    python scripts/golden_master.py selfcheck --runs-base runs --run <run-id>

`check` exits 1 on any diff (the Phase-1 gate). `selfcheck` exits 1 if two
consecutive builds disagree.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Repo-root import: scripts/ is a sibling of src/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from netcopilot.model import build_model  # noqa: E402
from netcopilot.graph.loader import _build_route_params, _build_vrf_members  # noqa: E402
from netcopilot.rules.engine import run_rules  # noqa: E402

#: Model collections that the determinism refactor can affect. We snapshot the
#: whole model dict, but list these explicitly so a *new* top-level key surfaces
#: as an intentional addition rather than silently riding along.
_MODEL_KEYS = ("devices", "interfaces", "links", "adjacencies", "shared_services", "l2_domains")

#: Route-param keys that are loader-stamped DB tags, NOT part of the deterministic
#: facts -> routes function (site = Neo4j multi-site isolation, run_id = the run
#: label). Stripped from the route snapshot so they never show as a spurious diff.
#: (R2 Phase 0 — the route/RIB layer is loader-materialised, outside build_model.)
_ROUTE_STRIP = frozenset({"site", "run_id"})

#: Wall-clock / per-run metadata that is volatile BY DESIGN and not part of the
#: deterministic facts -> (model, findings) function. Stripped before comparison
#: so the golden master tracks *content*, not when it ran. (e.g. each finding's
#: ``detected_at`` ISO timestamp.) Keep this list explicit, not a regex — a new
#: volatile field should be a deliberate addition we can see in review.
_VOLATILE_KEYS = frozenset({"detected_at"})


def _canon(obj: Any) -> Any:
    """Canonicalise for order-independent comparison.

    Dicts -> key-sorted (volatile keys dropped); lists -> sorted by each
    element's canonical JSON, so production *order* never shows up as a spurious
    diff. (Order-determinism is a separate concern, covered by `selfcheck` + the
    Phase-1.1 order-injection unit test — not by this content snapshot.)
    """
    if isinstance(obj, dict):
        return {k: _canon(obj[k]) for k in sorted(obj) if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        canon_items = [_canon(x) for x in obj]
        return sorted(canon_items, key=lambda x: json.dumps(x, sort_keys=True))
    return obj


def _build(runs_base: str, run_id: str) -> dict[str, Any]:
    """Run the pure model+findings+routes function for a run (mirrors process_run).

    Routes are the loader-materialised L3 layer (``:Route`` nodes); we build them
    Neo4j-free via the pure ``_build_route_params`` (extracted in R2 Phase 0) so the
    audit's route/RIB defects are inside the regression net, not outside it. ``site``
    is pinned to a constant — it is a DB-isolation tag, not facts-derived content.
    """
    model = build_model(run_id, runs_base=runs_base)        # also persists network_model.json
    rules = run_rules(str(run_id), runs_base=str(runs_base))  # reads that model back
    findings = rules.get("findings", rules if isinstance(rules, list) else [])
    run_dir = Path(runs_base) / str(run_id)
    route_params, _ = _build_route_params(
        run_dir, "golden", "golden", interfaces=model.get("interfaces"),
    )
    routes = [{k: v for k, v in r.items() if k not in _ROUTE_STRIP} for r in route_params]
    # VRF SharedService membership — loader-materialised, snapshotted Neo4j-free
    # (R2-COV-1). Sets → sorted lists so the snapshot is order-independent.
    vrf_members = _build_vrf_members(run_dir, model.get("interfaces"))
    vrfs = [{"vrf": v, "members": sorted(m)} for v, m in sorted(vrf_members.items())]
    return {
        "model": {k: model.get(k, []) for k in _MODEL_KEYS},
        "findings": findings,
        "routes": routes,
        "vrfs": vrfs,
    }


def _snapshot(built: dict[str, Any]) -> dict[str, Any]:
    """Canonical, counts-annotated snapshot ready to serialise."""
    canon = {
        "model": _canon(built["model"]),
        "findings": _canon(built["findings"]),
        "routes": _canon(built["routes"]),
        "vrfs": _canon(built["vrfs"]),
    }
    counts = {k: len(built["model"].get(k, [])) for k in _MODEL_KEYS}
    counts["findings"] = len(built["findings"])
    counts["routes"] = len(built["routes"])
    counts["vrfs"] = len(built["vrfs"])
    return {"_counts": counts, **canon}


def _dump(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False)


def _diff_section(name: str, expected: list, actual: list) -> list[str]:
    """Set-diff two canonical lists; report adds/removes (a change = remove+add)."""
    exp = {json.dumps(x, sort_keys=True) for x in expected}
    act = {json.dumps(x, sort_keys=True) for x in actual}
    removed = sorted(exp - act)
    added = sorted(act - exp)
    if not removed and not added:
        return []
    out = [f"  [{name}] -{len(removed)} +{len(added)}"]
    for r in removed[:8]:
        out.append(f"    - {r[:240]}")
    for a in added[:8]:
        out.append(f"    + {a[:240]}")
    if len(removed) > 8 or len(added) > 8:
        out.append("    … (truncated)")
    return out


def cmd_capture(args: argparse.Namespace) -> int:
    snap = _snapshot(_build(args.runs_base, args.run))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_dump(snap) + "\n", encoding="utf-8")
    print(f"captured {snap['_counts']} -> {out}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    expected = json.loads(Path(args.against).read_text(encoding="utf-8"))
    actual = _snapshot(_build(args.runs_base, args.run))
    lines: list[str] = []
    lines += _diff_section("model.devices", expected["model"]["devices"], actual["model"]["devices"])
    lines += _diff_section("model.interfaces", expected["model"]["interfaces"], actual["model"]["interfaces"])
    lines += _diff_section("model.links", expected["model"]["links"], actual["model"]["links"])
    lines += _diff_section("model.adjacencies", expected["model"]["adjacencies"], actual["model"]["adjacencies"])
    lines += _diff_section("model.shared_services", expected["model"]["shared_services"], actual["model"]["shared_services"])
    lines += _diff_section("model.l2_domains", expected["model"].get("l2_domains", []), actual["model"].get("l2_domains", []))
    lines += _diff_section("routes", expected.get("routes", []), actual.get("routes", []))
    lines += _diff_section("vrfs", expected.get("vrfs", []), actual.get("vrfs", []))
    lines += _diff_section("findings", expected["findings"], actual["findings"])
    if not lines:
        print(f"GOLDEN OK — identical to {args.against} ({actual['_counts']})")
        return 0
    print(f"GOLDEN DIFF vs {args.against}:")
    print(f"  expected counts: {expected.get('_counts')}")
    print(f"  actual   counts: {actual['_counts']}")
    print("\n".join(lines))
    print("\nClassify each delta in LEDGER.md: A=regression (must be 0 in Phase 1), "
          "B=convergence (review+accept), C=Phase-2 fix.")
    return 1


def cmd_selfcheck(args: argparse.Namespace) -> int:
    a = _dump(_snapshot(_build(args.runs_base, args.run)))
    b = _dump(_snapshot(_build(args.runs_base, args.run)))
    if a == b:
        print("SELFCHECK OK — two consecutive builds identical (run-to-run stable)")
        return 0
    print("SELFCHECK FAILED — consecutive builds differ (non-determinism present).")
    print("Note: same-machine selfcheck only catches obvious non-determinism; "
          "cross-filesystem-order is covered by the Phase-1.1 order-injection test.")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("capture", "check", "selfcheck"):
        sp = sub.add_parser(name)
        sp.add_argument("--runs-base", default="runs")
        sp.add_argument("--run", required=True)
        if name == "capture":
            sp.add_argument("--out", required=True)
        if name == "check":
            sp.add_argument("--against", required=True)
    args = p.parse_args()
    return {"capture": cmd_capture, "check": cmd_check, "selfcheck": cmd_selfcheck}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
