#!/usr/bin/env python3
"""Agent answer-quality eval (s21, ADR-0024) — routing accuracy + completeness.

Drives the REAL agent (``run_tool_loop`` + the configured provider) over
``question_catalog.yaml`` against the latest loaded run, and scores each
question on: routing decision, tools actually called, and facts present in the
final answer. A local gate in the ``golden_master.py`` tradition — it needs the
live LLM + Neo4j + a loaded run, so it runs on demand, not in CI (CI keeps the
deterministic router/orchestrator unit tests).

Usage:
    python scripts/eval/run_eval.py                  # score + diff baseline
    python scripts/eval/run_eval.py --capture        # write baseline.json
    python scripts/eval/run_eval.py --only vrrp_config_state
    python scripts/eval/run_eval.py --model <registry-id>
    python scripts/eval/run_eval.py --allow-run-mismatch   # cross-run diff, marked

Baseline discipline: capture only results you have seen twice (LLM
nondeterminism) — run without --capture first; if two runs agree, capture.

Hardening (s23-3):
- The catalogue is validated at load, `routing.yaml`-style: unknown keys,
  empty ``expect``, duplicate ids, and tool names absent from the registry all
  fail LOUD (``all({})`` is True, so an unvalidated typo'd key would pass
  forever and look like coverage).
- ``requires: [<feature>]`` marks a question network-dependent. Each feature
  maps to a deterministic probe (a real tool dispatched without the LLM,
  judged by ``ToolResult.status``). Feature absent → the question is SKIPPED,
  never FAILED, and skips are counted separately: the eval must distinguish
  "the agent regressed" from "the network changed".
- The baseline records the run it was captured against; diffing against a
  DIFFERENT run aborts unless ``--allow-run-mismatch`` (marked non-comparable).

Exit codes: 0 = no regression; 1 = regression vs baseline (or failures with no
baseline); 2 = environment not available (LLM/Neo4j/run) or invalid catalogue
— loud, never a silent 0-question pass (Constitution Art. III).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent
DEFAULT_CATALOG = HERE / "question_catalog.yaml"
DEFAULT_BASELINE = HERE / "baseline.json"
PER_QUESTION_TIMEOUT = 180  # seconds; a hung provider must not hang the gate

#: The complete assertion vocabulary. A key outside this set is a typo that
#: would otherwise pass forever (all({}) is True) — reject at load.
KNOWN_EXPECT_KEYS = frozenset({
    "routing_rule", "routing_absent", "tools_any", "tools_none",
    "answer_contains_all", "answer_contains_any",
})
KNOWN_QUESTION_KEYS = frozenset({"id", "question", "expect", "requires"})

#: ``requires`` feature → deterministic presence probe. Probes reuse the REAL
#: tools (no LLM, no hand-written Cypher to typo, no second source of truth):
#:   ("verdict", tool, args, key)  present iff ToolResult.verdict[key] > 0
#:   ("status",  tool, args)       present iff status not in no_data/not_found
#:   ("env",     var)              present iff the env var is set (config
#:                                 features like NetBox are deployment state,
#:                                 not run data — a tool probe is the wrong
#:                                 instrument and needs required args anyway)
#: Measured 2026-07-28: get_redundancy_assessment returns status=ok even with
#: zero FHRP groups (it assesses LAG/HA too), so the fhrp probe must read the
#: verdict counter, not the status (demo run: fhrp_groups=2; campus/branch: 0).
FEATURE_PROBES: dict[str, tuple] = {
    "fhrp": ("verdict", "get_redundancy_assessment", {}, "fhrp_groups"),
    "firewall": ("status", "get_firewall_policies", {}),
    "netbox": ("env", "NETBOX_URL"),
    # The drift pair needs the declared-state source (probed 2026-07-28: both
    # tools error with "set NETBOX_BOOTSTRAP_INVENTORY" when unconfigured).
    "declared_inventory": ("env", "NETBOX_BOOTSTRAP_INVENTORY"),
}


class CatalogError(ValueError):
    """The catalogue violates its own schema — fail loud at load."""


def _abort(msg: str) -> None:
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(2)


def _validate_catalog(catalog: object, tool_names: set[str]) -> list[dict]:
    """routing.yaml treatment for the catalogue: a bad entry fails LOUD."""
    if not isinstance(catalog, list) or not catalog:
        raise CatalogError("catalogue must be a non-empty list of questions")
    seen: set[str] = set()
    for q in catalog:
        if not isinstance(q, dict) or "id" not in q or "question" not in q:
            raise CatalogError(f"entry without id/question: {q!r:.80}")
        qid = q["id"]
        if qid in seen:
            raise CatalogError(f"duplicate id: {qid}")
        seen.add(qid)
        unknown = set(q) - KNOWN_QUESTION_KEYS
        if unknown:
            raise CatalogError(f"{qid}: unknown key(s) {sorted(unknown)}")
        expect = q.get("expect")
        if not expect or not isinstance(expect, dict):
            raise CatalogError(f"{qid}: empty or missing expect block — "
                               "an assertion-free question passes forever")
        bad = set(expect) - KNOWN_EXPECT_KEYS
        if bad:
            raise CatalogError(f"{qid}: unknown expect key(s) {sorted(bad)}")
        for key, want in (("routing_rule", str), ("routing_absent", bool),
                          ("tools_none", bool), ("tools_any", list),
                          ("answer_contains_all", list),
                          ("answer_contains_any", list)):
            if key in expect and not isinstance(expect[key], want):
                raise CatalogError(
                    f"{qid}: {key} must be {want.__name__}, "
                    f"got {type(expect[key]).__name__}")
        for name in expect.get("tools_any", []):
            if name not in tool_names:
                raise CatalogError(
                    f"{qid}: tools_any names unknown tool '{name}' — "
                    "stale after a rename?")
        for feat in q.get("requires", []) or []:
            if feat not in FEATURE_PROBES:
                raise CatalogError(
                    f"{qid}: unknown requires feature '{feat}' "
                    f"(known: {sorted(FEATURE_PROBES)})")
    return catalog


async def _ask(question: str, context: dict, provider) -> dict:
    """One question through the real loop → {routing, tools, answer, error}."""
    from netcopilot.orchestrator import run_tool_loop

    out = {"routing": None, "tools": [], "answer": "", "error": None}
    history = [{"role": "user", "content": question}]
    async for ev in run_tool_loop(history, context, provider=provider):
        if ev["type"] == "routing":
            out["routing"] = ev["data"]["rule"]
        elif ev["type"] == "tool_call":
            out["tools"].append(ev["data"]["name"])
        elif ev["type"] == "content":
            out["answer"] += ev["data"]
        elif ev["type"] == "error":
            out["error"] = ev["data"]
    return out


def _score(expect: dict, got: dict) -> dict:
    """Assertion → True/False; unasserted keys are absent from the result."""
    checks: dict[str, bool] = {}
    if got["error"]:
        # A failed run fails every declared assertion — never scored as pass.
        for key in ("routing_rule", "routing_absent", "tools_any", "tools_none",
                    "answer_contains_all", "answer_contains_any"):
            if key in expect:
                checks[key] = False
        return checks

    if "routing_rule" in expect:
        checks["routing_rule"] = got["routing"] == expect["routing_rule"]
    if expect.get("routing_absent"):
        checks["routing_absent"] = got["routing"] is None
    if "tools_any" in expect:
        checks["tools_any"] = any(t in got["tools"] for t in expect["tools_any"])
    if expect.get("tools_none"):
        # Security probes (injection / ghost-tool): the correct behavior is
        # refusing WITHOUT calling anything.
        checks["tools_none"] = got["tools"] == []
    answer_l = got["answer"].lower()
    if "answer_contains_all" in expect:
        checks["answer_contains_all"] = all(
            s.lower() in answer_l for s in expect["answer_contains_all"])
    if "answer_contains_any" in expect:
        checks["answer_contains_any"] = any(
            s.lower() in answer_l for s in expect["answer_contains_any"])
    return checks


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--capture", action="store_true",
                    help="write baseline.json from this run")
    ap.add_argument("--only", help="comma-separated question ids")
    ap.add_argument("--model", help="model registry id (default: registry default)")
    ap.add_argument("--run-id", help="pin a run (default: latest loaded)")
    ap.add_argument("--allow-run-mismatch", action="store_true",
                    help="diff against a baseline captured on a DIFFERENT run "
                         "(result is marked non-comparable)")
    args = ap.parse_args()

    # ── Preflight: every dependency loud, none silent (Art. III) ─────────────
    sys.path.insert(0, str(HERE.parent.parent / "src"))
    from netcopilot.context import build_context
    from netcopilot.graph.client import is_available
    from netcopilot.llm import get_provider

    if not is_available():
        _abort("Neo4j is not reachable — the eval needs the loaded graph.")
    context = build_context(run_id=args.run_id)
    if not context.get("run_id"):
        _abort("no loaded run found — collect/load a run first.")
    try:
        provider = get_provider(args.model)
    except Exception as exc:
        _abort(f"LLM provider not available: {exc}")

    from netcopilot.mcp import registry as tool_registry

    try:
        catalog = _validate_catalog(
            yaml.safe_load(args.catalog.read_text(encoding="utf-8")),
            {t["name"] for t in tool_registry.TOOL_SCHEMAS})
    except CatalogError as exc:
        _abort(f"invalid catalogue: {exc}")
    if args.only:
        wanted = set(args.only.split(","))
        catalog = [q for q in catalog if q["id"] in wanted]
    if not catalog:
        _abort("no questions selected.")

    # ── Preconditions: deterministic feature probes, one dispatch per feature ─
    import os

    def _probe(feat: str) -> bool:
        spec = FEATURE_PROBES[feat]
        if spec[0] == "env":
            return bool(os.environ.get(spec[1]))
        _, tool, tool_args, *rest = spec
        try:
            res = asyncio.run(tool_registry.dispatch(tool, tool_args, context))
        except Exception as exc:  # probe crash = environment problem, be loud
            _abort(f"feature probe '{feat}' ({tool}) crashed: {exc}")
        if res.status == "error":  # broken tool ≠ absent feature — never skip on it
            _abort(f"feature probe '{feat}' ({tool}) errored: {res.text[:200]}")
        if spec[0] == "verdict":
            return bool((res.verdict or {}).get(rest[0], 0))
        return res.status not in ("no_data", "not_found")

    feature_present: dict[str, bool] = {}
    for feat in sorted({f for q in catalog for f in q.get("requires", []) or []}):
        feature_present[feat] = _probe(feat)
        print(f"probe: {feat} → "
              f"{'present' if feature_present[feat] else 'ABSENT'}")

    print(f"eval: {len(catalog)} question(s) | run {context['run_id']} | "
          f"model {getattr(provider, 'model', provider.name)}\n")

    # ── Run ───────────────────────────────────────────────────────────────────
    # One event loop for ALL questions: providers hold aiohttp sessions whose
    # cleanup outlives a per-question asyncio.run (the "Event loop is closed"
    # noise measured on the first full run).
    skipped: dict[str, list[str]] = {}

    async def _run_all() -> dict[str, dict]:
        results: dict[str, dict] = {}
        for q in catalog:
            missing = [f for f in q.get("requires", []) or []
                       if not feature_present[f]]
            if missing:
                skipped[q["id"]] = missing
                print(f"  SKIP  {q['id']:24s} requires {missing} — absent on "
                      f"this run (never a FAIL)", flush=True)
                continue
            try:
                got = await asyncio.wait_for(
                    _ask(q["question"], context, provider), PER_QUESTION_TIMEOUT)
            except asyncio.TimeoutError:
                got = {"routing": None, "tools": [], "answer": "",
                       "error": f"timeout after {PER_QUESTION_TIMEOUT}s"}
            _record(results, q, got)
        return results

    def _record(results, q, got):
        if got["error"] and len(results) == 0:
            # First question already erroring ⇒ the provider is down, not the
            # question — abort instead of stamping 16 meaningless FAILs.
            _abort(f"first question errored ({got['error']}) — provider down?")

        checks = _score(q.get("expect", {}), got)
        passed = all(checks.values())
        results[q["id"]] = {"pass": passed, "checks": checks,
                            "tools": got["tools"], "routing": got["routing"],
                            "error": got["error"]}
        flag = "PASS" if passed else "FAIL"
        detail = ", ".join(f"{k}={'ok' if v else 'FAIL'}" for k, v in checks.items())
        extra = f"  [error: {got['error']}]" if got["error"] else ""
        print(f"  {flag}  {q['id']:24s} tools={got['tools']} {detail}{extra}", flush=True)

    results = asyncio.run(_run_all())

    total = len(results)
    passed_n = sum(1 for r in results.values() if r["pass"])
    # Skips reported separately, never folded into the pass count: "22 pass,
    # 0 fail, 3 skip" is honest; "22 pass" hiding three is not.
    print(f"\n{passed_n} pass, {total - passed_n} fail, {len(skipped)} skip"
          f"{'  (skipped: ' + ', '.join(sorted(skipped)) + ')' if skipped else ''}")

    # ── Baseline ──────────────────────────────────────────────────────────────
    if args.capture:
        payload = {"_meta": {"model": getattr(provider, "model", provider.name),
                             "run_id": context["run_id"],
                             "questions": total,
                             "skipped": sorted(skipped)}}
        payload.update({qid: {"pass": r["pass"], "checks": r["checks"]}
                        for qid, r in results.items()})
        args.baseline.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"baseline captured → {args.baseline}")
        return

    if not args.baseline.is_file():
        print("no baseline yet — run with --capture once results are stable "
              "(two agreeing runs).")
        sys.exit(0 if passed_n == total else 1)

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    meta = baseline.pop("_meta", {})
    if meta.get("model") and meta["model"] != getattr(provider, "model", provider.name):
        print(f"note: baseline model {meta['model']} != current "
              f"{getattr(provider, 'model', provider.name)} — diff is cross-model")
    if meta.get("run_id") and meta["run_id"] != context["run_id"]:
        # The catalogue asserts one network's facts; a cross-run diff compares
        # apples to oranges and reports phantom regressions. Written since s21,
        # read since s23 (it was write-only — the silent cross-network compare
        # the backlog flagged).
        if not args.allow_run_mismatch:
            _abort(f"baseline was captured on run '{meta['run_id']}' but the "
                   f"current run is '{context['run_id']}' — a cross-run diff "
                   "is not a regression signal. Re-capture on this run, or "
                   "pass --allow-run-mismatch to compare anyway (marked "
                   "non-comparable).")
        print(f"WARNING: cross-run diff ({meta['run_id']} → {context['run_id']}) "
              "— NON-COMPARABLE, informational only")
    # Regression scan covers only questions actually SCORED this run: a
    # skipped question (network change) or one filtered out by --only is not
    # evidence the agent regressed.
    regressions = [qid for qid, b in baseline.items()
                   if qid in results
                   and b["pass"] and not results[qid]["pass"]]
    improvements = [qid for qid, b in baseline.items()
                    if not b["pass"] and results.get(qid, {}).get("pass", False)]
    if improvements:
        print(f"improved vs baseline: {', '.join(improvements)} "
              "(re-capture to lock in)")
    if regressions:
        print(f"REGRESSION vs baseline: {', '.join(regressions)}")
        sys.exit(1)
    print("no regression vs baseline.")


if __name__ == "__main__":
    main()
