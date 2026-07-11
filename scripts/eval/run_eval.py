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

Baseline discipline: capture only results you have seen twice (LLM
nondeterminism) — run without --capture first; if two runs agree, capture.

Exit codes: 0 = no regression; 1 = regression vs baseline (or failures with no
baseline); 2 = environment not available (LLM/Neo4j/run) — loud, never a
silent 0-question pass (Constitution Art. III).
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


def _abort(msg: str) -> None:
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(2)


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

    catalog = yaml.safe_load(args.catalog.read_text(encoding="utf-8"))
    if args.only:
        wanted = set(args.only.split(","))
        catalog = [q for q in catalog if q["id"] in wanted]
    if not catalog:
        _abort("no questions selected.")

    print(f"eval: {len(catalog)} question(s) | run {context['run_id']} | "
          f"model {getattr(provider, 'model', provider.name)}\n")

    # ── Run ───────────────────────────────────────────────────────────────────
    # One event loop for ALL questions: providers hold aiohttp sessions whose
    # cleanup outlives a per-question asyncio.run (the "Event loop is closed"
    # noise measured on the first full run).
    async def _run_all() -> dict[str, dict]:
        results: dict[str, dict] = {}
        for q in catalog:
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
    print(f"\n{passed_n}/{total} passed")

    # ── Baseline ──────────────────────────────────────────────────────────────
    if args.capture:
        payload = {"_meta": {"model": getattr(provider, "model", provider.name),
                             "run_id": context["run_id"],
                             "questions": total}}
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
    regressions = [qid for qid, b in baseline.items()
                   if b["pass"] and not results.get(qid, {}).get("pass", False)]
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
