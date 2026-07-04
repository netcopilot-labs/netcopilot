"""NetCopilot CLI — run the pipeline, or ask the network a question.

    netcopilot run --inventory inventory.yaml --site dc
    netcopilot ask "how many devices are there?"

``run`` collects from an inventory and loads the result into Neo4j (collect →
parse → model → load). ``ask`` queries a loaded run via the LLM (selected by
NETCOPILOT_LLM = claude | ollama). Both need Neo4j up; ``ask`` also needs a
configured LLM provider.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path


def _progress_writer():
    """Return an ``(stage, message)`` callback appending JSON lines to the file
    named by ``NETCOPILOT_PROGRESS_FILE``, or ``None`` when the env var is unset.

    The dashboard "Run Now" watcher sets this to ``runs/.trigger/.progress.jsonl``
    so the SSE progress stream populates live; a manual ``netcopilot run`` leaves
    it unset and writes no progress file.
    """
    path = os.environ.get("NETCOPILOT_PROGRESS_FILE")
    if not path:
        return None

    import json
    from datetime import datetime, timezone
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    def _emit(stage: str, message: str) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "message": message,
        }
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    return _emit


def _cmd_ask(args: argparse.Namespace) -> None:
    from .context import build_context
    from .orchestrator import answer

    question = " ".join(args.question).strip()
    if not question:
        print('usage: netcopilot ask "<question>"')
        raise SystemExit(2)
    print(asyncio.run(answer(question, context=build_context())))


def _load_env_file(path: Path) -> int:
    """Load ``KEY=VALUE`` lines from a credentials.env into ``os.environ``.

    Used for folder-style inventories (``inventory/<tenant>/credentials.env``):
    a self-contained tenant carries its own SSH creds + FortiGate token. Values
    here take precedence over the process env for this run only (each ``run`` is
    a fresh subprocess), so two tenants never share credentials. Quotes are
    stripped; comments and blank lines ignored.
    """
    loaded = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            os.environ[key] = value.strip().strip('"').strip("'")
            loaded += 1
    return loaded


def _resolve_inventory_path(inventory: str) -> str:
    """Resolve a --inventory argument to the lab.yaml to load.

    A folder (``inventory/<tenant>/``) is a self-contained tenant: load its
    ``credentials.env`` (if present) into the environment, then use its
    ``lab.yaml``. A plain file is used as-is (credentials come from the global
    environment / root .env).
    """
    p = Path(inventory)
    if p.is_dir():
        creds = p / "credentials.env"
        if creds.is_file():
            n = _load_env_file(creds)
            logging.getLogger(__name__).info("Loaded %d credential(s) from %s", n, creds)
        lab = p / "lab.yaml"
        if not lab.is_file():
            print(f"inventory folder has no lab.yaml: {p}", file=sys.stderr)
            raise SystemExit(2)
        return str(lab)
    return inventory


def _cmd_run(args: argparse.Namespace) -> None:
    from .inventory import YAMLInventory
    from .pipeline import PipelineError, run_pipeline

    source = YAMLInventory(_resolve_inventory_path(args.inventory))
    progress = _progress_writer()
    try:
        result = run_pipeline(
            source,
            site=args.site,
            runs_dir=args.runs_dir,
            load=not args.no_load,
            dry_run=args.dry_run,
            parallel=not args.sequential,
            progress=progress,
        )
    except PipelineError as exc:
        # Clean abort (e.g. 0 devices reachable) — the run is already discarded
        # and an "error" progress event emitted. Report and exit non-zero so the
        # watcher marks the run failed, without a raw traceback.
        print(f"run aborted: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if result.get("dry_run"):
        return  # run_collection already printed the dry-run plan
    print(f"run_id: {result['run_id']}")
    print(f"  parsed:   {result['facts'].get('success_count', 0)} device(s)")
    print(f"  modelled: {result['model']}")
    print(f"  findings: {result.get('findings', 0)}")
    if "load" in result:
        print(f"  loaded:   {result['load']}")
    # Terminal event closes the dashboard SSE progress stream cleanly.
    if progress is not None:
        progress("done", f"Run complete — {result.get('findings', 0)} findings")


def _cmd_diagram(args: argparse.Namespace) -> None:
    import os

    from .diagram import build_diagram

    if args.runs_dir:
        os.environ["RUNS_DIR"] = args.runs_dir
    result = build_diagram(args.run_id)
    print(f"diagram for run: {args.run_id}")
    print(f"  success:  {result['success']}")
    print(f"  devices:  {result['device_count']}  links: {result['link_count']}  findings: {result['finding_count']}")
    print(f"  dot:      {result['dot_file']}")
    print(f"  svg:      {result['svg_file']}")
    print(f"  png:      {result['png_file']}")
    for w in result.get("warnings", []):
        print(f"  warning:  {w}")


def _short(value: object, width: int = 60) -> str:
    """Compact one-line repr of a field value for the diff printout."""
    text = repr(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _print_diff(result) -> None:
    """Human-readable tiered printout of a DiffResult."""
    from collections import defaultdict

    d = result.to_dict()
    s = d["summary"]
    print(f"diff {d['run_a']} → {d['run_b']}  (site: {d['site']})")
    print(f"  added: {s['added']}   removed: {s['removed']}   changed: {s['changed']}   info: {s['info']}")

    by_tier: dict[str, list] = defaultdict(list)
    for c in d["changes"]:
        by_tier[c["tier"]].append(c)

    for tier in ("removed", "added", "changed", "info"):
        items = by_tier.get(tier, [])
        if not items:
            continue
        print(f"\n{tier.upper()} ({len(items)})")
        for c in items:
            print(f"  [{c['entity_type']}] {c['key']}")
            for f in c.get("changed_fields", []):
                print(f"      {f['field']}: {_short(f['before'])} → {_short(f['after'])}")


def _cmd_diff(args: argparse.Namespace) -> None:
    from .diff.engine import compute_diff, load_run, previous_run

    runs_dir = args.runs_dir
    before, after = args.run_a, args.run_b
    try:
        if after is None:
            # One run given → treat it as the "after" and default the "before"
            # to the previous same-site run.
            after = before
            before = previous_run(after, runs_dir)
            if before is None:
                print(
                    f"no previous same-site run found for '{after}' — "
                    f"specify two: netcopilot diff <before> <after>",
                    file=sys.stderr,
                )
                raise SystemExit(2)
        result = compute_diff(load_run(before, runs_dir), load_run(after, runs_dir))
    except FileNotFoundError as exc:
        print(f"diff failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        print(f"diff failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    _print_diff(result)


def _cmd_validate(args: argparse.Namespace) -> None:
    """Judge a change between two runs; exit code mirrors the verdict.

    Exit 0 = pass, 1 = warn, 2 = fail (also 2 on unusable inputs) — usable as
    a pipeline gate: `netcopilot validate --after <run> --scope <dev> || stop`.
    """
    from .diff.engine import compute_diff, load_run, previous_run
    from .diff.verdict import evaluate_change

    runs_dir = args.runs_dir
    try:
        after = load_run(args.after, runs_dir)
        before_id = args.before or previous_run(args.after, runs_dir)
        if before_id is None:
            print(
                f"validate failed: no previous same-site run found for "
                f"'{args.after}' — specify --before",
                file=sys.stderr,
            )
            raise SystemExit(2)
        before = load_run(before_id, runs_dir)
        diff = compute_diff(before, after)
    except FileNotFoundError as exc:
        print(f"validate failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except ValueError as exc:  # cross-site, duplicate key, malformed run
        print(f"validate failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

    scope = frozenset(s.strip() for s in args.scope.split(",") if s.strip()) if args.scope else None
    verdict = evaluate_change(diff, before, after, scope)

    print(f"validate {before.run_id} → {after.run_id}  (site: {after.site})")
    print(f"  scope: {', '.join(sorted(scope)) if scope else '(none — threshold-only verdict)'}")
    print(f"  verdict: {verdict.result.upper()}")
    for r in verdict.reasons:
        print(f"    • {r['detail']}")
    c = verdict.counts
    print(f"  drift: {c['drift_total']}  new findings: {sum(c['new_findings'].values())}  "
          f"resolved: {c['resolved_findings']}  info: {c['info']}")
    raise SystemExit({"pass": 0, "warn": 1, "fail": 2}[verdict.result])


def _cmd_neo4j(args: argparse.Namespace) -> None:
    from .graph.client import get_driver
    from .graph.loader import delete_run, list_runs

    driver = get_driver()
    if args.neo4j_command == "runs":
        runs = list_runs(driver)
        if not runs:
            print("No runs loaded.")
            return
        for r in runs:
            print(f"  {r['site']:<14} {r['run_id']:<26} "
                  f"{r['devices']:>3} devices  {r['findings']:>4} findings")
    elif args.neo4j_command == "delete":
        n = delete_run(driver, args.run_id, site=args.site)
        if n > 0:
            print(f"Deleted run {args.run_id} ({n} nodes removed)")
        else:
            print(f"Run {args.run_id} not found in Neo4j", file=sys.stderr)
            raise SystemExit(1)


def _cmd_netbox(args: argparse.Namespace) -> None:
    """NetBox declared-state workflow: bootstrap → pending → approve/reject → history.

    Writes are gated by NETBOX_WRITE_ENABLED (Constitution Art. I) — approve
    fails with a clear message unless the deployment opted in.
    """
    from .declared_state import staging

    if args.netbox_command == "bootstrap":
        from .declared_state import bootstrap
        result = bootstrap.run(args.run_id, inventory_path=args.inventory)
        print(result.format_summary())
        for w in result.warnings:
            print(f"  warning: {w}", file=sys.stderr)

    elif args.netbox_command == "pending":
        rows = staging.list_pending(source=args.source, object_type=args.object_type)
        if not rows:
            print("No pending NetBox writes.")
            return
        for r in rows:
            payload = r.get("payload") or {}
            name = payload.get("name") or payload.get("slug") or payload.get("dedup_key") or ""
            print(f"  [{r.get('priority', '?'):>3}] {r.get('netbox_object_type', '?'):<16} "
                  f"{name:<32} source={r.get('source', '?')} id={r.get('id', '?')}")
        print(f"{len(rows)} candidate(s) pending.")

    elif args.netbox_command == "approve":
        if args.all:
            summary = staging.approve_bulk(source=args.source, object_type=args.object_type)
            print(f"written: {summary['written']}  auto-resolved: {summary['auto_resolved']}  "
                  f"failed: {summary['failed']}  ({summary['duration_ms']} ms)")
            if summary["aborted"]:
                print(f"ABORTED: {summary['abort_reason']}", file=sys.stderr)
                raise SystemExit(2)
            raise SystemExit(1 if summary["failed"] else 0)
        result = staging.approve(args.candidate_id)
        if result is None:
            print(f"Candidate {args.candidate_id} is no longer pending.", file=sys.stderr)
            raise SystemExit(1)
        print(f"{result['outcome']}: HTTP {result['api_response_status']} "
              f"netbox_id={result['netbox_object_id']} audit={result['audit_id']}")
        raise SystemExit(0 if result["outcome"] in ("success", "auto_resolved") else 1)

    elif args.netbox_command == "reject":
        if args.all:
            summary = staging.reject_bulk(source=args.source, object_type=args.object_type)
            print(f"rejected: {summary['rejected']}  not found: {summary['not_found']}")
            return
        ok = staging.reject(args.candidate_id)
        if not ok:
            print(f"Candidate {args.candidate_id} not found.", file=sys.stderr)
            raise SystemExit(1)
        print(f"Rejected {args.candidate_id} (audit row written).")

    elif args.netbox_command == "history":
        from .graph.client import get_driver
        with get_driver().session() as session:
            rows = [dict(rec["w"]) for rec in session.run(
                "MATCH (w:NetBoxWrite) RETURN w ORDER BY w.timestamp DESC LIMIT $n",
                n=args.limit,
            )]
        if not rows:
            print("No NetBox writes recorded.")
            return
        for w in rows:
            status = w.get("api_response_status")
            outcome = ("REJECTED" if w.get("source") == "manual_reject"
                       else f"OK {status}" if status and 200 <= status < 300
                       else f"FAILED {status}")
            print(f"  {w.get('timestamp', '?')[:19]}  {outcome:<10} "
                  f"{w.get('netbox_object_type', '?'):<16} {w.get('dedup_key', '')}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="netcopilot", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    ask_p = sub.add_parser("ask", help="ask a loaded run a question via the LLM")
    ask_p.add_argument("question", nargs="+", help="the question (quote it)")
    ask_p.set_defaults(func=_cmd_ask)

    run_p = sub.add_parser("run", help="collect → parse → model → load a network")
    run_p.add_argument("--inventory", required=True, help="path to an inventory YAML")
    run_p.add_argument("--site", required=True, help="site identifier (multi-site isolation)")
    run_p.add_argument("--runs-dir", default="runs", help="base directory for run folders")
    run_p.add_argument("--no-load", action="store_true", help="stop after network_model.json (skip Neo4j)")
    run_p.add_argument("--dry-run", action="store_true", help="print the collection plan, collect nothing")
    run_p.add_argument("--sequential", action="store_true", help="collect devices one at a time")
    run_p.set_defaults(func=_cmd_run)

    diff_p = sub.add_parser("diff", help="diff two runs of a site (drift): added/removed/changed + info")
    diff_p.add_argument("run_a", help="the 'before' run (or, if run_b omitted, the run to compare)")
    diff_p.add_argument("run_b", nargs="?", default=None,
                        help="the 'after' run; if omitted, defaults to the previous same-site run of run_a")
    diff_p.add_argument("--runs-dir", default="runs", help="base directory for run folders")
    diff_p.set_defaults(func=_cmd_diff)

    val_p = sub.add_parser(
        "validate",
        help="judge a change between two runs: pass/warn/fail verdict (exit 0/1/2 — pipeline gate)",
    )
    val_p.add_argument("--after", required=True, help="the post-change run")
    val_p.add_argument("--before", default=None,
                       help="the pre-change run (default: previous same-site run of --after)")
    val_p.add_argument("--scope", default=None,
                       help="comma-separated devices that were SUPPOSED to change; "
                            "drift outside this scope fails the verdict")
    val_p.add_argument("--runs-dir", default="runs", help="base directory for run folders")
    val_p.set_defaults(func=_cmd_validate)

    diagram_p = sub.add_parser("diagram", help="render a Graphviz topology diagram (SVG/PNG) for a run")
    diagram_p.add_argument("run_id", help="run identifier (directory under the runs dir)")
    diagram_p.add_argument("--runs-dir", default=None, help="base directory for run folders (overrides RUNS_DIR)")
    diagram_p.set_defaults(func=_cmd_diagram)

    neo4j_p = sub.add_parser("neo4j", help="manage loaded runs in Neo4j (list / delete)")
    neo4j_sub = neo4j_p.add_subparsers(dest="neo4j_command", required=True)
    neo4j_sub.add_parser("runs", help="list loaded runs")
    del_p = neo4j_sub.add_parser("delete", help="delete a run and all its graph data")
    del_p.add_argument("run_id", help="run identifier to delete")
    del_p.add_argument("--site", default=None, help="restrict deletion to this site")
    neo4j_p.set_defaults(func=_cmd_neo4j)

    nb_p = sub.add_parser("netbox", help="NetBox declared-state workflow (bootstrap / pending / approve / reject / history)")
    nb_sub = nb_p.add_subparsers(dest="netbox_command", required=True)
    nb_boot = nb_sub.add_parser("bootstrap", help="stage NetBox candidates from an inventory + collected run")
    nb_boot.add_argument("run_id", help="run identifier (directory under RUNS_DIR)")
    nb_boot.add_argument("--inventory", required=True, help="path to the inventory YAML the run came from")
    nb_pend = nb_sub.add_parser("pending", help="list staged candidates awaiting approval")
    nb_pend.add_argument("--source", default=None)
    nb_pend.add_argument("--object-type", dest="object_type", default=None)
    nb_appr = nb_sub.add_parser("approve", help="approve staged candidate(s) — writes to NetBox (requires NETBOX_WRITE_ENABLED=true)")
    nb_appr.add_argument("candidate_id", nargs="?", default=None, help="one candidate id (omit with --all)")
    nb_appr.add_argument("--all", action="store_true", help="approve all pending (topological order)")
    nb_appr.add_argument("--source", default=None)
    nb_appr.add_argument("--object-type", dest="object_type", default=None)
    nb_rej = nb_sub.add_parser("reject", help="reject staged candidate(s) — audit row, no NetBox call")
    nb_rej.add_argument("candidate_id", nargs="?", default=None)
    nb_rej.add_argument("--all", action="store_true")
    nb_rej.add_argument("--source", default=None)
    nb_rej.add_argument("--object-type", dest="object_type", default=None)
    nb_hist = nb_sub.add_parser("history", help="show the NetBox write audit log (newest first)")
    nb_hist.add_argument("--limit", type=int, default=20)
    nb_p.set_defaults(func=_cmd_netbox)

    args = parser.parse_args(sys.argv[1:])
    args.func(args)


if __name__ == "__main__":
    main()
