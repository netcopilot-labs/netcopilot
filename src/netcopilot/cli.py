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

    args = parser.parse_args(sys.argv[1:])
    args.func(args)


if __name__ == "__main__":
    main()
