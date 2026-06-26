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


def _cmd_run(args: argparse.Namespace) -> None:
    from .inventory import YAMLInventory
    from .pipeline import PipelineError, run_pipeline

    source = YAMLInventory(args.inventory)
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

    diagram_p = sub.add_parser("diagram", help="render a Graphviz topology diagram (SVG/PNG) for a run")
    diagram_p.add_argument("run_id", help="run identifier (directory under the runs dir)")
    diagram_p.add_argument("--runs-dir", default=None, help="base directory for run folders (overrides RUNS_DIR)")
    diagram_p.set_defaults(func=_cmd_diagram)

    args = parser.parse_args(sys.argv[1:])
    args.func(args)


if __name__ == "__main__":
    main()
