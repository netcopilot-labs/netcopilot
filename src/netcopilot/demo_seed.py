"""Demo replay — load the bundled synthetic demo network into Neo4j.

The synthetic ``demo/campus`` run (an 8-device containerlab capture) ships its
parsed ``facts/`` + ``manifest.json`` (the generated ``model/`` + ``findings/``
are gitignored). This rebuilds model + findings from the committed facts and
loads them — no devices, no pyATS — while emitting the same pipeline progress
events a real collection does, so the dashboard "Run Now" shows a live-looking
run (the installation-video demo).

The watcher invokes this when the demo inventory is the Run-Now target
(``.trigger/run_config.json`` mode=demo). Reloading is safe — the loader is
delete-first, so clicking Run Now again just refreshes the demo.

    python -m netcopilot.demo_seed
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
from pathlib import Path

from netcopilot.cli import _progress_writer
from netcopilot.graph.client import get_driver
from netcopilot.graph.loader import load_model
from netcopilot.model import build_model
from netcopilot.rules.engine import run_rules
from netcopilot.rules.findings_writer import write_findings

logging.basicConfig(level=logging.INFO, format="[demo-seed] %(message)s")
log = logging.getLogger("demo_seed")

# Which bundled demo lab to replay — set by the watcher from the picker
# selection. Each demo/<name>/ is its own site; defaults to the campus lab.
RUN_ID = os.environ.get("NETCOPILOT_DEMO_RUN", "campus")
SITE = os.environ.get("NETCOPILOT_DEMO_SITE") or RUN_ID
# /app/src/netcopilot/demo_seed.py → parents[2] == /app (repo root in the image).
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SRC = _REPO_ROOT / "demo" / RUN_ID


def main() -> int:
    runs_dir = os.environ.get("RUNS_DIR", "runs")
    # When launched by the watcher, NETCOPILOT_PROGRESS_FILE is set and these
    # events stream to the dashboard SSE; otherwise emit() is a no-op.
    emit = _progress_writer() or (lambda *_: None)

    if not (DEMO_SRC / "facts").is_dir():
        log.error("Demo facts not found at %s — image is missing demo/%s.", DEMO_SRC, RUN_ID)
        emit("error", f"Demo data missing at {DEMO_SRC}")
        return 1

    device_count = 0
    manifest = DEMO_SRC / "manifest.json"
    if manifest.is_file():
        device_count = json.loads(manifest.read_text()).get("device_count", 0)

    # Stage the committed demo run into the shared runs volume so the pipeline
    # (which reads runs_dir/<run_id>/facts) can rebuild from it.
    dst = Path(runs_dir) / RUN_ID
    log.info("Staging demo capture into %s", dst)
    shutil.copytree(DEMO_SRC, dst, dirs_exist_ok=True)
    emit("collect_complete", f"Demo capture — {device_count} device(s)")

    # The demo ships pre-built facts/ (device_facts.json + genie_*.json), NOT
    # raw/, so skip parse (build_facts parses raw/ → 0 devices) and rebuild
    # model → findings → load directly from the committed facts.
    emit("parse_complete", f"Parsed {device_count} device(s)")
    model = build_model(RUN_ID, runs_base=runs_dir)
    devices = len(model.get("devices", []))
    links = len(model.get("links", []))
    emit("model_complete", f"Model: {devices} devices, {links} links")

    rules_result = run_rules(str(RUN_ID), runs_base=str(runs_dir))
    write_findings(rules_result, RUN_ID, runs_base=str(runs_dir))
    findings = rules_result.get("metadata", {}).get("total_findings", 0)
    emit("rules_complete", f"Rules: {findings} findings")

    load_model(get_driver(), Path(runs_dir) / RUN_ID, site=SITE, run_id=RUN_ID)
    emit("load_complete", f"Loaded into Neo4j (site {SITE})")

    log.info("Loaded demo %s/%s: %d device(s), %d link(s), %d finding(s).",
             SITE, RUN_ID, devices, links, findings)
    emit("done", f"Demo loaded — {findings} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
