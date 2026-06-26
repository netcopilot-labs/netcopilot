"""Pipeline orchestrator — collect → parse → model → rules → load.

Chains the five stages into one run:

1. **collect** — pull raw evidence off every device in an inventory and write a
   run manifest (``run_collection``).
2. **parse** — turn the raw evidence into canonical ``device_facts.json``
   (``build_facts``).
3. **model** — reconcile per-device facts into one ``network_model.json``
   (``build_model``).
4. **rules** — run the 3-phase rule engine and persist ``findings/findings.json``
   + ``summary.json`` (``run_rules`` → ``write_findings``).
5. **load** — materialise the model graph + findings in Neo4j (``load_model``).

:func:`process_run` runs stages 2-5 over an already-collected run (so it is
testable on a synthetic run directory with no live devices). :func:`run_pipeline`
adds the collect front-end. Both return a summary dict of per-stage counts.
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any, Callable

from netcopilot.collect import run_collection
from netcopilot.inventory import InventorySource
from netcopilot.model import build_model
from netcopilot.parse import build_facts
from netcopilot.rules.engine import run_rules
from netcopilot.rules.findings_writer import write_findings

log = logging.getLogger(__name__)


class PipelineError(RuntimeError):
    """A run cannot proceed — e.g. collection reached 0 devices (dropped tunnel /
    all unreachable). Raised instead of letting an empty run crash build_model;
    the offending run directory is discarded so the dashboard never adopts it."""


#: Model collections summarised in the returned counts.
_MODEL_KEYS = ("devices", "interfaces", "links", "adjacencies", "shared_services")


def process_run(
    run_id: str,
    *,
    site: str,
    runs_dir: str | Path = "runs",
    load: bool = True,
    driver: Any | None = None,
    progress: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Parse → model → rules → (optionally) load an already-collected run.

    Args:
        run_id: The collected run folder name (under ``runs_dir``).
        site: Site identifier for multi-site isolation in Neo4j.
        runs_dir: Base directory holding run folders.
        load: When ``True``, load the model into Neo4j; when ``False``, stop
            after writing ``network_model.json`` + ``findings.json`` (no Neo4j
            needed).
        driver: Optional Neo4j driver; defaults to the shared singleton when
            ``load`` is ``True``.
        progress: Optional ``(stage, message)`` callback invoked at each stage
            boundary, so a caller (e.g. the CLI behind the dashboard "Run Now"
            button) can stream live progress. ``None`` = no progress emitted.

    Returns:
        Summary dict: ``{"run_id", "facts", "model", "findings", ["load"]}``.
    """
    def _emit(stage: str, message: str) -> None:
        if progress is not None:
            progress(stage, message)

    facts = build_facts(run_id, runs_base=runs_dir)
    success = facts.get("success_count", 0)
    log.info("Pipeline: parsed %d device(s) for run %s", success, run_id)
    _emit("parse_complete", f"Parsed {success} device(s)")

    # No device produced facts (all unreachable — e.g. a dropped tunnel/VPN).
    # Discard the empty run so the dashboard never adopts a half-run, and fail
    # with a clear message instead of crashing inside build_model/load_run_data.
    if success == 0:
        _emit("error", "Collection reached 0 devices — run discarded (check device reachability)")
        shutil.rmtree(Path(runs_dir) / run_id, ignore_errors=True)
        raise PipelineError(
            f"collection reached 0 devices for run {run_id} — run discarded "
            f"(check device reachability / tunnel)"
        )

    model = build_model(run_id, runs_base=runs_dir)
    model_counts = {k: len(model.get(k, [])) for k in _MODEL_KEYS}
    log.info("Pipeline: modelled run %s — %s", run_id, model_counts)
    _emit("model_complete",
          f"Model: {model_counts['devices']} devices, {model_counts['links']} links")

    # Rules: persist findings.json BEFORE load — load_model reads it to
    # materialise Finding nodes. A plain run with no rules pass yields an empty
    # FindingsPage and breaks delta analysis.
    rules_result = run_rules(str(run_id), runs_base=str(runs_dir))
    write_findings(rules_result, run_id, runs_base=str(runs_dir))
    finding_count = rules_result.get("metadata", {}).get("total_findings", 0)
    log.info("Pipeline: rules run %s — %d finding(s)", run_id, finding_count)
    _emit("rules_complete", f"Rules: {finding_count} findings")

    result: dict[str, Any] = {
        "run_id": run_id,
        "facts": facts,
        "model": model_counts,
        "findings": finding_count,
    }

    if load:
        # Imported lazily so the parse+model path needs no Neo4j driver/deps.
        from netcopilot.graph.client import get_driver
        from netcopilot.graph.loader import load_model

        driver = driver or get_driver()
        load_counts = load_model(driver, Path(runs_dir) / run_id, site=site, run_id=run_id)
        log.info("Pipeline: loaded run %s into Neo4j (site %s)", run_id, site)
        _emit("load_complete", f"Loaded into Neo4j (site {site})")
        result["load"] = load_counts

    return result


def run_pipeline(
    source: InventorySource,
    *,
    site: str,
    runs_dir: str | Path = "runs",
    load: bool = True,
    driver: Any | None = None,
    progress: Callable[[str, str], None] | None = None,
    **collect_kwargs: Any,
) -> dict[str, Any]:
    """Full pipeline: collect from ``source``, then parse → model → rules → load.

    Extra keyword args (``dry_run``, ``parallel``, ``max_workers``, ``chain``,
    ``run_prefix``) are forwarded to :func:`run_collection`. A dry run collects
    nothing and returns ``{"run_id": "", "dry_run": True}``.

    ``progress`` is an optional ``(stage, message)`` callback forwarded to
    :func:`process_run` (and fired once after collection) for live status.
    """
    run_id = run_collection(source, runs_dir=runs_dir, **collect_kwargs)
    if not run_id:  # dry run — nothing collected
        return {"run_id": "", "dry_run": True}
    if progress is not None:
        progress("collect_complete", "Collection complete")
    return process_run(
        run_id, site=site, runs_dir=runs_dir, load=load, driver=driver, progress=progress
    )
