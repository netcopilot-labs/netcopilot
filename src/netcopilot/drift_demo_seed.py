"""Load the synthetic drift demo pair (S01-7) into Neo4j + the runs dir.

Unlike :mod:`netcopilot.demo_seed` (which rebuilds model + findings from
committed genie facts), the drift pair is **model-only**: ``demo/drift-demo/
{before,after}/`` carry ``network_model.json`` + ``findings.json`` directly (no
facts). This stages both runs into ``RUNS_DIR`` under their timestamped run_ids
and loads each into Neo4j (site ``demo-drift``) so the dashboard's Audit ▸ Diff
can render the drift end-to-end.

    python -m netcopilot.drift_demo_seed

Reloading is safe — ``load_model`` is delete-first per (site, run_id).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

from netcopilot.graph.client import get_driver
from netcopilot.graph.loader import load_model

logging.basicConfig(level=logging.INFO, format="[drift-seed] %(message)s")
log = logging.getLogger("drift_demo_seed")

SITE = "demo-drift"
# /app/src/netcopilot/drift_demo_seed.py → parents[2] == repo root (/app in image).
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SRC = _REPO_ROOT / "demo" / "drift-demo"

#: (sub-dir under demo/drift-demo, run_id to load it as). The timestamped ids
#: sort chronologically, so the dashboard defaults the "before" as the previous
#: same-site run of the "after".
PAIR = [
    ("before", "2026-07-01_09-00-00"),
    ("after", "2026-07-01_10-00-00"),
]


def main() -> int:
    runs_dir = Path(os.environ.get("RUNS_DIR", "runs"))
    driver = get_driver()

    for sub, run_id in PAIR:
        src = DEMO_SRC / sub
        model_src = src / "model" / "network_model.json"
        findings_src = src / "findings" / "findings.json"
        if not model_src.is_file() or not findings_src.is_file():
            log.error("Drift demo missing at %s — image is out of date.", src)
            return 1

        dst = runs_dir / run_id
        (dst / "model").mkdir(parents=True, exist_ok=True)
        (dst / "findings").mkdir(parents=True, exist_ok=True)
        shutil.copy(model_src, dst / "model" / "network_model.json")
        shutil.copy(findings_src, dst / "findings" / "findings.json")

        counts = load_model(driver, dst, site=SITE, run_id=run_id)
        log.info("Loaded %s as %s (site %s): %s", sub, run_id, SITE, counts)

    log.info("Drift demo pair loaded — pick the '%s' runs in the dashboard, then ⇄ Diff.", SITE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
