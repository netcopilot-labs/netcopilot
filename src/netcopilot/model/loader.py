"""
Data loader for network model building.

Handles all I/O for model building: loading manifest.json and every device's
facts/<name>/device_facts.json, validating required files exist. Separating I/O
from logic keeps the model builder testable and explicit about its data
dependencies.

Design Principle:
    Load everything upfront, then build the model — fail fast if data is missing.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_run_data(run_path: Path) -> dict[str, Any]:
    """
    Load all data needed for model building from a run directory.

    Loads:
    1. manifest.json — device connection info and run metadata.
    2. facts/<name>/device_facts.json — per-device parsed facts.

    Args:
        run_path: Path to the run directory (e.g., runs/2026-01-30_17-53-12).

    Returns:
        Dictionary with:
        - "manifest": The loaded manifest.
        - "facts": Dict mapping inventory_name → facts dict.

    Raises:
        FileNotFoundError: If the run directory or manifest doesn't exist.
        ValueError: If the manifest or a facts file is invalid JSON.

    Example:
        >>> run_data = load_run_data(Path("runs/2026-01-30_17-53-12"))
        >>> print(list(run_data["facts"].keys()))
        ['core-rtr-01', 'dist-sw-01', ...]
    """
    # Validate the run directory exists
    if not run_path.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_path}")

    # Load manifest.json
    manifest_path = run_path / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in manifest: {manifest_path} - {e}") from e

    # Load all facts files
    facts_dir = run_path / "facts"
    if not facts_dir.is_dir():
        raise FileNotFoundError(f"Facts directory not found: {facts_dir}")

    # Each subdirectory is named after an inventory_name and holds device_facts.json.
    facts_subdirs = sorted(
        [d for d in facts_dir.iterdir() if d.is_dir()],
        key=lambda d: d.name,
    )

    if not facts_subdirs:
        raise ValueError(f"No device subdirectories found in: {facts_dir}")

    # Build dictionary: inventory_name -> facts
    facts_by_hostname: dict[str, Any] = {}

    for device_dir in facts_subdirs:
        facts_file = device_dir / "device_facts.json"
        if not facts_file.is_file():
            logger.warning("No device_facts.json in %s/ — skipping", device_dir.name)
            continue

        try:
            facts_text = facts_file.read_text(encoding="utf-8")
            facts = json.loads(facts_text)

            # The directory name is the canonical key (= inventory_name); the
            # hostname inside the facts file is the real collected hostname.
            hostname = device_dir.name
            facts_by_hostname[hostname] = facts

        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid JSON in facts file: {facts_file} - {e}"
            ) from e

    if not facts_by_hostname:
        raise ValueError(f"No valid device_facts.json files found in: {facts_dir}")

    # Verify we loaded all expected devices (compare against inventory_name)
    expected_hostnames = {
        d.get("inventory_name") or d["hostname"]
        for d in manifest.get("devices", [])
    }
    loaded_hostnames = set(facts_by_hostname.keys())

    missing = expected_hostnames - loaded_hostnames
    if missing:
        # Warning, not an error — a partial model can still be built.
        logger.warning("Missing facts files for: %s", sorted(missing))

    extra = loaded_hostnames - expected_hostnames
    if extra:
        logger.warning("Extra facts files not in manifest: %s", sorted(extra))

    return {
        "manifest": manifest,
        "facts": facts_by_hostname,
    }
