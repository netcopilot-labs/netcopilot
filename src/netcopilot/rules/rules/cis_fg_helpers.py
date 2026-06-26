"""
FortiGate CIS Rule Helpers — shared utilities for CIS FortiGate deep rules.

Architecture:
    FortiGate devices may not appear in network_model.json (model_builder
    targets Cisco devices). These helpers provide FortiGate device discovery
    by scanning the facts/ directory for fortigate_*.json files.

Design Principles:
    - Facts-directory scanning: find FortiGate devices regardless of model
    - Single JSON load per source per device: callers load once, check many fields
    - Graceful degradation: missing files return None, empty arrays return []
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import json
import logging
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# FortiGate device discovery
# -------------------------------------------------------------------------

def find_fortigate_devices(run_path: str | Path) -> list[tuple[str, Path]]:
    """
    Scan the facts/ directory for devices that have FortiGate facts files.

    FortiGate devices are identified by the presence of any
    ``fortigate_*.json`` file in their facts directory.

    Args:
        run_path: Path to the pipeline run directory.

    Returns:
        List of (hostname, device_facts_dir) tuples for each FortiGate
        device found. Sorted by hostname for deterministic ordering.
    """
    facts_dir = Path(run_path) / "facts"
    if not facts_dir.is_dir():
        return []

    devices: list[tuple[str, Path]] = []
    for device_dir in sorted(facts_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        # Check for at least one fortigate_*.json file
        fg_files = list(device_dir.glob("fortigate_*.json"))
        if fg_files:
            devices.append((device_dir.name, device_dir))

    return devices


def load_fg_json(device_dir: Path, source_name: str) -> Any | None:
    """
    Load a FortiGate JSON facts file and return the ``results`` payload.

    All FortiGate REST API responses wrap data in a ``results`` key.
    This helper unwraps that automatically so callers get the actual data.

    Args:
        device_dir: Path to the device's facts directory.
        source_name: File stem without .json (e.g., "fortigate_firewall_policy").

    Returns:
        The ``results`` value (dict or list), or None if file is missing
        or unparseable.
    """
    path = device_dir / f"{source_name}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("results")
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load {path}: {e}")
        return None
