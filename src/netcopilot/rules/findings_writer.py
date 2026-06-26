"""
Findings Writer - Save rule engine results to JSON files.

This module handles writing the rule engine output to persistent
JSON files for later analysis, reporting, and audit trails.

Architecture:
    run_rules() result
           │
           ▼
    write_findings()
           │
           ├──► findings/findings.json  (full details)
           │
           └──► findings/summary.json   (quick stats)

Output Files:
    runs/<run-id>/findings/
    ├── findings.json    Complete findings with evidence
    └── summary.json     Aggregated statistics

File Formats:
    - Pretty-printed JSON (indent=2) for human readability
    - UTF-8 encoding for international character support

Design Principles:
    - Atomic writes: Write to temp file, then rename (prevents corruption)
    - Idempotent: Running twice produces same files
    - Complete: All data from run_rules() is preserved

Example Usage:
    >>> from netcopilot.rules.engine import run_rules
    >>> from netcopilot.rules.findings_writer import write_findings
    >>>
    >>> result = run_rules("2026-01-15_12-00-00")
    >>> paths = write_findings(result, "2026-01-15_12-00-00")
    >>> print(paths["findings"])
    runs/2026-01-15_12-00-00/findings/findings.json
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import json
import logging
import os
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)


def write_findings(
    result: dict[str, Any],
    run_id: str,
    runs_base: str = "runs",
) -> dict[str, Path]:
    """
    Write rule engine results to JSON files.

    Creates two files in the findings directory:
    1. findings.json - Complete findings with metadata and evidence
    2. summary.json - Aggregated statistics for quick overview

    The function creates the findings/ directory if it doesn't exist.

    Args:
        result: The result dictionary from run_rules()
        run_id: The run identifier (e.g., "2026-01-15_12-00-00")
        runs_base: Base directory for runs (default: "runs")

    Returns:
        Dictionary with paths to created files:
        {
            "findings": Path to findings.json,
            "summary": Path to summary.json,
            "directory": Path to findings directory
        }

    Raises:
        ValueError: If result is missing required keys
        OSError: If file writing fails

    Example:
        >>> result = run_rules("2026-01-15_12-00-00")
        >>> paths = write_findings(result, "2026-01-15_12-00-00")
        >>> print(f"Findings saved to: {paths['findings']}")
    """
    # -------------------------------------------------------------------------
    # Validate result structure
    # -------------------------------------------------------------------------
    required_keys = {"metadata", "findings", "summary"}
    missing_keys = required_keys - set(result.keys())

    if missing_keys:
        raise ValueError(
            f"Result missing required keys: {sorted(missing_keys)}. "
            f"Expected keys from run_rules(): {sorted(required_keys)}"
        )

    # -------------------------------------------------------------------------
    # Create findings directory
    # -------------------------------------------------------------------------
    # mkdir(parents=True, exist_ok=True) creates all parent directories
    # and doesn't error if the directory already exists
    findings_dir = Path(runs_base) / run_id / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    logger.debug(f"Writing findings to: {findings_dir}")

    # -------------------------------------------------------------------------
    # Write findings.json (complete details)
    # -------------------------------------------------------------------------
    # This file contains the full result from run_rules()
    findings_path = findings_dir / "findings.json"
    _write_json(findings_path, {
        "metadata": result["metadata"],
        "findings": result["findings"],
    })

    logger.info(f"Wrote {len(result['findings'])} findings to {findings_path}")

    # -------------------------------------------------------------------------
    # Write summary.json (aggregated stats)
    # -------------------------------------------------------------------------
    # This file contains just the summary statistics for quick overview
    summary_path = findings_dir / "summary.json"
    summary_data = {
        "run_id": result["metadata"]["run_id"],
        "generated_at": result["metadata"]["generated_at"],
        "total_findings": result["metadata"]["total_findings"],
        "by_severity": result["summary"]["by_severity"],
        "by_rule": result["summary"]["by_rule"],
    }
    _write_json(summary_path, summary_data)

    logger.info(f"Wrote summary to {summary_path}")

    # -------------------------------------------------------------------------
    # Return paths to created files
    # -------------------------------------------------------------------------
    return {
        "findings": findings_path,
        "summary": summary_path,
        "directory": findings_dir,
    }


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """
    Write data to a JSON file with pretty formatting + atomic semantics.

    Uses UTF-8 encoding and 2-space indentation for human readability.
    The file is written atomically — content is serialised to a sibling
    `<name>.tmp`, then `os.replace()` swaps it onto the final path. If
    the process crashes mid-write, either the previous file remains
    untouched OR the new file is fully written; readers never observe
    a half-written file.

    `os.replace()` is the cross-platform atomic rename primitive in
    Python's stdlib; on POSIX it's `rename(2)`, on Windows it overrides
    an existing target.

    Args:
        path: Path to write to
        data: Dictionary to serialize as JSON
    """
    # -------------------------------------------------------------------------
    # Serialize to JSON string
    # -------------------------------------------------------------------------
    # indent=2 makes it human-readable
    # ensure_ascii=False allows non-ASCII characters (hostnames, etc.)
    json_content = json.dumps(data, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # Atomic write: write to <name>.tmp, then os.replace() onto final path
    # -------------------------------------------------------------------------
    # The .tmp suffix is sibling-scoped (same directory) so os.replace
    # is on the same filesystem — guarantees atomicity per POSIX rename(2).
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json_content, encoding="utf-8")
    os.replace(tmp_path, path)
