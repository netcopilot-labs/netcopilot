"""
Rule Engine - Main orchestration for running rules against network model.

This module is the heart of the rule engine. It coordinates three phases:

Phase 1 (Python rules): Model-based rules + deep CIS/protocol rules that
    use BaseRule subclasses in src/rules/rules/. These evaluate against the
    network model and/or load facts files directly.

Phase 2 (YAML surface rules): ~81 rules defined as eval specs in
    RULE_CATALOG.yaml. These are evaluated by the generic_evaluator against
    pre-loaded device facts JSON files.

Phase 3 (Cross-device rules): ~40 rules that compare parameters between
    connected devices using topology model adjacencies and links.
    Implemented in src/rules/cross_device/.

Architecture:
    run_rules(run_id)
         │
         ├──► Load network_model.json + manifest.json
         │
         ├──► Phase 1: Python rules
         │    discover_rules() → rule.evaluate(model, context)
         │
         ├──► Phase 2: YAML surface rules
         │    load_catalog() → scan facts/ → evaluate_device() per hostname
         │
         ├──► Phase 3: Cross-device rules
         │    run_cross_device_rules(model, facts_dir)
         │
         ├──► Merge + deduplicate (Phase 1 wins)
         │
         └──► {metadata, findings, summary, errors}

Data Flow:
    runs/<run-id>/model/network_model.json  ──┐
    runs/<run-id>/manifest.json             ──┤
    runs/<run-id>/facts/<hostname>/*.json   ──┼──► run_rules() ──► Result dict
    src/rules/rules/*.py (autodiscovered)   ──┤
    src/rules/cross_device/*.py             ──┤
    rule-catalog.yaml     ──┘

Design Principles:
    - Deterministic: Same model + facts always produces same findings
    - Fault-tolerant: One failing rule doesn't stop others
    - Graceful degradation: Phase 2/3 failure doesn't lose earlier findings
    - Traceable: Every finding links to model elements or facts files
    - Observable: Clear logging of what's happening

Example Usage:
    >>> from netcopilot.rules.engine import run_rules
    >>> result = run_rules("2026-01-15_12-00-00")
    >>> print(f"Found {result['metadata']['total_findings']} findings")
    Found 42 findings
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.discovery import discover_rules
from netcopilot.rules.finding import Finding

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Engine version
# -------------------------------------------------------------------------
# This is included in findings metadata for traceability
ENGINE_VERSION = "0.3.0"

# Default catalog path — the rule-catalog.yaml shipped inside this package.
DEFAULT_CATALOG_PATH = str(Path(__file__).parent / "rule-catalog.yaml")


def run_rules(
    run_id: str,
    runs_base: str = "runs",
    catalog_path: str = DEFAULT_CATALOG_PATH,
) -> dict[str, Any]:
    """
    Run all rules against a network model and collect findings.

    Executes three phases:
    - Phase 1: Python rules (model-based + deep CIS/protocol rules)
    - Phase 2: YAML surface rules (eval specs from RULE_CATALOG.yaml)
    - Phase 3: Cross-device rules (compare parameters between peers)

    Findings are merged and deduplicated by finding_id (Phase 1 wins).
    Phase 2/3 failures are isolated — earlier findings always returned.

    Args:
        run_id: The run identifier (e.g., "2026-01-15_12-00-00")
        runs_base: Base directory for runs (default: "runs")
        catalog_path: Path to rule-catalog.yaml (default: docs/domain/rules/)

    Returns:
        Dictionary with structure:
        {
            "metadata": {
                "run_id": "...",
                "generated_at": "ISO8601 timestamp",
                "engine_version": "0.3.0",
                "model_path": "relative path to model",
                "rules_executed": ["RULE_ID_1", ...],
                "rules_executed_phase1": 36,
                "rules_executed_phase2": 81,
                "rules_executed_phase3": 40,
                "total_findings": 42
            },
            "findings": [Finding.to_dict(), ...],
            "summary": {
                "by_severity": {"critical": 0, "high": 3, ...},
                "by_rule": {"LINK_DOWN": 3, ...}
            },
            "errors": [{"rule_id": "...", "error": "..."}, ...]
        }

    Raises:
        FileNotFoundError: If run directory or model doesn't exist
    """
    logger.info(f"Starting rule engine for run: {run_id}")

    # -------------------------------------------------------------------------
    # Step 1: Validate run directory exists
    # -------------------------------------------------------------------------
    run_path = Path(runs_base) / run_id

    if not run_path.exists():
        raise FileNotFoundError(f"Run directory not found: {run_path}")

    # -------------------------------------------------------------------------
    # Step 2: Load network model
    # -------------------------------------------------------------------------
    model_path = run_path / "model" / "network_model.json"

    if not model_path.exists():
        raise FileNotFoundError(
            f"Network model not found: {model_path}. "
            f"Run 'netcopilot run' first."
        )

    logger.debug(f"Loading model from: {model_path}")
    model = _load_json(model_path)

    # -------------------------------------------------------------------------
    # Step 3: Load manifest (for context)
    # -------------------------------------------------------------------------
    manifest_path = run_path / "manifest.json"

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    logger.debug(f"Loading manifest from: {manifest_path}")
    manifest = _load_json(manifest_path)

    # -------------------------------------------------------------------------
    # Step 4: Build context dictionary
    # -------------------------------------------------------------------------
    context: dict[str, Any] = {
        "manifest": manifest,
        "run_id": run_id,
        "run_path": str(run_path),
    }

    # =========================================================================
    # Phase 1: Python rules (model-based + deep rules)
    # =========================================================================
    phase1_findings, phase1_executed, phase1_errors = _run_phase1(
        model, context
    )

    logger.info(
        f"Phase 1 complete: {len(phase1_executed)} rules, "
        f"{len(phase1_findings)} findings, {len(phase1_errors)} errors"
    )

    # =========================================================================
    # Phase 2: YAML surface rules (catalog + generic_evaluator)
    # =========================================================================
    # If Phase 2 fails (bad YAML, missing catalog), Phase 1 findings survive.
    phase2_findings: list[Finding] = []
    phase2_executed: list[str] = []
    phase2_errors: list[dict[str, str]] = []

    try:
        phase2_findings, phase2_executed, phase2_errors = _run_phase2(
            run_path, catalog_path
        )
        logger.info(
            f"Phase 2 complete: {len(phase2_executed)} rules, "
            f"{len(phase2_findings)} findings, {len(phase2_errors)} errors"
        )
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.error(f"Phase 2 failed entirely: {error_msg}")
        phase2_errors.append({"rule_id": "PHASE2_LOAD", "error": error_msg})

    # =========================================================================
    # Phase 3: Cross-device rules (compare parameters between peers)
    # =========================================================================
    # Phase 3 failure is fully isolated — does not affect Phase 1+2.
    phase3_findings: list[Finding] = []
    phase3_executed: list[str] = []
    phase3_errors: list[dict[str, str]] = []

    try:
        facts_dir = run_path / "facts"
        if facts_dir.is_dir():
            from netcopilot.rules.cross_device import run_cross_device_rules

            phase3_findings, phase3_executed, phase3_errors = (
                run_cross_device_rules(model, facts_dir)
            )
            logger.info(
                f"Phase 3 complete: {len(phase3_executed)} rules, "
                f"{len(phase3_findings)} findings, "
                f"{len(phase3_errors)} errors"
            )
        else:
            logger.warning(
                f"Phase 3: facts directory not found: {facts_dir}"
            )
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.error(f"Phase 3 failed entirely: {error_msg}")
        phase3_errors.append({"rule_id": "PHASE3_LOAD", "error": error_msg})

    # =========================================================================
    # Merge and deduplicate
    # =========================================================================
    merged = _merge_and_dedup(
        phase1_findings, phase2_findings, phase3_findings
    )

    # =========================================================================
    # Post-processing: CIS findings get severity "cis"
    # =========================================================================
    merged = _apply_cis_severity(merged)

    all_executed = sorted(
        set(phase1_executed + phase2_executed + phase3_executed)
    )
    all_errors = phase1_errors + phase2_errors + phase3_errors

    # -------------------------------------------------------------------------
    # Build summary and result
    # -------------------------------------------------------------------------
    summary = _build_summary(merged)

    result: dict[str, Any] = {
        "metadata": {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine_version": ENGINE_VERSION,
            "model_path": f"{runs_base}/{run_id}/model/network_model.json",
            "rules_executed": all_executed,
            "rules_executed_phase1": len(phase1_executed),
            "rules_executed_phase2": len(phase2_executed),
            "rules_executed_phase3": len(phase3_executed),
            "total_findings": len(merged),
        },
        "findings": [f.to_dict() for f in merged],
        "summary": summary,
        "errors": all_errors,
    }

    total_pre_dedup = (
        len(phase1_findings) + len(phase2_findings) + len(phase3_findings)
    )
    logger.info(
        f"Rule engine completed: "
        f"{len(phase1_executed)}+{len(phase2_executed)}+"
        f"{len(phase3_executed)} rules executed, "
        f"{len(merged)} findings ({len(phase1_findings)} P1 + "
        f"{len(phase2_findings)} P2 + {len(phase3_findings)} P3, "
        f"{total_pre_dedup - len(merged)} deduped), "
        f"{len(all_errors)} errors"
    )

    return result


def _run_phase1(
    model: dict[str, Any],
    context: dict[str, Any],
) -> tuple[list[Finding], list[str], list[dict[str, str]]]:
    """
    Execute Phase 1: all Python rules against the network model.

    Phase 1 includes both model-based rules (LINK_DOWN, ISOLATED_DEVICE, etc.)
    and deep rules (CIS checks, protocol checks) that use BaseRule subclasses.
    Deep rules load facts files internally via load_device_facts()/load_running_config().

    Args:
        model: The loaded network model dict.
        context: Context dict with manifest, run_id, run_path.

    Returns:
        Tuple of (findings, executed_rule_ids, errors).
    """
    rules = discover_rules()
    logger.info(f"Phase 1: discovered {len(rules)} Python rules")

    findings: list[Finding] = []
    executed: list[str] = []
    errors: list[dict[str, str]] = []

    for rule in rules:
        if not rule.is_enabled():
            logger.debug(f"Skipping disabled rule: {rule.rule_id}")
            continue

        try:
            rule_findings = rule.evaluate(model, context)
            findings.extend(rule_findings)
            executed.append(rule.rule_id)
            logger.debug(f"Rule {rule.rule_id} produced {len(rule_findings)} findings")
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"Rule {rule.rule_id} failed: {error_msg}")
            errors.append({"rule_id": rule.rule_id, "error": error_msg})

    return findings, executed, errors


def _run_phase2(
    run_path: Path,
    catalog_path: str,
) -> tuple[list[Finding], list[str], list[dict[str, str]]]:
    """
    Execute Phase 2: YAML surface rules against device facts.

    Loads the rule catalog, scans the facts/ directory for device hostnames,
    pre-loads each device's JSON facts, and evaluates all matching YAML rules
    using the generic evaluator.

    Args:
        run_path: Path to the run directory (e.g., runs/mysite_...).
        catalog_path: Path to RULE_CATALOG.yaml.

    Returns:
        Tuple of (findings, executed_rule_ids, errors).
    """
    # Lazy imports to avoid circular dependencies and keep Phase 1 fast
    from netcopilot.rules.catalog_loader import load_catalog
    from netcopilot.rules.generic_evaluator import evaluate_device

    # -------------------------------------------------------------------------
    # Load catalog and get rules grouped by source
    # -------------------------------------------------------------------------
    catalog_result = load_catalog(catalog_path)
    rules_by_source = catalog_result.rules_by_source()

    if not catalog_result.rules:
        logger.warning("Phase 2: no YAML rules loaded from catalog")
        return [], [], []

    # Collect all rule_ids that were loaded for the executed list
    executed = sorted({r.rule_id for r in catalog_result.rules})

    logger.info(
        f"Phase 2: {len(executed)} YAML rules loaded across "
        f"{len(rules_by_source)} source families"
    )

    # -------------------------------------------------------------------------
    # Scan facts/ directory for device hostnames
    # -------------------------------------------------------------------------
    facts_dir = run_path / "facts"
    if not facts_dir.is_dir():
        logger.warning(f"Phase 2: facts directory not found: {facts_dir}")
        return [], executed, []

    # Each subdirectory in facts/ is a device hostname
    device_dirs = sorted(
        d for d in facts_dir.iterdir() if d.is_dir()
    )

    logger.info(f"Phase 2: found {len(device_dirs)} devices in {facts_dir}")

    # -------------------------------------------------------------------------
    # Evaluate each device
    # -------------------------------------------------------------------------
    all_findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    for device_dir in device_dirs:
        hostname = device_dir.name

        try:
            # Load all JSON facts for this device into a single dict
            device_facts = _load_device_facts_dir(device_dir)

            if not device_facts:
                continue

            # Get os_family from device_facts.json (the "os" field)
            os_family = None
            df = device_facts.get("device_facts")
            if isinstance(df, dict):
                os_family = df.get("os")

            # Evaluate all YAML rules against this device's facts
            findings = evaluate_device(
                hostname, device_facts, rules_by_source, os_family
            )
            all_findings.extend(findings)

            if findings:
                logger.debug(
                    f"Phase 2: {hostname} produced {len(findings)} findings"
                )

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"Phase 2 failed for device {hostname}: {error_msg}")
            errors.append({"rule_id": f"PHASE2:{hostname}", "error": error_msg})

    return all_findings, executed, errors


def _load_device_facts_dir(device_dir: Path) -> dict[str, Any]:
    """
    Load all JSON facts files from a device's facts directory.

    Each .json file becomes an entry in the returned dict, keyed by the
    file stem (e.g., "genie_ospf.json" → key "genie_ospf").

    Args:
        device_dir: Path to the device's facts directory
                    (e.g., runs/<id>/facts/core-rtr-01/).

    Returns:
        Dict mapping source names to parsed JSON data.
        Example: {"genie_ospf": {...}, "genie_bgp": {...}, "device_facts": {...}}
    """
    facts: dict[str, Any] = {}

    for json_file in sorted(device_dir.glob("*.json")):
        try:
            with open(json_file, encoding="utf-8") as f:
                facts[json_file.stem] = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load {json_file}: {e}")

    return facts


def _merge_and_dedup(
    phase1: list[Finding],
    phase2: list[Finding],
    phase3: list[Finding] | None = None,
) -> list[Finding]:
    """
    Merge Phase 1, Phase 2, and Phase 3 findings, deduplicating by finding_id.

    Priority order: Phase 1 > Phase 2 > Phase 3. If multiple phases produce
    a finding with the same finding_id, the earliest phase's finding is kept.

    Args:
        phase1: Findings from Python rules (highest priority).
        phase2: Findings from YAML surface rules.
        phase3: Findings from cross-device rules (optional).

    Returns:
        Merged list with duplicates removed.
    """
    seen: set[str] = set()
    merged: list[Finding] = []

    # Phase 1 first — these have priority
    for finding in phase1:
        if finding.finding_id not in seen:
            seen.add(finding.finding_id)
            merged.append(finding)

    # Phase 2 — skip if already seen from Phase 1
    dedup_count = 0
    for finding in phase2:
        if finding.finding_id not in seen:
            seen.add(finding.finding_id)
            merged.append(finding)
        else:
            dedup_count += 1

    # Phase 3 — skip if already seen from Phase 1 or 2
    if phase3:
        for finding in phase3:
            if finding.finding_id not in seen:
                seen.add(finding.finding_id)
                merged.append(finding)
            else:
                dedup_count += 1

    if dedup_count > 0:
        logger.info(f"Deduplication: {dedup_count} findings removed (duplicate finding_ids)")

    return merged


def _apply_cis_severity(findings: list[Finding]) -> list[Finding]:
    """
    Override severity to 'cis' for all CIS compliance findings.

    CIS findings get their own severity level so they
    don't drown out operational findings. CIS is the lowest priority:
    critical > high > medium > low > cis.

    Since Finding is a frozen dataclass, we create replacement Finding
    objects for CIS rules.

    Args:
        findings: Merged findings list.

    Returns:
        New list with CIS findings having severity='cis'.
    """
    _CIS_PREFIXES = ("CIS_FG_", "CIS_XE_", "CIS_XR_")
    result: list[Finding] = []
    cis_count = 0

    for f in findings:
        if f.rule_id.startswith(_CIS_PREFIXES) and f.severity != "cis":
            # Create replacement with severity="cis"
            result.append(Finding(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                severity="cis",
                title=f.title,
                message=f.message,
                evidence=f.evidence,
                recommendation=f.recommendation,
                detected_at=f.detected_at,
                tags=f.tags,
            ))
            cis_count += 1
        else:
            result.append(f)

    if cis_count > 0:
        logger.info(f"CIS severity override: {cis_count} findings set to severity='cis'")

    return result


def _load_json(path: Path) -> dict[str, Any]:
    """
    Load and parse a JSON file.

    Args:
        path: Path to the JSON file

    Returns:
        Parsed JSON as dictionary

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _build_summary(findings: list[Finding]) -> dict[str, Any]:
    """
    Build summary statistics from findings.

    Counts findings by severity and by rule, matching the
    summary.json schema defined in the handoff document.

    Args:
        findings: List of Finding objects

    Returns:
        Dictionary with structure:
        {
            "by_severity": {"critical": 0, "high": 3, "medium": 2, "info": 1},
            "by_rule": {"LINK_DOWN": 3, "ISOLATED_DEVICE": 2, ...}
        }
    """
    # -------------------------------------------------------------------------
    # Count by severity
    # -------------------------------------------------------------------------
    # Initialize all severity levels to 0 for consistent output
    by_severity: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "low": 0,
        "info": 0,
        "cis": 0,
    }

    for finding in findings:
        severity = finding.severity
        by_severity[severity] = by_severity.get(severity, 0) + 1

    # -------------------------------------------------------------------------
    # Count by rule
    # -------------------------------------------------------------------------
    by_rule: dict[str, int] = {}

    for finding in findings:
        rule_id = finding.rule_id
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1

    result = {
        "by_severity": by_severity,
        "by_rule": by_rule,
    }

    return result
