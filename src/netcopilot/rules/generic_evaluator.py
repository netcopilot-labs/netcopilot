"""
Generic Evaluator — Evaluate YAML-defined surface rules against device facts.

This module is the core of the hybrid rule engine's "surface" tier. It takes
YAML eval specs (loaded by catalog_loader) and evaluates them against pre-loaded
device facts using the path_resolver for JSON traversal.

Architecture:
    catalog_loader ──► rules_by_source ──┐
                                         │
    device facts ──► evaluate_device() ──┤──► list[Finding]
    (per hostname)         │             │
                           ▼             │
                    For each source group:
                      path_resolver.resolve(iterate, data)
                           │
                           ▼
                      _check_condition() / _check_conditions()
                           │
                           ▼
                      If violated → Finding.create()

    Evaluation flow per rule:
        1. Look up source data in device_facts
        2. If iterate path → resolve wildcards, get (context, value) tuples
        3. If no iterate → evaluate root object with empty context
        4. For each (context, value): check condition(s)
        5. If condition violated → template element_id, evidence, message
        6. Create Finding with mapped severity and full evidence trail

Design Principles:
    - Deterministic: same facts → same findings, every time
    - Evidence is mandatory: every finding traces to source file + JSON path
    - Graceful degradation: missing data, bad types → skip, don't crash
    - No cross-device: all evaluation is per-device

Example Usage:
    >>> from netcopilot.rules.generic_evaluator import evaluate_device
    >>> from netcopilot.rules.catalog_loader import load_catalog
    >>> result = load_catalog("rule-catalog.yaml")
    >>> by_source = result.rules_by_source()
    >>> facts = {"genie_ospf": {...}}
    >>> findings = evaluate_device("core-rtr-01", facts, by_source)
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import json
import logging
import re
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.catalog_loader import EvalCondition, EvalSpec, RuleDef
from netcopilot.rules.finding import Finding
from netcopilot.rules.path_resolver import resolve

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------


def evaluate_device(
    hostname: str,
    device_facts: dict[str, Any],
    rules_by_source: dict[str, list[RuleDef]],
    os_family: str | None = None,
) -> list[Finding]:
    """
    Evaluate all YAML surface rules against a single device's facts.

    This is the main entry point for per-device rule evaluation. It iterates
    over source groups (e.g., all OSPF rules, then all BGP rules), checks
    whether the device has data for that source, and evaluates each rule
    against the data.

    Args:
        hostname: The device hostname (e.g., "core-rtr-01"). Used in element_id
                  templates and evidence.
        device_facts: Dict mapping source keys to loaded JSON data.
                      Example: {"genie_ospf": {...}, "genie_bgp": {...}}
        rules_by_source: Rules grouped by source key, from
                         CatalogResult.rules_by_source().
        os_family: The device's OS family (e.g., "iosxe", "iosxr").
                   Used for os_family filtering. None means no filtering.

    Returns:
        List of Finding instances for all violated rules on this device.
        Empty list if no violations found or all sources are missing.

    Example:
        >>> findings = evaluate_device(
        ...     "core-rtr-01",
        ...     {"genie_ospf": {"vrf": {"default": {"neighbor": {...}}}}},
        ...     {"genie_ospf": [ospf_rule_def]},
        ... )
    """
    findings: list[Finding] = []

    # -------------------------------------------------------------------------
    # Iterate over source groups
    # -------------------------------------------------------------------------
    # Each source group corresponds to a Genie JSON file (e.g., genie_ospf).
    # If the device doesn't have data for a source, we skip all rules in
    # that group — the device doesn't run that protocol.
    for source_key, rules in rules_by_source.items():
        data = device_facts.get(source_key)

        if data is None:
            # Device doesn't have this source — skip entire group.
            # This is normal: not every device runs every protocol.
            continue

        # -----------------------------------------------------------------
        # Evaluate each rule in this source group
        # -----------------------------------------------------------------
        for rule_def in rules:
            try:
                rule_findings = _evaluate_rule(
                    rule_def, data, hostname, source_key, os_family
                )
                findings.extend(rule_findings)
            except Exception as e:
                # One rule failing must not stop other rules from evaluating.
                # Log the error and continue with the next rule.
                logger.warning(
                    f"Rule '{rule_def.rule_id}' failed on device '{hostname}': {e}"
                )

    return findings


# -------------------------------------------------------------------------
# Private Implementation
# -------------------------------------------------------------------------


def _evaluate_rule(
    rule_def: RuleDef,
    data: Any,
    hostname: str,
    source_key: str,
    os_family: str | None,
) -> list[Finding]:
    """
    Evaluate a single rule against device data.

    Handles the iterate/no-iterate branching, os_family filtering, and
    delegates condition checking to _check_condition/_check_conditions.

    Args:
        rule_def: The validated rule definition from the catalog.
        data: The source JSON data (e.g., contents of genie_ospf.json).
        hostname: Device hostname for template interpolation.
        source_key: The source key (e.g., "genie_ospf") for evidence.
        os_family: Device OS family for filtering.

    Returns:
        List of Findings for violations found by this rule.
    """
    spec = rule_def.eval

    # -------------------------------------------------------------------------
    # os_family filter: skip if device doesn't match. Normalize BOTH sides
    # (hyphen-stripped lowercase) so the catalog's 'ios-xe' matches a device
    # 'os' of either 'ios-xe' or 'iosxe' — the inventory convention is
    # inconsistent and was silently skipping every surface rule on iosxe devices.
    if spec.os_family and os_family:
        if spec.os_family.lower().replace("-", "") != os_family.lower().replace("-", ""):
            return []

    findings: list[Finding] = []

    if spec.iterate:
        # -----------------------------------------------------------------
        # Iterate mode: resolve wildcard path, evaluate each match
        # -----------------------------------------------------------------
        # resolve() yields (context, value) tuples where context captures
        # the wildcard key names and value is the data at that position.
        for context, value in resolve(spec.iterate, data):
            if _context_excluded(spec, context):
                continue
            finding = _evaluate_at_value(
                rule_def, value, context, hostname, source_key, spec
            )
            if finding is not None:
                findings.append(finding)
    else:
        # -----------------------------------------------------------------
        # Root mode: evaluate against the entire data object
        # -----------------------------------------------------------------
        # No wildcards, so context is empty
        finding = _evaluate_at_value(
            rule_def, data, {}, hostname, source_key, spec
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _context_excluded(spec: EvalSpec, context: dict[str, str]) -> bool:
    """Return True if any of spec.exclude (context_key, regex) pairs matches.

    Lets a surface rule skip specific iteration matches by their captured
    wildcard value — e.g. excluding loopback interfaces from a per-interface
    OSPF check, since loopbacks form no adjacency.
    """
    for key, pattern in spec.exclude:
        val = context.get(key)
        if val is not None and re.search(pattern, str(val)):
            return True
    return False


def _evaluate_at_value(
    rule_def: RuleDef,
    value: Any,
    context: dict[str, str],
    hostname: str,
    source_key: str,
    spec: EvalSpec,
) -> Finding | None:
    """
    Evaluate condition(s) against a single data value and emit a Finding if violated.

    This is the innermost evaluation function. It:
    1. Checks condition(s) against the current value
    2. If violated, templates the element_id, evidence, and message
    3. Creates and returns a Finding

    Args:
        rule_def: The rule definition (for rule_id, severity, etc.).
        value: The data object at the resolved path position.
        context: Wildcard context from path_resolver (e.g., {"vrf": "default"}).
        hostname: Device hostname.
        source_key: Source key for evidence (e.g., "genie_ospf").
        spec: The eval spec from the rule.

    Returns:
        A Finding if the condition is violated, None otherwise.
    """
    # -------------------------------------------------------------------------
    # Check condition(s)
    # -------------------------------------------------------------------------
    violated = False
    actual_values: dict[str, Any] = {}

    if spec.condition:
        # Single condition mode
        actual = _get_field_value(value, spec.condition.field)
        actual_values[spec.condition.field] = actual
        violated = _check_condition(spec.condition, actual)
    elif spec.conditions_logic and spec.conditions_checks:
        # Multi-condition mode (all/any logic)
        results = []
        for check in spec.conditions_checks:
            actual = _get_field_value(value, check.field)
            actual_values[check.field] = actual
            results.append(_check_condition(check, actual))

        if spec.conditions_logic == "all":
            # ALL conditions must be violated for the rule to fire
            violated = all(results)
        else:
            # ANY condition violated fires the rule
            violated = any(results)

    if not violated:
        return None

    # -------------------------------------------------------------------------
    # Build template variables for element_id and evidence strings
    # -------------------------------------------------------------------------
    # Template variables come from three sources:
    # 1. Wildcard context: {"vrf": "default", "neighbor": "192.0.2.1"}
    # 2. Data fields: {"state": "INIT", "dead_timer": 40}
    # 3. hostname: always available
    template_vars = _build_template_vars(context, value, hostname)

    # -------------------------------------------------------------------------
    # Interpolate element_id and evidence templates
    # -------------------------------------------------------------------------
    element_id = _safe_format(spec.element_id, template_vars)
    evidence_str = _safe_format(spec.evidence, template_vars)

    # -------------------------------------------------------------------------
    # Build the JSON path for evidence traceability
    # -------------------------------------------------------------------------
    # Combines the iterate path (with wildcards resolved) and condition field
    json_path = _build_json_path(spec, context)

    # -------------------------------------------------------------------------
    # Determine the expected value for evidence
    # -------------------------------------------------------------------------
    expected_value = _get_expected_value(spec)

    # -------------------------------------------------------------------------
    # Get the actual value that triggered the violation
    # -------------------------------------------------------------------------
    primary_field = (
        spec.condition.field if spec.condition
        else spec.conditions_checks[0].field if spec.conditions_checks
        else None
    )
    actual_value = actual_values.get(primary_field) if primary_field else None

    # -------------------------------------------------------------------------
    # Build the message
    # -------------------------------------------------------------------------
    message = (
        f"{rule_def.title}: {evidence_str} "
        f"on device {hostname}"
    )

    # -------------------------------------------------------------------------
    # Create Finding using the existing Finding.create() factory
    # -------------------------------------------------------------------------
    return Finding.create(
        rule_id=rule_def.rule_id,
        severity=rule_def.python_severity,
        title=rule_def.title,
        element_type="device",
        element_id=element_id,
        message=message,
        key_facts={
            "source_file": f"facts/{hostname}/{source_key}.json",
            "json_path": json_path,
            "actual_value": actual_value,
            "expected_value": expected_value,
            "hostname": hostname,
        },
        recommendation=rule_def.description,
    )


def _get_field_value(value: Any, field: str) -> Any:
    """
    Extract a field value from the data object.

    If value is a dict, looks up the field key. If the field contains
    dots (nested path), traverses into nested dicts. If value is not
    a dict or the field is missing, returns None.

    Args:
        value: The data object (typically a dict from Genie JSON).
        field: The field name to look up.

    Returns:
        The field value, or None if not found.
    """
    if not isinstance(value, dict):
        return None

    # Handle dotted field names (e.g., "counters.in_errors")
    if "." in field:
        parts = field.split(".")
        current = value
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
        return current

    return value.get(field)


def _check_condition(condition: EvalCondition, actual: Any) -> bool:
    """
    Check whether a condition is violated (i.e., the rule should fire).

    Returns True if the condition is VIOLATED — meaning the actual value
    matches the "bad" condition defined in the rule.

    For example, `not_equals` with value "full" is violated when actual
    IS NOT "full" — that's the unhealthy state we're looking for.

    The `is_null` operator fires when the actual value is None, which
    indicates missing or unconfigured data.

    Args:
        condition: The condition to check (field, operator, value).
        actual: The actual value from the device data.

    Returns:
        True if the condition is violated (finding should be emitted),
        False if the condition passes (device is healthy for this check).
    """
    operator = condition.operator
    expected = condition.value

    if operator == "is_null":
        return actual is None

    # For all other operators, None actual means we can't evaluate —
    # skip rather than produce a potentially false finding
    if actual is None:
        return False

    if operator == "equals":
        return _compare_equals(actual, expected)

    if operator == "not_equals":
        return not _compare_equals(actual, expected)

    if operator == "greater_than":
        return _compare_numeric(actual, expected, lambda a, e: a > e)

    if operator == "less_than":
        return _compare_numeric(actual, expected, lambda a, e: a < e)

    # Unknown operator — should not happen due to catalog validation
    logger.warning(f"Unknown operator '{operator}' — skipping condition")
    return False


def _compare_equals(actual: Any, expected: Any) -> bool:
    """
    Case-insensitive string comparison for equals/not_equals.

    Converts both values to lowercase strings before comparing.
    This handles Genie JSON inconsistencies where the same field might
    report "FULL" on one device and "full" on another.

    Args:
        actual: The actual value from device data.
        expected: The expected value from the rule.

    Returns:
        True if the values are equal (case-insensitive for strings).
    """
    # Convert both to strings and compare case-insensitively
    return str(actual).lower() == str(expected).lower()


def _compare_numeric(
    actual: Any,
    expected: Any,
    comparator: Any,
) -> bool:
    """
    Numeric comparison with safe type coercion.

    Converts both values to float before comparing. If either value
    can't be converted to a number, the comparison fails gracefully
    (returns False) rather than crashing.

    Args:
        actual: The actual value from device data.
        expected: The expected value from the rule.
        comparator: A lambda/function that takes (actual_float, expected_float)
                    and returns bool.

    Returns:
        True if the comparison holds, False if values aren't numeric.
    """
    try:
        actual_f = float(actual)
        expected_f = float(expected)
        return comparator(actual_f, expected_f)
    except (ValueError, TypeError):
        # Non-numeric values can't be compared — skip
        logger.debug(
            f"Numeric comparison failed: actual={actual!r}, expected={expected!r}"
        )
        return False


def _build_template_vars(
    context: dict[str, str],
    value: Any,
    hostname: str,
) -> dict[str, Any]:
    """
    Build the template variable dict for element_id and evidence interpolation.

    Template variables come from three sources (in priority order):
    1. hostname — always present
    2. Wildcard context — {"vrf": "default", "neighbor": "192.0.2.1"}
    3. Data fields — if value is a dict, all its top-level keys are available

    Context and hostname take priority over data fields to prevent accidental
    override of wildcard captures by data values.

    Args:
        context: Wildcard context from path_resolver.
        value: The current data object.
        hostname: The device hostname.

    Returns:
        Dict of template variables for str.format_map().
    """
    template_vars: dict[str, Any] = {}

    # Data fields are lowest priority — add first so they can be overridden
    if isinstance(value, dict):
        for k, v in value.items():
            template_vars[k] = v

    # Wildcard context overrides data fields
    template_vars.update(context)

    # hostname is always available and takes highest priority
    template_vars["hostname"] = hostname

    return template_vars


def _safe_format(template: str, variables: dict[str, Any]) -> str:
    """
    Safely interpolate template variables, replacing missing keys with '?'.

    Uses format_map with a defaultdict-like fallback so that missing
    template variables don't raise KeyError — they just show as '?'.
    This prevents broken eval specs from crashing the evaluator.

    Args:
        template: The template string with {variable} placeholders.
        variables: The available template variables.

    Returns:
        The interpolated string with missing variables shown as '?'.
    """
    # _SafeDict returns '?' for missing keys instead of raising KeyError
    return template.format_map(_SafeDict(variables))


class _SafeDict(dict):
    """
    A dict subclass that returns '{key}' for missing keys in str.format_map().

    This prevents KeyError when a template references a variable that isn't
    available. Instead, the missing variable name is preserved in the output
    wrapped in angle brackets for debugging.

    Example:
        >>> "{hostname}/{missing}".format_map(_SafeDict({"hostname": "core-rtr-01"}))
        'core-rtr-01/?'
    """

    def __missing__(self, key: str) -> str:
        """Return '?' for any missing key instead of raising KeyError."""
        return "?"


def _build_json_path(spec: EvalSpec, context: dict[str, str]) -> str:
    """
    Build the concrete JSON path for evidence, resolving wildcards from context.

    Takes the iterate path (e.g., "vrf.*.neighbor.*") and replaces each
    wildcard with the actual key from the context (e.g., "default", "192.0.2.1"),
    then appends the condition field.

    Args:
        spec: The eval spec (for iterate path and condition field).
        context: Wildcard context with resolved keys.

    Returns:
        The concrete JSON path string (e.g., "vrf.default.neighbor.192.0.2.1.state").
    """
    # Start with the iterate path or empty if no iteration
    if spec.iterate:
        path = spec.iterate
        # Replace each * with the corresponding context value
        # Context values are ordered by their position in the path
        for ctx_key, ctx_val in context.items():
            # Replace the first remaining * with the context value
            path = path.replace("*", ctx_val, 1)
    else:
        path = ""

    # Append the condition field
    field = None
    if spec.condition:
        field = spec.condition.field
    elif spec.conditions_checks:
        field = spec.conditions_checks[0].field

    if field:
        if path:
            path = f"{path}.{field}"
        else:
            path = field

    return path


def _get_expected_value(spec: EvalSpec) -> Any:
    """
    Extract the expected value from a rule's condition for evidence.

    For single conditions, returns the condition's value.
    For multi-conditions, returns a summary string.
    For is_null, returns "not null".

    Args:
        spec: The eval spec.

    Returns:
        The expected value for evidence reporting.
    """
    if spec.condition:
        if spec.condition.operator == "is_null":
            return "not null"
        return spec.condition.value

    if spec.conditions_checks:
        # Summarize multi-condition expected values
        parts = []
        for check in spec.conditions_checks:
            if check.operator == "is_null":
                parts.append(f"{check.field}: not null")
            else:
                parts.append(f"{check.field} {check.operator} {check.value}")
        return f"[{spec.conditions_logic}] " + ", ".join(parts)

    return None


# -------------------------------------------------------------------------
# Facts Loading Helpers (for deep Python rules)
# -------------------------------------------------------------------------


def load_device_facts(
    run_path: str | Path,
    hostname: str,
    source_name: str,
) -> dict | None:
    """
    Load a JSON facts file for a specific device from a pipeline run.

    Deep Python rules use this helper to access Genie/parsed JSON data
    that was collected during the pipeline run. Each facts file is stored
    at ``runs/<run-id>/facts/<hostname>/<source_name>.json``.

    Args:
        run_path: Path to the run directory (e.g., "runs/2026-01-15_12-00-00").
        hostname: Device hostname (e.g., "core-rtr-01").
        source_name: Facts file stem without .json (e.g., "genie_ospf",
                     "security_config", "parsed_lag").

    Returns:
        Parsed JSON as a dict, or None if the file doesn't exist or can't
        be parsed.

    Example:
        >>> data = load_device_facts("runs/my-run", "core-rtr-01", "genie_ospf")
        >>> if data:
        ...     neighbors = data.get("vrf", {})
    """
    path = Path(run_path) / "facts" / hostname / f"{source_name}.json"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to load facts file: %s", path)
        return None


def load_running_config(
    run_path: str | Path,
    hostname: str,
) -> str | None:
    """
    Load the raw running-config text for a specific device.

    CIS deep rules use this helper to check for specific configuration
    keywords that aren't captured in the structured security_config.json.

    Args:
        run_path: Path to the run directory.
        hostname: Device hostname.

    Returns:
        The full running config as a string, or None if unavailable.

    Example:
        >>> config = load_running_config("runs/my-run", "core-rtr-01")
        >>> if config and "aaa new-model" in config:
        ...     print("AAA enabled")
    """
    path = Path(run_path) / "facts" / hostname / "running_config.txt"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        logger.warning("Failed to load running config: %s", path)
        return None
