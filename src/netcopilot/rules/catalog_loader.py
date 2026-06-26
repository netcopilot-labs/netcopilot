"""
Catalog Loader — Load RULE_CATALOG.yaml and index surface rules by source family.

The rule catalog contains hundreds of rules across many protocols. Most are
"surface" rules
with simple conditions that can be evaluated by the GenericRule evaluator. This module loads the catalog, filters to rules that have an
`eval` block, validates each eval spec, and groups rules by their `source`
key for efficient per-device evaluation.

Architecture:
    RULE_CATALOG.yaml ──► load_catalog() ──► CatalogResult
           │                    │                   │
           ▼                    ▼                   ▼
    425 rules total     validate + filter    rules_by_source() index
                        (eval block? valid?  {"genie_ospf": [RuleDef, ...],
                         not cross-device?)   "genie_bgp":  [RuleDef, ...]}

    Filtering pipeline (live counts vary as the catalog evolves):
        425 rules → has eval block? → not cross-device? → valid eval? → loaded
                     ↓ no              ↓ yes               ↓ no
                   skipped           skipped             warned + skipped

    94 rules carry an `eval` block and 37 are flagged
    `cross_device: true`. The remainder are
    Phase-1 Python rules (BaseRule subclasses under src/rules/rules/) or
    catalog-only documentation entries.

Design Principles:
    - Defensive loading: invalid rules are skipped with a warning, never crash
    - Duplicate protection: YAML rule_ids that conflict with existing Python
      rules are rejected to prevent double-counting findings
    - Immutable output: RuleDef is a frozen dataclass — rules can't be
      accidentally mutated after loading
    - Stats transparency: CatalogResult exposes counts for every filter stage

Example Usage:
    >>> from netcopilot.rules.catalog_loader import load_catalog
    >>> result = load_catalog("rule-catalog.yaml")
    >>> print(result.stats["total"])  # rule-count varies as catalog evolves
    425
    >>> by_source = result.rules_by_source()
    >>> sorted(by_source.keys())[:3]
    ['genie_acl', 'genie_arp', 'genie_bgp']
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Third-party imports
# -------------------------------------------------------------------------
import yaml

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.discovery import discover_rules

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

# Valid operators for eval conditions (5 only — no DSL creep)
VALID_OPERATORS = {"equals", "not_equals", "greater_than", "less_than", "is_null"}

# Required fields inside an eval block
EVAL_REQUIRED_FIELDS = {"source", "element_id", "evidence"}

# Severity mapping from 3-level YAML catalog to 4-level Python engine.
# "warning" defaults to "high" but can be overridden per-rule with
# python_severity in the eval block.
SEVERITY_MAP = {
    "critical": "critical",
    "warning": "high",
    "informational": "info",
}

# Valid logic operators for multi-condition eval blocks
VALID_LOGIC = {"all", "any"}


# -------------------------------------------------------------------------
# Data Structures
# -------------------------------------------------------------------------


# @dataclass(frozen=True) makes instances immutable after creation —
# prevents accidental mutation of rule definitions during evaluation
@dataclass(frozen=True)
class EvalCondition:
    """
    A single condition within an eval block.

    Represents a check like "field X operator Y value" — e.g.,
    "state not_equals full" means flag when state is not "full".

    Attributes:
        field: The JSON key to check in the current data object.
        operator: One of 5 allowed operators (equals, not_equals, etc.).
        value: The expected/threshold value. Ignored for is_null operator.
    """

    field: str
    operator: str
    value: Any = None


@dataclass(frozen=True)
class EvalSpec:
    """
    The complete eval specification for a surface rule.

    This is the parsed, validated form of the `eval` block from the YAML
    catalog. It tells the GenericRule evaluator exactly what to check.

    Attributes:
        source: Key into device_facts dict (e.g., "genie_ospf").
        element_id: Template string for finding IDs (e.g., "{hostname}/ospf/{vrf}").
        evidence: Template string for evidence messages.
        iterate: Dot-path for path_resolver (e.g., "vrf.*.neighbor.*"). None = root.
        condition: Single condition (mutually exclusive with conditions).
        conditions_logic: "all" or "any" for multi-condition blocks.
        conditions_checks: List of conditions for multi-condition blocks.
        skip_if_missing: If True, skip silently when source file is absent.
        os_family: If set, only evaluate on devices with this OS family.
    """

    source: str
    element_id: str
    evidence: str
    iterate: str | None = None
    condition: EvalCondition | None = None
    conditions_logic: str | None = None
    conditions_checks: tuple[EvalCondition, ...] = ()
    skip_if_missing: bool = True
    os_family: str | None = None
    # Optional (context_key, regex) pairs: skip an iteration match when the
    # captured wildcard value matches — e.g. {"interfaces": "(?i)^loopback"} to
    # exclude loopback interfaces from an OSPF per-interface check (loopbacks
    # form no adjacency, so adjacency-related findings on them are noise).
    exclude: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RuleDef:
    """
    A validated surface rule definition loaded from the YAML catalog.

    Contains both the original catalog metadata (rule_id, severity, etc.)
    and the parsed eval spec that drives the GenericRule evaluator.

    The python_severity is the engine-level severity (4-level) mapped from
    the catalog-level severity (3-level) with optional per-rule override.

    Attributes:
        rule_id: SCREAMING_SNAKE_CASE identifier (e.g., "OSPF_NEIGHBOR_NOT_FULL").
        catalog_severity: Original 3-level severity from the YAML catalog.
        python_severity: Mapped 4-level severity for the Python engine.
        category: Rule category (e.g., "genie_infrastructure").
        protocol: Protocol family (e.g., "ospf", "bgp").
        tier: Rule tier ("surface" or "deep").
        title: Human-readable title derived from rule_id.
        description: Full description of what the rule detects.
        eval: The parsed eval specification.
    """

    rule_id: str
    catalog_severity: str
    python_severity: str
    category: str
    protocol: str
    tier: str
    title: str
    description: str
    eval: EvalSpec


@dataclass
class CatalogResult:
    """
    The result of loading and filtering the rule catalog.

    Holds all successfully loaded rule definitions plus stats about what
    was filtered out and why. The rules_by_source() method provides the
    index that the GenericRule evaluator uses for batched evaluation.

    Attributes:
        rules: List of all validated RuleDef instances.
        stats: Dict of counts for each filter stage.
    """

    rules: list[RuleDef] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def rules_by_source(self) -> dict[str, list[RuleDef]]:
        """
        Group rules by their eval source key for batched evaluation.

        The GenericRule evaluator processes rules per-device, per-source-family.
        This grouping lets it load genie_ospf.json once and evaluate all 34
        OSPF rules against it, then move to genie_bgp.json, etc.

        Returns:
            Dict mapping source keys to lists of RuleDefs.
            Example: {"genie_ospf": [RuleDef, ...], "genie_bgp": [RuleDef, ...]}
        """
        index: dict[str, list[RuleDef]] = {}
        for rule in self.rules:
            source = rule.eval.source
            if source not in index:
                index[source] = []
            index[source].append(rule)
        return index


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------


def load_catalog(
    catalog_path: str | Path,
    existing_rule_ids: set[str] | None = None,
) -> CatalogResult:
    """
    Load RULE_CATALOG.yaml, filter to surface rules with eval blocks, validate.

    This is the main entry point for the catalog loader. It performs:
    1. Parse the YAML file
    2. Discover existing Python rule IDs (for duplicate checking)
    3. Filter: has eval block? → not cross-device? → valid eval?
    4. Build RuleDef instances with severity mapping
    5. Group and return as CatalogResult

    Args:
        catalog_path: Path to the RULE_CATALOG.yaml file.
        existing_rule_ids: Optional set of rule IDs from existing Python rules.
                           If None, auto-discovers via discovery.discover_rules().

    Returns:
        CatalogResult with loaded rules and filter statistics.

    Raises:
        FileNotFoundError: If the catalog file doesn't exist.
        yaml.YAMLError: If the YAML is malformed.

    Example:
        >>> result = load_catalog("rule-catalog.yaml")
        >>> print(result.stats["loaded"])
        200
        >>> by_source = result.rules_by_source()
        >>> "genie_ospf" in by_source
        True
    """
    catalog_path = Path(catalog_path)

    # -------------------------------------------------------------------------
    # Step 1: Parse YAML
    # -------------------------------------------------------------------------
    # yaml.safe_load() prevents code execution vulnerabilities
    # (unlike yaml.load() which can execute arbitrary Python)
    with open(catalog_path, "r") as f:
        raw_rules = yaml.safe_load(f)

    if not isinstance(raw_rules, list):
        logger.error(f"Expected a list of rules in {catalog_path}, got {type(raw_rules)}")
        return CatalogResult(stats={"total": 0, "loaded": 0, "error": "not a list"})

    total = len(raw_rules)

    # -------------------------------------------------------------------------
    # Step 2: Discover existing Python rule IDs for duplicate checking
    # -------------------------------------------------------------------------
    # If not provided, auto-discover from src/rules/rules/*.py.
    # This prevents YAML rules from producing duplicate findings with
    # the same rule_id as existing Python rules.
    if existing_rule_ids is None:
        try:
            python_rules = discover_rules()
            existing_rule_ids = {r.rule_id for r in python_rules}
            logger.debug(f"Discovered {len(existing_rule_ids)} existing Python rule IDs")
        except Exception as e:
            logger.warning(f"Failed to discover existing rules: {e}")
            existing_rule_ids = set()

    # -------------------------------------------------------------------------
    # Step 3: Filter and validate each rule
    # -------------------------------------------------------------------------
    loaded: list[RuleDef] = []
    skipped_no_eval = 0
    skipped_cross_device = 0
    skipped_invalid = 0
    skipped_duplicate = 0

    for raw in raw_rules:
        rule_id = raw.get("rule_id", "<unknown>")

        # -----------------------------------------------------------------
        # Filter: must have an eval block
        # -----------------------------------------------------------------
        eval_block = raw.get("eval")
        if not eval_block:
            skipped_no_eval += 1
            continue

        # -----------------------------------------------------------------
        # Filter: must not be a cross-device rule
        # -----------------------------------------------------------------
        if raw.get("cross_device") is True or raw.get("cross_device_compare"):
            skipped_cross_device += 1
            logger.debug(f"Skipping cross-device rule: {rule_id}")
            continue

        # -----------------------------------------------------------------
        # Filter: must not duplicate an existing Python rule
        # -----------------------------------------------------------------
        if rule_id in existing_rule_ids:
            skipped_duplicate += 1
            logger.debug(
                f"Skipping YAML rule '{rule_id}' — superseded by Python rule."
            )
            continue

        # -----------------------------------------------------------------
        # Validate eval block and build RuleDef
        # -----------------------------------------------------------------
        rule_def = _validate_and_build(raw, eval_block, rule_id)
        if rule_def is None:
            skipped_invalid += 1
            continue

        loaded.append(rule_def)

    # -------------------------------------------------------------------------
    # Step 4: Sort by rule_id for deterministic order
    # -------------------------------------------------------------------------
    loaded.sort(key=lambda r: r.rule_id)

    stats = {
        "total": total,
        "loaded": len(loaded),
        "skipped_no_eval": skipped_no_eval,
        "skipped_cross_device": skipped_cross_device,
        "skipped_invalid": skipped_invalid,
        "skipped_duplicate": skipped_duplicate,
    }

    logger.info(
        f"Catalog loaded: {len(loaded)}/{total} rules "
        f"(no_eval={skipped_no_eval}, cross_device={skipped_cross_device}, "
        f"invalid={skipped_invalid}, duplicate={skipped_duplicate})"
    )

    return CatalogResult(rules=loaded, stats=stats)


# -------------------------------------------------------------------------
# Private Helpers
# -------------------------------------------------------------------------


def _validate_and_build(
    raw: dict[str, Any],
    eval_block: dict[str, Any],
    rule_id: str,
) -> RuleDef | None:
    """
    Validate an eval block and build a RuleDef if valid.

    Checks that required fields are present, operators are valid,
    and condition/conditions structure is correct. If anything fails,
    logs a warning and returns None (the rule is skipped).

    Args:
        raw: The full raw rule dict from YAML.
        eval_block: The eval sub-dict to validate.
        rule_id: The rule's ID (for error messages).

    Returns:
        A validated RuleDef, or None if validation fails.
    """
    # -------------------------------------------------------------------------
    # Check required eval fields
    # -------------------------------------------------------------------------
    missing = EVAL_REQUIRED_FIELDS - set(eval_block.keys())
    if missing:
        logger.warning(f"Rule '{rule_id}' eval block missing required fields: {sorted(missing)}")
        return None

    # -------------------------------------------------------------------------
    # Validate condition or conditions (must have exactly one)
    # -------------------------------------------------------------------------
    has_condition = "condition" in eval_block and eval_block["condition"]
    has_conditions = "conditions" in eval_block and eval_block["conditions"]

    if not has_condition and not has_conditions:
        logger.warning(f"Rule '{rule_id}' eval block has neither 'condition' nor 'conditions'")
        return None

    if has_condition and has_conditions:
        logger.warning(f"Rule '{rule_id}' eval block has both 'condition' and 'conditions' — use one")
        return None

    # -------------------------------------------------------------------------
    # Parse single condition
    # -------------------------------------------------------------------------
    single_condition = None
    if has_condition:
        single_condition = _parse_condition(eval_block["condition"], rule_id)
        if single_condition is None:
            return None

    # -------------------------------------------------------------------------
    # Parse multi-condition block
    # -------------------------------------------------------------------------
    conditions_logic = None
    conditions_checks: tuple[EvalCondition, ...] = ()
    if has_conditions:
        cond_block = eval_block["conditions"]
        logic = cond_block.get("logic")
        if logic not in VALID_LOGIC:
            logger.warning(
                f"Rule '{rule_id}' conditions.logic must be 'all' or 'any', got '{logic}'"
            )
            return None

        checks_raw = cond_block.get("checks", [])
        if not checks_raw:
            logger.warning(f"Rule '{rule_id}' conditions.checks is empty")
            return None

        parsed_checks = []
        for i, check in enumerate(checks_raw):
            parsed = _parse_condition(check, f"{rule_id}[{i}]")
            if parsed is None:
                return None
            parsed_checks.append(parsed)

        conditions_logic = logic
        # tuple() for immutability — frozen dataclass requires hashable fields
        conditions_checks = tuple(parsed_checks)

    # -------------------------------------------------------------------------
    # Map severity from 3-level catalog to 4-level engine
    # -------------------------------------------------------------------------
    catalog_severity = raw.get("severity", "warning")
    python_severity = _map_severity(catalog_severity, eval_block, rule_id)

    # -------------------------------------------------------------------------
    # Build human-readable title from rule_id
    # -------------------------------------------------------------------------
    # "OSPF_NEIGHBOR_NOT_FULL" → "OSPF Neighbor Not Full"
    title = rule_id.replace("_", " ").title()

    # -------------------------------------------------------------------------
    # Assemble the EvalSpec
    # -------------------------------------------------------------------------
    eval_spec = EvalSpec(
        source=eval_block["source"],
        element_id=eval_block["element_id"],
        evidence=eval_block["evidence"],
        iterate=eval_block.get("iterate"),
        condition=single_condition,
        conditions_logic=conditions_logic,
        conditions_checks=conditions_checks,
        skip_if_missing=eval_block.get("skip_if_missing", True),
        os_family=eval_block.get("os_family"),
        exclude=tuple((k, v) for k, v in (eval_block.get("exclude") or {}).items()),
    )

    # -------------------------------------------------------------------------
    # Assemble the RuleDef
    # -------------------------------------------------------------------------
    return RuleDef(
        rule_id=rule_id,
        catalog_severity=catalog_severity,
        python_severity=python_severity,
        category=raw.get("category", ""),
        protocol=raw.get("protocol", ""),
        tier=raw.get("tier", "surface"),
        title=title,
        description=raw.get("description", ""),
        eval=eval_spec,
    )


def _parse_condition(
    cond: dict[str, Any],
    context: str,
) -> EvalCondition | None:
    """
    Parse and validate a single condition dict from the eval block.

    A condition has the form {"field": "state", "operator": "not_equals", "value": "full"}.
    The "value" field is optional for the "is_null" operator.

    Args:
        cond: The condition dict from YAML.
        context: Rule ID or position string for error messages.

    Returns:
        A validated EvalCondition, or None if invalid.
    """
    if not isinstance(cond, dict):
        logger.warning(f"Rule '{context}' condition is not a dict: {type(cond)}")
        return None

    field_name = cond.get("field")
    operator = cond.get("operator")

    if not field_name:
        logger.warning(f"Rule '{context}' condition missing 'field'")
        return None

    if not operator:
        logger.warning(f"Rule '{context}' condition missing 'operator'")
        return None

    if operator not in VALID_OPERATORS:
        logger.warning(
            f"Rule '{context}' condition has invalid operator '{operator}'. "
            f"Valid: {sorted(VALID_OPERATORS)}"
        )
        return None

    # "value" is required for all operators except "is_null"
    value = cond.get("value")
    if operator != "is_null" and value is None:
        logger.warning(f"Rule '{context}' condition operator '{operator}' requires 'value'")
        return None

    return EvalCondition(field=field_name, operator=operator, value=value)


def _map_severity(
    catalog_severity: str,
    eval_block: dict[str, Any],
    rule_id: str,
) -> str:
    """
    Map 3-level catalog severity to 4-level Python engine severity.

    Default mapping:
        critical → critical
        warning → high
        informational → low

    The eval block can override with `python_severity` to downgrade
    "warning" rules to "medium" when appropriate.

    Args:
        catalog_severity: The severity from the YAML catalog.
        eval_block: The eval block (may contain python_severity override).
        rule_id: For logging purposes.

    Returns:
        The engine-level severity string.
    """
    # Check for per-rule override first
    override = eval_block.get("python_severity")
    if override:
        valid_severities = {"critical", "high", "low", "info"}
        if override in valid_severities:
            return override
        logger.warning(
            f"Rule '{rule_id}' has invalid python_severity '{override}', "
            f"falling back to default mapping"
        )

    # Apply default mapping
    mapped = SEVERITY_MAP.get(catalog_severity)
    if mapped:
        return mapped

    # Unknown severity — default to high and warn
    logger.warning(
        f"Rule '{rule_id}' has unknown severity '{catalog_severity}', defaulting to 'high'"
    )
    return "high"
