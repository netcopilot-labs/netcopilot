"""
Finding Data Class - Structured output from rule evaluation.

This module defines the Finding class that represents a single issue
detected by a rule. Findings are the primary output of the rule engine
and are written to findings.json for analysis.

Architecture:
    Rule.evaluate()
         │
         ▼
    Finding.create()  ──► Finding instance
         │
         ▼
    Finding.to_dict() ──► JSON-serializable dict
         │
         ▼
    findings.json

Finding ID Format:
    {RULE_ID}::{element_id}

    Examples:
    - LINK_DOWN::core-rtr-01:Hu1/0/1--dist-sw-01:Hu0/0/1/0
    - ISOLATED_DEVICE::edge-rtr-01
    - DUPLICATE_IP::192.0.2.100

    This format is:
    - Deterministic: Same issue = same ID across runs
    - Self-describing: ID tells you the rule and affected element
    - Traceable: Maps directly to model elements

Design Principles:
    - Immutable: Findings don't change after creation
    - Complete: All required fields must be provided
    - Traceable: Every finding links to model elements via evidence
    - Serializable: to_dict() produces JSON-ready output

Example Usage:
    >>> from netcopilot.rules.finding import Finding
    >>>
    >>> finding = Finding.create(
    ...     rule_id="LINK_DOWN",
    ...     severity="high",
    ...     title="Link Down",
    ...     element_type="link",
    ...     element_id="core-rtr-01:Hu1/0/1--dist-sw-01:Hu0/0/1/0",
    ...     message="Link is operationally down",
    ...     key_facts={"status": "down"},
    ...     recommendation="Check physical connectivity"
    ... )
    >>> print(finding.finding_id)
    LINK_DOWN::core-rtr-01:Hu1/0/1--dist-sw-01:Hu0/0/1/0
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# -------------------------------------------------------------------------
# Valid values for validation (finding-emit set)
# -------------------------------------------------------------------------
# These are the severity values a Finding can CARRY at output time.
# Includes "cis" which is post-applied by engine._apply_cis_severity()
# to findings produced by CIS-prefixed rules.
#
# NOTE — distinct from base_rule.py's VALID_SEVERITIES (rule-declaration
# set, 4 values). A rule subclass declares ∈ {critical, high, low, info};
# the engine post-processes CIS-rule findings to severity="cis" before
# they reach this Finding constructor's validator (which accepts all 5).
VALID_SEVERITIES = {"critical", "high", "low", "info", "cis"}
VALID_ELEMENT_TYPES = {"device", "interface", "link"}


@dataclass(frozen=True)
class Finding:
    """
    Represents a single finding from rule evaluation.

    This is a frozen dataclass, meaning instances are immutable after
    creation. This ensures findings don't accidentally change and
    supports using findings as dict keys or set members.

    The @dataclass decorator automatically generates:
    - __init__: Constructor from fields
    - __repr__: String representation for debugging
    - __eq__: Equality comparison
    - __hash__: Hash for use in sets/dicts (because frozen=True)

    Fields:
        finding_id: Unique identifier in format RULE_ID::element_id
        rule_id: Which rule generated this finding
        severity: Impact level ∈ {critical, high, low, info, cis}.
                  "cis" is post-applied to CIS-rule findings by the engine.
        title: Short human-readable name
        message: Detailed explanation of the issue
        evidence: Dict with element_type, element_id, key_facts
        recommendation: Suggested action to resolve
        detected_at: ISO8601 timestamp when finding was created

    Example:
        finding = Finding(
            finding_id="LINK_DOWN::some-link-id",
            rule_id="LINK_DOWN",
            severity="high",
            title="Link Down",
            message="Link between A and B is down",
            evidence={
                "element_type": "link",
                "element_id": "some-link-id",
                "key_facts": {"status": "down"}
            },
            recommendation="Check connectivity",
            detected_at="2026-01-31T10:00:00+00:00"
        )
    """

    # -------------------------------------------------------------------------
    # Required fields
    # -------------------------------------------------------------------------
    # All fields are required - no defaults except detected_at
    finding_id: str
    rule_id: str
    severity: str
    title: str
    message: str
    evidence: dict[str, Any]
    recommendation: str
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """
        Validate finding after initialization.

        __post_init__ is called by dataclass after __init__ completes.
        This is where we validate that all fields have valid values.

        Note: Because this is a frozen dataclass, we can't modify fields
        here. We can only raise errors for invalid values.

        Raises:
            ValueError: If any field has an invalid value
        """
        # -------------------------------------------------------------------------
        # Validate severity
        # -------------------------------------------------------------------------
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Allowed values: {sorted(VALID_SEVERITIES)}"
            )

        # -------------------------------------------------------------------------
        # Validate evidence structure
        # -------------------------------------------------------------------------
        if not isinstance(self.evidence, dict):
            raise ValueError("Evidence must be a dictionary")

        required_evidence_keys = {"element_type", "element_id", "key_facts"}
        missing_keys = required_evidence_keys - set(self.evidence.keys())
        if missing_keys:
            raise ValueError(
                f"Evidence missing required keys: {sorted(missing_keys)}. "
                f"Evidence must have: element_type, element_id, key_facts"
            )

        # Validate element_type value
        element_type = self.evidence.get("element_type")
        if element_type not in VALID_ELEMENT_TYPES:
            raise ValueError(
                f"Invalid element_type '{element_type}'. "
                f"Allowed values: {sorted(VALID_ELEMENT_TYPES)}"
            )

        # -------------------------------------------------------------------------
        # Validate finding_id format
        # -------------------------------------------------------------------------
        if "::" not in self.finding_id:
            raise ValueError(
                f"Invalid finding_id '{self.finding_id}'. "
                f"Must be in format RULE_ID::element_id"
            )

        # Check that finding_id starts with rule_id
        if not self.finding_id.startswith(f"{self.rule_id}::"):
            raise ValueError(
                f"Finding ID '{self.finding_id}' must start with rule_id '{self.rule_id}::'"
            )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert finding to JSON-serializable dictionary.

        The output matches the findings.json schema exactly:
        {
            "finding_id": "RULE_ID::element_id",
            "rule_id": "RULE_ID",
            "severity": "high",
            "title": "Rule Title",
            "message": "Detailed message",
            "evidence": {
                "element_type": "link",
                "element_id": "...",
                "key_facts": {...}
            },
            "recommendation": "What to do",
            "detected_at": "2026-01-31T10:00:00+00:00"
        }

        Returns:
            Dictionary ready for JSON serialization
        """
        d = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "detected_at": self.detected_at,
        }
        if self.tags:
            d["tags"] = list(self.tags)
        return d

    @classmethod
    def create(
        cls,
        rule_id: str,
        severity: str,
        title: str,
        element_type: str,
        element_id: str,
        message: str,
        key_facts: dict[str, Any],
        recommendation: str,
        detected_at: str | None = None,
        member_id: int | None = None,
    ) -> "Finding":
        """
        Factory method to create a Finding with automatic ID generation.

        This is the recommended way to create findings in rules. It:
        - Generates the finding_id from rule_id and element_id
        - Assembles the evidence dict from components
        - Sets detected_at to current time if not provided

        Why a factory method?
        - Simpler API: Callers don't need to build finding_id or evidence
        - Consistency: Ensures finding_id format is always correct
        - Convenience: Less boilerplate in rule implementations

        Args:
            rule_id: The rule ID (e.g., "LINK_DOWN")
            severity: Severity level ∈ {critical, high, low, info, cis}
            title: Short human-readable title
            element_type: Type of affected element (device, interface, link)
            element_id: ID of the affected element from the model
            message: Detailed explanation of the issue
            key_facts: Additional context about the finding
            recommendation: Suggested action to resolve
            detected_at: ISO8601 timestamp (default: current time)
            member_id: Optional stack/HA member ID for per-member attribution

        Returns:
            New Finding instance

        Example:
            finding = Finding.create(
                rule_id="LINK_DOWN",
                severity="high",
                title="Link Down",
                element_type="link",
                element_id="core-rtr-01:Hu1/0/1--dist-sw-01:Hu0/0/1/0",
                message="Link is operationally down",
                key_facts={"status": "down", "local_device": "core-rtr-01"},
                recommendation="Check physical connectivity"
            )
        """
        # -------------------------------------------------------------------------
        # Generate finding_id
        # -------------------------------------------------------------------------
        # Format: RULE_ID::element_id
        # This is deterministic - same rule + element = same ID
        finding_id = f"{rule_id}::{element_id}"

        # -------------------------------------------------------------------------
        # Build evidence structure
        # -------------------------------------------------------------------------
        evidence = {
            "element_type": element_type,
            "element_id": element_id,
            "key_facts": key_facts,
        }

        # Promote member_id to top-level evidence for dashboard access
        if member_id is not None:
            evidence["member_id"] = member_id

        # -------------------------------------------------------------------------
        # Set timestamp
        # -------------------------------------------------------------------------
        if detected_at is None:
            detected_at = datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------------------------------
        # Create and return Finding
        # -------------------------------------------------------------------------
        return cls(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            message=message,
            evidence=evidence,
            recommendation=recommendation,
            detected_at=detected_at,
        )

    @classmethod
    def create_from_rule(
        cls,
        rule: Any,  # BaseRule, but avoiding circular import
        element_type: str,
        element_id: str,
        message: str,
        key_facts: dict[str, Any],
        recommendation: str,
        severity_override: str | None = None,
        member_id: int | None = None,
    ) -> "Finding":
        """
        Factory method to create a Finding from a rule instance.

        This method extracts rule_id, severity, and title from the rule
        object, making it even simpler to create findings in rules.

        Args:
            rule: The rule instance (must have rule_id, severity, title)
            element_type: Type of affected element (device, interface, link)
            element_id: ID of the affected element from the model
            message: Detailed explanation of the issue
            key_facts: Additional context about the finding
            recommendation: Suggested action to resolve
            severity_override: Override the rule's default severity
            member_id: Optional stack/HA member ID for per-member attribution

        Returns:
            New Finding instance

        Example:
            # Inside a rule's evaluate() method:
            finding = Finding.create_from_rule(
                rule=self,
                element_type="link",
                element_id=link["link_id"],
                message="Link is down",
                key_facts={"status": link["status"]},
                recommendation="Check connectivity"
            )
        """
        return cls.create(
            rule_id=rule.rule_id,
            severity=severity_override or rule.severity,
            title=rule.title,
            element_type=element_type,
            element_id=element_id,
            message=message,
            key_facts=key_facts,
            recommendation=recommendation,
            member_id=member_id,
        )
