"""
Base Rule Class - Abstract contract for all network analysis rules.

This module defines the BaseRule abstract base class that all rules
must inherit from. It enforces the contract that rules must follow
and provides common functionality.

Architecture:
    BaseRule (Abstract)
         │
         ├── CollectionFailureRule
         ├── IsolatedDeviceRule
         ├── UnidirectionalLinkRule
         ├── LinkDownRule
         └── DuplicateIpRule

    Each rule inherits from BaseRule and:
    1. Sets required class attributes (rule_id, severity, title, description)
    2. Implements evaluate(model, context) -> list[Finding]
    3. Optionally overrides is_enabled() for conditional rules

Design Principles:
    - Contract enforcement: Missing attributes = clear error at class definition
    - Single responsibility: Each rule detects one type of issue
    - Independence: Rules don't depend on each other's output
    - Determinism: Same input always produces same output

Example Usage:
    >>> from netcopilot.rules.base_rule import BaseRule
    >>> from netcopilot.rules.finding import Finding
    >>>
    >>> class MyRule(BaseRule):
    ...     rule_id = "MY_RULE"
    ...     severity = "high"
    ...     title = "My Rule"
    ...     description = "Detects something"
    ...
    ...     def evaluate(self, model, context):
    ...         return []  # No findings
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

# -------------------------------------------------------------------------
# Type checking imports
# -------------------------------------------------------------------------
# TYPE_CHECKING is False at runtime, True during static analysis.
# This avoids circular imports while still providing type hints.
if TYPE_CHECKING:
    from netcopilot.rules.finding import Finding


# -------------------------------------------------------------------------
# Valid severity levels (rule-declaration set)
# -------------------------------------------------------------------------
# These are the only severity values a rule subclass can DECLARE via the
# `severity` class attribute. Used by __init_subclass__ for fail-fast
# validation at class-definition time (raises TypeError immediately).
#
# NOTE — distinct from finding.py's VALID_SEVERITIES (which is the
# 5-value set including "cis"). The "cis" severity is NEVER declared by
# a rule subclass; it is post-applied to findings produced by CIS-prefixed
# rules in engine._apply_cis_severity(). So:
#   - rule subclasses declare ∈ {critical, high, low, info}  (this set)
#   - findings carry        ∈ {critical, high, low, info, cis}  (finding.py)
VALID_SEVERITIES = {"critical", "high", "low", "info"}


class BaseRule(ABC):
    """
    Abstract base class for all network analysis rules.

    Every rule must inherit from this class and:
    1. Define class attributes: rule_id, severity, title, description
    2. Implement the evaluate() method

    The __init_subclass__ mechanism enforces this contract - attempting
    to define a subclass without these attributes raises TypeError
    immediately at class definition time.

    Class Attributes:
        rule_id (str): Unique identifier, e.g., "LINK_DOWN"
        severity (str): Default severity ∈ {critical, high, low, info}.
                        "cis" is post-applied by engine._apply_cis_severity()
                        and never declared by a rule subclass.
        title (str): Human-readable name, e.g., "Link Down"
        description (str): What this rule detects

    Methods:
        evaluate(model, context) -> list[Finding]: Abstract, must implement
        is_enabled() -> bool: Optional, defaults to True

    Example:
        class LinkDownRule(BaseRule):
            rule_id = "LINK_DOWN"
            severity = "high"
            title = "Link Down"
            description = "Detects links with down status"

            def evaluate(self, model, context):
                findings = []
                for link in model.get("links", []):
                    if link.get("status") == "down":
                        findings.append(...)
                return findings
    """

    # -------------------------------------------------------------------------
    # Required class attributes (must be overridden by subclasses)
    # -------------------------------------------------------------------------
    # These are declared here for documentation and type hints.
    # Actual values MUST be provided by subclasses.
    rule_id: str
    severity: str
    title: str
    description: str

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Validate that subclasses define required attributes.

        Python calls __init_subclass__ when a new subclass is defined.
        This is the perfect place to enforce our contract - errors
        happen immediately at class definition, not later at runtime.

        This pattern is cleaner than metaclasses and more Pythonic
        for simple validation like this.

        Args:
            **kwargs: Passed to parent __init_subclass__

        Raises:
            TypeError: If required attributes are missing or invalid
        """
        super().__init_subclass__(**kwargs)

        # -------------------------------------------------------------------------
        # Skip validation for abstract subclasses
        # -------------------------------------------------------------------------
        # If a subclass is also abstract (defines abstractmethod), we don't
        # require it to have all attributes - it might be an intermediate class.
        # We check if the class has any abstract methods.
        if getattr(cls, "__abstractmethods__", None):
            return

        # -------------------------------------------------------------------------
        # Check required attributes exist
        # -------------------------------------------------------------------------
        required_attrs = ["rule_id", "severity", "title", "description"]

        for attr in required_attrs:
            # Check if attribute exists on the class (not inherited from BaseRule)
            if not hasattr(cls, attr) or getattr(cls, attr, None) is None:
                raise TypeError(
                    f"Rule class '{cls.__name__}' must define '{attr}' attribute. "
                    f"Example: {attr} = \"{'MY_RULE' if attr == 'rule_id' else 'value'}\""
                )

        # -------------------------------------------------------------------------
        # Validate severity value
        # -------------------------------------------------------------------------
        severity = getattr(cls, "severity", None)
        if severity not in VALID_SEVERITIES:
            raise TypeError(
                f"Rule class '{cls.__name__}' has invalid severity '{severity}'. "
                f"Allowed values: {sorted(VALID_SEVERITIES)}"
            )

        # -------------------------------------------------------------------------
        # Validate rule_id format
        # -------------------------------------------------------------------------
        # Rule IDs should be uppercase with underscores (SCREAMING_SNAKE_CASE)
        rule_id = getattr(cls, "rule_id", "")
        if not rule_id.replace("_", "").isupper():
            raise TypeError(
                f"Rule class '{cls.__name__}' has invalid rule_id '{rule_id}'. "
                f"Rule IDs must be SCREAMING_SNAKE_CASE (e.g., 'LINK_DOWN')"
            )

    @abstractmethod
    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list["Finding"]:
        """
        Evaluate the rule against the network model.

        This is the main detection logic for the rule. Implementations
        should examine the model and context, then return a list of
        Finding objects for any issues detected.

        The method must be:
        - Deterministic: Same model/context → same findings
        - Side-effect free: Don't modify model or context
        - Independent: Don't rely on other rules' output

        Args:
            model: The network model dictionary containing:
                - model_metadata: Run info
                - devices: List of device dicts
                - interfaces: List of interface dicts
                - links: List of link dicts
                - topology_warnings: List of warning dicts

            context: Additional context dictionary containing:
                - manifest: The run manifest with device connection info
                - run_id: The current run ID
                - Additional context may be added in future

        Returns:
            List of Finding objects for detected issues.
            Return empty list if no issues found.

        Example:
            def evaluate(self, model, context):
                findings = []
                for link in model.get("links", []):
                    if link.get("status") == "down":
                        finding = Finding.create(
                            rule=self,
                            element_type="link",
                            element_id=link["link_id"],
                            message="Link is operationally down",
                            key_facts={"status": link["status"]},
                            recommendation="Check physical connectivity"
                        )
                        findings.append(finding)
                return findings
        """
        pass  # pragma: no cover

    def is_enabled(self) -> bool:
        """
        Check if this rule should be executed.

        Override this method to conditionally disable a rule based
        on configuration or context. Default implementation always
        returns True.

        This is useful for:
        - Feature flags
        - Environment-specific rules
        - Rules that require specific data to be present

        Returns:
            True if rule should run, False to skip

        Example:
            def is_enabled(self):
                # Only run in production
                return os.environ.get("ENV") == "production"
        """
        return True

    def __repr__(self) -> str:
        """
        String representation for debugging.

        Returns:
            String like "LinkDownRule(LINK_DOWN, severity=high)"
        """
        return f"{self.__class__.__name__}({self.rule_id}, severity={self.severity})"
