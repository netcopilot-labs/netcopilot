"""
Rule Autodiscovery - Automatically find and load all rule classes.

This module provides the autodiscovery mechanism that finds all rules
in the src/rules/rules/ directory. Adding a new rule is as simple as
adding a new .py file - no registration required.

Architecture:
    src/rules/rules/
    ├── collection_failure.py  ──┐
    ├── isolated_device.py     ──┼──► discover_rules() ──► [Rule instances]
    ├── unidirectional_link.py ──┤
    ├── link_down.py           ──┤
    └── duplicate_ip.py        ──┘

    For each .py file:
        1. Import the module dynamically
        2. Find classes that inherit from BaseRule
        3. Skip abstract classes
        4. Instantiate and collect

How It Works:
    Python's importlib allows us to import modules by name at runtime.
    We scan the rules/ directory, import each .py file, then use
    inspect to find classes that inherit from BaseRule.

    This is called "autodiscovery" because new rules are automatically
    found without needing to register them anywhere.

Design Principles:
    - Zero configuration: Just add a file
    - Graceful degradation: One bad file doesn't break others
    - Deterministic: Same files always produce same order (sorted by rule_id)
    - Explicit errors: Import failures are logged clearly

Example Usage:
    >>> from netcopilot.rules.discovery import discover_rules
    >>> rules = discover_rules()
    >>> for rule in rules:
    ...     print(f"{rule.rule_id}: {rule.title}")
    COLLECTION_FAILURE: Collection Failure
    DUPLICATE_IP: Duplicate IP Address
    ISOLATED_DEVICE: Isolated Device
    LINK_DOWN: Link Down
    UNIDIRECTIONAL_LINK: Unidirectional Link
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.base_rule import BaseRule

# -------------------------------------------------------------------------
# Type checking imports
# -------------------------------------------------------------------------
if TYPE_CHECKING:
    pass

# -------------------------------------------------------------------------
# Module-level logger
# -------------------------------------------------------------------------
# We use a logger instead of print() so log levels can be controlled
logger = logging.getLogger(__name__)


def discover_rules(rules_dir: Path | None = None) -> list[BaseRule]:
    """
    Discover and instantiate all rule classes in the rules directory.

    This function scans the rules directory for Python files, imports
    each one, finds classes that inherit from BaseRule, and returns
    instantiated rule objects.

    Algorithm:
        1. Find all .py files in rules directory (excluding __init__.py, _*.py)
        2. For each file:
           a. Import the module dynamically using importlib
           b. Find all classes defined in that module
           c. Filter to classes that inherit from BaseRule
           d. Skip abstract classes (they can't be instantiated)
           e. Instantiate each rule class
        3. Sort rules by rule_id for deterministic ordering
        4. Return the list

    Error Handling:
        - If a file fails to import, log warning and continue
        - If a class fails to instantiate, log warning and continue
        - One broken rule doesn't break the whole engine

    Args:
        rules_dir: Path to the rules directory. If None, uses the default
                   location (src/rules/rules/).

    Returns:
        List of instantiated BaseRule subclasses, sorted by rule_id.

    Example:
        >>> rules = discover_rules()
        >>> len(rules)
        5
        >>> rules[0].rule_id
        'COLLECTION_FAILURE'
    """
    # -------------------------------------------------------------------------
    # Determine rules directory
    # -------------------------------------------------------------------------
    # If not provided, use the default location relative to this file
    if rules_dir is None:
        # This file is at: src/rules/discovery.py
        # Rules are at: src/rules/rules/
        rules_dir = Path(__file__).parent / "rules"

    # -------------------------------------------------------------------------
    # Validate directory exists
    # -------------------------------------------------------------------------
    if not rules_dir.exists():
        logger.warning(f"Rules directory not found: {rules_dir}")
        return []

    if not rules_dir.is_dir():
        logger.warning(f"Rules path is not a directory: {rules_dir}")
        return []

    # -------------------------------------------------------------------------
    # Find all Python files in the rules directory
    # -------------------------------------------------------------------------
    # We use glob to find .py files, then filter out special files
    #
    # Excluded files:
    # - __init__.py: Package initialization, not a rule
    # - _*.py: Private modules by convention (e.g., _helpers.py)
    py_files = sorted(rules_dir.glob("*.py"))

    rule_files = [
        f for f in py_files
        if f.name != "__init__.py" and not f.name.startswith("_")
    ]

    logger.debug(f"Found {len(rule_files)} rule files in {rules_dir}")

    # -------------------------------------------------------------------------
    # Import each module and find rule classes
    # -------------------------------------------------------------------------
    discovered_rules: list[BaseRule] = []

    for rule_file in rule_files:
        try:
            # -----------------------------------------------------------------
            # Import the module dynamically
            # -----------------------------------------------------------------
            # We use importlib to load a module from a file path.
            # This is the standard way to do dynamic imports in Python.
            #
            # Steps:
            # 1. Create a module spec from the file location
            # 2. Create a module object from the spec
            # 3. Execute the module (runs the code)

            # Module name is the filename without .py extension
            module_name = f"netcopilot.rules.rules.{rule_file.stem}"

            # Create a spec that describes how to load the module
            spec = importlib.util.spec_from_file_location(module_name, rule_file)

            if spec is None or spec.loader is None:
                logger.warning(f"Could not create module spec for: {rule_file}")
                continue

            # Create an empty module object
            module = importlib.util.module_from_spec(spec)

            # Execute the module code (this runs the file)
            spec.loader.exec_module(module)

            # -----------------------------------------------------------------
            # Find all BaseRule subclasses in this module
            # -----------------------------------------------------------------
            # inspect.getmembers() returns all attributes of the module
            # We filter to classes (inspect.isclass) and check inheritance
            for name, obj in inspect.getmembers(module, inspect.isclass):

                # Skip if not a subclass of BaseRule
                if not issubclass(obj, BaseRule):
                    continue

                # Skip BaseRule itself (it gets imported into the module)
                if obj is BaseRule:
                    continue

                # Skip if the class was imported from another module
                # (we only want classes DEFINED in this file)
                if obj.__module__ != module_name:
                    continue

                # Skip abstract classes (they have __abstractmethods__)
                if getattr(obj, "__abstractmethods__", None):
                    logger.debug(f"Skipping abstract class: {name}")
                    continue

                # ---------------------------------------------------------
                # Instantiate the rule
                # ---------------------------------------------------------
                try:
                    rule_instance = obj()
                    discovered_rules.append(rule_instance)
                    logger.debug(f"Discovered rule: {rule_instance.rule_id}")

                except Exception as e:
                    logger.warning(
                        f"Failed to instantiate rule class '{name}' "
                        f"from {rule_file.name}: {e}"
                    )

        except Exception as e:
            # -----------------------------------------------------------------
            # Handle import errors gracefully
            # -----------------------------------------------------------------
            # One broken file shouldn't break the whole engine
            logger.warning(f"Failed to import rule file {rule_file.name}: {e}")

    # -------------------------------------------------------------------------
    # Sort rules by rule_id for deterministic ordering
    # -------------------------------------------------------------------------
    # This ensures the same rules always run in the same order,
    # making the output deterministic and predictable.
    discovered_rules.sort(key=lambda r: r.rule_id)

    logger.info(f"Discovered {len(discovered_rules)} rules")

    return discovered_rules


def get_rule_by_id(rule_id: str) -> BaseRule | None:
    """
    Find a specific rule by its rule_id.

    This is a convenience function for looking up a single rule.
    It discovers all rules and returns the one with the matching ID.

    Args:
        rule_id: The rule ID to find (e.g., "LINK_DOWN")

    Returns:
        The rule instance if found, None otherwise

    Example:
        >>> rule = get_rule_by_id("LINK_DOWN")
        >>> rule.title
        'Link Down'
    """
    rules = discover_rules()

    for rule in rules:
        if rule.rule_id == rule_id:
            return rule

    return None
