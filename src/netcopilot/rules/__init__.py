"""Rules & findings — evaluate a collected/modelled run into findings.

The rule engine reads ``network_model.json`` + per-device facts and emits
:class:`Finding` objects, written to ``findings/findings.json``. It is
file-in/file-out — no Neo4j (the graph loader owns that).

This package's foundation (F3a):

* :class:`BaseRule` — the abstract contract every rule inherits; the
  ``__init_subclass__`` hook fails fast on a malformed rule at import time.
* :class:`Finding` — the immutable result of a rule firing.
* :func:`discover_rules` / :func:`get_rule_by_id` — zero-config autodiscovery of
  rule classes under ``rules/``.
* :func:`resolve` — dot-path/wildcard traversal of nested Genie facts.

Engine core (F3b): :func:`run_rules` orchestrates the three phases and
:func:`write_findings` persists the result; :func:`load_catalog` +
:func:`evaluate_device` drive the Phase-2 YAML surface rules. The rules
themselves (Phase 1/3) and the catalog land in later slices.
"""
from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.catalog_loader import load_catalog
from netcopilot.rules.discovery import discover_rules, get_rule_by_id
from netcopilot.rules.engine import run_rules
from netcopilot.rules.finding import Finding
from netcopilot.rules.findings_writer import write_findings
from netcopilot.rules.generic_evaluator import evaluate_device
from netcopilot.rules.path_resolver import resolve

__all__ = [
    "BaseRule",
    "Finding",
    "discover_rules",
    "evaluate_device",
    "get_rule_by_id",
    "load_catalog",
    "resolve",
    "run_rules",
    "write_findings",
]
