"""Phase 1 deep rules — one module per rule (or rule family).

Every public class here inherits :class:`netcopilot.rules.base_rule.BaseRule` and
is picked up automatically by :func:`netcopilot.rules.discovery.discover_rules`
(no registration needed). Files prefixed with ``_`` are helpers, not rules.
"""
