"""Deprecated-rule manifest: filter behaviour + the drift-guarding contract.

Rules whose ``is_enabled()`` returns False must not surface in the dashboard,
even when historical Neo4j / JSON state still contains their findings from
past runs. The manifest (``DEPRECATED_RULE_IDS``) and the render-time filter
(``_strip_deprecated_rules``) enforce that, and the contract test below keeps
the manifest in sync with the rule implementations.

Pure-function tests — no Neo4j, no FastAPI, no HTTP.
"""

from netcopilot.deprecated_rules import DEPRECATED_RULE_IDS
from netcopilot.findings import _strip_deprecated_rules
from netcopilot.rules.discovery import discover_rules


# ── Filter behaviour ────────────────────────────────────────────────────────

def test_filter_removes_deprecated_rule_findings():
    findings = [
        {"rule_id": "STATIC_ROUTE_NO_REDUNDANCY", "finding_id": "f1"},
        {"rule_id": "STATIC_ROUTE_NEXT_HOP_UNREACHABLE", "finding_id": "f2"},
        {"rule_id": "VLAN_MISSING_SVI", "finding_id": "f3"},
        {"rule_id": "WEAK_PASSWORD_HASH", "finding_id": "f4"},
        {"rule_id": "INTF_ADMIN_DOWN", "finding_id": "f5"},
    ]
    result = _strip_deprecated_rules(findings)
    ids = [f["finding_id"] for f in result]
    assert ids == ["f2", "f4"], f"expected non-deprecated only, got {ids}"


def test_filter_passes_through_none():
    assert _strip_deprecated_rules(None) is None


def test_filter_passes_through_empty():
    assert _strip_deprecated_rules([]) == []


def test_filter_keeps_findings_without_rule_id():
    """Defensive: findings with no rule_id should not be silently dropped."""
    findings = [{"finding_id": "f1", "message": "synthetic"}]
    assert _strip_deprecated_rules(findings) == findings


# ── Contract: manifest ⇔ is_enabled() ───────────────────────────────────────

def test_deprecated_rules_match_is_enabled():
    """Invariant: rule.is_enabled() == False  ⇔  rule.rule_id in DEPRECATED_RULE_IDS."""
    rules = discover_rules()
    disabled_in_code = {r.rule_id for r in rules if not r.is_enabled()}

    missing_from_manifest = disabled_in_code - DEPRECATED_RULE_IDS
    stale_in_manifest = DEPRECATED_RULE_IDS - disabled_in_code

    assert not missing_from_manifest, (
        f"Rules with is_enabled()==False but not in DEPRECATED_RULE_IDS: "
        f"{sorted(missing_from_manifest)}. Add them to deprecated_rules.py."
    )
    assert not stale_in_manifest, (
        f"rule_ids in DEPRECATED_RULE_IDS but no longer disabled: "
        f"{sorted(stale_in_manifest)}. Remove from deprecated_rules.py — the rule is active again."
    )
