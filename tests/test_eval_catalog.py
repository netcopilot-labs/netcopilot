"""The eval catalogue schema gate (s23-3) — CI-safe, no LLM, no Neo4j.

Two jobs:

1. The SHIPPED catalogue loads clean against the live tool registry. This is
   the check that catches a tool rename leaving a stale name in an assertion
   (exactly what the s23-1 get_security_policies → get_cisco_policies rename
   would have silently broken: ``tools_any`` matched nothing, the check failed
   at eval time instead of load time).
2. The validator itself rejects each malformed shape LOUDLY. Motivation:
   ``all({})`` is True, so before s23-3 a question with an empty or typo'd
   ``expect`` block passed forever and looked like coverage.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netcopilot.mcp.registry import TOOL_SCHEMAS  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "run_eval", ROOT / "scripts" / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)

TOOL_NAMES = {t["name"] for t in TOOL_SCHEMAS}
CATALOG_PATH = ROOT / "scripts" / "eval" / "question_catalog.yaml"


def _load_catalog() -> list[dict]:
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


def test_shipped_catalog_is_valid():
    catalog = run_eval._validate_catalog(_load_catalog(), TOOL_NAMES)
    assert len(catalog) >= 40


def test_every_tool_is_asserted():
    """s23-2 exit criterion, kept true mechanically: all 33 registry tools
    appear in at least one question's tools_any."""
    asserted: set[str] = set()
    for q in _load_catalog():
        asserted.update(q["expect"].get("tools_any", []))
    missing = TOOL_NAMES - asserted
    assert not missing, (
        f"tools with zero eval coverage: {sorted(missing)} — every new tool "
        "ships with at least one catalogue question (s23-2)")


def test_probe_tools_exist_in_registry():
    for feat, spec in run_eval.FEATURE_PROBES.items():
        assert spec[0] in ("verdict", "status", "env"), f"'{feat}': bad kind"
        if spec[0] != "env":
            assert spec[1] in TOOL_NAMES, \
                f"probe '{feat}' names unknown tool '{spec[1]}'"


@pytest.mark.parametrize("bad, fragment", [
    ([], "non-empty"),
    ([{"question": "no id"}], "id/question"),
    ([{"id": "a", "question": "?", "expect": {"tools_any": ["get_findings"]}},
      {"id": "a", "question": "?", "expect": {"tools_any": ["get_findings"]}}],
     "duplicate"),
    ([{"id": "a", "question": "?"}], "empty or missing expect"),
    ([{"id": "a", "question": "?", "expect": {}}], "empty or missing expect"),
    ([{"id": "a", "question": "?", "expect": {"tools_anyy": ["get_findings"]}}],
     "unknown expect key"),
    ([{"id": "a", "question": "?", "expect": {"tools_any": ["not_a_tool"]}}],
     "unknown tool"),
    ([{"id": "a", "question": "?", "expect": {"tools_none": ["get_findings"]}}],
     "tools_none must be bool"),
    ([{"id": "a", "question": "?", "expect": {"tools_any": "get_findings"}}],
     "tools_any must be list"),
    ([{"id": "a", "question": "?", "expect": {"routing_absent": True},
       "requires": ["warp_drive"]}], "unknown requires feature"),
    ([{"id": "a", "question": "?", "expect": {"routing_absent": True},
       "typo_key": 1}], "unknown key"),
])
def test_validator_rejects(bad, fragment):
    with pytest.raises(run_eval.CatalogError, match=fragment):
        run_eval._validate_catalog(bad, TOOL_NAMES)
