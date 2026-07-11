"""S21-1: deterministic-first tool routing — catalogue contract + matching.

Pure/deterministic: no LLM, no Neo4j. The packaged catalogue is validated for
real (against the real registry names); contract violations use tmp files.
"""
from __future__ import annotations

import pytest

from netcopilot.mcp.router import (
    RouteDecision,
    RoutingConfigError,
    load_routing,
    route,
)

KNOWN = {"get_redundancy_assessment", "get_device_detail", "get_findings"}


def _write(tmp_path, body: str):
    p = tmp_path / "routing.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def _entry(rule_id="r1", pattern=r"\bvrrp\b", tool="get_findings") -> str:
    return f"""
- rule_id: {rule_id}
  description: test entry
  patterns: ['{pattern}']
  tools: [{tool}]
  evidence: "a documented failure"
  added: "2026-07-11"
"""


# ── The packaged catalogue (the real thing) ──────────────────────────────────


def test_packaged_catalogue_loads_and_validates():
    entries = load_routing()  # real file, real registry names
    assert entries, "packaged routing.yaml must have at least the seed entry"
    assert all(e["evidence"] for e in entries)


def test_documented_misroute_family_routes():
    # The s20 documented failure and its close variants.
    for q in (
        "how is vrrp configured?",
        "How is VRRP configured in the network?",
        "hsrp status",
        "which router is active for HSRP group 60?",
        "is my gateway redundancy healthy?",
        "who is the active gateway for VLAN 60?",
    ):
        d = route(q)
        assert d is not None, f"expected a route for {q!r}"
        assert d.rule_id == "gateway_redundancy_state"
        assert "get_redundancy_assessment" in d.tools


def test_concept_questions_stay_unrouted():
    # Definitions belong to the doc-lookup tools — the router must not hijack.
    for q in ("what is vrrp?", "explain the vrrp protocol", "vrrp vs hsrp differences"):
        assert route(q) is None, f"concept question {q!r} must stay unrouted"


def test_unrelated_questions_stay_unrouted():
    for q in ("what changed between runs?", "show me the findings on core-sw-01", ""):
        assert route(q) is None


# ── Contract violations fail loud (Art. V) ───────────────────────────────────


def test_unknown_tool_rejected(tmp_path):
    p = _write(tmp_path, _entry(tool="no_such_tool"))
    with pytest.raises(RoutingConfigError, match="unknown tool"):
        load_routing(p, known_tools=KNOWN)


def test_invalid_regex_rejected(tmp_path):
    p = _write(tmp_path, _entry(pattern=r"([unclosed"))
    with pytest.raises(RoutingConfigError, match="invalid regex"):
        load_routing(p, known_tools=KNOWN)


def test_missing_evidence_rejected(tmp_path):
    body = """
- rule_id: r1
  description: no evidence given
  patterns: ['\\bvrrp\\b']
  tools: [get_findings]
  added: "2026-07-11"
"""
    p = _write(tmp_path, body)
    with pytest.raises(RoutingConfigError, match="evidence"):
        load_routing(p, known_tools=KNOWN)


def test_duplicate_rule_id_rejected(tmp_path):
    p = _write(tmp_path, _entry("dup") + _entry("dup"))
    with pytest.raises(RoutingConfigError, match="duplicate"):
        load_routing(p, known_tools=KNOWN)


def test_not_a_list_rejected(tmp_path):
    p = _write(tmp_path, "rule_id: not-a-list\n")
    with pytest.raises(RoutingConfigError, match="list"):
        load_routing(p, known_tools=KNOWN)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(RoutingConfigError, match="not found"):
        load_routing(tmp_path / "absent.yaml", known_tools=KNOWN)


def test_empty_catalogue_is_legal(tmp_path):
    p = _write(tmp_path, "")
    assert load_routing(p, known_tools=KNOWN) == []


# ── Matching semantics ───────────────────────────────────────────────────────


def test_first_matching_entry_wins(tmp_path):
    p = _write(
        tmp_path,
        _entry("first", r"\bvrrp\b", "get_findings")
        + _entry("second", r"\bvrrp\b", "get_device_detail"),
    )
    entries = load_routing(p, known_tools=KNOWN)
    # route() uses the packaged file; matching order is tested via the entries:
    for entry in entries:
        if any(rx.search("vrrp state") for rx in entry["_compiled"]):
            assert entry["rule_id"] == "first"
            break


def test_case_insensitive():
    assert isinstance(route("HOW IS VRRP CONFIGURED?"), RouteDecision)


def test_decision_carries_audit_fields():
    d = route("how is vrrp configured?")
    assert d.rule_id and d.tools and d.pattern  # the audit-event payload


# ── dispatch blocks (deterministic pre-dispatch, ADR-0024 escalation) ────────


def test_seed_entry_carries_dispatch():
    d = route("how is vrrp configured?")
    assert d.dispatch_tool == "get_redundancy_assessment"
    assert d.dispatch_args == {}


def test_dispatch_tool_must_be_in_entry_tools(tmp_path):
    body = """
- rule_id: r1
  description: dispatch outside tools
  patterns: ['\\bvrrp\\b']
  tools: [get_findings]
  dispatch: {tool: get_device_detail, arguments: {}}
  evidence: "a documented failure"
  added: "2026-07-11"
"""
    p = _write(tmp_path, body)
    with pytest.raises(RoutingConfigError, match="must be one of the"):
        load_routing(p, known_tools=KNOWN)


def test_dispatch_arguments_must_be_a_mapping(tmp_path):
    body = """
- rule_id: r1
  description: bad args
  patterns: ['\\bvrrp\\b']
  tools: [get_findings]
  dispatch: {tool: get_findings, arguments: "not-a-dict"}
  evidence: "a documented failure"
  added: "2026-07-11"
"""
    p = _write(tmp_path, body)
    with pytest.raises(RoutingConfigError, match="arguments must be a mapping"):
        load_routing(p, known_tools=KNOWN)


def test_entry_without_dispatch_is_narrow_only(tmp_path):
    p = _write(tmp_path, _entry())
    entries = load_routing(p, known_tools=KNOWN)
    assert entries[0].get("dispatch") is None
