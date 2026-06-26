"""F3a: rules foundation — BaseRule contract, Finding model, discovery, path resolver."""

import pytest

from netcopilot.rules import BaseRule, Finding, discover_rules, get_rule_by_id, resolve


# --------------------------- BaseRule contract ---------------------------

class GoodRule(BaseRule):
    rule_id = "LINK_DOWN"
    severity = "high"
    title = "Link Down"
    description = "Detects down links"

    def evaluate(self, model, context):
        return []


def test_valid_rule_subclass():
    r = GoodRule()
    assert r.rule_id == "LINK_DOWN" and r.is_enabled() is True
    assert "LINK_DOWN" in repr(r)


def test_missing_attribute_raises_at_class_definition():
    with pytest.raises(TypeError, match="must define 'description'"):
        class NoDesc(BaseRule):
            rule_id = "X_RULE"
            severity = "high"
            title = "x"
            def evaluate(self, model, context): return []


def test_invalid_severity_rejected():
    with pytest.raises(TypeError, match="invalid severity"):
        class BadSev(BaseRule):
            rule_id = "X_RULE"
            severity = "cis"   # 'cis' is engine-applied, never declared
            title = "x"; description = "x"
            def evaluate(self, model, context): return []


def test_invalid_rule_id_format_rejected():
    with pytest.raises(TypeError, match="SCREAMING_SNAKE_CASE"):
        class BadId(BaseRule):
            rule_id = "lower_case"
            severity = "high"; title = "x"; description = "x"
            def evaluate(self, model, context): return []


# ------------------------------- Finding ---------------------------------

def test_finding_create_generates_id_and_evidence():
    f = Finding.create("LINK_DOWN", "high", "Link Down", "link", "a--b",
                       "down", {"status": "down"}, "fix it")
    assert f.finding_id == "LINK_DOWN::a--b"
    assert f.evidence == {"element_type": "link", "element_id": "a--b", "key_facts": {"status": "down"}}
    assert f.to_dict()["rule_id"] == "LINK_DOWN"


def test_finding_create_from_rule_and_member_id():
    f = Finding.create_from_rule(GoodRule(), "device", "core-rtr-01", "msg",
                                 {"k": "v"}, "fix", member_id=2)
    assert f.finding_id == "LINK_DOWN::core-rtr-01" and f.severity == "high"
    assert f.evidence["member_id"] == 2


def test_finding_cis_severity_allowed_at_emit():
    # engine post-applies 'cis'; the Finding constructor accepts it
    f = Finding.create("CIS_XE_1", "cis", "t", "device", "d", "m", {}, "r")
    assert f.severity == "cis"


def test_finding_validation_rejects_bad_values():
    with pytest.raises(ValueError, match="Invalid severity"):
        Finding.create("R", "bogus", "t", "device", "d", "m", {}, "r")
    with pytest.raises(ValueError, match="Invalid element_type"):
        Finding.create("R", "high", "t", "vlan", "d", "m", {}, "r")
    with pytest.raises(ValueError, match="format RULE_ID"):
        Finding(finding_id="no-sep", rule_id="R", severity="high", title="t",
                message="m", evidence={"element_type": "device", "element_id": "d", "key_facts": {}},
                recommendation="r")


def test_finding_is_frozen():
    f = Finding.create("R", "high", "t", "device", "d", "m", {}, "r")
    with pytest.raises(Exception):
        f.severity = "low"  # frozen dataclass


def test_finding_tags_in_dict_only_when_present():
    plain = Finding.create("R", "high", "t", "device", "d", "m", {}, "r")
    assert "tags" not in plain.to_dict()


# ------------------------------ discovery --------------------------------

_RULE_SRC = '''
from netcopilot.rules.base_rule import BaseRule
class SampleRule(BaseRule):
    rule_id = "SAMPLE_RULE"
    severity = "low"
    title = "Sample"
    description = "x"
    def evaluate(self, model, context):
        return []
'''


def test_discover_rules_finds_and_sorts(tmp_path):
    (tmp_path / "sample.py").write_text(_RULE_SRC)
    (tmp_path / "__init__.py").write_text("")     # excluded
    (tmp_path / "_helper.py").write_text("x = 1")  # underscore excluded
    rules = discover_rules(rules_dir=tmp_path)
    assert [r.rule_id for r in rules] == ["SAMPLE_RULE"]


def test_discover_rules_missing_dir_is_graceful(tmp_path):
    assert discover_rules(rules_dir=tmp_path / "nope") == []


def test_discover_rules_bad_file_does_not_break_others(tmp_path):
    (tmp_path / "sample.py").write_text(_RULE_SRC)
    (tmp_path / "broken.py").write_text("this is not valid python (((")
    rules = discover_rules(rules_dir=tmp_path)
    assert [r.rule_id for r in rules] == ["SAMPLE_RULE"]  # broken skipped


# ----------------------------- path_resolver -----------------------------

def test_resolve_literal_and_wildcard():
    data = {"vrf": {"default": {"neighbor": {"192.0.2.1": {"state": "FULL"}}}}}
    out = list(resolve("vrf.*.neighbor.*", data))
    assert out == [({"vrf": "default", "neighbor": "192.0.2.1"}, {"state": "FULL"})]


def test_resolve_greedy_dotted_key():
    # an IP key like 192.0.2.1 is matched greedily despite the dot separator
    data = {"neighbor": {"192.0.2.1": {"state": "up"}}}
    assert list(resolve("neighbor.192.0.2.1.state", data)) == [({}, "up")]


def test_resolve_missing_path_and_none_skip():
    assert list(resolve("missing.path", {"a": 1})) == []
    assert list(resolve("", {"a": 1})) == []
    # None children are skipped by wildcards
    data = {"x": {"a": None, "b": {"v": 1}}}
    assert list(resolve("x.*.v", data)) == [({"x": "b"}, 1)]


def test_resolve_deterministic_sorted_order():
    data = {"x": {"c": 3, "a": 1, "b": 2}}
    keys = [ctx["x"] for ctx, _ in resolve("x.*", data)]
    assert keys == ["a", "b", "c"]  # sorted
