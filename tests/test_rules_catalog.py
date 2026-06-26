"""F3g: the packaged rule-catalog.yaml — Phase-2 surface rules.

Validates the shipped catalog loads, carries no lab_coverage remnants, and
actually drives the engine's Phase 2 end-to-end (a real catalog rule fires on
synthetic facts via the default catalog path).
"""

import json
from pathlib import Path

import yaml

from netcopilot.rules.catalog_loader import load_catalog
from netcopilot.rules.engine import DEFAULT_CATALOG_PATH, run_rules

CATALOG = Path(DEFAULT_CATALOG_PATH)


def test_packaged_catalog_exists_and_is_valid():
    assert CATALOG.is_file(), f"catalog not shipped at {CATALOG}"
    raw = yaml.safe_load(CATALOG.read_text())
    assert isinstance(raw, list) and len(raw) >= 400          # the full rule set
    # the redlist strip: no rule carries a lab_coverage key
    assert all("lab_coverage" not in r for r in raw if isinstance(r, dict))


def test_catalog_loads_phase2_rules():
    cr = load_catalog(str(CATALOG))
    assert cr.stats["total"] >= 400
    assert cr.stats["loaded"] >= 60                            # net Phase-2 surface rules
    assert len(cr.rules_by_source()) >= 10                    # many genie_* source families


def test_engine_phase2_with_packaged_catalog(tmp_path):
    # a real catalog rule (ARP_INCOMPLETE_ENTRIES) fires through the default catalog
    run = tmp_path / "runs" / "r1"
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps({"devices": [], "interfaces": [], "links": []}))
    (run / "manifest.json").write_text(json.dumps({"run_id": "r1", "devices": []}))
    facts = run / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_arp.json").write_text(json.dumps(
        {"interfaces": {"GigabitEthernet0/1": {"ipv4": {"neighbors": {
            "192.0.2.9": {"link_layer_address": "incomplete"}}}}}}))

    # no catalog_path → uses the packaged DEFAULT_CATALOG_PATH
    result = run_rules("r1", runs_base=str(run.parent))
    arp = [f for f in result["findings"] if f["rule_id"] == "ARP_INCOMPLETE_ENTRIES"]
    assert arp, "expected ARP_INCOMPLETE_ENTRIES from the packaged catalog"
    assert result["metadata"]["rules_executed_phase2"] >= 60


# --- surface-rule `exclude` capability (loopback skip in OSPF auth) ---------

from netcopilot.rules.catalog_loader import EvalSpec
from netcopilot.rules.generic_evaluator import _context_excluded


def test_context_excluded_matches_by_pattern():
    spec = EvalSpec(source="genie_ospf", element_id="x", evidence="y",
                    exclude=(("interfaces", "(?i)^loopback"),))
    assert _context_excluded(spec, {"interfaces": "Loopback0"}) is True
    assert _context_excluded(spec, {"interfaces": "GigabitEthernet0/1"}) is False
    assert _context_excluded(spec, {}) is False                       # key absent
    # no exclude configured -> never excluded
    spec2 = EvalSpec(source="g", element_id="x", evidence="y")
    assert _context_excluded(spec2, {"interfaces": "Loopback0"}) is False


def test_ospf_no_auth_excludes_loopback_keeps_transit(tmp_path):
    # Both a loopback and a transit interface lack OSPF auth; only the transit
    # interface should be flagged (loopbacks form no adjacency).
    run = tmp_path / "runs" / "r1"
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps(
        {"devices": [{"hostname": "sw1", "os_family": "iosxe"}], "interfaces": [], "links": []}))
    (run / "manifest.json").write_text(json.dumps({"run_id": "r1", "devices": [{"hostname": "sw1"}]}))
    facts = run / "facts" / "sw1"
    facts.mkdir(parents=True)
    (facts / "genie_ospf.json").write_text(json.dumps({"vrf": {"default": {"address_family": {"ipv4": {
        "instance": {"1": {"areas": {"0.0.0.0": {"interfaces": {
            "Loopback0": {},               # no authentication -> would fire, but excluded
            "GigabitEthernet0/1": {},      # no authentication -> fires
        }}}}}}}}}}))

    result = run_rules("r1", runs_base=str(run.parent))
    auth = [(f.get("evidence", {}) or {}).get("element_id", "")
            for f in result["findings"] if f["rule_id"] == "OSPF_INTERFACE_NO_AUTHENTICATION"]
    assert any("GigabitEthernet0/1" in e for e in auth), "transit interface should fire"
    assert not any("Loopback0" in e for e in auth), "loopback must be excluded"


def test_ospf_nsr_rule_is_deferred_not_loaded():
    # OSPF_NSR_DISABLED is disabled (eval -> eval_deferred) pending a
    # supervisor-redundancy signal; it must not load as an active surface rule.
    result = load_catalog(str(CATALOG))
    assert not any(r.rule_id == "OSPF_NSR_DISABLED" for r in result.rules)
