"""F3c: model-based & facts-based Phase-1 rules (topology / interface / routing / config).

Contract (all discover + instantiate), a clean-evaluate smoke over every rule
(no crash on an empty model + a factless run), and behavioral checks for the
model-based topology rules. Deep behavioral coverage comes in the F3h goldens.
"""

import tempfile
from pathlib import Path

from netcopilot.rules.discovery import discover_rules, get_rule_by_id

# rule_ids that must be present after F3c (one representative per family)
EXPECTED = {
    "COLLECTION_FAILURE", "DUPLICATE_IP", "ISOLATED_DEVICE", "LINK_DOWN",
    "DAD_LINK_DOWN", "UNIDIRECTIONAL_LINK", "INTF_ERROR_RATE_HIGH",
    "INTF_CRC_ERROR_RATE_HIGH", "SSH_FALLBACK", "CONFIG_PLAINTEXT_CREDENTIALS",
}

EMPTY_MODEL = {"devices": [], "interfaces": [], "links": [], "shared_services": []}


def _ctx(tmp_path):
    return {"run_id": "r1", "run_path": str(tmp_path), "manifest": {"devices": []}}


def test_f3c_rules_discover_and_instantiate():
    ids = {r.rule_id for r in discover_rules()}
    missing = EXPECTED - ids
    assert not missing, f"missing rules: {missing}"


def test_every_rule_evaluates_cleanly(tmp_path):
    # empty model + a run dir with no facts → every rule returns a list, no crash
    ctx = _ctx(tmp_path)
    for rule in discover_rules():
        out = rule.evaluate(EMPTY_MODEL, ctx)
        assert isinstance(out, list), f"{rule.rule_id} did not return a list"


def test_link_down_severities(tmp_path):
    rule = get_rule_by_id("LINK_DOWN")
    model = {**EMPTY_MODEL, "links": [
        # down + high-confidence (real cable) → high severity
        {"link_id": "a--b", "status": "down", "confidence": "high"},
        {"link_id": "c--d", "status": "admin_down"},   # admin_down → always info
        {"link_id": "e--f", "status": "up", "confidence": "high"},
    ]}
    findings = {f.finding_id: f for f in rule.evaluate(model, _ctx(tmp_path))}
    assert findings["LINK_DOWN::a--b"].severity == "high"
    assert findings["LINK_DOWN::c--d"].severity == "info"   # admin_down → info
    assert "LINK_DOWN::e--f" not in findings                # up → not flagged


def test_duplicate_ip_fires_on_shared_address(tmp_path):
    rule = get_rule_by_id("DUPLICATE_IP")
    model = {**EMPTY_MODEL, "interfaces": [
        {"interface_id": "core-rtr-01:Gi0/1", "device_id": "core-rtr-01", "name": "Gi0/1", "ip_address": "192.0.2.1"},
        {"interface_id": "dist-sw-01:Gi0/2", "device_id": "dist-sw-01", "name": "Gi0/2", "ip_address": "192.0.2.1"},
        {"interface_id": "edge-rtr-01:Gi0/3", "device_id": "edge-rtr-01", "name": "Gi0/3", "ip_address": "192.0.2.9"},
    ]}
    findings = rule.evaluate(model, _ctx(tmp_path))
    # the shared 192.0.2.1 is flagged; the unique 192.0.2.9 is not
    assert any("192.0.2.1" in f.finding_id for f in findings)
    assert not any("192.0.2.9" in f.finding_id for f in findings)


def test_isolated_device_fires_when_no_links(tmp_path):
    rule = get_rule_by_id("ISOLATED_DEVICE")
    model = {**EMPTY_MODEL,
             "devices": [{"device_id": "lonely-01", "hostname": "lonely-01"},
                         {"device_id": "core-rtr-01", "hostname": "core-rtr-01"},
                         {"device_id": "dist-sw-01", "hostname": "dist-sw-01"}],
             "links": [{"link_id": "a--b", "status": "up",
                        "local_device_id": "core-rtr-01", "remote_device_id": "dist-sw-01"}]}
    flagged = {f.evidence["element_id"] for f in rule.evaluate(model, _ctx(tmp_path))}
    assert "lonely-01" in flagged          # no links → isolated
    assert "core-rtr-01" not in flagged    # has a link
