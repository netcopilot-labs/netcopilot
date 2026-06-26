"""Over-fire tuning regression tests (rules audit).

Locks the two logic-heavy tunings: TRUNK_ALL_VLANS_ALLOWED uplink suppression
and CIS_FG_3_1 disabled-policy aggregation. (The INTF_OPER_DOWN soft->low
downgrade and INTF_NO_DESCRIPTION LAG skip are covered by the golden master.)
"""

import json

from netcopilot.rules.rules.trunk_all_vlans import TrunkAllVlansAllowedRule
from netcopilot.rules.rules.cis_fg_firewall import CisFgUnusedPolicyRule


def test_trunk_all_vlans_suppresses_uplinks_keeps_access():
    # All-VLAN trunks are EXPECTED on uplinks (inter-switch links + port-channel
    # bundles); the finding only matters on access-facing trunks.
    rule = TrunkAllVlansAllowedRule()
    model = {
        "interfaces": [
            {"device_id": "sw-a", "name": "Gi1/0/1", "switchport_mode": "trunk",
             "trunk_vlans": None},                                   # access trunk, no link -> KEPT
            {"device_id": "sw-a", "name": "Hu1/0/49", "switchport_mode": "trunk",
             "trunk_vlans": None},                                   # inter-switch link -> suppressed
            {"device_id": "sw-a", "name": "Po10", "switchport_mode": "trunk",
             "trunk_vlans": None},                                   # port-channel bundle -> suppressed
            {"device_id": "sw-a", "name": "Gi1/0/2", "switchport_mode": "trunk",
             "trunk_vlans": [10, 20]},                               # explicit prune -> not flagged
        ],
        "links": [
            {"local_interface_id": "sw-a:Hu1/0/49", "remote_interface_id": "sw-b:Hu1/0/3"},
        ],
    }
    flagged = {f.evidence["element_id"] for f in rule.evaluate(model, {})}
    assert flagged == {"sw-a:Gi1/0/1/trunk-all-allowed"}   # only the access trunk


def test_cis_fg_3_1_aggregates_disabled_policies(tmp_path):
    # A disabled policy is often intentional -> one review finding per device
    # listing them, not N separate findings.
    d = tmp_path / "run" / "facts" / "fw-01"
    d.mkdir(parents=True)
    (d / "fortigate_firewall_policy.json").write_text(json.dumps({"results": [
        {"policyid": 1, "name": "A", "status": "enable"},
        {"policyid": 2, "name": "B", "status": "disable"},
        {"policyid": 3, "name": "C", "status": "disable"},
    ]}))
    findings = CisFgUnusedPolicyRule().evaluate({}, {"run_path": str(tmp_path / "run")})
    assert len(findings) == 1                                  # aggregated, not 2
    kf = findings[0].evidence["key_facts"]
    assert kf["disabled_count"] == 2
    assert {p["policyid"] for p in kf["policies"]} == {2, 3}
