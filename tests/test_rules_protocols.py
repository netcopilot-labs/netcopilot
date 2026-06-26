"""F3d: Phase-1 protocol deep rules (BGP / OSPF / NTP / STP / VLAN / QoS / stack / SVL / cluster / HA).

Contract (the expected rule_ids are discovered) + a behavioral check for a
facts-based deep rule (NTP offset), proving the load_device_facts path works
end-to-end. Every rule's clean-evaluate is already covered by
test_rules_topology.test_every_rule_evaluates_cleanly (it iterates all rules).
Deep per-rule behavioral coverage lands in the F3h goldens.
"""

import json

from netcopilot.rules.discovery import discover_rules, get_rule_by_id

# one representative rule_id per F3d family (verified against the extracted files)
EXPECTED = {
    "BGP_NEIGHBOR_NOT_ESTABLISHED", "OSPF_AREA_HIGH_SPF_RUNS", "NTP_NOT_SYNCHRONIZED",
    "NTP_OFFSET_EXCESSIVE", "STP_TOPOLOGY_CHANGE_RECENT", "SVL_DEGRADED",
    "HA_NOT_SYNCHRONIZED", "CLUSTER_VERSION_MISMATCH", "STACK_PORT_DOWN",
    "VLAN_SVI_SHUTDOWN", "QOS_POLICER_EXCEED",
}


def test_f3d_protocol_rules_present():
    ids = {r.rule_id for r in discover_rules()}
    missing = EXPECTED - ids
    assert not missing, f"missing protocol rules: {missing}"


def test_rule_count_includes_protocol_batch():
    # F3c (~34) + F3d (~69) Phase-1 rules
    assert len(discover_rules()) >= 100


def test_ntp_offset_excessive_behavioral(tmp_path):
    rule = get_rule_by_id("NTP_OFFSET_EXCESSIVE")
    model = {"devices": [{"hostname": "core-rtr-01"}, {"hostname": "dist-sw-01"}],
             "interfaces": [], "links": []}
    run = tmp_path / "run"
    for host, offset in [("core-rtr-01", 600.0), ("dist-sw-01", 100.0)]:  # 600 > 500ms, 100 ok
        d = run / "facts" / host
        d.mkdir(parents=True)
        (d / "genie_ntp.json").write_text(json.dumps(
            {"clock_state": {"system_status": {"clock_offset": offset}}}))

    findings = rule.evaluate(model, {"run_id": "r1", "run_path": str(run), "manifest": {}})
    flagged = {f.evidence["element_id"] for f in findings}
    assert flagged == {"core-rtr-01"}   # only the 600ms device fires
    assert findings[0].severity == "high"
    assert findings[0].evidence["key_facts"]["offset_ms"] == 600.0
