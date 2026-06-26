"""Positive-trigger fixtures for zero-coverage OSPF advanced rules.

These rules read Genie OSPF facts (facts/<host>/genie_ospf.json), nested
vrf -> address_family.ipv4 -> instance(process) -> areas -> interfaces ->
neighbors. None fire on the goldens (the audited OSPF is healthy), so their
firing logic was unexercised. One shared violating fixture (written to two
hosts so the duplicate-router-id rule fires) triggers every rule.
"""

import json

import pytest

from netcopilot.rules.discovery import get_rule_by_id


# One OSPF process engineered so each zero-coverage rule fires.
_PROCESS = {
    "router_id": "1.1.1.1",                                            # same on 2 hosts -> ROUTER_ID_DUPLICATE
    "mpls": {"ldp": {"autoconfig": True, "igp_sync": False}},          # LDP_IGP_SYNC_DISABLED
    "spf_control": {"throttle": {}},                                   # LSA_THROTTLE + SPF_THROTTLE not configured
    "database_control": {"max_lsa": 7000},                            # MAX_LSA_APPROACHING (6000/7000 = 85%)
    "redistribution": {"bgp": {"65000": {}}},                         # REDISTRIBUTION_FROM_BGP
    "stub_router": {"always": {"always": True}},                      # STUB_ROUTER_PERMANENT
    "areas": {
        "0.0.0.0": {
            "statistics": {
                "area_scope_lsa_count": 6000,                          # AREA_HIGH_LSA_COUNT (>5000)
                "spf_runs_count": 200,                                 # AREA_HIGH_SPF_RUNS (>100)
            },
            "interfaces": {
                "GigabitEthernet0/0": {
                    "interface_type": "broadcast",
                    "priority": 0,                                     # INTERFACE_PRIORITY_ZERO (broadcast + prio 0)
                    "passive": True,                                   # PASSIVE_INTERFACE_UNEXPECTED (passive + neighbors)
                    "dead_interval": 40,
                    "neighbors": {
                        "2.2.2.2": {
                            "dead_timer": "00:00:03",                 # DEAD_TIMER_EXPIRING (3s < 15% of 40s)
                            "statistics": {
                                "nbr_event_count": 100,               # NEIGHBOR_EVENT_RATE_HIGH (>50)
                                "nbr_retrans_qlen": 20,               # NEIGHBOR_HIGH_RETRANS_QUEUE (>10)
                            },
                        },
                    },
                },
            },
        },
    },
}

_GENIE_OSPF = {"vrf": {"default": {"address_family": {"ipv4": {"instance": {"1": _PROCESS}}}}}}

_OSPF_RULES = [
    "OSPF_AREA_HIGH_LSA_COUNT",
    "OSPF_AREA_HIGH_SPF_RUNS",
    "OSPF_INTERFACE_PRIORITY_ZERO",
    "OSPF_LDP_IGP_SYNC_DISABLED",
    "OSPF_LSA_THROTTLE_NOT_CONFIGURED",
    "OSPF_MAX_LSA_APPROACHING",
    "OSPF_NEIGHBOR_DEAD_TIMER_EXPIRING",
    "OSPF_NEIGHBOR_EVENT_RATE_HIGH",
    "OSPF_NEIGHBOR_HIGH_RETRANS_QUEUE",
    "OSPF_PASSIVE_INTERFACE_UNEXPECTED",
    "OSPF_REDISTRIBUTION_FROM_BGP",
    "OSPF_ROUTER_ID_DUPLICATE",
    "OSPF_SPF_THROTTLE_NOT_CONFIGURED",
    "OSPF_STUB_ROUTER_PERMANENT",
]


@pytest.mark.parametrize("rule_id", _OSPF_RULES)
def test_ospf_rule_fires_on_violation(rule_id, tmp_path):
    # Two devices share router-id 1.1.1.1 so ROUTER_ID_DUPLICATE fires; the
    # other rules fire per-device on the same violating process.
    run = tmp_path / "run"
    hosts = ["rtr-a", "rtr-b"]
    for host in hosts:
        d = run / "facts" / host
        d.mkdir(parents=True)
        (d / "genie_ospf.json").write_text(json.dumps(_GENIE_OSPF))
    model = {"devices": [{"hostname": h, "os_family": "iosxe"} for h in hosts], "interfaces": [], "links": []}
    findings = get_rule_by_id(rule_id).evaluate(
        model, {"run_path": str(run), "run_id": "r1", "manifest": {}}
    )
    assert len(findings) >= 1, f"{rule_id} did not fire on the OSPF violation fixture"
