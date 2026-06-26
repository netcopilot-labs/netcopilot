"""Positive-trigger fixtures for zero-coverage BGP advanced rules.

These rules read Genie BGP facts (facts/<host>/genie_bgp.json) with shape
{"instance": {<n>: {"bgp_id": <as>, "peer_session": {...},
 "vrf": {<v>: {"address_family": {...}, "neighbor": {<addr>: {...}}}}}}}.
None fire on the goldens (the audited BGP sessions are healthy), so their
firing logic was unexercised. One shared violating fixture below triggers
every rule; each test asserts its rule produces >=1 finding.
"""

import json

import pytest

from netcopilot.rules.discovery import get_rule_by_id


# A single Genie BGP fixture engineered so each zero-coverage rule fires on
# at least one neighbor/instance. local AS 65000; neighbors are eBGP.
_GENIE_BGP = {
    "instance": {
        "default": {
            "bgp_id": 65000,
            "peer_session": {
                "TEMPLATE1": {"shutdown": True},                       # PEER_SESSION_SHUTDOWN
            },
            "vrf": {
                "default": {
                    "address_family": {
                        "ipv4 unicast": {"dampening": True},           # ROUTE_DAMPENING_ENABLED (vrf-level AF)
                    },
                    "neighbor": {
                        # The "everything wrong" established eBGP neighbor.
                        "10.0.0.1": {
                            "remote_as": 65001,
                            "session_state": "established",
                            "shutdown": True,                          # NEIGHBOR_SHUTDOWN
                            "up_time": "00:30:00",                     # UPTIME_TOO_SHORT (<1h, HH:MM:SS)
                            "ebgp_multihop_max_hop": 20,               # EBGP_MULTIHOP_EXCESSIVE (>10)
                            "bgp_negotiated_keepalive_timers": {"hold_time": 10},  # HOLD_TIME_TOO_SHORT (<30)
                            "bgp_neighbor_counters": {"messages": {"out_queue_depth": 100, "in_queue_depth": 0}},  # MESSAGE_QUEUE_BACKED_UP (>50)
                            "bgp_negotiated_capabilities": {
                                "four_octets_asn": "advertised",       # NO_FOUR_OCTET_ASN (no "received")
                                "route_refresh": "advertised",         # NO_ROUTE_REFRESH (no "received")
                            },
                            "address_family": {
                                "ipv4 unicast": {                      # no route_map in/out → MISSING_INBOUND/OUTBOUND_POLICY
                                    "maximum_prefix_max_prefix_no": 100,
                                    "prefixes": {"received": 90},      # PREFIX_LIMIT_APPROACHING (90% >= 80)
                                },
                            },
                        },
                        # Established eBGP neighbor receiving zero prefixes.
                        "10.0.0.2": {
                            "remote_as": 65002,
                            "session_state": "established",
                            "address_family": {
                                "ipv4 unicast": {
                                    "route_map_name_in": "IN", "route_map_name_out": "OUT",
                                    "prefixes": {"received": 0},       # ZERO_PREFIXES
                                },
                            },
                        },
                        # Neighbor not in Established state.
                        "10.0.0.3": {
                            "remote_as": 65003,
                            "session_state": "idle",                   # NOT_ESTABLISHED
                        },
                    },
                },
            },
        },
    },
}

_BGP_RULES = [
    "BGP_EBGP_MULTIHOP_EXCESSIVE",
    "BGP_HOLD_TIME_TOO_SHORT",
    "BGP_MESSAGE_QUEUE_BACKED_UP",
    "BGP_NEIGHBOR_MISSING_INBOUND_POLICY",
    "BGP_NEIGHBOR_MISSING_OUTBOUND_POLICY",
    "BGP_NEIGHBOR_NOT_ESTABLISHED",
    "BGP_NEIGHBOR_NO_FOUR_OCTET_ASN",
    "BGP_NEIGHBOR_NO_ROUTE_REFRESH",
    "BGP_NEIGHBOR_SHUTDOWN",
    "BGP_NEIGHBOR_UPTIME_TOO_SHORT",
    "BGP_NEIGHBOR_ZERO_PREFIXES",
    "BGP_PEER_SESSION_SHUTDOWN",
    "BGP_PREFIX_LIMIT_APPROACHING",
    "BGP_ROUTE_DAMPENING_ENABLED",
]


@pytest.mark.parametrize("rule_id", _BGP_RULES)
def test_bgp_rule_fires_on_violation(rule_id, tmp_path):
    host = "core-rtr-01"
    run = tmp_path / "run"
    d = run / "facts" / host
    d.mkdir(parents=True)
    (d / "genie_bgp.json").write_text(json.dumps(_GENIE_BGP))
    model = {"devices": [{"hostname": host, "os_family": "iosxe"}], "interfaces": [], "links": []}
    findings = get_rule_by_id(rule_id).evaluate(
        model, {"run_path": str(run), "run_id": "r1", "manifest": {}}
    )
    assert len(findings) >= 1, f"{rule_id} did not fire on the BGP violation fixture"
