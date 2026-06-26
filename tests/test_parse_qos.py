"""F2-5z-a: cisco_native QoS parser — Genie policy-map → per-interface QoS."""

from netcopilot.parse.cisco_native.qos import parse_qos_for_interfaces

# policy definitions (show policy-map)
PM_DATA = {"policy_map": {
    "INGRESS-POLICER": {"class": {"class-default": {"police": {"cir_bps": 1000000}}}},
    "system-cpp-policy": {"class": {"class-default": {"police": {}}}},  # excluded
}}

# per-interface counters (show policy-map interface)
PMI_DATA = {"GigabitEthernet0/0": {"service_policy": {"input": {"policy_name": {
    "INGRESS-POLICER": {"class_map": {"class-default": {"police": {
        "cir_bps": 1000000,
        "conformed": {"packets": 100, "bytes": 200},
        "exceeded": {"packets": 5, "bytes": 10, "actions": {"drop": True}},
    }}}},
}}}}}


def test_parse_qos_policer():
    qos = parse_qos_for_interfaces(PM_DATA, PMI_DATA)
    inp = qos["GigabitEthernet0/0"]["input"]
    assert inp["policy_name"] == "INGRESS-POLICER"
    assert inp["type"] == "policer"
    assert inp["cir_bps"] == 1000000
    assert inp["conform_packets"] == 100
    assert inp["exceed_action"] == "drop"


def test_parse_qos_shaper():
    pmi = {"Gi0/1": {"service_policy": {"output": {"policy_name": {
        "EGRESS-SHAPER": {"class_map": {"class-default": {
            "shape_cir_bps": 5000000, "total_drops": 0, "queue_depth": 0,
            "pkts_output": 850, "bytes_output": 99000,
        }}},
    }}}}}
    qos = parse_qos_for_interfaces({"policy_map": {}}, pmi)
    out = qos["Gi0/1"]["output"]
    assert out["type"] == "shaper"
    assert out["cir_bps"] == 5000000
    assert out["conform_packets"] == 850


def test_parse_qos_excludes_system_policy():
    pmi = {"Gi0/2": {"service_policy": {"input": {"policy_name": {
        "system-cpp-policy": {"class_map": {"class-default": {"police": {"cir_bps": 1}}}},
    }}}}}
    assert parse_qos_for_interfaces(PM_DATA, pmi) == {}


def test_parse_qos_no_service_policy():
    assert parse_qos_for_interfaces(PM_DATA, {"Gi0/3": {}}) == {}
