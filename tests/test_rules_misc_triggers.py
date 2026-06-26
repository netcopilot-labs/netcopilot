"""Positive-trigger fixtures for the remaining zero-coverage rules.

INTF / NTP / QOS / ROUTE / VRF / STP / VLAN / SSH-fallback / collection-failure
families. None fire on the goldens (the audited devices are healthy / fully
collected), so their firing logic was unexercised. A single comprehensive run
(facts + model interfaces + manifest) is built with one violation per rule;
each test asserts its rule produces >=1 finding.
"""

import json

import pytest

from netcopilot.rules.discovery import get_rule_by_id

HOST = "sw1"

# --- Genie facts for HOST (one violation per rule) -------------------------
_GENIE_INTERFACE = {
    "GigabitEthernet0/0": {
        "oper_status": "up", "enabled": True,
        "bandwidth": 1000000, "port_speed": "100",          # BANDWIDTH_SPEED_MISMATCH (1Gkbps vs 100Mbps)
        "last_change": "00:00:30",                          # LAST_CHANGE_RECENT
        "counters": {
            "in_errors": 100, "in_pkts": 1000,              # INPUT_ERROR_RATE_HIGH (10% > 1%)
            "in_crc_errors": 50,                            # CRC_ERROR_RATE_HIGH (>10)
            "rate": {"in_rate": 900000000, "out_rate": 900000000},  # IN/OUT_UTILIZATION_HIGH (90% of 1Gbps)
        },
    },
}

# NTP peers live under associations.address[addr].local_mode.<mode>.isconfigured.<k>
_NTP_PEER_UNREACH = {"local_mode": {"client": {"isconfigured": {"a": {"reach": 0, "stratum": 16}}}}}
_NTP_PEER_DEGRADED = {"local_mode": {"client": {"isconfigured": {"a": {"reach": 100, "stratum": 15}}}}}
_GENIE_NTP = {
    "clock_state": {"system_status": {"clock_state": "unsynchronized"}},   # NOT_SYNCHRONIZED
    "vrf": {"default": {"associations": {"address": {
        "10.0.0.1": _NTP_PEER_UNREACH,                                     # PEER_UNREACHABLE (reach 0)
        "10.0.0.2": _NTP_PEER_DEGRADED,                                    # REACHABILITY_DEGRADED + HIGH_STRATUM
    }}}},
}

_GENIE_VLAN = {"vlans": {"99": {"vlan_id": 99, "name": "ORPHAN", "state": "active", "shutdown": False}}}

_GENIE_STP = {
    "global": {"bpdu_filter": True},                                        # BPDUFILTER_ENABLED_GLOBALLY
    "rapid_pvst": {"vlan_inst": {"vlans": {"10": {"interfaces": {
        "GigabitEthernet0/1": {"role": "backup", "port_state": "forwarding"},    # BACKUP_PORT_DETECTED
        "GigabitEthernet0/2": {"role": "disabled", "port_state": "forwarding"},  # PORT_ROLE_DISABLED
    }}}}},
}

# Dynamic RIB (genie_routing): a non-static inactive route + no default route.
_GENIE_ROUTING = {"vrf": {"default": {"address_family": {"ipv4": {"routes": {
    "20.0.0.0/8": {"active": False, "source_protocol": "ospf"},                  # ROUTE_INACTIVE (non-static)
    # no 0.0.0.0/0 present, routes non-empty -> ROUTE_DEFAULT_MISSING
}}}}}}

# Static routing table (genie_static_routing): blackhole + inactive read here.
_GENIE_STATIC_ROUTING = {"vrf": {"default": {"address_family": {"ipv4": {"routes": {
    "10.0.0.0/8": {"active": False,                                              # STATIC_ROUTE_INACTIVE (route-level active=False)
                   "next_hop": {"nhl": {"1": {"outgoing_interface": "GigabitEthernet0/0"}}}},
    "192.0.2.0/24": {"next_hop": {"nhl": {"1": {"outgoing_interface": "Null0"}}}},  # ROUTE_BLACKHOLE_STATIC (Null0)
}}}}}}

_GENIE_VRF = {"vrfs": {"CUST-A": {"interfaces": []}}}                            # VRF_EMPTY_NO_INTERFACES + VRF_NO_RD_CONFIGURED

# A filtered trunk (so trunk_vlans is a set, not None) that does NOT carry
# VLAN 99 -> VLAN 99 is orphaned (no access/trunk/SVI).
_RUNNING_CONFIG = (
    "hostname sw1\n"
    "vlan 99\n"                                  # locally-configured (not VTP-inherited) -> eligible for orphan check
    " name ORPHAN\n"
    "interface GigabitEthernet0/5\n"
    " switchport mode trunk\n"
    " switchport trunk allowed vlan 10,20\n"
    "router bgp 65000\n"                         # L3VPN PE context: VRF RD/RT rules only apply when BGP VPNv4 runs
    " address-family vpnv4\n"
)

# --- Model interfaces for the QoS rules ------------------------------------
_MODEL_INTERFACES = [
    # candidate switchport, qos has output but no input -> NO_INPUT_POLICY
    {"device_id": HOST, "name": "GigabitEthernet1/0/1", "type": "ethernet",
     "admin_status": "up", "switchport_mode": "access",
     "qos": {"output": {"policy_name": "SHAPE-OUT"}}},
    # candidate switchport, qos has input but no output -> NO_OUTPUT_POLICY
    {"device_id": HOST, "name": "GigabitEthernet1/0/2", "type": "ethernet",
     "admin_status": "up", "switchport_mode": "access",
     "qos": {"input": {"policy_name": "POLICE-IN"}}},
    # policer dropping >1% -> POLICER_EXCEED
    {"device_id": HOST, "name": "GigabitEthernet1/0/3", "type": "ethernet", "speed": "1000mbps",
     "qos": {"input": {"type": "policer", "conform_packets": 1000, "exceed_packets": 100}}},
    # shaper queue drops with traffic -> SHAPER_DROPS
    {"device_id": HOST, "name": "GigabitEthernet1/0/4", "type": "ethernet", "speed": "1000mbps",
     "qos": {"input": {"type": "shaper", "queue_drops": 5000, "conform_packets": 1000000}}},
    # CIR 10G on a 1G port -> RATE_SPEED_MISMATCH
    {"device_id": HOST, "name": "GigabitEthernet1/0/5", "type": "ethernet", "speed": "1000mbps",
     "qos": {"input": {"cir_bps": 10000000000}}},
]

_MANIFEST = {"devices": [
    {"hostname": "ssh-dev", "os_family": "iosxe", "collection_strategy": "ssh", "status": "success"},   # SSH_FALLBACK
    {"hostname": "fail-dev", "os_family": "iosxe", "status": "failed", "error": "auth timeout"},          # COLLECTION_FAILURE (absent from model)
]}


def _build_run(tmp_path):
    run = tmp_path / "run"
    d = run / "facts" / HOST
    d.mkdir(parents=True)
    (d / "genie_interface.json").write_text(json.dumps(_GENIE_INTERFACE))
    (d / "genie_ntp.json").write_text(json.dumps(_GENIE_NTP))
    (d / "genie_vlan.json").write_text(json.dumps(_GENIE_VLAN))
    (d / "genie_stp.json").write_text(json.dumps(_GENIE_STP))
    (d / "genie_routing.json").write_text(json.dumps(_GENIE_ROUTING))
    (d / "genie_static_routing.json").write_text(json.dumps(_GENIE_STATIC_ROUTING))
    (d / "genie_vrf.json").write_text(json.dumps(_GENIE_VRF))
    (d / "running_config.txt").write_text(_RUNNING_CONFIG)
    return run


def _model():
    # fail-dev is intentionally ABSENT (it failed collection -> no model device).
    return {
        "devices": [
            {"hostname": HOST, "os_family": "iosxe"},
            {"hostname": "ssh-dev", "os_family": "iosxe"},
        ],
        "interfaces": _MODEL_INTERFACES,
        "links": [],
    }


_MISC_RULES = [
    "INTF_BANDWIDTH_SPEED_MISMATCH", "INTF_CRC_ERROR_RATE_HIGH",
    "INTF_INPUT_ERROR_RATE_HIGH", "INTF_INPUT_UTILIZATION_HIGH",
    "INTF_LAST_CHANGE_RECENT", "INTF_OUTPUT_UTILIZATION_HIGH",
    "NTP_HIGH_STRATUM", "NTP_NOT_SYNCHRONIZED", "NTP_PEER_UNREACHABLE",
    "NTP_REACHABILITY_DEGRADED",
    "QOS_NO_INPUT_POLICY", "QOS_NO_OUTPUT_POLICY", "QOS_POLICER_EXCEED",
    "QOS_RATE_SPEED_MISMATCH", "QOS_SHAPER_DROPS",
    "ROUTE_BLACKHOLE_STATIC", "ROUTE_DEFAULT_MISSING", "ROUTE_INACTIVE",
    "SSH_FALLBACK", "STATIC_ROUTE_INACTIVE",
    "STP_BACKUP_PORT_DETECTED", "STP_BPDUFILTER_ENABLED_GLOBALLY",
    "STP_PORT_ROLE_DISABLED",
    "VLAN_NO_INTERFACES", "VRF_EMPTY_NO_INTERFACES", "VRF_NO_RD_CONFIGURED",
    "COLLECTION_FAILURE",
]


@pytest.mark.parametrize("rule_id", _MISC_RULES)
def test_misc_rule_fires_on_violation(rule_id, tmp_path):
    run = _build_run(tmp_path)
    findings = get_rule_by_id(rule_id).evaluate(
        _model(),
        {"run_path": str(run), "run_id": "r1", "manifest": _MANIFEST},
    )
    assert len(findings) >= 1, f"{rule_id} did not fire on its violation fixture"


def test_vrf_rd_rt_skipped_on_vrf_lite(tmp_path):
    # A VRF-lite device (no BGP VPNv4) must NOT be flagged for missing RD/RT —
    # those are MPLS L3VPN constructs, irrelevant to VRF-lite.
    run = tmp_path / "run"
    d = run / "facts" / "sw1"
    d.mkdir(parents=True)
    (d / "genie_vrf.json").write_text(json.dumps(
        {"vrfs": {"RED": {"address_family": {"ipv4 unicast": {}}}}}))   # no rd, no route_targets
    (d / "running_config.txt").write_text("hostname sw1\nvrf definition RED\n")  # VRF-lite, no vpnv4
    model = {"devices": [{"hostname": "sw1", "os_family": "iosxe"}], "interfaces": [], "links": []}
    ctx = {"run_path": str(run), "run_id": "r1", "manifest": {}}
    assert get_rule_by_id("VRF_NO_RD_CONFIGURED").evaluate(model, ctx) == []
    assert get_rule_by_id("VRF_MISSING_RT").evaluate(model, ctx) == []
