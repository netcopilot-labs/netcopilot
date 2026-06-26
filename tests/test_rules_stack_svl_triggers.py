"""Positive-trigger fixtures for the STACK/SVL health rules.

These rules are silent on the hw golden only because the C9500 SVL operational
data (`show stackwise-virtual link` -> genie_svl_link.json -> device.stack_ports)
isn't collected in that frozen run — NOT because the rules are broken. These
synthetic fixtures prove the rule logic fires on the correct data shape, and
serve as the regression/trigger tests for an otherwise-unexercised family.
"""

from netcopilot.rules.rules.svl_link_down import SvlLinkDownRule
from netcopilot.rules.rules.stack_port_down import StackPortDownRule
from netcopilot.rules.rules.svl_degraded import SvlDegradedRule
from netcopilot.rules.rules.stack_half_ring import StackHalfRingRule
from netcopilot.rules.rules.stack_port_absent import StackPortAbsentRule
from netcopilot.rules.rules.stack_bandwidth_degraded import StackBandwidthDegradedRule
from netcopilot.rules.rules.dad_link_down import DadLinkDownRule


def _dev(stack_ports):
    return {"devices": [{"hostname": "sw-01", "stack_ports": stack_ports}]}


def test_svl_degraded_fires_on_partial_svl():
    # 2 SVL links, one Down -> degraded (still up but no redundancy)
    m = _dev([
        {"port_type": "svl", "link_status": "Up", "interface": "Hu1/0/1"},
        {"port_type": "svl", "link_status": "Down", "interface": "Hu2/0/1"},
    ])
    assert len(SvlDegradedRule().evaluate(m, {})) == 1
    assert len(StackBandwidthDegradedRule().evaluate(m, {})) == 1  # same partial-SVL trigger


def test_stack_port_absent_fires():
    m = _dev([{"port_type": "cable", "status": "ABSENT", "member_id": 1, "port_id": 2}])
    assert len(StackPortAbsentRule().evaluate(m, {})) >= 1


def test_stack_half_ring_fires_on_single_active_cable():
    # member 1 has only one OK cable port (the other down) -> half ring
    m = _dev([
        {"port_type": "cable", "status": "OK", "member_id": 1, "port_id": 1},
        {"port_type": "cable", "status": "DOWN", "member_id": 1, "port_id": 2},
    ])
    assert len(StackHalfRingRule().evaluate(m, {})) == 1


def test_dad_link_down_fires():
    m = _dev([{"port_type": "dad", "link_status": "Down", "member_id": 1, "interface": "Hu1/0/48"}])
    assert len(DadLinkDownRule().evaluate(m, {})) == 1


def test_svl_link_down_fires_on_down_svl_link():
    model = {"devices": [{"hostname": "sw-svl-01", "stack_ports": [
        {"port_type": "svl", "link_status": "Up", "member_id": 1,
         "interface": "HundredGigE1/0/1", "svl_id": 1},
        {"port_type": "svl", "link_status": "Down", "member_id": 2,
         "interface": "HundredGigE2/0/1", "svl_id": 1},
    ]}]}
    findings = SvlLinkDownRule().evaluate(model, {})
    assert len(findings) == 1                                  # only the Down link
    assert findings[0].severity == "critical"
    assert "HundredGigE2/0/1" in findings[0].message


def test_stack_port_down_fires_on_down_cable():
    model = {"devices": [{"hostname": "sw-stack-01", "stack_ports": [
        {"port_type": "cable", "status": "OK", "member_id": 1, "port_id": 1},
        {"port_type": "cable", "status": "DOWN", "member_id": 2, "port_id": 1},
    ]}]}
    findings = StackPortDownRule().evaluate(model, {})
    assert len(findings) == 1
    assert "2/1" in findings[0].message


def test_stack_svl_clean_when_all_up():
    # No findings when every stack/SVL port is healthy (the normal case — which
    # is also why a healthy stack legitimately produces 0 findings).
    model = {"devices": [{"hostname": "sw-ok", "stack_ports": [
        {"port_type": "svl", "link_status": "Up", "member_id": 1, "interface": "Hu1/0/1", "svl_id": 1},
        {"port_type": "cable", "status": "OK", "member_id": 1, "port_id": 1},
    ]}]}
    assert SvlLinkDownRule().evaluate(model, {}) == []
    assert StackPortDownRule().evaluate(model, {}) == []
