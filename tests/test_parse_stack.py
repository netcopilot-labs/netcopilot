"""F2-5z-a: cisco_native stack parser — Genie stack data → unified stack_ports."""

from netcopilot.parse.cisco_native.stack import parse_stack_ports


def test_c9300_cable():
    facts = {"genie": {"stack_ports": {"stackports": {
        "1/1": {"port_status": "OK", "neighbor": "2/1", "cable_length": "50cm",
                "link_ok": "Yes", "link_active": "Yes", "sync_ok": "Yes"},
    }}}}
    ports = parse_stack_ports(facts)
    assert len(ports) == 1
    p = ports[0]
    assert p["port_type"] == "cable"
    assert p["member_id"] == 1 and p["port_id"] == 1
    assert p["neighbor_member"] == 2
    assert p["link_active"] is True


def test_c9500_svl():
    facts = {"genie": {"svl_link": {"switch": {1: {"svl": {1: {"ports": {
        "HundredGigE1/0/25": {"link_status": "U", "protocol_status": "P"},
    }}}}}}}}
    ports = parse_stack_ports(facts)
    assert len(ports) == 1
    p = ports[0]
    assert p["port_type"] == "svl"
    assert p["interface"] == "HundredGigE1/0/25"
    assert p["link_status"] == "Up"          # "U" → "Up"
    assert p["protocol_status"] == "Ready"   # "P" → "Ready"


def test_svl_takes_priority_and_includes_dad():
    facts = {"genie": {
        "svl_link": {"switch": {1: {"svl": {1: {"ports": {
            "HundredGigE1/0/1": {"link_status": "U", "protocol_status": "P"}}}}}}},
        "svl_dad": {"switch": {1: {"dad": {1: {"ports": {
            "TwentyFiveGigE1/0/1": {"link_status": "U", "protocol_status": "P"}}}}}}},
        "stack_ports": {"stackports": {"1/1": {"port_status": "OK"}}},  # ignored (SVL wins)
    }}
    ports = parse_stack_ports(facts)
    types = {p["port_type"] for p in ports}
    assert types == {"svl", "dad"}   # cable ignored when SVL present


def test_no_stack_data():
    assert parse_stack_ports({}) == []
    assert parse_stack_ports({"genie": {}}) == []
