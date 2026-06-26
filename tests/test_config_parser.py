"""F2-5-final: running-config parsers — security / management / route-policy / prefix-list.

Pure text→dict parsers consumed (eventually) by the rules layer. Synthetic
configs with RFC 5737 documentation IPs only.
"""

from netcopilot.collect.config_parser import (
    parse_management,
    parse_prefix_lists,
    parse_route_policies,
    parse_security_config,
    parse_stack_ports_summary,
)

IOSXE_CONFIG = "\n".join([
    "hostname core-sw-01",
    "service password-encryption",
    "service timestamps log datetime",
    "aaa authentication login default group AAA-GROUP local",
    "aaa authorization exec default group AAA-GROUP local",
    "aaa accounting exec default start-stop group AAA-GROUP",
    "enable secret 9 $9$abcdef",
    "security passwords min-length 8",
    "ip ssh version 2",
    "ip ssh time-out 60",
    "ip ssh authentication-retries 3",
    "ip ssh source-interface Loopback0",
    "ntp authenticate",
    "ntp trusted-key 5",
    "ntp server 192.0.2.200 key 5",
    "logging buffered 16384",
    "logging trap informational",
    "logging host 192.0.2.201",
    "logging source-interface Loopback0",
    "no cdp run",
    "lldp run",
    "no ip domain lookup",
    "no ip source-route",
    "snmp-server community TESTCOMM-RO RO MGMT-ACL",
    "snmp-server host 192.0.2.202",
    "ip http server",
    "ip http secure-server",
    "ip http access-class 99",
    "banner login ^C Authorized only ^C",
    "interface Loopback0",
    " ip address 192.0.2.103 255.255.255.255",
    " ip vrf forwarding MGMT",
    "line con 0",
    " exec-timeout 5 0",
    " logging synchronous",
    "line vty 0 15",
    " access-class 99 in",
    " exec-timeout 10 0",
    " transport input ssh",
    "ip prefix-list LOCAL-NETS seq 10 permit 192.0.2.0/24",
    "ip prefix-list LOCAL-NETS seq 20 deny 0.0.0.0/0 le 32",
    "route-map SET-LOCALPREF permit 10",
    " match ip address prefix-list LOCAL-NETS",
    " set local-preference 150",
])

IOSXR_CONFIG = "\n".join([
    "hostname edge-rtr-01",
    "cdp",
    "lldp",
    "domain lookup disable",
    "no ipv4 source-route",
    "ssh server v2",
    "ssh timeout 60",
    "aaa password-policy STRICT",
    " min-length 10",
    "username netops",
    " secret 5 $1$abcdef",
    "line default",
    " access-class ingress MGMT-ACL",
    " exec-timeout 10 0",
    " transport input ssh",
])


def test_security_config_iosxe_sections():
    sec = parse_security_config(IOSXE_CONFIG, os_family="ios-xe")
    assert sec["ssh"]["version"] == 2
    assert sec["ssh"]["timeout"] == 60
    assert sec["ssh"]["max_retries"] == 3
    assert sec["services"]["password_encryption"] is True
    assert sec["aaa"]["authentication_login_default"] == "group AAA-GROUP local"
    assert sec["aaa"]["accounting_configured"] is True
    assert sec["password_policy"]["min_length"] == 8
    assert sec["password_policy"]["secret_encryption_type"] == 9
    assert sec["ntp"]["authentication_enabled"] is True
    assert sec["ntp"]["trusted_keys"] == [5]
    assert sec["logging"]["hosts"] == ["192.0.2.201"]
    # IOS XE opt-out: 'no cdp run' disables CDP; 'lldp run' enables LLDP
    assert sec["cdp_lldp"]["cdp_enabled"] is False
    assert sec["cdp_lldp"]["lldp_enabled"] is True
    assert sec["domain_lookup"]["enabled"] is False
    assert sec["ip_source_routing"]["enabled"] is False
    assert sec["http_server"]["http_enabled"] is True
    assert sec["http_server"]["acl"] == "99"
    assert sec["snmp"]["communities"][0] == {"name": "TESTCOMM-RO", "mode": "RO", "acl": "MGMT-ACL"}
    assert sec["banner"]["login_present"] is True
    assert sec["vty_lines"]["transport_input"] == "ssh"
    assert sec["vty_lines"]["exec_timeout_minutes"] == 10
    cov = sec["_parser_coverage"]
    assert cov["sections_attempted"] == 15
    assert cov["sections_parsed"] >= 12


def test_security_config_iosxr_optin_cdp_and_password_policy():
    # IOS XR opt-in: bare 'cdp'/'lldp' enables; hyphenated os normalised internally
    sec = parse_security_config(IOSXR_CONFIG, os_family="ios-xr")
    assert sec["cdp_lldp"]["cdp_enabled"] is True
    assert sec["cdp_lldp"]["lldp_enabled"] is True
    assert sec["password_policy"]["min_length"] == 10
    # source's XR secret regex captures a single digit (types 0/5/7/8/9)
    assert sec["password_policy"]["secret_encryption_type"] == 5
    assert sec["domain_lookup"]["enabled"] is False
    assert sec["ip_source_routing"]["enabled"] is False
    assert sec["ssh"]["version"] == 2


def test_os_family_normalisation_accepts_both_spellings():
    # both 'ios-xr' and 'iosxr' must drive the XR opt-in branch identically
    a = parse_security_config(IOSXR_CONFIG, os_family="ios-xr")["cdp_lldp"]
    b = parse_security_config(IOSXR_CONFIG, os_family="iosxr")["cdp_lldp"]
    assert a == b == {"cdp_enabled": True, "lldp_enabled": True}


def test_security_config_empty_returns_coverage():
    sec = parse_security_config("", os_family="ios-xe")
    assert sec["_parser_coverage"]["sections_attempted"] == 15
    # booleans count as 'parsed' (we made a determination); empty lists do not


def test_parse_management_iosxe():
    mgmt = parse_management(IOSXE_CONFIG)
    assert mgmt["management_interface"] == "Loopback0"
    assert mgmt["management_ip"] == "192.0.2.103"
    assert mgmt["ssh_source_interface"] == "Loopback0"
    assert mgmt["management_vrf"] == "MGMT"


def test_parse_route_policies():
    rp = parse_route_policies(IOSXE_CONFIG)
    assert "SET-LOCALPREF" in rp
    seq = rp["SET-LOCALPREF"]["sequences"][0]
    assert seq["seq"] == 10
    assert seq["action"] == "permit"
    assert "ip address prefix-list LOCAL-NETS" in seq["match"]
    assert "local-preference 150" in seq["set"]


def test_parse_prefix_lists():
    pl = parse_prefix_lists(IOSXE_CONFIG)
    assert "LOCAL-NETS" in pl
    entries = pl["LOCAL-NETS"]["entries"]
    assert {"seq": 10, "action": "permit", "prefix": "192.0.2.0/24"} in entries
    assert any(e["seq"] == 20 and e["action"] == "deny" for e in entries)


def test_parsers_return_empty_on_blank_config():
    assert parse_management("") == {}
    assert parse_route_policies("") == {}
    assert parse_prefix_lists("") == {}


# `show switch stack-ports summary` text fallback (Genie parser fails on this).
# A healthy 3-member C9300 stack ring: each member has 2 cable ports, all OK.
STACK_PORTS_SUMMARY = "\n".join([
    "Sw#/Port#  Port Status  Neighbor/Port  Cable Length   Link OK   Link Active   Sync OK   #Changes to LinkOK  In Loopback ",
    "-----------------------------------------------------------------------------------------------------------------------",
    "1/1        OK           3/2            50cm           Yes       Yes           Yes       1                   No           ",
    "1/2        OK           2/1            50cm           Yes       Yes           Yes       1                   No           ",
    "2/1        OK           1/2            50cm           Yes       Yes           Yes       1                   No           ",
    "2/2        OK           3/1            50cm           Yes       Yes           Yes       1                   No           ",
    "3/1        OK           2/2            50cm           Yes       Yes           Yes       1                   No           ",
    "3/2        OK           1/1            50cm           Yes       Yes           Yes       1                   No           ",
])


def test_parse_stack_ports_summary_full_ring():
    out = parse_stack_ports_summary(STACK_PORTS_SUMMARY)
    sp = out["stackports"]
    assert set(sp) == {"1/1", "1/2", "2/1", "2/2", "3/1", "3/2"}
    # Schema matches Genie ShowSwitchStackPortsSummary (drop-in for the consumer).
    assert sp["1/1"] == {
        "stackport_id": "1/1",
        "port_status": "OK",
        "neighbor": "3/2",
        "cable_length": "50cm",
        "link_ok": "Yes",
        "link_active": "Yes",
        "sync_ok": "Yes",
    }


def test_parse_stack_ports_summary_down_port():
    text = "\n".join([
        "Sw#/Port#  Port Status  Neighbor/Port  Cable Length   Link OK   Link Active   Sync OK   #Changes  In Loopback ",
        "1/1        DOWN         NONE/NONE      --             No        No            No        0         No          ",
    ])
    sp = parse_stack_ports_summary(text)["stackports"]
    assert sp["1/1"]["port_status"] == "DOWN"
    assert sp["1/1"]["link_ok"] == "No"
    assert sp["1/1"]["neighbor"] == "NONE/NONE"


def test_parse_stack_ports_summary_empty_or_header_only():
    # A non-stacked device returns only a header/banner (or "% Invalid input").
    assert parse_stack_ports_summary("") == {}
    assert parse_stack_ports_summary("% Invalid input detected at '^' marker.") == {}
    header_only = "Stackwise Virtual Link(SVL) Information:\nFlags:\nU-Up D-Down"
    assert parse_stack_ports_summary(header_only) == {}
