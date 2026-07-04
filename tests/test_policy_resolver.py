"""F2-6-c-1: policy_resolver — FortiGate address/service/zone resolution + ACL parsing.

Pure parsers (stdlib only). FortiGate facts written as synthetic JSON files;
RFC 5737 IPs. The running-config-based parsers (route-policy / ACL-binding) are
tested alongside their loader consumers in 6c-2 / 6d.
"""

import json

from netcopilot.parse.policy_resolver import (
    build_address_resolver,
    build_service_resolver,
    build_zone_map,
    extract_isdb_refs,
    fg_dst_to_cidr,
    ip_in_isdb_ranges,
    parse_genie_acl,
    service_allows,
)


def _write(facts_dir, name, obj):
    (facts_dir / name).write_text(json.dumps(obj))


# ── S07-3: shared 5-tuple matcher ────────────────────────────────────────────

def test_service_allows_protocol_only_when_no_port():
    # dst_port=None → protocol-level match; None protocol → IP-only (True).
    assert service_allows(None, None, "TCP/443") is True
    assert service_allows("tcp", None, "TCP/443") is True
    assert service_allows("udp", None, "TCP/443") is False


def test_service_allows_all_and_empty_permissive():
    assert service_allows("tcp", 443, "ALL") is True
    assert service_allows("tcp", 443, "") is True
    assert service_allows("tcp", 443, "any") is True


def test_service_allows_fortigate_grammar():
    assert service_allows("tcp", 443, "TCP/443") is True
    assert service_allows("tcp", 444, "TCP/443") is False
    assert service_allows("tcp", 443, "TCP/443-445") is True
    assert service_allows("tcp", 446, "TCP/443-445") is False
    assert service_allows("tcp", 53, "TCP/443, UDP/53") is False  # 53 is UDP here
    assert service_allows("udp", 53, "TCP/443, UDP/53") is True


def test_service_allows_acl_grammar():
    assert service_allows("tcp", 443, "tcp 443") is True
    assert service_allows("tcp", 85, "tcp 80-90") is True
    assert service_allows("tcp", 2000, "tcp gt 1024") is True
    assert service_allows("tcp", 500, "tcp gt 1024") is False
    assert service_allows("tcp", 79, "tcp lt 80") is True
    # src-port spec is not a dst match
    assert service_allows("tcp", 53, "tcp src 53") is False


def test_service_allows_unparseable_is_permissive():
    # Don't fabricate a block from a spec we can't parse.
    assert service_allows("tcp", 443, "tcp weird-spec") is True


def test_ip_in_isdb_ranges():
    ranges = ["192.0.2.5", "198.51.100.0-198.51.100.255"]
    assert ip_in_isdb_ranges("192.0.2.5", ranges) is True
    assert ip_in_isdb_ranges("198.51.100.128", ranges) is True
    assert ip_in_isdb_ranges("203.0.113.1", ranges) is False
    assert ip_in_isdb_ranges("not-an-ip", ranges) is False


def test_fg_dst_to_cidr():
    assert fg_dst_to_cidr("192.0.2.0 255.255.255.0") == "192.0.2.0/24"
    assert fg_dst_to_cidr("0.0.0.0 0.0.0.0") == "0.0.0.0/0"
    assert fg_dst_to_cidr("not-an-ip") == "not-an-ip"  # passthrough


def test_build_zone_map(tmp_path):
    _write(tmp_path, "fortigate_system_zone.json",
           {"results": [{"name": "trust", "interface": [{"interface-name": "port1"},
                                                        {"interface-name": "port2"}]}]})
    assert build_zone_map(tmp_path) == {"port1": "trust", "port2": "trust"}


def test_build_zone_map_missing_file(tmp_path):
    assert build_zone_map(tmp_path) == {}  # graceful when absent


def test_build_address_resolver_ipmask_fqdn_and_group(tmp_path):
    _write(tmp_path, "fortigate_firewall_address.json", {"results": [
        {"name": "web", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0"},
        {"name": "site", "type": "fqdn", "fqdn": "example.com"},
        {"name": "pool", "type": "iprange", "start-ip": "192.0.2.10", "end-ip": "192.0.2.20"},
    ]})
    _write(tmp_path, "fortigate_firewall_addrgrp.json",
           {"results": [{"name": "webgrp", "member": [{"name": "web"}, {"name": "site"}]}]})
    r = build_address_resolver(tmp_path)
    assert r["all"] == "0.0.0.0/0"            # built-in
    assert r["web"] == "192.0.2.0/24"
    assert r["site"] == "example.com"
    assert r["pool"] == "192.0.2.10-192.0.2.20"
    assert r["webgrp"] == "192.0.2.0/24, example.com"  # group expanded


def test_build_service_resolver(tmp_path):
    _write(tmp_path, "fortigate_firewall_service_custom.json", {"results": [
        {"name": "HTTPS", "tcp-portrange": "443"},
        {"name": "DNS", "udp-portrange": "53"},
        {"name": "PING", "protocol": "ICMP"},
    ]})
    _write(tmp_path, "fortigate_firewall_service_group.json",
           {"results": [{"name": "web-svcs", "member": [{"name": "HTTPS"}]}]})
    r = build_service_resolver(tmp_path)
    assert r["ALL"] is None                    # "any"
    assert r["HTTPS"] == "TCP/443"
    assert r["DNS"] == "UDP/53"
    assert r["PING"] == "ICMP"
    assert r["web-svcs"] == "TCP/443"          # group resolved


def test_build_service_resolver_sctp(tmp_path):
    # SF-SVC-1: a TCP/UDP/SCTP service whose ports live only in sctp-portrange
    # used to resolve to the bare object name, silently dropping the ports.
    _write(tmp_path, "fortigate_firewall_service_custom.json", {"results": [
        {"name": "DIAMETER", "protocol": "TCP/UDP/SCTP", "sctp-portrange": "3868"},
        {"name": "M3UA", "protocol": "TCP/UDP/SCTP",
         "tcp-portrange": "2905", "sctp-portrange": "2905"},
    ]})
    r = build_service_resolver(tmp_path)
    assert r["DIAMETER"] == "SCTP/3868"             # was "DIAMETER" (name, no ports)
    assert r["M3UA"] == "TCP/2905, SCTP/2905"       # all protocols kept


def test_build_service_resolver_icmp(tmp_path):
    # SF-ICMP-1: ICMP6 used to fall through to the bare object name; ICMP collapsed
    # its type. Now both keep the protocol and surface icmptype (incl. 0).
    _write(tmp_path, "fortigate_firewall_service_custom.json", {"results": [
        {"name": "PING", "protocol": "ICMP", "icmptype": 8},
        {"name": "ECHO-REPLY", "protocol": "ICMP", "icmptype": 0},   # 0 is valid
        {"name": "ICMP-ANY", "protocol": "ICMP"},                    # no type
        {"name": "PING6", "protocol": "ICMP6", "icmptype": 128},
    ]})
    r = build_service_resolver(tmp_path)
    assert r["PING"] == "ICMP/type:8"
    assert r["ECHO-REPLY"] == "ICMP/type:0"          # not collapsed/ignored
    assert r["ICMP-ANY"] == "ICMP"
    assert r["PING6"] == "ICMP6/type:128"            # was "PING6" (bare name)


def test_parse_genie_acl():
    data = {"acls": {"BLOCK-IN": {"type": "ipv4-acl-type", "aces": {
        "10": {"actions": {"forwarding": "deny"},
               "matches": {"l3": {"ipv4": {
                   "source_ipv4_network": {"192.0.2.0/24": {}},
                   "destination_ipv4_network": {"203.0.113.0/24": {}},
                   "protocol": "tcp"}}}},
        "20": {"actions": {"forwarding": "permit"},
               "matches": {"l3": {"ipv4": {"protocol": "ip"}}}},
    }}}}
    acls = parse_genie_acl(data)
    assert len(acls) == 1
    acl = acls[0]
    assert acl["name"] == "BLOCK-IN"
    aces = {a["seq"]: a for a in acl["aces"]}
    assert aces[10]["action"] == "deny"
    assert aces[10]["source"] == "192.0.2.0/24"
    assert aces[10]["destination"] == "203.0.113.0/24"
    assert aces[20]["action"] == "permit"  # "permit" forwarding → permit


def test_parse_genie_acl_multi_network_ace():
    # SF-ACE-1: an ACE matching >1 source/dest network kept only the first
    # (by genie dict-insertion order) — lossy + order-dependent. Now all are
    # kept, sorted, so the result is complete and deterministic.
    data = {"acls": {"MULTI": {"type": "ipv4-acl-type", "aces": {
        "10": {"actions": {"forwarding": "deny"},
               "matches": {"l3": {"ipv4": {
                   "source_ipv4_network": {
                       "192.0.2.0/24": {}, "198.51.100.0/24": {}, "10.0.0.0/8": {}},
                   "destination_ipv4_network": {
                       "203.0.113.0/24": {}, "172.16.0.0/12": {}},
                   "protocol": "tcp"}}}},
    }}}}
    ace = parse_genie_acl(data)[0]["aces"][0]
    assert ace["source"] == "10.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24"   # all, sorted
    assert ace["destination"] == "172.16.0.0/12, 203.0.113.0/24"
