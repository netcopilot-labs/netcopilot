"""F2-6-c: ARP + firewall-policy loaders (fake driver, no Neo4j).

ARP from Cisco Genie + FortiGate; firewall policies from FortiGate (with
address/service/zone resolution via policy_resolver) + Cisco ACLs. RFC 5737 IPs.
"""

import json

from netcopilot.graph.loader import (
    _load_arp_entries,
    _load_firewall_policies,
    _normalize_mac,
)
from test_graph_load_model import FakeDriver

SITE, RUN = "dc", "r1"


def test_normalize_mac():
    assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("garbage") == "garbage"  # passthrough on bad length


def _facts(tmp_path, device):
    d = tmp_path / "run" / "facts" / device
    d.mkdir(parents=True)
    return d


def test_load_arp_genie_and_fortigate(tmp_path):
    _facts(tmp_path, "core-rtr-01").joinpath("genie_arp.json").write_text(json.dumps(
        {"interfaces": {"GigabitEthernet0/1": {"ipv4": {"neighbors": {
            "192.0.2.5": {"link_layer_address": "aabb.ccdd.eeff", "origin": "dynamic"}}}}}}))
    _facts(tmp_path, "fw-01").joinpath("fortigate_arp.json").write_text(json.dumps(
        {"results": [{"ip": "192.0.2.6", "mac": "11:22:33:44:55:66", "interface": "port1"}]}))

    driver = FakeDriver()
    n = _load_arp_entries(driver, tmp_path / "run", SITE, RUN)
    assert n == 2
    entries = next(p["entries"] for c, p in driver.calls if "[:HAS_ARP]" in c)
    by_ip = {e["ip"]: e for e in entries}
    assert by_ip["192.0.2.5"]["mac"] == "aa:bb:cc:dd:ee:ff"  # normalised
    assert by_ip["192.0.2.5"]["device"] == "core-rtr-01"
    assert by_ip["192.0.2.6"]["mac"] == "11:22:33:44:55:66"


def test_load_arp_no_facts_returns_zero(tmp_path):
    assert _load_arp_entries(FakeDriver(), tmp_path / "nope", SITE, RUN) == 0


def test_load_firewall_fortigate_with_resolution(tmp_path):
    d = _facts(tmp_path, "fw-01")
    (d / "fortigate_firewall_address.json").write_text(json.dumps(
        {"results": [{"name": "web", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0"}]}))
    (d / "fortigate_firewall_service_custom.json").write_text(json.dumps(
        {"results": [{"name": "HTTPS", "tcp-portrange": "443"}]}))
    (d / "fortigate_system_zone.json").write_text(json.dumps(
        {"results": [{"name": "dmz", "interface": [{"interface-name": "port2"}]}]}))
    (d / "fortigate_firewall_policy.json").write_text(json.dumps({"results": [
        {"policyid": 1, "name": "allow-web", "status": "enable", "action": "accept",
         "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
         "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "web"}], "service": [{"name": "HTTPS"}]},
    ]}))

    driver = FakeDriver()
    n = _load_firewall_policies(driver, tmp_path / "run", SITE, RUN)
    assert n == 1
    policies = next(p["policies"] for c, p in driver.calls if "[:HAS_POLICY]" in c)
    pol = policies[0]
    assert pol["name"] == "allow-web" and pol["action"] == "accept"
    assert pol["policy_type"] == "fortigate"
    assert pol["dstaddr"] == "192.0.2.0/24"    # address resolved
    assert pol["service"] == "TCP/443"         # service resolved
    assert "dmz" in pol["dst_zones"]           # zone resolved
    assert pol["dst_negate"] is False and pol["src_negate"] is False  # SF-NEGATE-1


def test_load_firewall_negate_flags(tmp_path):
    # SF-NEGATE-1: an enabled *-negate inverts the policy; it must be captured so
    # it can't silently invert the stored meaning.
    d = _facts(tmp_path, "fw-01")
    (d / "fortigate_firewall_address.json").write_text(json.dumps(
        {"results": [{"name": "web", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0"}]}))
    (d / "fortigate_firewall_policy.json").write_text(json.dumps({"results": [
        {"policyid": 5, "name": "block-all-but-web", "status": "enable", "action": "accept",
         "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
         "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "web"}], "service": [{"name": "ALL"}],
         "dstaddr-negate": "enable", "srcaddr-negate": "disable", "service-negate": "enable"},
    ]}))
    driver = FakeDriver()
    _load_firewall_policies(driver, tmp_path / "run", SITE, RUN)
    pol = next(p["policies"] for c, p in driver.calls if "[:HAS_POLICY]" in c)[0]
    assert pol["dst_negate"] is True            # was silently dropped
    assert pol["src_negate"] is False
    assert pol["service_negate"] is True


def test_load_firewall_cisco_acl(tmp_path):
    d = _facts(tmp_path, "core-rtr-01")
    (d / "genie_acl.json").write_text(json.dumps({"acls": {"BLOCK-IN": {
        "type": "ipv4-acl-type", "aces": {"10": {
            "actions": {"forwarding": "deny"},
            "matches": {"l3": {"ipv4": {
                "source_ipv4_network": {"192.0.2.0/24": {}}, "protocol": "tcp"}}}}}}}}))
    driver = FakeDriver()
    n = _load_firewall_policies(driver, tmp_path / "run", SITE, RUN)
    assert n == 1
    pol = next(p["policies"] for c, p in driver.calls if "[:HAS_POLICY]" in c)[0]
    assert pol["policy_type"] == "acl"
    assert pol["name"] == "BLOCK-IN" and pol["action"] == "deny"
    assert pol["srcaddr"] == "192.0.2.0/24"
    assert pol["seq"] == 10  # SF-ORDER-1: ACE seq written so ORDER BY p.seq is defined


def test_load_firewall_acl_seq_is_ace_order(tmp_path):
    # SF-ORDER-1: every ACL node must carry seq=ACE-seq, so get_firewall_policies'
    # `ORDER BY p.device, p.seq` is deterministic for ACL nodes (was seq=NULL →
    # Neo4j scan order). ACEs given out-of-order in the JSON to prove the row
    # `seq` follows the ACE seq, not dict insertion order.
    d = _facts(tmp_path, "core-rtr-01")
    (d / "genie_acl.json").write_text(json.dumps({"acls": {"ORD": {
        "type": "ipv4-acl-type", "aces": {
            "30": {"actions": {"forwarding": "permit"},
                   "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.3/32": {}}}}}},
            "10": {"actions": {"forwarding": "deny"},
                   "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.1/32": {}}}}}},
            "20": {"actions": {"forwarding": "permit"},
                   "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.2/32": {}}}}}},
        }}}}))
    driver = FakeDriver()
    _load_firewall_policies(driver, tmp_path / "run", SITE, RUN)
    policies = next(p["policies"] for c, p in driver.calls if "[:HAS_POLICY]" in c)
    # Every node carries seq, and sorting by it yields the ACE evaluation order.
    assert all("seq" in p for p in policies)
    by_seq = sorted(policies, key=lambda p: p["seq"])
    assert [p["seq"] for p in by_seq] == [10, 20, 30]
    assert [p["srcaddr"] for p in by_seq] == ["192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"]
