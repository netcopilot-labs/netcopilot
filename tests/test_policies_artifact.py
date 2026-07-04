"""S09-1 / S09-2: the shared firewall-policy builder + the policies.json artifact.

`build_firewall_policies` is the one source of truth the Neo4j loader and the
diff artifact share (S09-1). `process_run` writes its output to
`policies/policies.json` alongside model/ and findings/ (S09-2). Pure facts →
dicts; no Neo4j here (synthetic run dirs on tmp_path).
"""

import json

from netcopilot.parse.policy_resolver import build_firewall_policies


def _facts(run_dir, device):
    d = run_dir / "facts" / device
    d.mkdir(parents=True)
    return d


def _write(dev_dir, name, obj):
    (dev_dir / name).write_text(json.dumps(obj))


# ── S09-1: shared builder ────────────────────────────────────────────────────

def test_fortigate_policy_resolved(tmp_path):
    fg = _facts(tmp_path, "fw-01")
    _write(fg, "fortigate_system_zone.json",
           {"results": [{"name": "trust", "interface": [{"interface-name": "port1"}]}]})
    _write(fg, "fortigate_firewall_address.json",
           {"results": [{"name": "web", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0"}]})
    _write(fg, "fortigate_firewall_service_custom.json",
           {"results": [{"name": "HTTPS", "tcp-portrange": "443"}]})
    _write(fg, "fortigate_firewall_policy.json", {"results": [{
        "policyid": 7, "name": "allow-web", "status": "enable", "action": "accept",
        "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "web"}],
        "service": [{"name": "HTTPS"}],
        "internet-service-name": [{"name": "Tor-Relay"}],
    }]})

    policies = build_firewall_policies(tmp_path, "site1", "run-A")

    assert len(policies) == 1
    p = policies[0]
    assert p["policyid"] == 7
    assert p["action"] == "accept"
    assert p["srcaddr"] == "0.0.0.0/0"          # "all" resolved
    assert p["dstaddr"] == "192.0.2.0/24"       # address object resolved
    assert p["service"] == "TCP/443"            # service resolved
    assert p["dst_isdb"] == "Tor-Relay"        # ISDB reference surfaced
    assert p["src_zones"] == ["trust"]
    assert p["policy_type"] == "fortigate"
    assert p["device"] == "fw-01" and p["site"] == "site1" and p["run_id"] == "run-A"


def test_cisco_acl_flattened_to_aces(tmp_path):
    sw = _facts(tmp_path, "sw-01")
    _write(sw, "genie_acl.json", {"acls": {"BLOCK-IN": {
        "type": "ipv4-acl-type",
        "aces": {
            "10": {"actions": {"forwarding": "permit"},
                   "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.0/24": {}}}}}},
            "20": {"actions": {"forwarding": "deny"},
                   "matches": {"l3": {"ipv4": {"destination_ipv4_network": {"198.51.100.0/24": {}}}}}},
        }}}})

    policies = build_firewall_policies(tmp_path, "site1", "run-A")

    assert len(policies) == 2
    assert {p["seq"] for p in policies} == {10, 20}
    assert all(p["policy_type"] == "acl" for p in policies)
    assert all(p["name"] == "BLOCK-IN" for p in policies)
    permit = next(p for p in policies if p["seq"] == 10)
    assert permit["action"] == "permit" and permit["srcaddr"] == "192.0.2.0/24"


def test_none_valued_properties_stripped(tmp_path):
    # ALL service resolves to None → the key must be absent (Neo4j has no nulls).
    fg = _facts(tmp_path, "fw-01")
    _write(fg, "fortigate_firewall_service_custom.json", {"results": []})
    _write(fg, "fortigate_firewall_policy.json", {"results": [{
        "policyid": 1, "action": "accept",
        "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
    }]})

    p = build_firewall_policies(tmp_path, "site1", "run-A")[0]
    # service resolver maps ALL→None; ", ".join over [None] would crash, so the
    # builder stringifies — assert it never emits a literal None value.
    assert None not in p.values()


def test_no_facts_dir_returns_empty(tmp_path):
    assert build_firewall_policies(tmp_path, "site1", "run-A") == []


def test_no_policies_returns_empty(tmp_path):
    _facts(tmp_path, "sw-01")  # device dir with no policy/acl files
    assert build_firewall_policies(tmp_path, "site1", "run-A") == []
