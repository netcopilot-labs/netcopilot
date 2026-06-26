"""Positive-trigger fixtures for zero-coverage CIS compliance rules.

These CIS rules had no positive-trigger test and do not fire on the goldens
(the audited devices are compliant for them), so their firing logic was
unexercised. Each fixture below is the minimal violating input that should
make the rule produce >=1 finding — proving the trigger works.

Config-based rules (CIS_XE_*, CIS_XR_*) read facts/<host>/running_config.txt
or security_config.json and gate on os_family. FortiGate rules (CIS_FG_*)
scan facts/<host>/ for fortigate_*.json (load_fg_json unwraps {"results": ...}).

Three CIS rules are inert BY DESIGN (superseded by cross-platform Genie-based
rules) and correctly return [] — locked separately at the bottom.
"""

import json

import pytest

from netcopilot.rules.discovery import get_rule_by_id


def _make_run(tmp_path, hostname, files):
    run = tmp_path / "run"
    d = run / "facts" / hostname
    d.mkdir(parents=True)
    for fname, content in files.items():
        p = d / fname
        p.write_text(json.dumps(content) if fname.endswith(".json") else content)
    return run


# rule_id -> (os_family, {facts_filename: content})  — each is a VIOLATION.
_TRIGGERS = {
    # --- IOS XE (config / security_config based) ---
    "CIS_XE_1_1_AUTH":       ("iosxe", {"running_config.txt": "hostname dev-01\n"}),               # no aaa authentication
    "CIS_XE_1_1_ENABLE":     ("iosxe", {"running_config.txt": "hostname dev-01\n"}),               # no aaa new-model
    "CIS_XE_2_2_REMOTE_LOG": ("iosxe", {"security_config.json": {"logging": {"hosts": []}}}),      # no syslog host
    "CIS_XE_3_3_OSPF_AUTH":  ("iosxe", {"running_config.txt": "hostname dev-01\nrouter ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n!\n"}),

    # --- IOS XR (config based) ---
    "CIS_XR_1_1_AUTH":   ("iosxr", {"running_config.txt": "hostname r1\n"}),                       # no aaa authentication login
    "CIS_XR_1_1_AUTHZ":  ("iosxr", {"running_config.txt": "hostname r1\naaa authentication login default local\n"}),  # no aaa authorization exec
    "CIS_XR_1_2_SSH":    ("iosxr", {"running_config.txt": "hostname r1\nssh server timeout 120\n"}),  # SSH timeout 120s > 60s
    "CIS_XR_1_6_ACCESS": ("iosxr", {"running_config.txt": "hostname r1\ntelnet vrf default ipv4 server max-servers 5\n"}),
    "CIS_XR_2_1_KEYCHAINS": ("iosxr", {"running_config.txt": "hostname r1\nrouter ospf 1\n area 0\n"}),  # routing, no key chain
    "CIS_XR_2_1_OSPF_AUTH": ("iosxr", {"running_config.txt": "hostname r1\nrouter ospf 1\n area 0\n"}),  # router ospf, no authentication
    "CIS_XR_2_3_VRRP_AUTH": ("iosxr", {"running_config.txt": "hostname r1\ninterface Gi0/0/0/0\n vrrp 1\n  address 10.1.1.1\n"}),
    "CIS_XR_2_4_HSRP_AUTH": ("iosxr", {"running_config.txt": "hostname r1\ninterface Gi0/0/0/0\n hsrp 1\n  address 10.1.1.1\n"}),

    # --- FortiGate (fortigate_*.json, {"results": [...]}) ---
    "CIS_FG_1_2":   ("fortios", {"fortigate_system_zone.json": {"results": [{"name": "trust", "intrazone": "allow"}]}}),
    "CIS_FG_1_3":   ("fortios", {"fortigate_system_interface.json": {"results": [{"name": "wan1", "role": "wan", "type": "physical", "allowaccess": "ping https ssh http telnet snmp"}]}}),
    "CIS_FG_2_3_2": ("fortios", {"fortigate_snmp_community.json": {"results": [{"id": 1, "name": "public"}]}}),
    "CIS_FG_2_4_5": ("fortios", {"fortigate_system_interface.json": {"results": [{"name": "port1", "allowaccess": "http telnet ping"}]}}),
    "CIS_FG_3_5":   ("fortios", {"fortigate_firewall_policy.json": {"results": [{"policyid": 1, "action": "accept", "status": "enable"}]}}),
    "CIS_FG_3_6":   ("fortios", {"fortigate_firewall_policy.json": {"results": [{"policyid": 1, "action": "accept", "status": "enable", "logtraffic": "disable"}]}}),
    "CIS_FG_4_2_4": ("fortios", {"fortigate_antivirus_profile.json": {"results": [{"name": "default", "http": {"emulator": "disable"}}]}}),
    "CIS_FG_4_3_2": ("fortios", {"fortigate_dnsfilter_profile.json": {"results": [{"name": "default", "ftgd-dns": {"filters": [{"id": 1, "log": "disable"}]}}]}}),
}


@pytest.mark.parametrize("rule_id", sorted(_TRIGGERS))
def test_cis_rule_fires_on_violation(rule_id, tmp_path):
    os_family, files = _TRIGGERS[rule_id]
    host = "dev-01"
    run = _make_run(tmp_path, host, files)
    model = {"devices": [{"hostname": host, "os_family": os_family}], "interfaces": [], "links": []}
    findings = get_rule_by_id(rule_id).evaluate(
        model, {"run_path": str(run), "run_id": "r1", "manifest": {}}
    )
    assert len(findings) >= 1, f"{rule_id} did not fire on its violation fixture"


# These three CIS rules are inert BY DESIGN — superseded by cross-platform,
# Genie-based rules (NTP_NO_AUTHENTICATION / BGP_NEIGHBOR_NO_PASSWORD). They
# always return [] even on a would-be violation. Lock that contract.
_INERT = ["CIS_XE_2_3_NTP", "CIS_XE_3_3_BGP_AUTH", "CIS_XR_2_1_BGP_AUTH"]


@pytest.mark.parametrize("rule_id", _INERT)
def test_cis_inert_rules_return_empty(rule_id, tmp_path):
    host = "dev-01"
    run = _make_run(tmp_path, host, {
        "running_config.txt": "hostname dev-01\nrouter bgp 65000\n neighbor 10.0.0.1 remote-as 65001\n",
    })
    model = {"devices": [{"hostname": host, "os_family": "iosxe"}], "interfaces": [], "links": []}
    findings = get_rule_by_id(rule_id).evaluate(
        model, {"run_path": str(run), "run_id": "r1", "manifest": {}}
    )
    assert findings == [], f"{rule_id} is meant to be inert (superseded) but fired"
