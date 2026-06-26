"""F2-4d: RESTCONF JSON parsers + facts_builder route (restconf + ios-xe).

Synthetic JSON fixtures (RFC 5737 IPs, invented names/serials).
"""

import json

from netcopilot.parse import build_facts
from netcopilot.parse.restconf import cdp as rc_cdp
from netcopilot.parse.restconf import interfaces as rc_interfaces
from netcopilot.parse.restconf import lldp as rc_lldp
from netcopilot.parse.restconf import system as rc_system

NATIVE = {"Cisco-IOS-XE-native:native": {"hostname": "core-rtr-01", "version": "17.12"}}

HARDWARE = {
    "Cisco-IOS-XE-device-hardware-oper:device-hardware-data": {
        "device-hardware": {
            "device-inventory": [
                {"hw-type": "hw-type-chassis", "dev-name": "Switch 1",
                 "part-number": "C9300-24T", "serial-number": "SYNTHRC0001"},
            ],
            "device-system-data": {
                "software-version": "Cisco IOS XE Software, Version 17.12.5, RELEASE",
            },
        }
    }
}

INTERFACES = {
    "openconfig-interfaces:interfaces": {
        "interface": [
            {"name": "GigabitEthernet1",
             "state": {"admin-status": "UP", "oper-status": "UP"},
             "subinterfaces": {"subinterface": [
                 {"openconfig-if-ip:ipv4": {"addresses": {"address": [{"ip": "192.0.2.1"}]}}}
             ]}},
        ]
    }
}

CDP = {
    "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details": {
        "cdp-neighbor-detail": [
            {"device-name": "dist-sw-01.example.com",
             "local-intf-name": "GigabitEthernet1/0/1",
             "port-id": "GigabitEthernet1/0/24",
             "platform-name": "cisco C9500", "capability": "R S"},
        ]
    }
}

LLDP = {
    "openconfig-lldp:lldp": {"interfaces": {"interface": [
        {"name": "GigabitEthernet2", "neighbors": {"neighbor": [
            {"state": {"system-name": "edge-fw-01.example.com", "port-id": "port3",
                       "system-description": "FortiGate-VM"}}
        ]}},
    ]}}
}


def test_interfaces(tmp_path):
    f = tmp_path / "restconf_interfaces.json"
    f.write_text(json.dumps(INTERFACES))
    r = rc_interfaces.parse(str(f))
    assert r["interfaces"] == [
        {"name": "GigabitEthernet1", "ip_address": "192.0.2.1", "status": "up", "protocol": "up"}
    ]


def test_interfaces_missing_file():
    assert rc_interfaces.parse("/no/file.json") is None


def test_cdp(tmp_path):
    f = tmp_path / "restconf_cdp.json"
    f.write_text(json.dumps(CDP))
    n = rc_cdp.parse(str(f))["neighbors"][0]
    assert n["neighbor_hostname"] == "dist-sw-01"
    assert n["neighbor_interface"] == "GigabitEthernet1/0/24"


def test_lldp(tmp_path):
    f = tmp_path / "restconf_lldp.json"
    f.write_text(json.dumps(LLDP))
    n = rc_lldp.parse(str(f))["neighbors"][0]
    assert n["neighbor_hostname"] == "edge-fw-01"
    assert n["neighbor_platform"] == "FortiGate-VM"
    assert n["capability"] is None


def test_system(tmp_path):
    (tmp_path / "restconf_native.json").write_text(json.dumps(NATIVE))
    (tmp_path / "restconf_device_hardware.json").write_text(json.dumps(HARDWARE))
    r = rc_system.parse(str(tmp_path))
    assert r["hostname"] == "core-rtr-01"
    assert r["platform"] == "C9300-24T"
    assert r["serial"] == "SYNTHRC0001"
    assert r["version"] == "17.12.5"          # full version from software-version
    assert r["cluster_members"] == []         # single chassis


def test_empty_cdp_204(tmp_path):
    f = tmp_path / "restconf_cdp.json"
    f.write_text("{}")                          # RESTCONF 204 -> empty object
    assert rc_cdp.parse(str(f))["neighbors"] == []


def test_build_facts_restconf_iosxe(tmp_path):
    run_id = "rc-run"
    run_path = tmp_path / run_id
    raw = run_path / "raw" / "core-rtr-01"
    raw.mkdir(parents=True)
    (raw / "restconf_native.json").write_text(json.dumps(NATIVE))
    (raw / "restconf_device_hardware.json").write_text(json.dumps(HARDWARE))
    (raw / "restconf_interfaces.json").write_text(json.dumps(INTERFACES))
    (raw / "restconf_cdp.json").write_text(json.dumps(CDP))
    (raw / "restconf_lldp.json").write_text(json.dumps(LLDP))
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T10:00:00Z",
        "devices": [{
            "inventory_name": "core-rtr-01", "hostname": "core-rtr-01", "os": "ios-xe",
            "role": "core_router", "site": "demo", "collection_strategy": "restconf",
            "status": "success",
        }],
    }))

    build_facts(run_id, runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "core-rtr-01" / "device_facts.json").read_text())
    assert facts["device_info"]["platform"] == "C9300-24T"
    assert facts["device_info"]["serial"] == "SYNTHRC0001"
    assert facts["device_info"]["role"] == "core_router"
    assert facts["interfaces"][0]["ip_address"] == "192.0.2.1"
    hosts = {n["neighbor_hostname"] for n in facts["cdp_neighbors"]}
    assert hosts == {"dist-sw-01", "edge-fw-01"}    # CDP + LLDP merged
