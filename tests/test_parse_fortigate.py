"""F2-4e: FortiGate REST JSON parsers + facts_builder route (rest + fortios).

Synthetic JSON fixtures (RFC 5737 IPs, invented names/serials).
"""

import json

from netcopilot.parse import build_facts
from netcopilot.parse.fortigate import interfaces as fg_interfaces
from netcopilot.parse.fortigate import system as fg_system

STATUS = {
    "results": {"model_name": "FortiGate", "model_number": "VM64", "hostname": "edge-fw-01"},
    "serial": "FGVMSYNTH0001", "version": "v7.4.1",
}

HA_PEER = {"results": [
    {"serial_no": "FGVMSYNTH0001", "hostname": "edge-fw-01", "priority": 200},
    {"serial_no": "FGVMSYNTH0002", "hostname": "edge-fw-02", "priority": 100},
]}

INTERFACE_CFG = {"results": [
    {"name": "port1", "ip": "192.0.2.254 255.255.255.0", "type": "physical",
     "status": "up", "description": "uplink"},
    {"name": "port2", "ip": "0.0.0.0 0.0.0.0", "type": "physical", "status": "down"},
]}

INTERFACE_MON = {"results": {"port1": {"link": True}, "port2": {"link": False}}}


def test_system_standalone(tmp_path):
    (tmp_path / "fortigate_system_status.json").write_text(json.dumps(STATUS))
    r = fg_system.parse(str(tmp_path))
    assert r["hostname"] == "edge-fw-01"
    assert r["platform"] == "FortiGate-VM64"
    assert r["serial"] == "FGVMSYNTH0001"
    assert r["version"] == "v7.4.1"
    assert r["cluster_members"] == []          # no ha_peer -> standalone


def test_system_ha_members(tmp_path):
    (tmp_path / "fortigate_system_status.json").write_text(json.dumps(STATUS))
    (tmp_path / "fortigate_ha_peer.json").write_text(json.dumps(HA_PEER))
    r = fg_system.parse(str(tmp_path))
    members = r["cluster_members"]
    assert len(members) == 2
    assert members[0]["role"] == "master" and members[0]["serial_number"] == "FGVMSYNTH0001"
    assert members[1]["role"] == "slave" and members[1]["serial_number"] == "FGVMSYNTH0002"
    assert r["ha_status"] == "active" and r["ha_peer_serial"] == "FGVMSYNTH0002"


def test_system_missing_status_is_failed(tmp_path):
    r = fg_system.parse(str(tmp_path))
    assert r["_parse_status"] == "failed"
    assert r["os_family"] == "fortios"


def test_interfaces(tmp_path):
    (tmp_path / "fortigate_system_interface.json").write_text(json.dumps(INTERFACE_CFG))
    (tmp_path / "fortigate_monitor_interface.json").write_text(json.dumps(INTERFACE_MON))
    ifaces = {i["name"]: i for i in fg_interfaces.parse(str(tmp_path))["interfaces"]}
    assert ifaces["port1"]["ip_address"] == "192.0.2.254/24"   # addr+mask -> CIDR
    assert ifaces["port1"]["status"] == "up" and ifaces["port1"]["protocol"] == "up"
    assert ifaces["port2"]["ip_address"] is None               # 0.0.0.0 -> no IP
    assert ifaces["port2"]["protocol"] == "down"               # from monitor link=False


def test_interfaces_missing_config_returns_none(tmp_path):
    assert fg_interfaces.parse(str(tmp_path)) is None


def test_build_facts_fortigate(tmp_path):
    run_id = "fg-run"
    run_path = tmp_path / run_id
    raw = run_path / "raw" / "edge-fw-01"
    raw.mkdir(parents=True)
    (raw / "fortigate_system_status.json").write_text(json.dumps(STATUS))
    (raw / "fortigate_ha_peer.json").write_text(json.dumps(HA_PEER))
    (raw / "fortigate_system_interface.json").write_text(json.dumps(INTERFACE_CFG))
    (raw / "fortigate_monitor_interface.json").write_text(json.dumps(INTERFACE_MON))
    (raw / "fortigate_firewall_policy.json").write_text(json.dumps({"results": [{"policyid": 1}]}))
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T10:00:00Z",
        "devices": [{
            "inventory_name": "edge-fw-01", "hostname": "edge-fw-01", "os": "fortios",
            "role": "firewall", "site": "demo", "collection_strategy": "rest",
            "status": "success",
        }],
    }))

    build_facts(run_id, runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "edge-fw-01" / "device_facts.json").read_text())
    assert facts["device_info"]["platform"] == "FortiGate-VM64"
    assert facts["device_info"]["role"] == "firewall"
    assert len(facts["cluster_members"]) == 2
    assert facts["interfaces"][0]["name"] == "port1"
    # raw FortiGate evidence carried forward for the rules layer
    assert "system_status" in facts["fortigate"]
    assert facts["fortigate"]["firewall_policy"]["results"][0]["policyid"] == 1
