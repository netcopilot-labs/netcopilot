"""F2-5-final: facts_builder embeds facts["genie"] from genie_*.json.

Schema commitment #3 — the pyATS strategy writes genie_<family>.json into
facts/<name>/ during collection; facts_builder embeds each into
facts["genie"][family] so the model layer reads LAG/interface/SVL data
straight from device_facts.json. Non-pyATS devices get an empty dict.
"""

import json

from netcopilot.parse import build_facts

SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a

core-sw-01 uptime is 10 weeks, 2 days

Model Number                       : C9500
System Serial Number               : 9ABCDEF0001
Base Ethernet MAC Address          : 00:11:22:33:44:55
"""

GENIE_INTERFACE = {"GigabitEthernet1/0/1": {"ipv4": {"192.0.2.1/30": {"ip": "192.0.2.1"}}}}
GENIE_LAG = {"interfaces": {"Port-channel1": {"members": {"GigabitEthernet1/0/1": {}}}}}
GENIE_SVL_LINK = {"slot": {"1": {"port": {"1": {"state": "U"}}}}}


def _write_pyats_device(run_path):
    raw = run_path / "raw" / "core-sw-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION)
    # genie evidence the pyATS adapter would have written during collection
    facts_dir = run_path / "facts" / "core-sw-01"
    facts_dir.mkdir(parents=True)
    (facts_dir / "genie_interface.json").write_text(json.dumps(GENIE_INTERFACE))
    (facts_dir / "genie_lag.json").write_text(json.dumps(GENIE_LAG))
    (facts_dir / "genie_svl_link.json").write_text(json.dumps(GENIE_SVL_LINK))


def _manifest(devices):
    return {"run_id": "genie-run", "timestamp_utc": "2026-06-18T10:00:00Z", "devices": devices}


def test_genie_evidence_embedded_for_pyats_device(tmp_path):
    run_path = tmp_path / "genie-run"
    _write_pyats_device(run_path)
    (run_path / "manifest.json").write_text(json.dumps(_manifest([{
        "inventory_name": "core-sw-01", "hostname": "core-sw-01", "os": "ios-xe",
        "role": "core", "site": "dc", "collection_strategy": "pyats", "status": "success",
    }])))

    build_facts("genie-run", runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "core-sw-01" / "device_facts.json").read_text())

    genie = facts["genie"]
    # keyed by family (genie_<family>.json → family)
    assert set(genie) == {"interface", "lag", "svl_link"}
    assert genie["interface"] == GENIE_INTERFACE
    assert genie["lag"]["interfaces"]["Port-channel1"]["members"]
    assert genie["svl_link"] == GENIE_SVL_LINK


def test_genie_empty_for_non_pyats_device(tmp_path):
    run_path = tmp_path / "genie-run"
    raw = run_path / "raw" / "ssh-sw-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION)
    (run_path / "manifest.json").write_text(json.dumps(_manifest([{
        "inventory_name": "ssh-sw-01", "hostname": "ssh-sw-01", "os": "ios-xe",
        "role": "core", "site": "dc", "collection_strategy": "ssh", "status": "success",
    }])))

    build_facts("genie-run", runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "ssh-sw-01" / "device_facts.json").read_text())

    # no genie_*.json present → empty dict, schema still has the key
    assert facts["genie"] == {}


RR_RUNNING_CONFIG = """\
!
router bgp 64496
 bgp router-id 198.51.100.100
 bgp cluster-id 198.51.100.100
 neighbor 198.51.100.101 remote-as 64496
 address-family ipv4
  neighbor 198.51.100.101 activate
  neighbor 198.51.100.101 route-reflector-client
 exit-address-family
!
"""


def test_bgp_config_fact_written_from_running_config(tmp_path):
    # facts_builder parses the collected running_config.txt into bgp_config.json
    # so the config-only route-reflector topology (which genie omits) reaches
    # the model + cross-device rules.
    run_path = tmp_path / "genie-run"
    raw = run_path / "raw" / "core-sw-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION)
    facts_dir = run_path / "facts" / "core-sw-01"
    facts_dir.mkdir(parents=True)
    (facts_dir / "running_config.txt").write_text(RR_RUNNING_CONFIG)
    (run_path / "manifest.json").write_text(json.dumps(_manifest([{
        "inventory_name": "core-sw-01", "hostname": "core-sw-01", "os": "ios-xe",
        "role": "core", "site": "dc", "collection_strategy": "pyats", "status": "success",
    }])))

    build_facts("genie-run", runs_base=tmp_path)

    bgp_cfg = json.loads((facts_dir / "bgp_config.json").read_text())
    assert bgp_cfg["cluster_id"] == "198.51.100.100"
    assert bgp_cfg["neighbors"]["198.51.100.101"]["route_reflector_client"] is True


def test_no_bgp_config_fact_without_running_config(tmp_path):
    # A device with no running_config.txt → no bgp_config.json (no phantom file).
    run_path = tmp_path / "genie-run"
    raw = run_path / "raw" / "acc-sw-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION)
    (run_path / "manifest.json").write_text(json.dumps(_manifest([{
        "inventory_name": "acc-sw-01", "hostname": "acc-sw-01", "os": "ios-xe",
        "role": "access", "site": "dc", "collection_strategy": "pyats", "status": "success",
    }])))

    build_facts("genie-run", runs_base=tmp_path)
    assert not (run_path / "facts" / "acc-sw-01" / "bgp_config.json").exists()
