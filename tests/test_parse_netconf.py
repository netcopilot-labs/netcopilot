"""F2-4c: NETCONF XML parsers (cisco_native + openconfig) + facts_builder route.

Synthetic NETCONF XML fixtures (RFC 5737 IPs, invented names/serials).
"""

import json

from netcopilot.parse import build_facts
from netcopilot.parse.cisco_native import cdp as native_cdp
from netcopilot.parse.cisco_native import system as native_system
from netcopilot.parse.openconfig import interfaces as oc_interfaces
from netcopilot.parse.openconfig import lldp as oc_lldp

XE_SYSTEM = """<rpc-reply><data>
  <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
    <hostname>core-rtr-01</hostname>
    <version>17.12</version>
  </native>
</data></rpc-reply>"""

XE_HARDWARE = """<rpc-reply><data>
  <device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper">
    <device-hardware>
      <device-inventory>
        <hw-type>hw-type-chassis</hw-type>
        <dev-name>Switch 1</dev-name>
        <part-number>C9300-24T</part-number>
        <serial-number>SYNTHXE0001</serial-number>
      </device-inventory>
      <device-system-data>
        <software-version>Cisco IOS XE Software, Version 17.12.5</software-version>
      </device-system-data>
    </device-hardware>
  </device-hardware-data>
</data></rpc-reply>"""

XE_CDP = """<rpc-reply><data>
  <cdp-neighbor-details xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-cdp-oper">
    <cdp-neighbor-detail>
      <device-name>dist-sw-01.example.com</device-name>
      <local-intf-name>GigabitEthernet1/0/1</local-intf-name>
      <port-id>GigabitEthernet1/0/24</port-id>
      <platform-name>cisco C9500</platform-name>
      <capability>Router Switch</capability>
    </cdp-neighbor-detail>
  </cdp-neighbor-details>
</data></rpc-reply>"""

OC_INTERFACES = """<rpc-reply><data>
  <interfaces xmlns="http://openconfig.net/yang/interfaces">
    <interface>
      <name>GigabitEthernet1</name>
      <state><admin-status>UP</admin-status><oper-status>UP</oper-status></state>
      <subinterfaces><subinterface>
        <ipv4 xmlns="http://openconfig.net/yang/interfaces/ip">
          <addresses><address><ip>192.0.2.1</ip></address></addresses>
        </ipv4>
      </subinterface></subinterfaces>
    </interface>
  </interfaces>
</data></rpc-reply>"""

OC_LLDP = """<rpc-reply><data>
  <lldp xmlns="http://openconfig.net/yang/lldp">
    <interfaces><interface>
      <name>GigabitEthernet2</name>
      <neighbors><neighbor><state>
        <system-name>edge-fw-01.example.com</system-name>
        <port-id>port3</port-id>
        <system-description>FortiGate-VM</system-description>
      </state></neighbor></neighbors>
    </interface></interfaces>
  </lldp>
</data></rpc-reply>"""


def test_openconfig_interfaces(tmp_path):
    f = tmp_path / "netconf_interfaces.xml"
    f.write_text(OC_INTERFACES)
    r = oc_interfaces.parse(str(f))
    assert r["interfaces"] == [
        {"name": "GigabitEthernet1", "ip_address": "192.0.2.1", "status": "up", "protocol": "up"}
    ]


def test_openconfig_interfaces_missing_file():
    assert oc_interfaces.parse("/no/file.xml") is None


def test_openconfig_lldp(tmp_path):
    f = tmp_path / "netconf_lldp.xml"
    f.write_text(OC_LLDP)
    n = oc_lldp.parse(str(f))["neighbors"][0]
    assert n["neighbor_hostname"] == "edge-fw-01"       # domain stripped
    assert n["local_interface"] == "GigabitEthernet2"
    assert n["neighbor_interface"] == "port3"
    assert n["capability"] is None


def test_cisco_native_cdp_iosxe(tmp_path):
    f = tmp_path / "netconf_cdp.xml"
    f.write_text(XE_CDP)
    n = native_cdp.parse_iosxe(str(f))["neighbors"][0]
    assert n["neighbor_hostname"] == "dist-sw-01"
    assert n["neighbor_interface"] == "GigabitEthernet1/0/24"


def test_cisco_native_system_iosxe(tmp_path):
    (tmp_path / "netconf_system.xml").write_text(XE_SYSTEM)
    (tmp_path / "netconf_device_hardware.xml").write_text(XE_HARDWARE)
    r = native_system.parse_iosxe(str(tmp_path))
    assert r["hostname"] == "core-rtr-01"
    assert r["platform"] == "C9300-24T"
    assert r["serial"] == "SYNTHXE0001"
    assert r["version"] == "17.12.5"                     # full version from software-version
    assert r["cluster_members"] == []                    # single chassis -> not a stack


def test_cisco_native_system_iosxr(tmp_path):
    (tmp_path / "netconf_system_hostname.xml").write_text(
        '<host-names xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-cfg">'
        "<host-name>core-xr-01</host-name></host-names>"
    )
    (tmp_path / "netconf_system_version.xml").write_text(
        '<install xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-install-oper">'
        "<version><label>7.11.21</label></version></install>"
    )
    (tmp_path / "netconf_system_platform.xml").write_text(
        '<platform-inventory xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-plat-chas-invmgr-ng-oper">'
        "<basic-info><model-name>NCS-5500</model-name><serial-number>SYNTHXR0001</serial-number>"
        "</basic-info></platform-inventory>"
    )
    r = native_system.parse_iosxr(str(tmp_path))
    assert r["hostname"] == "core-xr-01"
    assert r["version"] == "7.11.21"
    assert r["platform"] == "NCS-5500"
    assert r["serial"] == "SYNTHXR0001"
    assert r["cluster_members"] == []                    # XR standalone


def test_build_facts_netconf_iosxe(tmp_path):
    run_id = "nc-run"
    run_path = tmp_path / run_id
    raw = run_path / "raw" / "core-rtr-01"
    raw.mkdir(parents=True)
    (raw / "netconf_system.xml").write_text(XE_SYSTEM)
    (raw / "netconf_device_hardware.xml").write_text(XE_HARDWARE)
    (raw / "netconf_cdp.xml").write_text(XE_CDP)
    (raw / "netconf_interfaces.xml").write_text(OC_INTERFACES)
    (raw / "netconf_lldp.xml").write_text(OC_LLDP)
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T10:00:00Z",
        "devices": [{
            "inventory_name": "core-rtr-01", "hostname": "core-rtr-01", "os": "ios-xe",
            "role": "core_router", "site": "demo", "collection_strategy": "netconf",
            "status": "success",
        }],
    }))

    build_facts(run_id, runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "core-rtr-01" / "device_facts.json").read_text())
    assert facts["device_info"]["platform"] == "C9300-24T"
    assert facts["device_info"]["serial"] == "SYNTHXE0001"
    assert facts["device_info"]["role"] == "core_router"
    assert facts["interfaces"][0]["ip_address"] == "192.0.2.1"
    # CDP + LLDP neighbors merged
    hosts = {n["neighbor_hostname"] for n in facts["cdp_neighbors"]}
    assert hosts == {"dist-sw-01", "edge-fw-01"}
