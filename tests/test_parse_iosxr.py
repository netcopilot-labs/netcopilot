"""F2-4b: IOS XR text parsers + facts_builder (IOS XR SSH path).

Synthetic, column-aligned fixtures (RFC 5737 IPs, invented names/serials).
"""

import json

from netcopilot.parse import build_facts
from netcopilot.parse.iosxr import (
    show_cdp_neighbors,
    show_inventory,
    show_ipv4_interface_brief,
    show_version,
)

SHOW_VERSION = """\
Cisco IOS XR Software, Version 7.11.21
Copyright (c) 2024 by Cisco Systems, Inc.

cisco NCS-5500 () processor
System uptime is 15 weeks 5 days 10 hours 26 minutes
"""

SHOW_INVENTORY = """\
NAME: "Rack 0", DESCR: "NCS-5500 Series Chassis"
PID: NCS-55A2-MOD-S, VID: V01, SN: SYNTHXR0001
"""


def _ipbrief(rows):
    header = ("Interface".ljust(31) + "IP-Address".ljust(16)
              + "Status".ljust(22) + "Protocol".ljust(12) + "Vrf-Name")
    out = [header]
    for name, ip, status, proto, vrf in rows:
        out.append(name.ljust(31) + ip.ljust(16) + status.ljust(22) + proto.ljust(12) + vrf)
    return "\n".join(out) + "\n"


def _cdp(rows):
    header = ("Device ID".ljust(17) + "Local Intrfce".ljust(18) + "Holdtme".ljust(11)
              + "Capability".ljust(12) + "Platform".ljust(16) + "Port ID")
    out = [header]
    for dev, local, hold, cap, plat, port in rows:
        out.append(dev.ljust(17) + local.ljust(18) + hold.ljust(11)
                   + cap.ljust(12) + plat.ljust(16) + port)
    return "\n".join(out) + "\n"


def test_show_version(tmp_path):
    f = tmp_path / "show_version.txt"
    f.write_text(SHOW_VERSION)
    r = show_version.parse(str(f))
    assert r["version"] == "7.11.21"
    assert r["platform"] == "NCS-5500"
    assert "15 weeks" in r["uptime_text"]
    assert r["hostname"] is None and r["serial"] is None     # not in XR show version


def test_show_inventory(tmp_path):
    f = tmp_path / "show_inventory.txt"
    f.write_text(SHOW_INVENTORY)
    assert show_inventory.parse(str(f))["serial"] == "SYNTHXR0001"


def test_ipv4_interface_brief(tmp_path):
    f = tmp_path / "show_ipv4_interface_brief.txt"
    f.write_text(_ipbrief([
        ("TenGigE0/0/0/0", "203.0.113.1", "Up", "Up", "default"),
        ("TenGigE0/0/0/1", "Shutdown", "Shutdown", "Down", "default"),
    ]))
    ifaces = {i["name"]: i for i in show_ipv4_interface_brief.parse(str(f))["interfaces"]}
    assert ifaces["TenGigE0/0/0/0"]["ip_address"] == "203.0.113.1"
    assert ifaces["TenGigE0/0/0/1"]["status"] == "Shutdown"


def test_cdp_strips_dot_and_domain(tmp_path):
    f = tmp_path / "show_cdp_neighbors.txt"
    f.write_text(_cdp([
        ("dist-sw-01", "TenGigE0/0/0/2", "150", "R S", "C9500", "Hu0/0/1"),
        ("edge-rtr-99.exam", "TenGigE0/0/0/3", "140", "R", "NCS-540", "Gi0/0"),
    ]))
    hosts = {n["neighbor_hostname"] for n in show_cdp_neighbors.parse(str(f))["neighbors"]}
    assert hosts == {"dist-sw-01", "edge-rtr-99"}     # trailing-dot/domain stripped


def test_build_facts_iosxr_ssh(tmp_path):
    run_id = "xr-run"
    run_path = tmp_path / run_id
    raw = run_path / "raw" / "core-xr-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION)
    (raw / "show_inventory.txt").write_text(SHOW_INVENTORY)
    (raw / "show_ipv4_interface_brief.txt").write_text(
        _ipbrief([("TenGigE0/0/0/0", "203.0.113.1", "Up", "Up", "default")])
    )
    (raw / "show_cdp_neighbors.txt").write_text(
        _cdp([("dist-sw-01", "TenGigE0/0/0/2", "150", "R", "C9500", "Hu0/0/1")])
    )
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T10:00:00Z",
        "devices": [{
            "inventory_name": "core-xr-01", "hostname": "core-xr-01", "os": "ios-xr",
            "role": "border_router", "site": "demo", "collection_strategy": "ssh",
            "status": "success",
        }],
    }))

    build_facts(run_id, runs_base=tmp_path)
    facts = json.loads((run_path / "facts" / "core-xr-01" / "device_facts.json").read_text())
    info = facts["device_info"]
    assert info["hostname"] == "core-xr-01"     # from manifest (XR show version lacks it)
    assert info["version"] == "7.11.21"
    assert info["platform"] == "NCS-5500"
    assert info["serial"] == "SYNTHXR0001"      # from show inventory
    assert info["role"] == "border_router"
    assert facts["interfaces"][0]["ip_address"] == "203.0.113.1"
    assert facts["cdp_neighbors"][0]["neighbor_hostname"] == "dist-sw-01"
