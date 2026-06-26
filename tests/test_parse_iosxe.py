"""F2-4a: IOS XE text parsers + facts_builder (IOS XE SSH path).

All fixtures are synthetic (RFC 5737 IPs, invented hostnames/serials),
column-aligned via ljust so the fixed-width parsers are exercised exactly.
"""

import json

from netcopilot.parse import build_facts
from netcopilot.parse.iosxe import show_cdp_neighbors, show_ip_interface_brief, show_version


# --------------------------- fixture builders ----------------------------

def _ipbrief(rows):
    # (interface, ip, ok, method, status, protocol)
    widths = (23, 16, 4, 7, 22)
    header = ("Interface".ljust(23) + "IP-Address".ljust(16) + "OK?".ljust(4)
              + "Method".ljust(7) + "Status".ljust(22) + "Protocol")
    out = [header]
    for iface, ip, ok, method, status, proto in rows:
        out.append(iface.ljust(23) + ip.ljust(16) + ok.ljust(4)
                   + method.ljust(7) + status.ljust(22) + proto)
    return "\n".join(out) + "\n"


def _cdp_header():
    return ("Device ID".ljust(17) + "Local Intrfce".ljust(18) + "Holdtme".ljust(11)
            + "Capability".ljust(12) + "Platform".ljust(16) + "Port ID")


def _cdp_single(dev, local, hold, cap, plat, port):
    return (dev.ljust(17) + local.ljust(18) + hold.ljust(11)
            + cap.ljust(12) + plat.ljust(16) + port)


def _cdp_data_only(local, hold, cap, plat, port):
    return ("".ljust(17) + local.ljust(18) + hold.ljust(11)
            + cap.ljust(12) + plat.ljust(16) + port)


SHOW_VERSION_SIMPLE = """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino]

core-rtr-01 uptime is 10 weeks, 2 days, 3 hours
System returned to ROM by reload

Model Number                       : CSR1000V
System Serial Number               : 9ABCDEF0001
Base Ethernet MAC Address          : 00:11:22:33:44:55
"""

SHOW_VERSION_STACK = """\
Cisco IOS XE Software, Version 17.06.05

dist-sw-01 uptime is 5 weeks, 1 day

Switch Ports Model              SW Version        SW Image        Mode
------ ----- -----              ----------        ----------      ----
*    1 41    C9300-24T          17.06.05          CAT9K_IOSXE     INSTALL
     2 41    C9300-24T          17.06.05          CAT9K_IOSXE     INSTALL

Model Number                       : C9300-24T
System Serial Number               : STACK0001MEMBER1
Base Ethernet MAC Address          : 00:aa:bb:cc:dd:01

Switch 02
---------
Model Number                       : C9300-24T
System Serial Number               : STACK0001MEMBER2
Base Ethernet MAC Address          : 00:aa:bb:cc:dd:02
"""


# ------------------------------ show version -----------------------------

def test_show_version_simple(tmp_path):
    f = tmp_path / "show_version.txt"
    f.write_text(SHOW_VERSION_SIMPLE)
    r = show_version.parse(str(f))
    assert r["hostname"] == "core-rtr-01"
    assert r["version"] == "17.09.04a"
    assert r["platform"] == "CSR1000V"
    assert r["serial"] == "9ABCDEF0001"
    assert r["mac_address"] == "00:11:22:33:44:55"
    assert "cluster_members" not in r          # not a stack


def test_show_version_stack_members(tmp_path):
    f = tmp_path / "show_version.txt"
    f.write_text(SHOW_VERSION_STACK)
    r = show_version.parse(str(f))
    assert r["platform"] == "C9300-24T"
    members = r["cluster_members"]
    assert len(members) == 2
    assert members[0]["member_id"] == 1 and members[0]["role"] == "active"
    assert members[0]["serial_number"] == "STACK0001MEMBER1"
    assert members[1]["member_id"] == 2 and members[1]["role"] == "member"
    assert members[1]["serial_number"] == "STACK0001MEMBER2"


def test_show_version_missing_file():
    assert show_version.parse("/no/such/file.txt") is None


# --------------------------- ip interface brief --------------------------

def test_ip_interface_brief(tmp_path):
    f = tmp_path / "show_ip_interface_brief.txt"
    f.write_text(_ipbrief([
        ("GigabitEthernet1", "192.0.2.1", "YES", "NVRAM", "up", "up"),
        ("GigabitEthernet2", "unassigned", "YES", "unset", "administratively down", "down"),
        ("Loopback0", "198.51.100.1", "YES", "NVRAM", "up", "up"),
    ]))
    r = show_ip_interface_brief.parse(str(f))
    ifaces = {i["name"]: i for i in r["interfaces"]}
    assert ifaces["GigabitEthernet1"]["ip_address"] == "192.0.2.1"
    assert ifaces["GigabitEthernet1"]["status"] == "up"
    assert ifaces["GigabitEthernet2"]["status"] == "administratively down"
    assert ifaces["Loopback0"]["protocol"] == "up"


# ----------------------------- cdp neighbors -----------------------------

def test_cdp_single_and_two_line(tmp_path):
    f = tmp_path / "show_cdp_neighbors.txt"
    text = "\n".join([
        _cdp_header(),
        # two-line entry: long FQDN device id overflows, data on next line
        "core-rtr-01.example.com",
        _cdp_data_only("Ten 1/1/1", "120", "R", "CSR1000V", "Gig 2"),
        # single-line entry
        _cdp_single("dist-sw-01", "Gig 1/0/1", "150", "R S I", "C9300", "Gig 1/0/24"),
    ]) + "\n"
    f.write_text(text)
    r = show_cdp_neighbors.parse(str(f))
    by_host = {n["neighbor_hostname"]: n for n in r["neighbors"]}
    assert set(by_host) == {"core-rtr-01", "dist-sw-01"}    # domain suffix stripped
    assert by_host["core-rtr-01"]["neighbor_interface"] == "Gig 2"
    assert by_host["dist-sw-01"]["local_interface"] == "Gig 1/0/1"


def test_cdp_disabled(tmp_path):
    f = tmp_path / "show_cdp_neighbors.txt"
    f.write_text("% CDP is not enabled\n")
    assert show_cdp_neighbors.parse(str(f))["neighbors"] == []


# ------------------------- facts_builder end-to-end ----------------------

def test_build_facts_iosxe_ssh(tmp_path):
    run_id = "demo-run"
    run_path = tmp_path / run_id
    raw = run_path / "raw" / "core-rtr-01"
    raw.mkdir(parents=True)
    (raw / "show_version.txt").write_text(SHOW_VERSION_SIMPLE)
    (raw / "show_ip_interface_brief.txt").write_text(
        _ipbrief([("GigabitEthernet1", "192.0.2.1", "YES", "NVRAM", "up", "up")])
    )
    (raw / "show_cdp_neighbors.txt").write_text(
        "\n".join([_cdp_header(), _cdp_single("dist-sw-01", "Gig 1/0/1", "150", "R", "C9300", "Gig 1/0/2")]) + "\n"
    )
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T10:00:00Z",
        "devices": [{
            "inventory_name": "core-rtr-01", "hostname": "core-rtr-01", "os": "ios-xe",
            "role": "core_router", "site": "demo", "collection_strategy": "ssh",
            "status": "success",
        }],
    }))

    summary = build_facts(run_id, runs_base=tmp_path)
    assert summary == {"devices": [{"hostname": "core-rtr-01", "status": "success"}],
                       "success_count": 1, "error_count": 0}

    facts = json.loads((run_path / "facts" / "core-rtr-01" / "device_facts.json").read_text())
    assert facts["os"] == "ios-xe"
    assert facts["collection_strategy"] == "ssh"
    assert facts["device_info"]["platform"] == "CSR1000V"
    assert facts["device_info"]["role"] == "core_router"    # carried from manifest
    assert facts["device_info"]["site"] == "demo"
    assert facts["interfaces"][0]["ip_address"] == "192.0.2.1"
    assert facts["cdp_neighbors"][0]["neighbor_hostname"] == "dist-sw-01"
    assert "_role" not in facts and "_site" not in facts     # scratch keys stripped


def test_build_facts_unparseable_device_is_error(tmp_path):
    run_id = "demo-run"
    run_path = tmp_path / run_id
    run_path.mkdir(parents=True)
    # ios-xr ssh route not implemented until F2-4b -> no parse -> error entry, no crash.
    (run_path / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "t",
        "devices": [{"inventory_name": "xr-01", "os": "ios-xr", "collection_strategy": "ssh", "status": "success"}],
    }))
    summary = build_facts(run_id, runs_base=tmp_path)
    assert summary["error_count"] == 1
    assert summary["success_count"] == 0
