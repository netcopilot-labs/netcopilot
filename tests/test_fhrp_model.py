"""S20-2 — FHRP (HSRP/VRRP) discovered as first-class fhrp_group shared services.

Fixtures mirror the real genie_hsrp.json / genie_vrrp.json (show vrrp all) shapes
captured from the campus-ha lab.
"""
import json
from pathlib import Path

from netcopilot.model.link_builder import _discover_fhrp_groups


def _hsrp(intf, group, vip, vmac, priority, state, preempt=True):
    return {
        intf: {
            "address_family": {"ipv4": {"version": {"2": {"groups": {
                str(group): {
                    "priority": priority,
                    "preempt": preempt,
                    "group_number": group,
                    "primary_ipv4_address": {"address": vip},
                    "virtual_mac_address": vmac,
                    "hsrp_router_state": state,  # "active" | "standby"
                }
            }}}}}
        }
    }


def _vrrp(intf, group, vip, vmac, priority, state):
    return {
        "interface": {
            intf: {"group": {str(group): {
                "state": state,  # "MASTER" | "BACKUP"
                "virtual_ip_address": vip,
                "virtual_mac_address": vmac,
                "priority": priority,
                "preemption": "enabled",
            }}}
        }
    }


def _write(base, host, files):
    d = base / host
    d.mkdir()
    for name, obj in files.items():
        (d / name).write_text(json.dumps(obj))
    return d


def test_hsrp_and_vrrp_groups_discovered(tmp_path):
    dirs = {
        "core-sw-01": _write(tmp_path, "core-sw-01", {
            "genie_hsrp.json": _hsrp("Vlan60", 60, "198.51.100.129", "0000.0c9f.f03c", 120, "active"),
            "genie_vrrp.json": _vrrp("Vlan61", 61, "198.51.100.145", "0000.5E00.013D", 120, "MASTER"),
        }),
        "acc-sw-03": _write(tmp_path, "acc-sw-03", {
            "genie_hsrp.json": _hsrp("Vlan60", 60, "198.51.100.129", "0000.0c9f.f03c", 100, "standby"),
            "genie_vrrp.json": _vrrp("Vlan61", 61, "198.51.100.145", "0000.5E00.013D", 100, "BACKUP"),
        }),
    }
    groups = _discover_fhrp_groups(dirs)
    assert len(groups) == 2

    hsrp = next(g for g in groups if g["protocol"] == "hsrp")
    assert hsrp["service_type"] == "fhrp_group"
    assert hsrp["identifier"] == "198.51.100.129/60"
    assert hsrp["vip"] == "198.51.100.129"
    assert hsrp["active_device"] == "core-sw-01"
    assert {m["hostname"] for m in hsrp["members"]} == {"core-sw-01", "acc-sw-03"}

    vrrp = next(g for g in groups if g["protocol"] == "vrrp")
    assert vrrp["active_device"] == "core-sw-01"           # MASTER normalized
    assert {m["state"] for m in vrrp["members"]} == {"master", "backup"}


def test_single_member_group_is_emitted_as_unprotected(tmp_path):
    dirs = {
        "core-sw-01": _write(tmp_path, "core-sw-01", {
            "genie_hsrp.json": _hsrp("Vlan70", 70, "198.51.100.161", "0000.0c9f.f046", 120, "active"),
        }),
    }
    groups = _discover_fhrp_groups(dirs)
    assert len(groups) == 1
    assert len(groups[0]["members"]) == 1        # no peer -> unprotected gateway
    assert groups[0]["active_device"] == "core-sw-01"


def test_no_fhrp_facts_yields_no_groups(tmp_path):
    dirs = {"acc-sw-01": _write(tmp_path, "acc-sw-01", {})}
    assert _discover_fhrp_groups(dirs) == []
