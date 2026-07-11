"""S22-3: LAG first-class on the Port-channel Interface record.

The bundle enriches the EXISTING Po interface dict (genie already models the
LAG as an interface — ADR-0025): protocol / bundle_id / per-member LACP state.
Fixtures mirror the live campus-ha genie_lag.json shape (verified 2026-07-11).
"""
from __future__ import annotations

from netcopilot.model.model_builder import _build_interfaces


def _facts(lag_interfaces: dict, iface_names: list[str]):
    return {
        "core-sw-01": {
            "os": "ios-xe",
            "interfaces": [{"name": n, "status": "up", "protocol": "up"}
                           for n in iface_names],
            "genie": {"lag": {"system_priority": 32768,
                              "interfaces": lag_interfaces}},
        }
    }


LAG = {
    "Port-channel1": {
        "name": "Port-channel1",
        "bundle_id": 1,
        "protocol": "lacp",
        "oper_status": "up",
        "members": {
            "GigabitEthernet1/0/5": {
                "interface": "GigabitEthernet1/0/5", "bundled": True,
                "activity": "active", "lacp_port_priority": 32768,
                "partner_id": "0c00.017d.1a00", "oper_key": 1,
            },
            "GigabitEthernet1/0/6": {
                "interface": "GigabitEthernet1/0/6", "bundled": False,
                "activity": "active", "lacp_port_priority": 32768,
                "partner_id": "0000.0000.0000", "oper_key": 1,
            },
        },
    }
}


def test_po_interface_carries_the_bundle():
    intfs = _build_interfaces(_facts(LAG, ["Port-channel1", "GigabitEthernet1/0/5",
                                           "GigabitEthernet1/0/6"]))
    po = next(i for i in intfs if i["name"] == "Po1")
    assert po["lag_protocol"] == "lacp"
    assert po["lag_bundle_id"] == 1
    assert po["lag_oper_status"] == "up"
    members = {m["name"]: m for m in po["lag_members"]}
    assert members["Gi1/0/5"]["bundled"] is True
    assert members["Gi1/0/5"]["partner_id"] == "0c00.017d.1a00"
    assert members["Gi1/0/6"]["bundled"] is False   # the unbundled member survives
    assert po["port_channel_members"] == ["Gi1/0/5", "Gi1/0/6"]  # existing field intact


def test_member_interfaces_keep_reverse_mapping():
    intfs = _build_interfaces(_facts(LAG, ["Port-channel1", "GigabitEthernet1/0/5"]))
    member = next(i for i in intfs if i["name"] == "Gi1/0/5")
    assert member["port_channel_int"] == "Po1"      # pre-existing behavior intact
    assert "lag_members" not in member               # bundle detail only on the Po


def test_non_lag_interfaces_untouched():
    intfs = _build_interfaces(_facts({}, ["GigabitEthernet1/0/1"]))
    i = intfs[0]
    for k in ("lag_protocol", "lag_bundle_id", "lag_oper_status", "lag_members"):
        assert k not in i
