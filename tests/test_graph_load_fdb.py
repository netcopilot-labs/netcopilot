"""S16-2: MAC-table (FDB) loader — genie_fdb.json → MacEntry nodes.

Fake driver, no Neo4j. Synthetic MACs / RFC 5737-adjacent test data.
"""

import json

from netcopilot.graph.loader import _load_mac_entries
from test_graph_load_model import FakeDriver

SITE, RUN = "dc", "r1"


def _facts(tmp_path, device):
    d = tmp_path / "run" / "facts" / device
    d.mkdir(parents=True)
    return d


def _fdb(entries_by_vlan):
    vlans = {}
    for vid, rows in entries_by_vlan.items():
        vlans[str(vid)] = {
            "vlan": vid,
            "mac_addresses": {
                mac: {"mac_address": mac,
                      "interfaces": {intf: {"interface": intf, "entry_type": etype}}}
                for mac, intf, etype in rows
            },
        }
    return {"mac_aging_time": 300, "mac_table": {"vlans": vlans},
            "total_mac_addresses": sum(len(r) for r in entries_by_vlan.values())}


def test_load_mac_entries_genie_shape(tmp_path):
    d = _facts(tmp_path, "acc-sw-01")
    (d / "genie_fdb.json").write_text(json.dumps(_fdb({
        10: [("1234.5678.9abc", "GigabitEthernet1/0/5", "dynamic")],
        50: [("0c00.b909.e368", "Vlan50", "static")],
    })))
    driver = FakeDriver()
    n = _load_mac_entries(driver, tmp_path / "run", SITE, RUN)
    assert n == 2
    entries = next(p["entries"] for c, p in driver.calls if "[:HAS_MAC]" in c)
    by_mac = {e["mac"]: e for e in entries}
    e = by_mac["12:34:56:78:9a:bc"]                 # normalized dotted → colon
    assert e["vlan"] == "10" and e["interface"] == "GigabitEthernet1/0/5"
    assert e["entry_type"] == "dynamic" and e["device"] == "acc-sw-01"
    assert e["site"] == SITE and e["run_id"] == RUN
    assert by_mac["0c:00:b9:09:e3:68"]["entry_type"] == "static"


def test_load_mac_entries_absent_file_zero(tmp_path):
    _facts(tmp_path, "bdr-rtr-01")                   # L3 box: no genie_fdb.json
    assert _load_mac_entries(FakeDriver(), tmp_path / "run", SITE, RUN) == 0


def test_load_mac_entries_malformed_json_warned_not_fatal(tmp_path, caplog):
    d = _facts(tmp_path, "acc-sw-01")
    (d / "genie_fdb.json").write_text("{not json")
    d2 = _facts(tmp_path, "acc-sw-02")
    (d2 / "genie_fdb.json").write_text(json.dumps(_fdb({10: [("aaaa.bbbb.cccc", "Gi1/0/1", "dynamic")]})))
    import logging
    with caplog.at_level(logging.WARNING):
        n = _load_mac_entries(FakeDriver(), tmp_path / "run", SITE, RUN)
    assert n == 1                                    # good device still loads
    assert "acc-sw-01" in caplog.text


def test_load_mac_entries_multi_interface_mac(tmp_path):
    # One MAC on two interfaces (e.g. flapping/static+dynamic) → one row each
    d = _facts(tmp_path, "acc-sw-01")
    fdb = _fdb({10: [("aaaa.bbbb.cccc", "Gi1/0/1", "dynamic")]})
    fdb["mac_table"]["vlans"]["10"]["mac_addresses"]["aaaa.bbbb.cccc"]["interfaces"]["Gi1/0/2"] = {
        "interface": "Gi1/0/2", "entry_type": "static"}
    (d / "genie_fdb.json").write_text(json.dumps(fdb))
    driver = FakeDriver()
    assert _load_mac_entries(driver, tmp_path / "run", SITE, RUN) == 2
