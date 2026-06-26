"""F2-6-a: load_model() — network_model.json → Neo4j (fake-driver unit test).

Drives load_model against a recording fake driver (no Neo4j needed) to verify
it reads the model, deletes prior run data, and issues the expected Cypher with
the right parameters. Real Cypher execution is covered by the gated live test.
"""

import json

import pytest

from netcopilot.graph.loader import load_model


# --------------------------------------------------------------------------
# Recording fake driver
# --------------------------------------------------------------------------

class _Counters:
    nodes_deleted = 0


class _Result:
    """Records nothing on read: returns empty rows so reader-loaders (classify/
    enrich) no-op, while writer-loaders still record their CREATE calls."""

    def __iter__(self):
        return iter(())

    def single(self):
        return None

    def consume(self):
        class _S:
            counters = _Counters()
        return _S()


class _Session:
    def __init__(self, calls):
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self._calls.append((cypher, params))
        return _Result()


class FakeDriver:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def session(self):
        return _Session(self.calls)


# --------------------------------------------------------------------------
# Synthetic network_model.json (RFC 5737 IPs, generic names)
# --------------------------------------------------------------------------

MODEL = {
    "model_metadata": {"run_id": "r1", "site": "dc"},
    "devices": [
        {"device_id": "core-rtr-01", "hostname": "core-rtr-01", "platform": "C9500",
         "os_family": "ios-xe", "version": "17.9", "role": "core", "serial": "SYN1",
         "management_ip": "192.0.2.1", "site": "dc",
         "vlans": [{"vlan_id": 10, "name": "DATA", "state": "active", "interfaces": ["Gi1/0/1"]}]},
        {"device_id": "dist-sw-01", "hostname": "dist-sw-01", "platform": "C9300",
         "os_family": "ios-xe", "version": "17.6", "role": "distribution", "serial": "SYN2",
         "management_ip": "192.0.2.2", "site": "dc", "vlans": []},
    ],
    "interfaces": [
        {"interface_id": "core-rtr-01:Gi1/0/1", "name": "GigabitEthernet1/0/1",
         "device_id": "core-rtr-01", "admin_status": "up", "oper_status": "up",
         "ip_address": "192.0.2.1", "type": "physical"},
        {"interface_id": "dist-sw-01:Gi1/0/3", "name": "GigabitEthernet1/0/3",
         "device_id": "dist-sw-01", "admin_status": "up", "oper_status": "down",
         "ip_address": "unassigned", "type": "physical"},
    ],
    "links": [
        {"link_id": "l1", "link_type": "physical", "local_device_id": "core-rtr-01",
         "remote_device_id": "dist-sw-01", "local_interface_id": "core-rtr-01:Gi1/0/1",
         "remote_interface_id": "dist-sw-01:Gi1/0/3", "discovery_method": "cdp_bilateral",
         "confidence": "high", "status": "up"},
    ],
    "adjacencies": [
        {"device_a": "core-rtr-01", "device_b": "dist-sw-01", "protocol": "ospf",
         "peer_collected": True, "area": "0", "process_id": 1},
    ],
    "shared_services": [
        {"service_type": "vlan", "identifier": 10, "name": "DATA",
         "members": ["core-rtr-01", "dist-sw-01"]},
    ],
    "ospf_lsdb": [],
}


def _write_model(tmp_path, model=MODEL):
    model_dir = tmp_path / "run" / "model"
    model_dir.mkdir(parents=True)
    (model_dir / "network_model.json").write_text(json.dumps(model))
    return tmp_path / "run"


def test_load_model_returns_counts(tmp_path):
    run_dir = _write_model(tmp_path)
    counts = load_model(FakeDriver(), run_dir, site="dc", run_id="r1")
    assert counts["devices"] == 2
    assert counts["interfaces"] == 2
    assert counts["links"] == 1
    assert counts["adjacencies"] == 1
    assert counts["shared_services"] == 1
    assert counts["vlans"] == 1
    assert counts["ospf_lsdb"] == 0


def test_load_model_deletes_then_loads(tmp_path):
    run_dir = _write_model(tmp_path)
    driver = FakeDriver()
    load_model(driver, run_dir, site="dc", run_id="r1")
    cyphers = [c for c, _ in driver.calls]
    # idempotent reload deletes prior (site, run_id) first
    assert any("DETACH DELETE" in c for c in cyphers)
    delete_idx = next(i for i, c in enumerate(cyphers) if "DETACH DELETE" in c)
    device_idx = next(i for i, c in enumerate(cyphers) if "CREATE (dev:Device)" in c)
    assert delete_idx < device_idx  # delete happens before create


def test_load_model_device_params_and_status(tmp_path):
    run_dir = _write_model(tmp_path)
    driver = FakeDriver()
    load_model(driver, run_dir, site="dc", run_id="r1")
    # find the Device-create call
    dev_params = next(p["devices"] for c, p in driver.calls if "CREATE (dev:Device)" in c)
    by_name = {d["name"]: d for d in dev_params}
    assert set(by_name) == {"core-rtr-01", "dist-sw-01"}
    assert by_name["core-rtr-01"]["mgmt_ip"] == "192.0.2.1"
    assert by_name["core-rtr-01"]["os_type"] == "ios-xe"
    # interface counts derived from the interfaces array
    assert by_name["core-rtr-01"]["interfaces_up"] == 1
    assert by_name["dist-sw-01"]["interfaces_down"] == 1


def test_load_model_typed_physical_link(tmp_path):
    run_dir = _write_model(tmp_path)
    driver = FakeDriver()
    load_model(driver, run_dir, site="dc", run_id="r1")
    # the physical link → a PHYSICAL_CABLE relationship create
    assert any("[r:PHYSICAL_CABLE]" in c for c, _ in driver.calls)
    # and a CONNECTS_TO between the two interface nodes
    assert any("[r:CONNECTS_TO]" in c for c, _ in driver.calls)


def test_load_model_unassigned_ip_cleaned(tmp_path):
    run_dir = _write_model(tmp_path)
    driver = FakeDriver()
    load_model(driver, run_dir, site="dc", run_id="r1")
    iface_params = next(p["interfaces"] for c, p in driver.calls if "CREATE (iface:Interface)" in c)
    by_id = {i["interface_id"]: i for i in iface_params}
    # "unassigned" ip is dropped (None removed by _clean_properties)
    assert "ip" not in by_id["dist-sw-01:Gi1/0/3"]
    assert by_id["core-rtr-01:Gi1/0/1"]["ip"] == "192.0.2.1"


def test_load_model_missing_model_raises(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(FileNotFoundError, match="Network model not found"):
        load_model(FakeDriver(), tmp_path / "empty", site="dc", run_id="r1")
