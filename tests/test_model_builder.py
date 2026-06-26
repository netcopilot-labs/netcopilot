"""F2-5z-b: model_builder.build_model() — facts run → network_model.json.

End-to-end: a synthetic run (manifest + per-device device_facts.json in the
F2-4 canonical schema, with CDP neighbors) is turned into the unified network
model. Without genie_*.json the model is the reduced CDP/interface graph
(Option A: full topology needs pyATS). Synthetic devices + RFC 5737 IPs.
"""

import json

from netcopilot.model.model_builder import build_model


def _device_facts(name, ip, peer, peer_intf, local_intf="GigabitEthernet1/0/1"):
    return {
        "hostname": name, "os": "ios-xe", "collection_strategy": "ssh",
        "device_info": {"hostname": name, "version": "17.9", "platform": "C9500",
                        "serial": f"SYNTH{name[-1]}", "uptime_text": "1d",
                        "mac_address": None, "role": "core", "site": "dc"},
        "interfaces": [{"name": local_intf, "ip_address": ip,
                        "status": "up", "protocol": "up"}],
        "cdp_neighbors": [{"local_interface": local_intf,
                           "neighbor_hostname": peer, "neighbor_interface": peer_intf}],
        "cluster_members": [], "fortigate": {}, "_metadata": {},
    }


def _build_run(tmp_path):
    run = tmp_path / "test-run"
    facts = run / "facts"
    (facts / "core-rtr-01").mkdir(parents=True)
    (facts / "dist-sw-01").mkdir(parents=True)
    (facts / "core-rtr-01" / "device_facts.json").write_text(json.dumps(
        _device_facts("core-rtr-01", "192.0.2.1", "dist-sw-01", "GigabitEthernet1/0/3")))
    (facts / "dist-sw-01" / "device_facts.json").write_text(json.dumps(
        _device_facts("dist-sw-01", "192.0.2.2", "core-rtr-01", "GigabitEthernet1/0/1",
                      local_intf="GigabitEthernet1/0/3")))
    # management IPs are on a separate OOB network from the data interfaces,
    # so the data uplink classifies as physical (not management).
    (run / "manifest.json").write_text(json.dumps({
        "run_id": "test-run", "timestamp_utc": "2026-06-18T00:00:00Z",
        "devices": [
            {"inventory_name": "core-rtr-01", "hostname": "core-rtr-01",
             "target": "198.51.100.1", "role": "core", "site": "dc"},
            {"inventory_name": "dist-sw-01", "hostname": "dist-sw-01",
             "target": "198.51.100.2", "role": "distribution", "site": "dc"},
        ],
    }))
    return run


def test_build_model_end_to_end(tmp_path):
    _build_run(tmp_path)
    model = build_model("test-run", runs_base=str(tmp_path))

    # metadata
    assert model["model_metadata"]["run_id"] == "test-run"

    # devices
    devs = {d["device_id"]: d for d in model["devices"]}
    assert set(devs) == {"core-rtr-01", "dist-sw-01"}
    assert devs["core-rtr-01"]["management_ip"] == "198.51.100.1"
    assert devs["core-rtr-01"]["platform"] == "C9500"
    assert devs["core-rtr-01"]["role"] == "core"

    # interfaces (normalized short names)
    intf_ids = {i["interface_id"] for i in model["interfaces"]}
    assert "core-rtr-01:Gi1/0/1" in intf_ids
    assert "dist-sw-01:Gi1/0/3" in intf_ids

    # one CDP-bilateral physical link
    assert len(model["links"]) == 1
    link = model["links"][0]
    assert link["discovery_method"] == "cdp_bilateral"
    assert link["link_type"] == "physical"
    assert {link["local_device_id"], link["remote_device_id"]} == {"core-rtr-01", "dist-sw-01"}

    # no genie → no routing adjacencies or shared services
    assert model["adjacencies"] == []
    assert model["shared_services"] == []
    assert isinstance(model["topology_warnings"], list)


def test_build_model_writes_json(tmp_path):
    run = _build_run(tmp_path)
    build_model("test-run", runs_base=str(tmp_path))
    out = run / "model" / "network_model.json"
    assert out.is_file()
    written = json.loads(out.read_text())
    assert len(written["devices"]) == 2
    assert len(written["links"]) == 1
