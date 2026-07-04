"""S10-3: model enrichment — _enrich_l2_security maps security_config.l2_security
onto interfaces (port_security/bpduguard/protected) and devices (dhcp_snooping/
bpduguard_default).

Emit-when-present is the golden-safety contract: interfaces/devices without L2
security are left untouched, so a network that runs none produces a byte-identical
model. Synthetic facts dir on tmp_path; no Neo4j.
"""

import json

from netcopilot.model.model_builder import _enrich_l2_security


def _facts(tmp_path, hostname, l2_security):
    d = tmp_path / hostname
    d.mkdir(parents=True)
    (d / "security_config.json").write_text(json.dumps({"l2_security": l2_security}))
    return d


L2 = {
    "dhcp_snooping": {"enabled": True, "vlans": [10], "trust_interfaces": ["Port-channel1"]},
    "port_security": {"GigabitEthernet1/0/1": {"enabled": True, "maximum": 3, "violation": "restrict"}},
    "bpduguard": {"global_default": True, "interfaces": ["GigabitEthernet1/0/1"]},
    "protected": ["GigabitEthernet1/0/1"],
}


def _intf(device_id, name):
    return {"interface_id": f"{device_id}:{name}", "device_id": device_id, "name": name}


def test_interface_and_device_enriched(tmp_path):
    facts = _facts(tmp_path, "sw-01", L2)
    interfaces = [_intf("sw-01", "GigabitEthernet1/0/1"), _intf("sw-01", "GigabitEthernet1/0/2")]
    devices = [{"device_id": "sw-01"}]

    _enrich_l2_security(interfaces, devices, {"sw-01": facts})

    g1, g2 = interfaces
    assert g1["port_security"] == {"enabled": True, "maximum": 3, "violation": "restrict"}
    assert g1["bpduguard"] is True
    assert g1["protected"] is True
    # emit-when-present: Gi1/0/2 has no L2-sec → no new keys at all
    assert "port_security" not in g2 and "bpduguard" not in g2 and "protected" not in g2
    # device-level
    assert devices[0]["dhcp_snooping"] == L2["dhcp_snooping"]
    assert devices[0]["bpduguard_default"] is True


def test_no_l2sec_leaves_model_untouched(tmp_path):
    # A device whose security_config has an empty l2_security → zero new keys
    # (this is what keeps the demo goldens byte-identical).
    facts = _facts(tmp_path, "sw-01", {})
    interfaces = [_intf("sw-01", "Gi1/0/1")]
    devices = [{"device_id": "sw-01"}]
    _enrich_l2_security(interfaces, devices, {"sw-01": facts})
    assert interfaces[0] == {"interface_id": "sw-01:Gi1/0/1", "device_id": "sw-01", "name": "Gi1/0/1"}
    assert devices[0] == {"device_id": "sw-01"}


def test_missing_security_config_is_skipped(tmp_path):
    # facts dir exists but no security_config.json → no error, no enrichment.
    d = tmp_path / "sw-01"
    d.mkdir()
    interfaces = [_intf("sw-01", "Gi1/0/1")]
    devices = [{"device_id": "sw-01"}]
    _enrich_l2_security(interfaces, devices, {"sw-01": d})
    assert "port_security" not in interfaces[0]


def test_bpduguard_default_only_no_per_interface(tmp_path):
    # Global default set, but no per-interface bpduguard → device flag set,
    # interfaces get no bpduguard key.
    facts = _facts(tmp_path, "sw-01", {"bpduguard": {"global_default": True, "interfaces": []}})
    interfaces = [_intf("sw-01", "Gi1/0/1")]
    devices = [{"device_id": "sw-01"}]
    _enrich_l2_security(interfaces, devices, {"sw-01": facts})
    assert devices[0]["bpduguard_default"] is True
    assert "bpduguard" not in interfaces[0]
