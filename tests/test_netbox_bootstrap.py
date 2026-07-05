"""S11-3: bootstrap candidate generator — sites/manufacturers/platforms,
clusters (HA), virtual-chassis (stacks), per-physical devices, interfaces,
inventory items (SFPs) — from synthetic facts. Staging + NetBox are mocked
(candidates recorded in-memory); no Neo4j. RFC 5737 IPs, invented serials.
"""
from __future__ import annotations

import json

import pytest

from netcopilot.declared_state import bootstrap


INVENTORY = """\
devices:
  - name: acc-sw-01
    mgmt_ip: 192.0.2.11
    os: iosxe
    role: access_switch
    site: demo
  - name: core-st-01
    mgmt_ip: 192.0.2.21
    os: iosxe
    role: core_switch
    site: demo
    cluster: {name: CORE_STACK, size: 2}
  - name: edge-fw-01
    mgmt_ip: 192.0.2.1
    os: fortios
    role: firewall
    site: demo
    cluster: {name: FW_HA, size: 2}
"""


def _write_run(tmp_path, run_id="demo-run"):
    """Synthetic collected run: standalone switch, 2-member stack, HA pair."""
    run = tmp_path / run_id
    for dev, members in (
        ("acc-sw-01", []),
        ("core-st-01", [
            {"member_id": 1, "role": "active", "serial_number": "SYNTH0001",
             "platform": "C9500-32C", "priority": 15},
            {"member_id": 2, "role": "standby", "serial_number": "SYNTH0002",
             "platform": "C9500-32C", "priority": 14},
        ]),
        ("edge-fw-01", [
            {"member_id": 0, "role": "active", "serial_number": "SYNTHFW01"},
            {"member_id": 1, "role": "standby", "serial_number": "SYNTHFW02"},
        ]),
    ):
        d = run / "facts" / dev
        d.mkdir(parents=True)
        (d / "device_facts.json").write_text(json.dumps({
            "device_info": {"platform": "C9500-32C" if "st" in dev else None},
            "cluster_members": members,
        }))
        (d / "genie_interface.json").write_text(json.dumps({
            "GigabitEthernet1/0/1": {"oper_status": "up", "type": "1000base-t"},
        }))
    return run


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    inv = tmp_path / "lab.yaml"
    inv.write_text(INVENTORY)
    _write_run(tmp_path)

    staged: list[dict] = []

    def fake_stage(**kwargs):
        staged.append(kwargs)
        return f"cand-{len(staged)}"

    monkeypatch.setattr(bootstrap, "stage_candidate", fake_stage)
    # No NetBox reachable → dedup uses staged-only; no infra provisioning.
    monkeypatch.setattr(bootstrap, "_index_existing_pending", lambda: {})

    real_get_source = bootstrap.get_source

    def fake_get_source(name, **kw):
        if name == "netbox":
            raise RuntimeError("no NetBox in unit tests")
        return real_get_source(name, **kw)

    monkeypatch.setattr(bootstrap, "get_source", fake_get_source)
    return tmp_path, staged


def _by_type(staged):
    out: dict[str, list[dict]] = {}
    for c in staged:
        out.setdefault(c["object_type"], []).append(c)
    return out


def test_bootstrap_stages_expected_candidates(env):
    tmp_path, staged = env
    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")

    by = _by_type(staged)
    # site / manufacturer / platform derivation
    assert [c["payload"]["slug"] for c in by["site"]] == ["demo"]
    assert {c["payload"]["name"] for c in by["manufacturer"]} == {"Cisco", "Fortinet"}
    assert {c["payload"]["slug"] for c in by["platform"]} == {"cisco-ios-xe", "fortinet-fortios"}
    # HA pair → one dcim.Cluster; stack → one VirtualChassis
    assert [c["payload"]["name"] for c in by["cluster"]] == ["FW_HA"]
    assert [c["payload"]["name"] for c in by["virtual_chassis"]] == ["core-st-01"]
    # per-physical devices: 1 standalone + 2 stack members + 2 HA members
    names = [c["payload"]["name"] for c in by["device"]]
    assert names == ["acc-sw-01", "core-st-01-1", "core-st-01-2", "edge-fw-01-1", "edge-fw-01-2"]
    assert result.total_new == len(staged)


def test_stack_members_carry_vc_fk_and_serials(env):
    tmp_path, staged = env
    bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    members = [c for c in _by_type(staged)["device"] if c["payload"]["name"].startswith("core-st-01-")]
    m1 = members[0]["payload"]
    assert m1["virtual_chassis"] == {"name": "core-st-01"}
    assert m1["vc_position"] == 1 and m1["serial"] == "SYNTH0001"
    assert m1["custom_fields"] == {"stack_cluster": "core-st-01", "stack_size": 2}


def test_ha_members_carry_cluster_fk(env):
    tmp_path, staged = env
    bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    ha = [c for c in _by_type(staged)["device"] if c["payload"]["name"].startswith("edge-fw-01-")]
    assert all(c["payload"]["cluster"] == {"name": "FW_HA"} for c in ha)
    assert "virtual_chassis" not in ha[0]["payload"]


def test_idempotent_rerun_stages_zero(env, monkeypatch):
    tmp_path, staged = env
    bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    first = len(staged)
    # Second run: the pending index now contains everything from run 1.
    index = {}
    for c in staged:
        key_field = {"site": "slug", "manufacturer": "name", "platform": "slug",
                     "device": "name", "cluster": "name", "virtual_chassis": "name",
                     "interface": "dedup_key", "inventory_item": "dedup_key"}[c["object_type"]]
        val = c["payload"].get(key_field)
        if val is None and c["object_type"] == "interface":
            val = f"{c['payload']['device']['name']}::{c['payload']['name']}"
        index[(c["object_type"], str(val))] = "cand"
    monkeypatch.setattr(bootstrap, "_index_existing_pending", lambda: index)

    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    assert len(staged) == first          # zero new candidates staged
    assert result.total_new == 0 and result.total_skipped > 0


def test_missing_facts_dir_warns_not_crashes(env):
    tmp_path, staged = env
    result = bootstrap.run("ghost-run", inventory_path=tmp_path / "lab.yaml")
    assert any("facts dir not found" in w for w in result.warnings)


def test_rerun_against_populated_netbox_stages_zero(env, monkeypatch):
    """s13 fix: interfaces/manufacturers/platforms/VCs/SFPs were pending-only
    deduped — re-clicking Bootstrap against a fully-documented NetBox
    re-staged all of them. With NetBox-side dedup, a second run stages 0."""
    tmp_path, staged = env

    class PopulatedNetBox:
        """Fake NetBox that already holds everything this run would stage."""

        def ensure_infrastructure(self):
            return {}

        def ensure_device_type(self, *a, **kw):
            return 1

        def get_devices(self):
            return [{"name": n} for n in (
                "acc-sw-01", "core-st-01-1", "core-st-01-2",
                "edge-fw-01-1", "edge-fw-01-2")]

        def get_sites(self):
            return [{"slug": "demo", "name": "demo"}]

        def get_clusters(self):
            return [{"name": "FW_HA"}]

        def get_manufacturers(self):
            return [{"slug": "cisco", "name": "Cisco"},
                    {"slug": "fortinet", "name": "Fortinet"}]

        def get_platforms(self):
            return [{"slug": "cisco-ios-xe", "name": "Cisco IOS-XE"},
                    {"slug": "fortinet-fortios", "name": "Fortinet FortiOS"}]

        def get_virtual_chassis(self):
            return [{"name": "core-st-01"}]

        def get_interfaces(self, device):
            return [{"name": "GigabitEthernet1/0/1"}]

        def get_inventory_items(self, device):
            return []

    real_get_source = bootstrap.get_source

    def fake_get_source(name, **kw):
        if name == "netbox":
            return PopulatedNetBox()
        return real_get_source(name, **kw)

    monkeypatch.setattr(bootstrap, "get_source", fake_get_source)
    # device-type provisioning is exercised via ensure_device_type above;
    # _provision_device_types needs no further stubbing.

    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    assert len(staged) == 0, [c["object_type"] for c in staged]
    assert result.total_new == 0
    assert result.total_skipped > 0


# ── s14: IPAM + cables (model-sourced) ───────────────────────────────────────


def _write_model(tmp_path, run_id="demo-run"):
    """Synthetic network_model.json matching _write_run's devices."""
    model = {
        "devices": [
            {"hostname": "acc-sw-01", "site": "demo",
             "vlans": [{"vlan_id": 50, "name": "GUEST-USERS", "state": "active"}]},
            {"hostname": "core-st-01", "site": "demo",
             "vlans": [{"vlan_id": 50, "name": "GUEST-USERS", "state": "active"},
                        {"vlan_id": 60, "name": "SRV-USERS", "state": "active"}]},
        ],
        "interfaces": [
            {"interface_id": "acc-sw-01:Gi1/0/1", "device_id": "acc-sw-01",
             "name": "Gi1/0/1", "ip_address": "198.51.100.1", "prefix_length": 30,
             "vrf": None},
            {"interface_id": "core-st-01:Gi1/0/1", "device_id": "core-st-01",
             "name": "Gi1/0/1", "ip_address": "198.51.100.2", "prefix_length": 30,
             "vrf": "TENANT-VRF"},
            # /32 host address → IP staged, no prefix derived
            {"interface_id": "acc-sw-01:Lo0", "device_id": "acc-sw-01",
             "name": "Lo0", "ip_address": "192.0.2.201", "prefix_length": 32,
             "vrf": None},
        ],
        "links": [
            {"link_id": "acc-sw-01:Gi1/0/1--core-st-01:Gi1/0/1",
             "local_device_id": "acc-sw-01", "local_interface_id": "acc-sw-01:Gi1/0/1",
             "remote_device_id": "core-st-01", "remote_interface_id": "core-st-01:Gi1/0/1",
             "confidence": "very_high", "discovery_method": "cdp"},
            {"link_id": "acc-sw-01:Gi1/0/1--edge-fw-01:port1",
             "local_device_id": "acc-sw-01", "local_interface_id": "acc-sw-01:Gi1/0/1",
             "remote_device_id": "unmanaged-sw", "remote_interface_id": "unmanaged-sw:Gi1",
             "confidence": "very_high", "discovery_method": "cdp"},
            {"link_id": "arp-inferred",
             "local_device_id": "acc-sw-01", "local_interface_id": "acc-sw-01:Gi1/0/1",
             "remote_device_id": "core-st-01", "remote_interface_id": "core-st-01:Gi1/0/1",
             "confidence": "medium", "discovery_method": "arp_subnet"},
        ],
    }
    mdir = tmp_path / run_id / "model"
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "network_model.json").write_text(json.dumps(model))


def _by_type_s14(staged):
    out = {}
    for c in staged:
        out.setdefault(c["object_type"], []).append(c)
    return out


def test_ipam_staged_from_model(env):
    tmp_path, staged = env
    # Loopback needs a genie entry so the IP can resolve its full name
    lo = json.loads((tmp_path / "demo-run/facts/acc-sw-01/genie_interface.json").read_text())
    lo["Loopback0"] = {"oper_status": "up"}
    (tmp_path / "demo-run/facts/acc-sw-01/genie_interface.json").write_text(json.dumps(lo))
    _write_model(tmp_path)

    bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    by = _by_type_s14(staged)

    assert [c["payload"]["name"] for c in by["vrf"]] == ["TENANT-VRF"]
    # VLAN 50 dedups across devices; VLAN 60 from the stack
    assert {(c["payload"]["site"]["slug"], c["payload"]["vid"]) for c in by["vlan"]} == {
        ("demo", 50), ("demo", 60)}
    # one shared /30 prefix per vrf side; /32 derives none
    assert {(c["payload"].get("vrf", {}).get("name") if "vrf" in c["payload"] else None,
             c["payload"]["prefix"]) for c in by["prefix"]} == {
        (None, "198.51.100.0/30"), ("TENANT-VRF", "198.51.100.0/30")}
    ips = {c["payload"]["address"]: c["payload"] for c in by["ipaddress"]}
    assert set(ips) == {"198.51.100.1/30", "198.51.100.2/30", "192.0.2.201/32"}
    # hint carries the FULL genie name via the canonical bridge
    assert ips["198.51.100.1/30"]["_resolve_interface_name"] == "GigabitEthernet1/0/1"
    # stack IP attributes to the member device
    assert ips["198.51.100.2/30"]["_resolve_device_name"] == "core-st-01-1"
    assert ips["192.0.2.201/32"]["_resolve_interface_name"] == "Loopback0"


def test_cables_confidence_gated_and_endpoint_honest(env):
    tmp_path, staged = env
    _write_model(tmp_path)
    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    by = _by_type_s14(staged)

    cables = by.get("cable", [])
    assert len(cables) == 1  # very_high managed link only; medium never stages
    p = cables[0]["payload"]
    assert p["_resolve_a_device"] == "acc-sw-01"
    assert p["_resolve_b_device"] == "core-st-01-1"  # stack member attribution
    assert p["_resolve_b_interface"] == "GigabitEthernet1/0/1"
    assert "--" in p["dedup_key"]
    # the unmanaged endpoint is disclosed, not silently dropped
    assert any("unmanaged" in w or "not documentable" in w for w in result.warnings)


def test_ipam_rerun_against_populated_netbox_stages_zero(env, monkeypatch):
    tmp_path, staged = env
    _write_model(tmp_path)

    class PopulatedNetBox:
        def ensure_infrastructure(self):
            return {}

        def ensure_device_type(self, *a, **kw):
            return 1

        def get_devices(self):
            return [{"name": n} for n in (
                "acc-sw-01", "core-st-01-1", "core-st-01-2",
                "edge-fw-01-1", "edge-fw-01-2")]

        def get_sites(self):
            return [{"slug": "demo", "name": "demo"}]

        def get_clusters(self):
            return [{"name": "FW_HA"}]

        def get_manufacturers(self):
            return [{"slug": "cisco", "name": "Cisco"},
                    {"slug": "fortinet", "name": "Fortinet"}]

        def get_platforms(self):
            return [{"slug": "cisco-ios-xe", "name": "Cisco IOS-XE"},
                    {"slug": "fortinet-fortios", "name": "Fortinet FortiOS"}]

        def get_virtual_chassis(self):
            return [{"name": "core-st-01"}]

        def get_interfaces(self, device):
            # cable=1 → both cable ends already terminated in NetBox
            return [{"name": "GigabitEthernet1/0/1", "cable": 1}]

        def get_inventory_items(self, device):
            return []

        def get_vrfs(self):
            return [{"name": "TENANT-VRF"}]

        def get_vlans(self):
            return [{"vid": 50, "name": "GUEST-USERS", "site": "demo"},
                    {"vid": 60, "name": "SRV-USERS", "site": "demo"}]

        def get_prefixes(self):
            return [{"prefix": "198.51.100.0/30", "vrf": None},
                    {"prefix": "198.51.100.0/30", "vrf": "TENANT-VRF"}]

        def get_ip_addresses(self):
            return [{"address": "198.51.100.1/30"},
                    {"address": "198.51.100.2/30"},
                    {"address": "192.0.2.201/32"}]

    real_get_source = bootstrap.get_source

    def fake_get_source(name, **kw):
        if name == "netbox":
            return PopulatedNetBox()
        return real_get_source(name, **kw)

    monkeypatch.setattr(bootstrap, "get_source", fake_get_source)
    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    ipam_staged = [c for c in staged if c["object_type"] in
                   ("vrf", "vlan", "prefix", "ipaddress", "cable")]
    assert ipam_staged == [], [c["object_type"] for c in ipam_staged]
    assert result.total_new == 0


def test_fortigate_interfaces_staged_from_rest_facts(env):
    tmp_path, staged = env
    # No genie file for the firewall — the REST facts are the source
    (tmp_path / "demo-run/facts/edge-fw-01/genie_interface.json").unlink()
    (tmp_path / "demo-run/facts/edge-fw-01/fortigate_system_interface.json").write_text(json.dumps({
        "results": [
            {"name": "port1", "status": "up", "type": "physical",
             "description": "", "alias": "", "macaddr": "00:00:00:00:00:00"},
            {"name": "fortilink", "status": "up", "type": "aggregate",
             "description": "sw fabric", "alias": "", "macaddr": ""},
            {"name": "ssl.root", "status": "up", "type": "tunnel",
             "description": "", "alias": "SSL VPN interface", "macaddr": ""},
            # real FortiGate naming the genie key-pattern would reject:
            {"name": "100", "status": "up", "type": "vlan",
             "description": "users vlan", "alias": "", "macaddr": ""},
            {"name": "S2S_TUNNEL_1", "status": "up", "type": "tunnel",
             "description": "", "alias": "", "macaddr": ""},
        ]}))
    bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    fw_ifaces = {c["payload"]["name"]: c["payload"] for c in staged
                 if c["object_type"] == "interface"
                 and c["payload"]["device"]["name"].startswith("edge-fw-01")}
    assert set(fw_ifaces) == {"port1", "fortilink", "ssl.root", "100", "S2S_TUNNEL_1"}
    assert fw_ifaces["100"]["type"] == "virtual"          # vlan sub-interface
    assert fw_ifaces["port1"]["type"] == "other"
    assert fw_ifaces["fortilink"]["type"] == "lag"
    assert fw_ifaces["fortilink"]["description"] == "sw fabric"
    assert fw_ifaces["ssl.root"]["type"] == "virtual"
    assert fw_ifaces["ssl.root"]["description"] == "SSL VPN interface"
    assert fw_ifaces["port1"]["mac_address"] is None  # all-zero MAC dropped
    # HA pair: interfaces attribute to the master member device
    assert fw_ifaces["port1"]["device"]["name"] == "edge-fw-01-1"


def test_ip_embedded_mask_and_ambiguous_claims(env):
    tmp_path, staged = env
    model = {
        "devices": [], "links": [],
        "interfaces": [
            # FortiGate-style: mask embedded, prefix_length None
            {"device_id": "acc-sw-01", "name": "Gi1/0/1",
             "ip_address": "198.51.100.9/30", "prefix_length": None, "vrf": None},
            # the same address claimed twice → ambiguous, never staged
            {"device_id": "acc-sw-01", "name": "Gi1/0/1",
             "ip_address": "192.0.2.99", "prefix_length": 24, "vrf": None},
            {"device_id": "core-st-01", "name": "Gi1/0/1",
             "ip_address": "192.0.2.99", "prefix_length": 24, "vrf": None},
            # 'unassigned' rows are silently valid no-ops
            {"device_id": "acc-sw-01", "name": "Gi1/0/2",
             "ip_address": "unassigned", "prefix_length": None, "vrf": None},
        ],
    }
    mdir = tmp_path / "demo-run" / "model"
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "network_model.json").write_text(json.dumps(model))

    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    ips = [c["payload"]["address"] for c in staged if c["object_type"] == "ipaddress"]
    assert ips == ["198.51.100.9/30"]        # embedded mask parsed + staged
    assert any("192.0.2.99/24" in w and "ambiguous" in w for w in result.warnings)


def test_dedup_key_maps_stay_in_sync():
    """bootstrap._DEDUP_KEY_FIELD and staging._AUDIT_DEDUP_KEY_FIELD are
    documented mirrors (kept local to avoid a circular import) — s14 caught
    them drifting (vlan keyed by bare vid; vrf/prefix/cable missing), which
    broke pending-queue idempotency for the IPAM types."""
    from netcopilot.declared_state.staging import _AUDIT_DEDUP_KEY_FIELD
    assert bootstrap._DEDUP_KEY_FIELD == _AUDIT_DEDUP_KEY_FIELD


def test_cable_guards_lag_and_conflicting_claims(env):
    """Real-hardware lessons: NetBox forbids cables on LAG interfaces, and
    transitive FDB links can claim an interface a better link already owns."""
    tmp_path, staged = env
    model = {
        "devices": [], "interfaces": [],
        "links": [
            # winner: very_high direct link
            {"link_id": "direct", "confidence": "very_high", "discovery_method": "cdp",
             "local_device_id": "acc-sw-01", "local_interface_id": "acc-sw-01:Gi1/0/1",
             "remote_device_id": "core-st-01", "remote_interface_id": "core-st-01:Gi1/0/1"},
            # transitive FDB link claiming the same core port → conflict warning
            {"link_id": "fdb_indirect", "confidence": "high", "discovery_method": "fdb",
             "local_device_id": "acc-sw-01", "local_interface_id": "acc-sw-01:Gi1/0/2",
             "remote_device_id": "core-st-01", "remote_interface_id": "core-st-01:Gi1/0/1"},
        ],
    }
    # give acc-sw-01 a second genie interface + make core's port exist
    gi = json.loads((tmp_path / "demo-run/facts/acc-sw-01/genie_interface.json").read_text())
    gi["GigabitEthernet1/0/2"] = {"oper_status": "up"}
    (tmp_path / "demo-run/facts/acc-sw-01/genie_interface.json").write_text(json.dumps(gi))
    mdir = tmp_path / "demo-run" / "model"
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "network_model.json").write_text(json.dumps(model))

    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    cables = [c for c in staged if c["object_type"] == "cable"]
    assert len(cables) == 1
    # the very_high direct link wins the contested core port
    assert "acc-sw-01:GigabitEthernet1/0/1" in cables[0]["payload"]["dedup_key"]
    assert any("already claimed by a different cable" in w for w in result.warnings)


def test_cable_guard_lag_endpoint(env):
    tmp_path, staged = env
    # FortiGate with an aggregate interface as the link endpoint
    (tmp_path / "demo-run/facts/edge-fw-01/genie_interface.json").unlink()
    (tmp_path / "demo-run/facts/edge-fw-01/fortigate_system_interface.json").write_text(json.dumps({
        "results": [{"name": "AGG1", "status": "up", "type": "aggregate",
                     "description": "", "alias": "", "macaddr": ""}]}))
    model = {
        "devices": [], "interfaces": [],
        "links": [
            {"link_id": "lag_link", "confidence": "very_high", "discovery_method": "lacp",
             "local_device_id": "edge-fw-01", "local_interface_id": "edge-fw-01:AGG1",
             "remote_device_id": "acc-sw-01", "remote_interface_id": "acc-sw-01:Gi1/0/1"},
        ],
    }
    mdir = tmp_path / "demo-run" / "model"
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "network_model.json").write_text(json.dumps(model))

    result = bootstrap.run("demo-run", inventory_path=tmp_path / "lab.yaml")
    assert [c for c in staged if c["object_type"] == "cable"] == []
    assert any("is a LAG" in w for w in result.warnings)
