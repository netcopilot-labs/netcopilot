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
