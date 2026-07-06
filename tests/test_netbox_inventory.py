"""S15-1: NetBox-backed collection inventory source.

The adapter surface is duck-typed (the source calls only ``ping()`` +
``get_devices(site=)``), so tests drive it with a plain fake returning
adapter-shaped dicts. RFC 5737 IPs, synthetic names throughout.
"""
import logging

import pytest

from netcopilot.inventory.netbox_source import (
    NetBoxInventory,
    NetBoxInventoryError,
    _slug_to_os,
)


def _dev(**kw) -> dict:
    """An adapter-shaped device dict with collectable defaults."""
    base = {
        "name": "acc-sw-01",
        "mgmt_ip": "192.0.2.41",
        "role": "Access Switch",
        "platform": "Cisco IOS-XE",
        "site": "demo",
        "status": "Active",
        "serial": None,
        "netbox_id": 1,
        "platform_slug": "cisco-ios-xe",
        "role_slug": "access-switch",
        "site_slug": "demo",
        "status_value": "active",
        "virtual_chassis": None,
        "cluster": None,
        "config_context": {},
    }
    base.update(kw)
    return base


class FakeAdapter:
    def __init__(self, devices, *, ping_exc=None):
        self._devices = devices
        self._ping_exc = ping_exc
        self.seen_site = None

    def ping(self):
        if self._ping_exc:
            raise self._ping_exc

    def get_devices(self, site=None):
        self.seen_site = site
        return list(self._devices)


# ── field mapping ────────────────────────────────────────────────────────────

def test_standalone_device_maps_to_inventory_entry():
    adapter = FakeAdapter([_dev()])
    inv = NetBoxInventory("demo", adapter=adapter)
    assert adapter.seen_site == "demo"          # server-side site scoping
    devices = inv.get_devices()
    assert devices == [{
        "name": "acc-sw-01",
        "mgmt_ip": "192.0.2.41",
        "os": "ios-xe",                          # recovered from the platform slug
        "site": "demo",
        "role": "access_switch",                 # slug hyphens → YAML underscore form
    }]
    assert inv.get_device("acc-sw-01")["os"] == "ios-xe"
    assert inv.get_device("nope") is None


def test_config_context_hints_merge_allowlisted_only():
    cc = {"netcopilot": {"api_token": "${FW1_TOKEN}", "ssh_only": True,
                         "skip_families": ["bgp"], "vdom": "root",
                         "rogue_key": "ignored"},
          "other_tool": {"x": 1}}
    adapter = FakeAdapter([_dev(name="edge-fw-01", platform_slug="fortinet-fortios",
                                mgmt_ip="192.0.2.1", config_context=cc)])
    entry = NetBoxInventory("demo", adapter=adapter).get_device("edge-fw-01")
    assert entry["os"] == "fortios"
    assert entry["api_token"] == "${FW1_TOKEN}"   # env REFERENCE, expanded at collect time
    assert entry["ssh_only"] is True
    assert entry["skip_families"] == ["bgp"]
    assert entry["vdom"] == "root"
    assert "rogue_key" not in entry and "other_tool" not in entry


def test_config_context_netcopilot_non_mapping_ignored(caplog):
    adapter = FakeAdapter([_dev(config_context={"netcopilot": "oops"})])
    with caplog.at_level(logging.WARNING):
        inv = NetBoxInventory("demo", adapter=adapter)
    assert inv.get_devices()[0]["name"] == "acc-sw-01"   # device still collectable
    assert "not a mapping" in caplog.text


# ── honesty: skips are warned, never silent ──────────────────────────────────

def test_device_without_primary_ip_skipped_with_warning(caplog):
    adapter = FakeAdapter([_dev(mgmt_ip=None), _dev(name="acc-sw-02", mgmt_ip="192.0.2.42", netbox_id=2)])
    with caplog.at_level(logging.WARNING):
        inv = NetBoxInventory("demo", adapter=adapter)
    assert [d["name"] for d in inv.get_devices()] == ["acc-sw-02"]
    assert "no primary IPv4" in caplog.text and "acc-sw-01" in caplog.text


def test_unknown_platform_slug_skipped_listing_accepted(caplog):
    adapter = FakeAdapter([_dev(platform_slug="junos")])
    with caplog.at_level(logging.WARNING):
        inv = NetBoxInventory("demo", adapter=adapter)
    assert inv.get_devices() == []
    assert "junos" in caplog.text and "cisco-ios-xe" in caplog.text  # accepted slugs listed


def test_non_active_device_filtered():
    adapter = FakeAdapter([_dev(status_value="offline"),
                           _dev(name="acc-sw-02", netbox_id=2)])
    inv = NetBoxInventory("demo", adapter=adapter)
    assert [d["name"] for d in inv.get_devices()] == ["acc-sw-02"]


def test_netbox_down_raises_never_empty():
    adapter = FakeAdapter([], ping_exc=ConnectionError("connection refused"))
    with pytest.raises(NetBoxInventoryError, match="unreachable"):
        NetBoxInventory("demo", adapter=adapter)


def test_missing_netbox_env_raises(monkeypatch):
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_API_TOKEN", raising=False)
    with pytest.raises(NetBoxInventoryError, match="NETBOX_URL"):
        NetBoxInventory("demo")


def test_empty_site_rejected():
    with pytest.raises(ValueError, match="site"):
        NetBoxInventory("")


# ── per-physical → logical folding (ADR-0016 round-trip) ─────────────────────

def test_virtual_chassis_members_fold_to_one_entry():
    members = [
        _dev(name="acc-stack-01-1", mgmt_ip="192.0.2.45", virtual_chassis="acc-stack-01", netbox_id=10),
        _dev(name="acc-stack-01-2", mgmt_ip=None, virtual_chassis="acc-stack-01", netbox_id=11),
        _dev(name="acc-sw-02", mgmt_ip="192.0.2.42", netbox_id=2),
    ]
    inv = NetBoxInventory("demo", adapter=FakeAdapter(members))
    names = [d["name"] for d in inv.get_devices()]
    assert names == ["acc-stack-01", "acc-sw-02"]        # one LOGICAL stack entry
    stack = inv.get_device("acc-stack-01")
    assert stack["mgmt_ip"] == "192.0.2.45"              # via the member holding primary_ip4


def test_vc_without_any_primary_ip_skipped_naming_the_vc(caplog):
    members = [
        _dev(name="acc-stack-01-1", mgmt_ip=None, virtual_chassis="acc-stack-01", netbox_id=10),
        _dev(name="acc-stack-01-2", mgmt_ip=None, virtual_chassis="acc-stack-01", netbox_id=11),
    ]
    with caplog.at_level(logging.WARNING):
        inv = NetBoxInventory("demo", adapter=FakeAdapter(members))
    assert inv.get_devices() == []
    assert "acc-stack-01" in caplog.text and "primary_ip4" in caplog.text


def test_ha_cluster_members_fold_to_the_member_stem_not_the_cluster_label():
    # Real shape (caught live on HA hardware): the cluster is a grouping
    # LABEL (e.g. "FW-HA-GROUP"), the device identity is the members' stem.
    members = [
        _dev(name="edge-fw-01-1", mgmt_ip="192.0.2.1", cluster="FW-HA-GROUP",
             platform_slug="fortinet-fortios", role_slug="firewall", netbox_id=20),
        _dev(name="edge-fw-01-2", mgmt_ip=None, cluster="FW-HA-GROUP",
             platform_slug="fortinet-fortios", role_slug="firewall", netbox_id=21),
    ]
    inv = NetBoxInventory("demo", adapter=FakeAdapter(members))
    entry = inv.get_device("edge-fw-01")                 # the stem, NOT "FW-HA-GROUP"
    assert entry is not None
    assert inv.get_device("FW-HA-GROUP") is None
    assert entry["os"] == "fortios" and entry["mgmt_ip"] == "192.0.2.1"


def test_ha_cluster_without_positional_names_falls_back_to_cluster_name():
    # Hand-modeled cluster: member names carry no <stem>-<pos> convention →
    # the cluster name is the only available logical identity.
    members = [
        _dev(name="fw-alpha", mgmt_ip="192.0.2.1", cluster="edge-fw-01",
             platform_slug="fortinet-fortios", netbox_id=20),
        _dev(name="fw-beta", mgmt_ip=None, cluster="edge-fw-01",
             platform_slug="fortinet-fortios", netbox_id=21),
    ]
    entry = NetBoxInventory("demo", adapter=FakeAdapter(members)).get_device("edge-fw-01")
    assert entry is not None and entry["mgmt_ip"] == "192.0.2.1"


def test_multiple_members_with_primary_ip_pick_is_deterministic():
    members = [
        _dev(name="edge-fw-01-2", mgmt_ip="192.0.2.2", cluster="FW-HA-GROUP",
             platform_slug="fortinet-fortios", netbox_id=21),
        _dev(name="edge-fw-01-1", mgmt_ip="192.0.2.1", cluster="FW-HA-GROUP",
             platform_slug="fortinet-fortios", netbox_id=20),
    ]
    entry = NetBoxInventory("demo", adapter=FakeAdapter(members)).get_device("edge-fw-01")
    assert entry["mgmt_ip"] == "192.0.2.1"               # lowest member name wins


# ── factory + netbox:// scheme (S15-2) ───────────────────────────────────────

def test_factory_yaml_path(tmp_path):
    import netcopilot.inventory as inv_pkg
    p = tmp_path / "lab.yaml"
    p.write_text("devices:\n  - {name: acc-sw-01, mgmt_ip: 192.0.2.41, os: ios-xe}\n")
    src = inv_pkg.get_inventory_source(str(p))
    assert isinstance(src, inv_pkg.YAMLInventory)
    assert src.get_device("acc-sw-01")["os"] == "ios-xe"


def test_factory_netbox_scheme(monkeypatch):
    import netcopilot.inventory as inv_pkg
    built = {}

    class FakeSource:
        def __init__(self, site):
            built["site"] = site

    monkeypatch.setattr(inv_pkg, "NetBoxInventory", FakeSource)
    assert isinstance(inv_pkg.get_inventory_source("netbox://demo"), FakeSource)
    assert built["site"] == "demo"
    # site may come from the keyword when the URI leaves it off
    inv_pkg.get_inventory_source("netbox://", site="t75")
    assert built["site"] == "t75"


def test_factory_netbox_requires_a_site():
    from netcopilot.inventory import get_inventory_source
    with pytest.raises(ValueError, match="netbox://<site>"):
        get_inventory_source("netbox://")


def test_factory_netbox_site_mismatch_aborts(monkeypatch):
    import netcopilot.inventory as inv_pkg
    monkeypatch.setattr(inv_pkg, "NetBoxInventory", lambda site: site)
    with pytest.raises(ValueError, match="one site per run"):
        inv_pkg.get_inventory_source("netbox://demo", site="t75")
    # agreement passes
    assert inv_pkg.get_inventory_source("netbox://demo", site="demo") == "demo"


# ── writer/reader map cannot drift ───────────────────────────────────────────

def test_slug_map_is_exact_inverse_of_bootstrap_map():
    from netcopilot.declared_state.bootstrap import OS_TO_PLATFORM
    inverse = _slug_to_os()
    assert len(inverse) == len(OS_TO_PLATFORM)           # no slug collisions
    for os_name, (slug, _display) in OS_TO_PLATFORM.items():
        assert inverse[slug] == os_name
