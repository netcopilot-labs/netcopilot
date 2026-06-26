"""F2-1: inventory source (InventorySource ABC + YAMLInventory adapter)."""

from pathlib import Path

import pytest

from netcopilot.inventory import InventorySource, YAMLInventory

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "inventory.yaml"


def test_abc_cannot_be_instantiated():
    with pytest.raises(TypeError):
        InventorySource()  # type: ignore[abstract]


def test_yaml_inventory_is_a_source():
    assert issubclass(YAMLInventory, InventorySource)


def test_loads_example_inventory():
    inv = YAMLInventory(EXAMPLE)
    devices = inv.get_devices()
    assert len(devices) == 5
    names = {d["name"] for d in devices}
    assert names == {"core-rtr-01", "dist-sw-01", "access-sw-01", "access-sw-02", "edge-fw-01"}


def test_get_device_by_name():
    inv = YAMLInventory(EXAMPLE)
    dev = inv.get_device("core-rtr-01")
    assert dev is not None
    assert dev["mgmt_ip"] == "192.0.2.1"
    assert dev["os"] == "ios-xe"


def test_get_device_unknown_returns_none():
    inv = YAMLInventory(EXAMPLE)
    assert inv.get_device("does-not-exist") is None


def test_per_device_hints_passed_through():
    inv = YAMLInventory(EXAMPLE)
    assert inv.get_device("access-sw-02")["skip_families"] == ["bgp", "routing"]
    assert inv.get_device("access-sw-01")["ssh_only"] is True


def test_get_devices_returns_independent_copies():
    inv = YAMLInventory(EXAMPLE)
    inv.get_devices().append({"name": "rogue"})
    assert len(inv.get_devices()) == 5


def test_missing_file_raises():
    with pytest.raises(ValueError, match="not found"):
        YAMLInventory("/no/such/inventory.yaml")


def test_empty_devices_key(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("devices: []\n", encoding="utf-8")
    assert YAMLInventory(p).get_devices() == []

    p2 = tmp_path / "nodevices.yaml"
    p2.write_text("site: demo\n", encoding="utf-8")
    assert YAMLInventory(p2).get_devices() == []
