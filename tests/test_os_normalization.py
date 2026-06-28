"""Inventory `os` normalization: an inventory written with joined spellings
(`iosxr`/`iosxe`, any case) loads verbatim — the collect layer always sees the
canonical `ios-xe` / `ios-xr` / `fortios`."""

from netcopilot.collect.collector import KNOWN_OS
from netcopilot.inventory.base import _OS_ALIASES, normalize_os
from netcopilot.inventory.yaml_source import YAMLInventory


def test_joined_spellings_map_to_canonical():
    assert normalize_os("iosxr") == "ios-xr"
    assert normalize_os("iosxe") == "ios-xe"


def test_case_insensitive():
    assert normalize_os("IOS-XE") == "ios-xe"
    assert normalize_os("  IosXr ") == "ios-xr"


def test_canonical_passthrough():
    for c in ("ios-xe", "ios-xr", "fortios"):
        assert normalize_os(c) == c


def test_unknown_passes_through_lowercased():
    # not silently coerced — validation rejects it later with a clear message
    assert normalize_os("Junos") == "junos"


def test_alias_targets_are_all_collector_known():
    # guard against drift: every canonical target must be a family the collector accepts
    assert set(_OS_ALIASES.values()) <= KNOWN_OS


def test_yaml_inventory_normalizes_on_load(tmp_path):
    p = tmp_path / "inv.yaml"
    p.write_text(
        "devices:\n"
        "  - {name: r1, mgmt_ip: 10.0.0.1, os: iosxr,  role: border_router, site: s}\n"
        "  - {name: s1, mgmt_ip: 10.0.0.2, os: IOSXE,  role: core_switch,   site: s}\n"
        "  - {name: fw, mgmt_ip: 10.0.0.3, os: fortios, role: firewall,      site: s}\n"
    )
    devs = YAMLInventory(p).get_devices()
    assert [d["os"] for d in devs] == ["ios-xr", "ios-xe", "fortios"]
