"""F2-5a: interface-name foundations for the model layer.

Covers the three pure modules the link/model builders depend on:
- ``interface_classifier.classify_interface`` (name → InterfaceType)
- ``interface_normalizer.normalize_interface_name`` / ``canonicalize``
- ``interface_taxonomy.is_virtual_interface``
"""

import pytest

from netcopilot.model import (
    canonicalize,
    classify_interface,
    is_virtual_interface,
    normalize_interface_name,
)


# =========================================================================
# classify_interface — IOS XE
# =========================================================================
@pytest.mark.parametrize("name,expected", [
    # Management — most specific, checked first
    ("Mgmt0", "management"),
    ("MgmtEth0", "management"),
    ("mgmt0", "management"),
    ("GigabitEthernet0/0", "management"),  # special case: Gi0/0 is mgmt on IOS XE
    ("Gi0/0", "management"),
    # Aggregated — Port-channel + abbreviation
    ("Port-channel1", "aggregated"),
    ("Po1", "aggregated"),
    ("Po10", "aggregated"),
    # Logical — Loopback / Tunnel / BDI
    ("Loopback0", "logical"),
    ("Lo0", "logical"),
    ("Tunnel100", "logical"),
    ("Tu1", "logical"),
    ("BDI100", "logical"),
    # VLAN
    ("Vlan100", "vlan"),
    ("Vl100", "vlan"),
    # Physical — full names + abbreviations
    ("GigabitEthernet1/0/1", "physical"),
    ("HundredGigE1/0/1", "physical"),
    ("Te1/0/1", "physical"),
    ("Hu1/0/1", "physical"),
    ("Fa0/1", "physical"),
])
def test_classify_iosxe(name, expected):
    assert classify_interface(name, "iosxe") == expected


# =========================================================================
# classify_interface — IOS XR
# =========================================================================
@pytest.mark.parametrize("name,expected", [
    ("MgmtEth0/RP0/CPU0/0", "management"),
    ("MgmtLan0", "management"),
    ("Mgmt0", "management"),
    ("Bundle-Ether1", "aggregated"),
    ("BE1", "aggregated"),
    ("BE100", "aggregated"),
    ("Loopback0", "logical"),
    ("Lo0", "logical"),
    ("tunnel-te1", "logical"),
    ("tunnel-ip1", "logical"),
    ("Tunnel1", "logical"),
    ("BVI100", "logical"),
    ("Vlan100", "vlan"),
    ("GigabitEthernet0/0/0/0", "physical"),
    ("HundredGigE0/0/0/0", "physical"),
    ("TenGigE0/0/0/0", "physical"),
])
def test_classify_iosxr(name, expected):
    assert classify_interface(name, "iosxr") == expected


# =========================================================================
# classify_interface — generic (unknown OS)
# =========================================================================
@pytest.mark.parametrize("name,expected", [
    ("Mgmt0", "management"),
    ("mgmt0", "management"),  # generic is case-insensitive
    ("Bundle-Ether1", "aggregated"),
    ("Port-channel1", "aggregated"),
    ("Loopback0", "logical"),
    ("Tunnel1", "logical"),
    ("BDI100", "logical"),
    ("BVI100", "logical"),
    ("Vlan100", "vlan"),
    ("vlan100", "vlan"),  # case-insensitive
    ("Gi0/1", "physical"),
    ("Te0/0", "physical"),
])
def test_classify_generic(name, expected):
    assert classify_interface(name, "unknown_os") == expected


@pytest.mark.parametrize("name", [
    "twoFactorAuth",     # "tw" prefix → not TenGigE
    "foreignKey",        # "fo" prefix → not FortyGigE
    "telephone",         # "te" prefix → not TenGigE
    "fabric",            # "fa" prefix → not FastEthernet
    "ethereal",          # "et" prefix → not Ethernet
    "general",           # unrelated, sanity
])
def test_generic_greedy_2letter_prefixes_require_digit_suffix(name):
    """Generic classifier physical prefixes must require a digit suffix."""
    assert classify_interface(name, "unknown_os") == "unknown"


@pytest.mark.parametrize("name", ["", " ", "\t\n"])
def test_classify_empty_or_whitespace_returns_unknown(name):
    assert classify_interface(name, "iosxe") == "unknown"
    assert classify_interface(name, "iosxr") == "unknown"


@pytest.mark.parametrize("name,os_family,expected", [
    (" Po1", "iosxe", "aggregated"),
    ("\tPo1", "iosxe", "aggregated"),
    ("Po1 ", "iosxe", "aggregated"),
    ("  GigabitEthernet1/0/1  ", "iosxe", "physical"),
    (" BE1", "iosxr", "aggregated"),
    ("\tBundle-Ether1", "iosxr", "aggregated"),
])
def test_classify_leading_trailing_whitespace_normalized(name, os_family, expected):
    assert classify_interface(name, os_family) == expected


@pytest.mark.parametrize("name,os_family", [
    # IOS XE — 2-letter abbreviations should NOT match arbitrary names
    ("Pop3Manager", "iosxe"),       # "Po" prefix but no digit after → not Port-channel
    ("PolicyMap", "iosxe"),         # same
    ("LongHaul", "iosxe"),          # "Lo" prefix → not Loopback
    ("VlsmCalculator", "iosxe"),    # "Vl" prefix → not Vlan
    # IOS XR — BE is the riskiest (very short)
    ("BERtest", "iosxr"),           # "BE" prefix → not Bundle-Ether
    ("BEacon", "iosxr"),            # same
])
def test_classify_greedy_2letter_prefixes_require_digit_suffix(name, os_family):
    """2-letter prefixes (Po, Lo, Vl, BE) must require a digit suffix."""
    assert classify_interface(name, os_family) == "unknown"


# =========================================================================
# normalize_interface_name — short form for CDP display matching
# =========================================================================
@pytest.mark.parametrize("name,expected", [
    ("HundredGigE0/0/1/0", "Hu0/0/1/0"),
    ("Hun 1/0/1", "Hu1/0/1"),            # IOS XE CDP space form
    ("Hu0/0/1/0", "Hu0/0/1/0"),
    ("GigabitEthernet0/0", "Gi0/0"),
    ("Gig 1/0/3", "Gi1/0/3"),
    ("TenGigabitEthernet1/0/1", "Te1/0/1"),
    ("TwentyFiveGigE1/0/10", "Tw1/0/10"),
    ("Twe 1/0/8", "Tw1/0/8"),
    ("Bundle-Ether1", "BE1"),
    ("Port-channel35", "Po35"),
    ("Mg0/RP0/CPU0/0", "Mgmt0/RP0/CPU0/0"),
    ("MgmtEth0/RP0/CPU0/0", "Mgmt0/RP0/CPU0/0"),
    ("Loopback0", "Lo0"),
    ("Vlan99", "Vl99"),
])
def test_normalize_interface_name(name, expected):
    assert normalize_interface_name(name) == expected


@pytest.mark.parametrize("name", ["", None])
def test_normalize_empty_passthrough(name):
    # Empty / None pass through unchanged (caller decides).
    assert normalize_interface_name(name) == name


def test_normalize_unknown_passthrough():
    # Unrecognized interface types are returned unchanged.
    assert normalize_interface_name("WeirdInterface7") == "WeirdInterface7"


# =========================================================================
# canonicalize — full lowercase identity key for cross-source matching
# =========================================================================
@pytest.mark.parametrize("name,expected", [
    ("Gi1/0/1", "gigabitethernet1/0/1"),
    ("GigabitEthernet1/0/1", "gigabitethernet1/0/1"),
    ("Gig 1/0/3", "gigabitethernet1/0/3"),
    ("Hun 2/0/1", "hundredgige2/0/1"),
    ("HundredGigE0/0/1/0", "hundredgige0/0/1/0"),
    ("Hu0/0/1/0", "hundredgige0/0/1/0"),
    ("Bundle-Ether13", "bundle-ether13"),
    ("MgmtEth0/RP0/CPU0/0", "mgmteth0/rp0/cpu0/0"),
    ("port1", "port1"),          # FortiGate passthrough
    ("internal", "internal"),    # FortiGate passthrough
])
def test_canonicalize(name, expected):
    assert canonicalize(name) == expected


def test_canonicalize_cross_source_identity():
    """The same physical interface from three sources canonicalizes identically."""
    cdp_xe = canonicalize("Hun 2/0/1")          # IOS XE CDP
    genie = canonicalize("HundredGigE2/0/1")    # Genie full form
    cdp_xr = canonicalize("Hu2/0/1")            # IOS XR CDP
    assert cdp_xe == genie == cdp_xr == "hundredgige2/0/1"


@pytest.mark.parametrize("mac", [
    "00:1a:2b:3c:4d:5e",   # colon-separated
    "001a.2b3c.4d5e",      # Cisco dot-quad
    "00-1a-2b-3c-4d-5e",   # dash-separated
])
def test_canonicalize_rejects_mac(mac):
    # LLDP port_id can be a MAC — not matchable to an interface name.
    assert canonicalize(mac) is None


@pytest.mark.parametrize("name", [None, "", "   "])
def test_canonicalize_empty_is_none(name):
    assert canonicalize(name) is None


def test_canonicalize_port_not_portchannel():
    """FortiGate 'port1' must not be swallowed by the 'po' → port-channel rule."""
    assert canonicalize("port1") == "port1"
    assert canonicalize("Po1") == "port-channel1"


# =========================================================================
# is_virtual_interface — shared virtual / L3-only definition
# =========================================================================
@pytest.mark.parametrize("name", [
    "Loopback0", "Lo0", "Vlan99", "Vl99", "BVI100", "BDI100",
    "Tunnel1", "Tu1", "nve1", "4094",  # FortiGate numeric VLAN
])
def test_is_virtual_true(name):
    assert is_virtual_interface(name) is True


@pytest.mark.parametrize("name", [
    "GigabitEthernet1/0/1", "Hu1/0/1", "Port-channel1", "Po1",
    "Bundle-Ether1", "BE1",  # LAG aggregates are NOT virtual
    "local",                 # "lo" prefix but not "lo<digit>"
    "valid",                 # "vl" prefix but not "vl<digit>"
    None, "",
])
def test_is_virtual_false(name):
    assert is_virtual_interface(name) is False
