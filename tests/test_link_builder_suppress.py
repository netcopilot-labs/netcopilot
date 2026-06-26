"""F2-5k: link_builder port-channel suppression (CDP bilateral > LACP bilateral).

When CDP bilateral and LACP bilateral links exist for the same device pair, the
LACP ones are likely duplicates with wrong interface attribution (SVL shared
system_id_mac) and are suppressed in favour of the authoritative CDP links.
FortiGate LACP links (no CDP possible) are preserved. Synthetic hostnames.
"""

from netcopilot.model.link_builder import (
    _is_portchannel_intf,
    suppress_cdp_portchannel_when_lacp_bilateral,
    suppress_unilateral_cable_on_bilateral_port,
)


def _link(method, a, b):
    return {"discovery_method": method, "local_device_id": a, "remote_device_id": b}


def _il(method, li, ri=""):
    """Link keyed by endpoint interface ids (for port-level suppression)."""
    return {"discovery_method": method, "local_interface_id": li, "remote_interface_id": ri}


# =========================================================================
# _is_portchannel_intf
# =========================================================================
def test_is_portchannel_true():
    for intf in ("core-sw-01:Po1", "core-sw-01:Po10", "core-sw-01:Port-channel1",
                 "core-sw-01:port-channel10", "rtr-01:Be1", "rtr-01:bundle-ether10",
                 "Po1"):
        assert _is_portchannel_intf(intf) is True


def test_is_portchannel_false():
    for intf in ("core-sw-01:Gi1/0/1", "core-sw-01:Hu2/0/3", "core-sw-01:Te1/0/24",
                 "Gi1/0/1", None, ""):
        assert _is_portchannel_intf(intf) is False


# =========================================================================
# suppress_cdp_portchannel_when_lacp_bilateral
# =========================================================================
def test_suppress_lacp_when_cdp_bilateral_for_same_pair():
    cdp = _link("cdp_bilateral", "core-sw-01", "dist-sw-01")
    lacp = _link("lacp_bilateral", "core-sw-01", "dist-sw-01")
    result = suppress_cdp_portchannel_when_lacp_bilateral([cdp, lacp])
    assert cdp in result
    assert lacp not in result


def test_suppress_reverse_pair_order():
    """Pair membership is order-independent (frozenset)."""
    cdp = _link("cdp_bilateral", "core-sw-01", "dist-sw-01")
    lacp = _link("lacp_bilateral", "dist-sw-01", "core-sw-01")  # reversed
    result = suppress_cdp_portchannel_when_lacp_bilateral([cdp, lacp])
    assert result == [cdp]


def test_keep_lacp_without_cdp_for_pair():
    lacp = _link("lacp_bilateral", "core-sw-01", "dist-sw-01")
    other_cdp = _link("cdp_bilateral", "core-sw-01", "rtr-99")  # different pair
    result = suppress_cdp_portchannel_when_lacp_bilateral([lacp, other_cdp])
    assert lacp in result


def test_fortigate_lacp_preserved():
    """FortiGate has no CDP, so its LACP bilateral links are never suppressed."""
    cdp = _link("cdp_bilateral", "core-sw-01", "dist-sw-01")
    fw_lacp = _link("lacp_bilateral", "dist-sw-01", "edge-fw-01")
    result = suppress_cdp_portchannel_when_lacp_bilateral([cdp, fw_lacp])
    assert fw_lacp in result


def test_no_cdp_returns_unchanged():
    links = [_link("lacp_bilateral", "a", "b"), _link("lacp_unilateral", "a", "c")]
    assert suppress_cdp_portchannel_when_lacp_bilateral(links) == links


def test_suppress_empty():
    assert suppress_cdp_portchannel_when_lacp_bilateral([]) == []


# =========================================================================
# suppress_unilateral_cable_on_bilateral_port (one port = one cable)
# =========================================================================
def test_suppress_unilateral_on_bilateral_port():
    """The real case: CDP confirms acc-sw-03:Gi1/0/1 <-> core-sw-01:Gi1/0/5; a
    mac_fingerprint_unilateral resolved only core-sw-01:Gi1/0/5 (empty far end)
    → same cable, phantom edge, suppressed."""
    bil = _il("cdp_bilateral", "acc-sw-03:Gi1/0/1", "core-sw-01:Gi1/0/5")
    uni = _il("mac_fingerprint_unilateral", "core-sw-01:Gi1/0/5", "acc-sw-03:")
    out = suppress_unilateral_cable_on_bilateral_port([bil, uni])
    assert bil in out and uni not in out


def test_keep_unilateral_on_uncabled_port():
    """A unilateral cable on a port with NO bilateral cable survives."""
    bil = _il("cdp_bilateral", "acc-sw-03:Gi1/0/1", "core-sw-01:Gi1/0/5")
    uni = _il("mac_fingerprint_unilateral", "core-sw-01:Gi1/0/9", "ext-rtr:")
    out = suppress_unilateral_cable_on_bilateral_port([bil, uni])
    assert uni in out


def test_suppress_when_far_port_matches_bilateral():
    """Suppressed even if it's the unilateral's far (remote) port that the
    bilateral already cabled — a port hosts one cable either way."""
    bil = _il("cdp_bilateral", "core-sw-01:Gi1/0/5", "acc-sw-03:Gi1/0/1")
    uni = _il("mac_fingerprint_unilateral", "x-rtr:Gi9", "core-sw-01:Gi1/0/5")
    out = suppress_unilateral_cable_on_bilateral_port([bil, uni])
    assert uni not in out


def test_canonical_port_match_short_vs_full():
    """Port match is canonical: short Gi1/0/5 == full GigabitEthernet1/0/5."""
    bil = _il("mac_fingerprint_bilateral", "a:GigabitEthernet1/0/5", "b:Gi0/1")
    uni = _il("cdp_unilateral", "a:Gi1/0/5", "")
    out = suppress_unilateral_cable_on_bilateral_port([bil, uni])
    assert uni not in out


def test_no_bilateral_unchanged():
    links = [_il("mac_fingerprint_unilateral", "a:Gi1", "b:"),
             _il("cdp_unilateral", "c:Gi2", "d:")]
    assert suppress_unilateral_cable_on_bilateral_port(links) == links


def test_suppress_unilateral_empty():
    assert suppress_unilateral_cable_on_bilateral_port([]) == []
