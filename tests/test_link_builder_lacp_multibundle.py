"""R2-LAG-1 / R2-LAG-2: LACP correctness on multi-bundle / reused-system-id topologies.

These are the two cases the demo + hw golden masters do NOT contain, so the
order-coupled LACP picks could never be reproduced or validated against them.
Synthetic fixtures reproduce each bug deterministically:

  - R2-LAG-1: TWO port-channels between ONE device pair. Bilateral promotion
    pairs the reverse candidate by device-pair only and substitutes its
    local_interface as the remote — so it can fuse member A:Gi0/1 with the
    WRONG far member (B:Gi0/2), crossing two physically-separate cables.

  - R2-LAG-2: a system_id MAC reused across two devices (the IOL hazard).
    _build_mac_lookup is last-writer-wins, so the partner resolves to whichever
    twin was indexed last — not the device that actually points back.

The system is already deterministic (same facts -> same output); these tests
assert CORRECTNESS (right cable pairing + right partner owner) and
order-INDEPENDENCE (shuffling device/member order yields identical, correct
links). See labs fixtures/golden/LEDGER-R2-L2L3.md (R2-LAG-1/2/3).
"""

import itertools
import json

from netcopilot.model.link_builder import _build_mac_lookup, discover_lacp_links

MAC_A = "aaaa.0000.000a"
MAC_B = "bbbb.0000.000b"
MAC_D = "dddd.0000.000d"
MAC_UNCOLLECTED = "eeee.0000.00ee"  # an LACP neighbour outside collection scope
MAC_SHARED = "cccc.0000.00cc"  # reused system_id across two twins (IOL hazard)


def _write(facts_dir, name, doc):
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / name).write_text(json.dumps(doc))


def _po(system_id_mac, members):
    """members: list of (member_name, partner_id, port_num, partner_port_num, prio)."""
    return {
        "system_id_mac": system_id_mac,
        "members": {
            name: {
                "partner_id": pid,
                "port_num": pn,
                "partner_port_num": ppn,
                "lacp_port_priority": prio,
            }
            for (name, pid, pn, ppn, prio) in members
        },
    }


def _lag(pos):
    """pos: ordered list of (po_name, system_id_mac, members) -> genie_lag.json doc."""
    return {"interfaces": {name: _po(sid, members) for (name, sid, members) in pos}}


def _intf(pairs):
    """pairs: list of (intf_name, mac) -> genie_interface.json doc."""
    return {name: {"phys_address": mac} for (name, mac) in pairs}


def _bilateral_pairs(cands):
    """Return the set of frozenset({(dev, canonical_intf), (dev, canonical_intf)})
    for every lacp_bilateral candidate — the physical cable endpoints."""
    pairs = set()
    for c in cands:
        if c.discovery_method != "lacp_bilateral":
            continue
        pairs.add(frozenset({
            (c.local_device, c.local_interface_canonical),
            (c.remote_device, c.remote_interface_canonical),
        }))
    return pairs


# =========================================================================
# R2-LAG-1 — two port-channels between one device pair must not cross cables
# =========================================================================
def _two_bundle_facts(tmp_path, b_member_order):
    """A(core)=MAC_A and B(dist)=MAC_B joined by PO1 (Gi0/1<->Gi0/1) and
    PO2 (Gi0/2<->Gi0/2). b_member_order controls the order B's reverse members
    are emitted, which is what the order-coupled pick is sensitive to."""
    a = tmp_path / "core-rtr-01"
    b = tmp_path / "dist-sw-01"

    _write(a, "genie_interface.json", _intf([
        ("GigabitEthernet0/1", MAC_A), ("GigabitEthernet0/2", MAC_A),
    ]))
    _write(a, "genie_lag.json", _lag([
        ("Port-channel1", MAC_A, [("GigabitEthernet0/1", MAC_B, 11, 21, 32768)]),
        ("Port-channel2", MAC_A, [("GigabitEthernet0/2", MAC_B, 12, 22, 32768)]),
    ]))

    b_members = {
        "Port-channel1": ("Port-channel1", MAC_B, [("GigabitEthernet0/1", MAC_A, 21, 11, 32768)]),
        "Port-channel2": ("Port-channel2", MAC_B, [("GigabitEthernet0/2", MAC_A, 22, 12, 32768)]),
    }
    _write(b, "genie_interface.json", _intf([
        ("GigabitEthernet0/1", MAC_B), ("GigabitEthernet0/2", MAC_B),
    ]))
    _write(b, "genie_lag.json", _lag([b_members[k] for k in b_member_order]))
    return {"core-rtr-01": a, "dist-sw-01": b}


# The two physically-correct cables (member ports pair by partner_port_num).
# canonicalize() lowercases the full Genie name (no Gi abbreviation).
_CORRECT_PAIRS = {
    frozenset({("core-rtr-01", "gigabitethernet0/1"), ("dist-sw-01", "gigabitethernet0/1")}),
    frozenset({("core-rtr-01", "gigabitethernet0/2"), ("dist-sw-01", "gigabitethernet0/2")}),
}


def test_two_bundles_pair_correct_cables(tmp_path):
    """Natural-order fixture: both bundles must pair like-for-like, not crossed."""
    facts = _two_bundle_facts(tmp_path, ["Port-channel2", "Port-channel1"])
    cands = discover_lacp_links(facts, {"core-rtr-01", "dist-sw-01"})
    assert _bilateral_pairs(cands) == _CORRECT_PAIRS


def test_two_bundles_order_independent(tmp_path):
    """Cable pairing must be identical AND correct under every device/member order."""
    seen = []
    for member_order in (["Port-channel1", "Port-channel2"],
                         ["Port-channel2", "Port-channel1"]):
        facts = _two_bundle_facts(tmp_path / "_".join(member_order), member_order)
        items = list(facts.items())
        for perm in itertools.permutations(items):
            cands = discover_lacp_links(dict(perm), {"core-rtr-01", "dist-sw-01"})
            pairs = _bilateral_pairs(cands)
            assert pairs == _CORRECT_PAIRS, (
                f"member_order={member_order} perm={[h for h, _ in perm]} -> {pairs}"
            )
            seen.append(pairs)
    assert all(p == seen[0] for p in seen)


# =========================================================================
# R2-LAG-2 — reused system_id MAC must resolve to the true partner
# =========================================================================
_DEVICES = ["acc-sw-01", "iol-sw-01", "iol-sw-02", "dist-sw-99"]

# The two correct cables. MAC_SHARED is reused by iol-sw-01 (B) and iol-sw-02 (C);
# only LACP symmetry tells the two cables apart: B points back at A, C points back
# at D. Last-writer-wins collapses both to one twin.
_AB_CABLE = frozenset({("acc-sw-01", "gigabitethernet0/0"),
                       ("iol-sw-01", "gigabitethernet1/0/1")})
_CD_CABLE = frozenset({("iol-sw-02", "gigabitethernet1/0/9"),
                       ("dist-sw-99", "gigabitethernet2/0/1")})


def _reused_mac_facts(tmp_path, device_order):
    """B (iol-sw-01) and C (iol-sw-02) BOTH advertise system_id MAC_SHARED.
    A pairs with B, D pairs with C. A's partner (MAC_SHARED) must resolve to the
    twin that points back at A (B), and D's to the twin that points back at D (C)
    — never the last-indexed one."""
    a = tmp_path / "acc-sw-01"
    b = tmp_path / "iol-sw-01"   # true partner of A — bundle back to A (MAC_A)
    c = tmp_path / "iol-sw-02"   # twin — same system_id, paired with D (MAC_D)
    d = tmp_path / "dist-sw-99"  # true partner of C — bundle back to C

    _write(a, "genie_interface.json", _intf([("GigabitEthernet0/0", MAC_A)]))
    _write(a, "genie_lag.json", _lag([
        ("Port-channel1", MAC_A, [("GigabitEthernet0/0", MAC_SHARED, 10, 20, 32768)]),
    ]))

    _write(b, "genie_interface.json", _intf([("GigabitEthernet1/0/1", MAC_SHARED)]))
    _write(b, "genie_lag.json", _lag([
        ("Port-channel1", MAC_SHARED, [("GigabitEthernet1/0/1", MAC_A, 20, 10, 32768)]),
    ]))

    _write(c, "genie_interface.json", _intf([("GigabitEthernet1/0/9", MAC_SHARED)]))
    _write(c, "genie_lag.json", _lag([
        ("Port-channel9", MAC_SHARED, [("GigabitEthernet1/0/9", MAC_D, 90, 91, 32768)]),
    ]))

    _write(d, "genie_interface.json", _intf([("GigabitEthernet2/0/1", MAC_D)]))
    _write(d, "genie_lag.json", _lag([
        ("Port-channel1", MAC_D, [("GigabitEthernet2/0/1", MAC_SHARED, 91, 90, 32768)]),
    ]))

    dirs = {"acc-sw-01": a, "iol-sw-01": b, "iol-sw-02": c, "dist-sw-99": d}
    return {h: dirs[h] for h in device_order}


def test_reused_system_id_resolves_true_partner(tmp_path):
    """C indexed last must NOT steal A's partner from B (last-writer-wins bug)."""
    facts = _reused_mac_facts(tmp_path, _DEVICES)
    cands = discover_lacp_links(facts, set(facts))
    # The two cables must pair like-for-like via symmetry, not collapse onto one twin.
    assert _bilateral_pairs(cands) == {_AB_CABLE, _CD_CABLE}
    # A must never end up cabled to the wrong twin (iol-sw-02).
    a_neighbours = {
        c.remote_device for c in cands if c.local_device == "acc-sw-01"
    } | {c.local_device for c in cands if c.remote_device == "acc-sw-01"}
    assert "iol-sw-02" not in a_neighbours, a_neighbours


def test_reused_system_id_order_independent(tmp_path):
    """Cable pairing must be identical AND correct under every device order
    (the resolver is set-based, so last-writer-wins can't leak back in)."""
    for order in itertools.permutations(_DEVICES):
        facts = _reused_mac_facts(tmp_path / "_".join(order), list(order))
        cands = discover_lacp_links(facts, set(facts))
        assert _bilateral_pairs(cands) == {_AB_CABLE, _CD_CABLE}, (
            f"order={order} -> {_bilateral_pairs(cands)}"
        )


# =========================================================================
# R2-LAG-5 — the enrichment must not fabricate a partner from a reused
#            system_id; and must STILL fill a genuinely-missing MAC.
# =========================================================================
def test_enrichment_fills_missing_mac_via_symmetry(tmp_path):
    """LEGITIMATE path (must never regress): A omits its own identity (no
    phys_address, no LAG system_id_mac). The _build_mac_lookup LACP cross-
    reference enrichment fills A's MAC via symmetry — A points at B's unique
    MAC, B points back at the unknown MAC, so it must be A's. Bridges on a
    UNIQUE identity MAC, so the R2-LAG-5 reused-system_id guard leaves it alone."""
    a = tmp_path / "rtr-a"
    b = tmp_path / "rtr-b"
    # A: empty interface record (no phys_address) + LAG with no system_id_mac.
    _write(a, "genie_interface.json", {"GigabitEthernet0/0": {}})
    _write(a, "genie_lag.json", {"interfaces": {"Port-channel1": {"members": {
        "GigabitEthernet0/0": {"partner_id": MAC_B, "port_num": 10,
                               "partner_port_num": 20, "lacp_port_priority": 32768}}}}})
    _write(b, "genie_interface.json", _intf([("GigabitEthernet1/0/1", MAC_B)]))
    _write(b, "genie_lag.json", _lag([
        ("Port-channel1", MAC_B, [("GigabitEthernet1/0/1", MAC_A, 20, 10, 32768)]),
    ]))

    facts = {"rtr-a": a, "rtr-b": b}
    # A's MAC is absent until the enrichment infers it via LACP symmetry.
    assert _build_mac_lookup(facts).get("aaaa0000000a") == "rtr-a"
    # And the bilateral cable forms.
    assert _bilateral_pairs(discover_lacp_links(facts, set(facts))) == {
        frozenset({("rtr-a", "gigabitethernet0/0"), ("rtr-b", "gigabitethernet1/0/1")})
    }


def _twin_uncollected_facts(tmp_path, device_order):
    """B and C share system_id MAC_SHARED. A pairs with B; C's LACP neighbour is
    OUTSIDE collection (partner MAC_UNCOLLECTED, no owner). Last-writer-wins can
    route MAC_SHARED to C, after which the enrichment fabricates
    MAC_UNCOLLECTED -> A and a phantom C<->A link. Must not happen."""
    a = tmp_path / "acc-sw-01"
    b = tmp_path / "iol-sw-01"   # true partner of A
    c = tmp_path / "iol-sw-02"   # twin — neighbour uncollected

    _write(a, "genie_interface.json", _intf([("GigabitEthernet0/0", MAC_A)]))
    _write(a, "genie_lag.json", _lag([
        ("Port-channel1", MAC_A, [("GigabitEthernet0/0", MAC_SHARED, 10, 20, 32768)]),
    ]))
    _write(b, "genie_interface.json", _intf([("GigabitEthernet1/0/1", MAC_SHARED)]))
    _write(b, "genie_lag.json", _lag([
        ("Port-channel1", MAC_SHARED, [("GigabitEthernet1/0/1", MAC_A, 20, 10, 32768)]),
    ]))
    _write(c, "genie_interface.json", _intf([("GigabitEthernet1/0/9", MAC_SHARED)]))
    _write(c, "genie_lag.json", _lag([
        ("Port-channel9", MAC_SHARED, [("GigabitEthernet1/0/9", MAC_UNCOLLECTED, 90, 91, 32768)]),
    ]))
    dirs = {"acc-sw-01": a, "iol-sw-01": b, "iol-sw-02": c}
    return {h: dirs[h] for h in device_order}


def test_reused_system_id_no_phantom_to_uncollected(tmp_path):
    """No device ordering may fabricate a phantom acc-sw-01 <-> iol-sw-02 link
    out of iol-sw-02's uncollected LACP neighbour (R2-LAG-5)."""
    devices = ["acc-sw-01", "iol-sw-01", "iol-sw-02"]
    for order in itertools.permutations(devices):
        facts = _twin_uncollected_facts(tmp_path / "_".join(order), list(order))
        cands = discover_lacp_links(facts, set(facts))
        phantom = [
            c for c in cands
            if {c.local_device, c.remote_device} == {"acc-sw-01", "iol-sw-02"}
        ]
        assert not phantom, f"order={order} fabricated {[(c.local_device, c.remote_device) for c in phantom]}"
        # The real A<->B cable must still be present.
        assert _AB_CABLE in _bilateral_pairs(cands), f"order={order} lost A<->B"
