"""S01-7: synthetic drift demo pair — engine-output regression golden.

Loads the committed before/after pair (demo/drift-demo/) and asserts the
engine's diff exactly matches the committed golden (fixtures/golden/
drift-demo.json). This is the drift feature's regression guard: any change to
the engine or field policy that alters the diff of this curated pair fails
here and must be reviewed. Also asserts the pair covers every change type ×
tier (the S01-7 acceptance).
"""

from __future__ import annotations

import json
from pathlib import Path

from netcopilot.diff.engine import compute_diff, load_run

ROOT = Path(__file__).resolve().parents[1]
PAIR_DIR = ROOT / "demo" / "drift-demo"
GOLDEN = ROOT / "fixtures" / "golden" / "drift-demo.json"


def _diff():
    a = load_run("before", runs_dir=PAIR_DIR)
    b = load_run("after", runs_dir=PAIR_DIR)
    return compute_diff(a, b).to_dict()


def test_drift_golden_matches():
    got = _diff()
    expected = json.loads(GOLDEN.read_text())
    # Compare canonically (sorted keys) so ordering is not spuriously flagged.
    assert json.dumps(got, sort_keys=True) == json.dumps(expected, sort_keys=True), (
        "drift engine output diverged from the committed golden — review the "
        "diff and, if intended, regenerate fixtures/golden/drift-demo.json"
    )


def test_drift_pair_covers_every_type_and_tier():
    d = _diff()
    changes = d["changes"]

    def has(tier, entity_type):
        return any(c["tier"] == tier and c["entity_type"] == entity_type for c in changes)

    # removed: a device, a link (and the interface + finding that go with them)
    assert has("removed", "devices")
    assert has("removed", "links")
    # added: a link, an interface, a route (OSPF LSA), and an ACL (finding)
    assert has("added", "links")
    assert has("added", "interfaces")
    assert has("added", "ospf_lsdb")  # added route
    assert has("added", "findings")  # added/modified ACL
    # changed: interface up->down, a VLAN (shared service), an l2 domain
    assert has("changed", "interfaces")
    assert has("changed", "shared_services")  # changed VLAN
    assert has("changed", "l2_domains")
    # info: all four semi-volatile signal families land in info, not drift
    info_fields = {
        f["field"]
        for c in changes
        if c["tier"] == "info"
        for f in c.get("changed_fields", [])
    }
    assert "prefixes_received" in info_fields
    assert "arp_count" in info_fields
    assert "dhcp_leases" in info_fields
    assert any(f.startswith("up_down") for f in info_fields)  # session flap/uptime


def test_drift_interface_up_to_down_is_the_changed_interface():
    d = _diff()
    changed_ifaces = [c for c in d["changes"] if c["tier"] == "changed" and c["entity_type"] == "interfaces"]
    assert changed_ifaces, "expected an up->down interface change"
    fields = {f["field"] for c in changed_ifaces for f in c["changed_fields"]}
    assert "oper_status" in fields


def test_golden_is_deterministic():
    # Two independent diffs of the pair are byte-identical.
    a = json.dumps(_diff(), sort_keys=True)
    b = json.dumps(_diff(), sort_keys=True)
    assert a == b
