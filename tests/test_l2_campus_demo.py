"""End-to-end L2 teaching demo: the committed demo/l2-campus run.

A synthetic switched campus built from the demo switches that exercises BOTH
L2-domain behaviours in one run:
  - acc-sw-03 + core-sw-01 are trunk-connected and BOTH claim STP root for
    VLAN 10 at the same priority -> a real same-domain conflict that FIRES
    (true positive: the domain-gated rule still catches genuine conflicts).
  - acc-sw-01 is isolated (only L3 to the rest) but also has VLAN 10 -> a
    separate broadcast domain, the same VLAN id -> NOT flagged (the false
    positive the ID-based grouping used to raise).

The run is built in tmp_path so the committed fixture stays pristine
(build_model writes a model/ dir).
"""

import shutil
from pathlib import Path

import pytest

from netcopilot.model import build_model
from netcopilot.rules.engine import run_rules

CAMPUS = Path(__file__).resolve().parent.parent / "demo" / "l2-campus"


@pytest.fixture
def campus_base(tmp_path):
    dst = tmp_path / "l2-campus"
    shutil.copytree(CAMPUS / "facts", dst / "facts")
    shutil.copy(CAMPUS / "manifest.json", dst / "manifest.json")
    return str(tmp_path)


def test_vlan10_splits_into_two_domains(campus_base):
    model = build_model("l2-campus", runs_base=campus_base)
    v10 = sorted(
        sorted(d["member_devices"]) for d in model["l2_domains"] if d["vlan_id"] == 10
    )
    # the isolated switch is its own domain; the trunked pair is another
    assert v10 == [["acc-sw-01"], ["acc-sw-03", "core-sw-01"]]


def test_same_domain_dual_root_fires_but_cross_domain_does_not(campus_base):
    build_model("l2-campus", runs_base=campus_base)
    result = run_rules("l2-campus", runs_base=campus_base)
    stp = [f for f in result["findings"] if f["rule_id"] == "STP_ROOT_BRIDGE_CONFLICT"]

    # Exactly one conflict — the same-domain dual-root.
    assert len(stp) == 1
    kf = stp[0]["evidence"]["key_facts"]
    assert kf["vlan_id"] == "10"
    assert sorted(kf["devices"]) == ["acc-sw-03", "core-sw-01"]

    # The isolated acc-sw-01 shares the VLAN id but a different domain -> never
    # flagged. This is the false positive the feature removed.
    assert "acc-sw-01" not in kf["devices"]
