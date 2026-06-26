"""VLAN cross-device rules under L2-domain awareness (L2-c).

- VLAN_CONSISTENCY is scoped to the real broadcast domain (l2_domains), so a
  router that merely shares a VLAN's subnet (not in the domain) is never flagged.
- VLAN_NATIVE_MISMATCH and VLAN_ALLOWED_MISMATCH are link-local by construction
  (they compare the two ends of one trunk) — domain-awareness is a no-op; these
  tests pin that they fire purely on a single link.
"""

from netcopilot.rules.cross_device.interface_rules import (
    _check_vlan_allowed,
    _check_vlan_consistency,
    _check_vlan_native,
)


def _facts_with_vlans(*vids):
    return {"genie_vlan": {"vlans": {str(v): {"name": f"V{v}"} for v in vids}}}


# --- VLAN_CONSISTENCY (domain-scoped) --------------------------------------

def test_consistency_fires_for_domain_member_missing_vlan():
    # Both switches are in VLAN 10's broadcast domain; sw-b's DB lacks VLAN 10.
    facts = {
        "sw-a": _facts_with_vlans(10, 20),
        "sw-b": _facts_with_vlans(20),          # missing 10
    }
    domains = [{"vlan_id": 10, "name": "USERS", "id": "vlan10-dom0",
                "member_devices": ["sw-a", "sw-b"]}]
    findings = _check_vlan_consistency(facts, domains)
    assert len(findings) == 1
    assert findings[0].evidence["key_facts"]["missing_from"] == ["sw-b"]


def test_consistency_ignores_device_outside_the_domain():
    # A router shares VLAN 30's subnet but is NOT in the broadcast domain
    # (l2_domains has only the two switches). It must never be flagged, even
    # though its DB lacks VLAN 30.
    facts = {
        "sw-a": _facts_with_vlans(30),
        "sw-b": _facts_with_vlans(30),
        "rtr-1": _facts_with_vlans(999),        # no VLAN 30, but not in domain
    }
    domains = [{"vlan_id": 30, "name": "X", "id": "vlan30-dom0",
                "member_devices": ["sw-a", "sw-b"]}]
    assert _check_vlan_consistency(facts, domains) == []


def test_consistency_singleton_domain_is_silent():
    facts = {"sw-a": _facts_with_vlans(40)}
    domains = [{"vlan_id": 40, "name": "X", "id": "vlan40-dom0",
                "member_devices": ["sw-a"]}]
    assert _check_vlan_consistency(facts, domains) == []


def test_consistency_legacy_shared_services_fallback():
    # No l2_domains -> legacy shared_services membership keeps working.
    facts = {"sw-a": _facts_with_vlans(10), "sw-b": _facts_with_vlans(20)}
    shared = [{"service_type": "vlan", "identifier": "10", "name": "USERS",
               "members": ["sw-a", "sw-b"]}]
    findings = _check_vlan_consistency(facts, None, shared)
    assert len(findings) == 1
    assert findings[0].evidence["key_facts"]["missing_from"] == ["sw-b"]


# --- VLAN_NATIVE_MISMATCH / VLAN_ALLOWED_MISMATCH (link-local) --------------

def test_native_mismatch_is_link_local():
    # Fires on a single trunk link's two ends — no l2_domains involved.
    findings = _check_vlan_native(
        "sw-a", "Gi0/1", {"native_vlan": 1},
        "sw-b", "Gi0/1", {"native_vlan": 99}, "sw-a:Gi0/1__sw-b:Gi0/1",
    )
    assert len(findings) == 1 and findings[0].rule_id == "VLAN_NATIVE_MISMATCH"


def test_native_match_is_silent():
    assert _check_vlan_native(
        "sw-a", "Gi0/1", {"native_vlan": 1},
        "sw-b", "Gi0/1", {"native_vlan": 1}, "eid",
    ) == []


def test_allowed_mismatch_is_link_local():
    # ifa/ifb are raw genie_interface dicts (trunk_vlans is a range string).
    findings = _check_vlan_allowed(
        "sw-a", "Gi0/1", {"trunk_vlans": "10,20"},
        "sw-b", "Gi0/1", {"trunk_vlans": "10,30"}, "eid",
    )
    assert len(findings) == 1 and findings[0].rule_id == "VLAN_ALLOWED_MISMATCH"
