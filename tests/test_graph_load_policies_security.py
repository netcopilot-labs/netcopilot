"""F2-6-d: route-policy/prefix-set, security-config, and VRF loaders (fake driver).

Reads facts (parsed_route_policy/prefix_list from config_parser, security_config,
genie_vrf). RFC 5737 IPs. Real Cypher covered by the gated live test.
"""

import json

from netcopilot.graph.loader import (
    _build_vrf_members,
    _flatten_security_section,
    _load_route_policies_and_prefix_sets,
    _load_security_configs,
    _load_vrfs,
)
from test_graph_load_model import FakeDriver

SITE, RUN = "dc", "r1"


def _facts(tmp_path, device):
    d = tmp_path / "run" / "facts" / device
    d.mkdir(parents=True)
    return d


def test_flatten_security_section():
    flat = _flatten_security_section("ssh", {"version": 2, "timeout": 60, "_skip": "x", "none": None})
    assert flat == {"ssh_version": 2, "ssh_timeout": 60}  # _ and None dropped, nested skipped


def test_load_route_policies_and_prefix_sets(tmp_path):
    d = _facts(tmp_path, "core-rtr-01")
    (d / "parsed_route_policy.json").write_text(json.dumps({
        "SET-LOCALPREF": {"sequences": [
            {"seq": 10, "action": "permit", "match": ["ip address prefix-list LOCAL"],
             "set": ["local-preference 150"]}]}}))
    (d / "parsed_prefix_list.json").write_text(json.dumps({
        "LOCAL": {"entries": [{"seq": 10, "action": "permit", "prefix": "192.0.2.0/24"}]}}))

    driver = FakeDriver()
    rp, pse = _load_route_policies_and_prefix_sets(driver, tmp_path / "run", SITE, RUN)
    assert rp == 1 and pse == 1
    rp_params = next(p["rps"] for c, p in driver.calls if "[:HAS_ROUTE_POLICY]" in c)
    assert rp_params[0]["name"] == "SET-LOCALPREF"
    assert any("local-preference 150" in line for line in rp_params[0]["body"])
    pse_params = next(p["ents"] for c, p in driver.calls if "[:HAS_PREFIX_ENTRY]" in c)
    assert pse_params[0]["name"] == "LOCAL" and pse_params[0]["prefix"] == "192.0.2.0/24"


def test_load_security_configs(tmp_path):
    d = _facts(tmp_path, "core-rtr-01")
    (d / "security_config.json").write_text(json.dumps({
        "ssh": {"version": 2, "timeout": 60},
        "snmp": {"communities": [{"name": "TESTCOMM-RO", "mode": "RO"}]},
        "_parser_coverage": {"sections_parsed": 2},  # internal — skipped
    }))
    driver = FakeDriver()
    n = _load_security_configs(driver, tmp_path / "run", SITE, RUN)
    assert n == 1
    cfg = next(p["configs"] for c, p in driver.calls if "[:HAS_SECURITY_CONFIG]" in c)[0]
    assert cfg["config_source"] == "cisco"
    assert cfg["ssh_version"] == 2 and cfg["ssh_timeout"] == 60
    assert "_parser_coverage" not in cfg  # internal field dropped


def test_load_vrfs_as_shared_services(tmp_path):
    d = _facts(tmp_path, "core-rtr-01")
    (d / "genie_vrf.json").write_text(json.dumps({"vrfs": {"MGMT": {}, "__hidden": {}}}))
    (d / "genie_routing.json").write_text(json.dumps({"vrf": {}}))  # marks device as Cisco → 'default'
    driver = FakeDriver()
    n = _load_vrfs(driver, tmp_path / "run", SITE, RUN)
    assert n == 2  # MGMT + default ('__hidden' platform VRF skipped)
    svc = next(p["services"] for c, p in driver.calls if "(svc:SharedService)" in c)
    names = {s["identifier"] for s in svc}
    assert names == {"MGMT", "default"}
    assert all(s["service_type"] == "vrf" for s in svc)


def test_build_vrf_members_unions_interface_vrf(tmp_path):
    """R2-VRF-1: genie_vrf.json is empty for IOS-XR, so an XR VRF must come from
    interface.vrf (running-config). Membership unions genie_vrf ∪ interface.vrf ∪
    default(RIB-present), skips platform '__' VRFs, and routes 'default' through
    the RIB rule (not doubled from interfaces)."""
    xr = _facts(tmp_path, "bdr-rtr-01")  # XR: empty genie_vrf, VRF lives on the interface
    (xr / "genie_vrf.json").write_text(json.dumps({"vrfs": {}}))
    (xr / "genie_routing.json").write_text(json.dumps({"vrf": {}}))
    sw = _facts(tmp_path, "core-sw-01")  # XE: genie_vrf has RED; interface adds BLUE
    (sw / "genie_vrf.json").write_text(json.dumps({"vrfs": {"RED": {}}}))
    (sw / "genie_routing.json").write_text(json.dumps({"vrf": {}}))
    interfaces = [
        {"device_id": "bdr-rtr-01", "name": "Mgmt0", "vrf": "clab-mgmt"},
        {"device_id": "core-sw-01", "name": "Vlan10", "vrf": "RED"},
        {"device_id": "core-sw-01", "name": "Vlan20", "vrf": "BLUE"},
        {"device_id": "core-sw-01", "name": "Gi0/0", "vrf": "default"},   # → RIB rule, not doubled
        {"device_id": "core-sw-01", "name": "Gi0/1", "vrf": "__internal"},  # platform → skipped
    ]
    m = _build_vrf_members(tmp_path / "run", interfaces)
    assert m["clab-mgmt"] == {"bdr-rtr-01"}                 # interface.vrf (genie empty for XR)
    assert m["RED"] == {"core-sw-01"}                       # genie ∪ interface
    assert m["BLUE"] == {"core-sw-01"}                      # interface-only
    assert m["default"] == {"bdr-rtr-01", "core-sw-01"}     # RIB presence
    assert "__internal" not in m                            # platform VRF skipped


def test_loaders_no_facts_return_zero(tmp_path):
    assert _load_route_policies_and_prefix_sets(FakeDriver(), tmp_path / "x", SITE, RUN) == (0, 0)
    assert _load_security_configs(FakeDriver(), tmp_path / "x", SITE, RUN) == 0
    assert _load_vrfs(FakeDriver(), tmp_path / "x", SITE, RUN) == 0
