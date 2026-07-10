"""S16-3: the service join — NetBox-named IPs × observed ARP/FDB → :Service.

Fake adapter + fake session (queries routed by substring); no Neo4j, no
NetBox. RFC 5737 IPs, synthetic names.
"""

import pytest

from netcopilot.declared_state.services import (
    ServiceSourceUnavailable,
    run_service_join,
)

SITE, RUN = "demo", "r1"


def _ip(address, dns=None, desc=None, status="active", **kw):
    return {"address": address, "netbox_id": 1, "dns_name": dns,
            "description": desc, "status_value": status, "role": None,
            "tenant": kw.get("tenant"), "tags": kw.get("tags") or [],
            "vrf": kw.get("vrf"), "assigned_device": None,
            "assigned_interface": None}


class FakeAdapter:
    def __init__(self, ips, ping_exc=None, prefixes=()):
        self._ips = ips
        self._ping_exc = ping_exc
        self._prefixes = list(prefixes)

    def ping(self):
        if self._ping_exc:
            raise self._ping_exc

    def get_ip_addresses(self, *, strict=False):
        return list(self._ips)

    def get_prefixes(self, *, strict=False):
        return list(self._prefixes)


def _pfx(cidr, desc=None, tags=("client-network",), status="active", **kw):
    return {"prefix": cidr, "vrf": kw.get("vrf"), "netbox_id": 9,
            "description": desc, "status_value": status, "role": None,
            "tags": list(tags)}


class FakeSession:
    """Routes the join's queries by substring to canned rows; records writes."""

    def __init__(self, *, infra=(), subnets=(), uplinks=(), arp=None, mac=None, roles=None):
        self.infra = list(infra)          # rows: {device, interface, ip}
        self.subnets = list(subnets)      # rows: {device, interface, ip} (cidr)
        self.uplinks = list(uplinks)      # rows: {a, ai, b, bi}
        self.arp = arp or {}              # ip → rows {device, interface, mac}
        self.mac = mac or {}              # mac → rows {device, interface, vlan}
        self.roles = roles or {}          # device → role
        self.writes: list[tuple[str, dict]] = []

    def run(self, query, **params):
        q = " ".join(query.split())
        if "DETACH DELETE" in q or "CREATE (s:Service)" in q or "REACHED_VIA" in q:
            self.writes.append((q, params))
            return []
        if "d.role AS role" in q:
            return [{"name": k, "role": v} for k, v in self.roles.items()]
        if "l.local_interface IS NOT NULL" in q:
            return list(self.uplinks)
        if ":ArpEntry" in q:
            return list(self.arp.get(params["ip"], []))
        if ":MacEntry" in q:
            return list(self.mac.get(params["mac"], []))
        if "prefix_length" in q:
            return list(self.subnets)
        if "i.ip IS NOT NULL" in q:
            return list(self.infra)
        raise AssertionError(f"unrouted query: {q}")


class FakeDriver:
    def __init__(self, session):
        self._s = session

    def session(self):
        s = self._s

        class _Ctx:
            def __enter__(self):
                return s

            def __exit__(self, *a):
                return False
        return _Ctx()


def _join(adapter, session):
    return run_service_join(RUN, adapter=adapter, driver=FakeDriver(session), site=SITE)


# ── location ladder ──────────────────────────────────────────────────────────

def test_arp_tier_locates_on_the_resolving_device():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01")])
    session = FakeSession(arp={"198.51.100.26": [
        {"device": "acc-sw-03", "interface": "Vlan10", "mac": "12:34:56:78:9a:bc"}]})
    report = _join(adapter, session)
    svc = report.services[0]
    assert svc["located"] is True and svc["location_method"] == "arp"
    assert svc["device"] == "acc-sw-03" and svc["mac"] == "12:34:56:78:9a:bc"
    assert any("RESIDES_ON" in q for q, _ in session.writes)


def test_arp_fdb_tier_refines_to_the_edge_port():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01")])
    session = FakeSession(
        arp={"198.51.100.26": [
            {"device": "core-sw-01", "interface": "Vl10", "mac": "12:34:56:78:9a:bc"}]},
        mac={"12:34:56:78:9a:bc": [
            {"device": "core-sw-01", "interface": "Gi1/0/24", "vlan": "10"},
            {"device": "acc-sw-03", "interface": "Gi1/0/5", "vlan": "10"},
            {"device": "acc-sw-03", "interface": "Vl10", "vlan": "10"}]},
        uplinks=[{"a": "core-sw-01", "ai": "Gi1/0/24",
                  "b": "acc-sw-03", "bi": "Gi1/0/48"}],
    )
    report = _join(adapter, session)
    svc = report.services[0]
    # core's sighting is an uplink; acc's SVI is skipped → ONE edge port
    assert svc["location_method"] == "arp+fdb"
    assert svc["device"] == "acc-sw-03" and svc["interface"] == "Gi1/0/5"
    assert any("REACHED_VIA" in q for q, _ in session.writes)


def test_fdb_multiple_edge_ports_stays_at_arp():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01")])
    session = FakeSession(
        arp={"198.51.100.26": [
            {"device": "acc-sw-03", "interface": "Vlan10", "mac": "aa:aa:aa:aa:aa:01"}]},
        mac={"aa:aa:aa:aa:aa:01": [
            {"device": "acc-sw-03", "interface": "Gi1/0/5", "vlan": "10"},
            {"device": "acc-sw-04", "interface": "Gi1/0/9", "vlan": "10"}]},
    )
    svc = _join(adapter, session).services[0]
    assert svc["location_method"] == "arp" and svc["device"] == "acc-sw-03"


def test_subnet_tier_most_specific_gateway():
    adapter = FakeAdapter([_ip("198.51.100.30/28", desc="printer floor 2")])
    session = FakeSession(subnets=[
        {"device": "core-sw-01", "interface": "Vlan1", "ip": "198.51.100.1",
         "prefix_length": 24},
        {"device": "acc-sw-03", "interface": "Vlan10", "ip": "198.51.100.17",
         "prefix_length": 28}])
    svc = _join(adapter, session).services[0]
    assert svc["location_method"] == "subnet"
    assert svc["device"] == "acc-sw-03"                  # /28 beats /24


def test_unlocated_service_is_first_class():
    adapter = FakeAdapter([_ip("203.0.113.99/32", dns="ghost-svc")])
    session = FakeSession()
    report = _join(adapter, session)
    svc = report.services[0]
    assert svc["located"] is False and svc["location_method"] == "none"
    assert svc["device"] is None
    # persisted as a standalone node (CREATE without RESIDES_ON)
    assert any("CREATE (s:Service)" in q and "RESIDES_ON" not in q
               for q, _ in session.writes)


# ── filters + exclusions ─────────────────────────────────────────────────────

def test_infrastructure_ips_excluded_with_note():
    adapter = FakeAdapter([_ip("192.0.2.41/24", dns="acc-sw-01.mgmt")])
    session = FakeSession(infra=[
        {"device": "acc-sw-01", "interface": "GigabitEthernet0/0", "ip": "192.0.2.41/24"}])
    report = _join(adapter, session)
    assert report.services == []
    assert len(report.skipped_infrastructure) == 1
    assert "acc-sw-01/GigabitEthernet0/0" in report.skipped_infrastructure[0]


def test_unnamed_and_inactive_ips_are_not_candidates():
    adapter = FakeAdapter([
        _ip("198.51.100.5/28"),                            # no name → not a service
        _ip("198.51.100.6/28", dns="old-host", status="deprecated"),
    ])
    report = _join(adapter, FakeSession())
    assert report.services == []


def test_declared_metadata_travels():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01",
                               desc="Lobby camera", tenant="facilities",
                               tags=["cctv"], vrf="TENANT-VRF")])
    svc = _join(adapter, FakeSession()).services[0]
    assert svc["name"] == "cam-lobby-01"                   # dns_name preferred
    assert svc["description"] == "Lobby camera"
    assert svc["tenant"] == "facilities" and svc["tags"] == ["cctv"]
    assert svc["vrf"] == "TENANT-VRF"


# ── honesty ──────────────────────────────────────────────────────────────────

def test_netbox_down_raises_never_empty():
    adapter = FakeAdapter([], ping_exc=ConnectionError("refused"))
    with pytest.raises(ServiceSourceUnavailable, match="unknown, not empty"):
        _join(adapter, FakeSession())


def test_unloaded_run_raises_with_guidance(monkeypatch):
    from netcopilot.declared_state import services as svc_mod
    monkeypatch.setattr(svc_mod, "get_site_for_run", lambda run_id: None)
    with pytest.raises(ValueError, match="not loaded"):
        run_service_join(RUN, adapter=FakeAdapter([]), driver=FakeDriver(FakeSession()))


def test_rerun_deletes_before_reload():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01")])
    session = FakeSession(arp={"198.51.100.26": [
        {"device": "acc-sw-03", "interface": "Vlan10", "mac": "aa:aa:aa:aa:aa:01"}]})
    _join(adapter, session)
    assert "DETACH DELETE" in session.writes[0][0]         # our rows first, only ours
    assert ":Service {site: $site, run_id: $run_id}" in session.writes[0][0]


# ── s17: client networks (kind=network) located at their gateway ─────────────

def test_client_network_locates_at_exact_gateway_svi():
    adapter = FakeAdapter([], prefixes=[
        _pfx("198.51.100.128/26", desc="Acme Corp — client network")])
    session = FakeSession(subnets=[
        {"device": "prov-edge-01", "interface": "Vl302", "ip": "198.51.100.129",
         "prefix_length": 26}])
    report = _join(adapter, session)
    svc = report.services[0]
    assert svc["kind"] == "network" and svc["located"] is True
    assert svc["location_method"] == "gateway"
    assert svc["ip"] == "198.51.100.128/26"          # the CIDR is the key
    assert svc["name"] == "Acme Corp — client network"
    assert svc["device"] == "prov-edge-01" and svc["gateways"] == ["prov-edge-01/Vl302"]
    assert any("RESIDES_ON" in q for q, _ in session.writes)
    assert any("REACHED_VIA" in q for q, _ in session.writes)


def test_client_network_multi_gateway_attaches_all():
    adapter = FakeAdapter([], prefixes=[_pfx("198.51.100.128/26", desc="Acme")])
    session = FakeSession(subnets=[
        {"device": "gw-b", "interface": "Vl302", "ip": "198.51.100.130", "prefix_length": 26},
        {"device": "gw-a", "interface": "Vl302", "ip": "198.51.100.129", "prefix_length": 26}])
    svc = _join(adapter, session).services[0]
    assert svc["gateways"] == ["gw-a/Vl302", "gw-b/Vl302"]   # all + deterministic
    attach = next(p for q, p in session.writes if "RESIDES_ON" in q)
    assert {r["device"] for r in attach["rows"]} == {"gw-a", "gw-b"}


def test_client_network_containing_fallback_is_labeled():
    # Operator declared an aggregate /24; the gateway SVI serves a /26 inside it.
    adapter = FakeAdapter([], prefixes=[_pfx("198.51.100.0/24", desc="Acme agg")])
    session = FakeSession(subnets=[
        {"device": "prov-edge-01", "interface": "Vl302", "ip": "198.51.100.129",
         "prefix_length": 26}])
    svc = _join(adapter, session).services[0]
    assert svc["location_method"] == "gateway-containing"     # approximate, said aloud
    assert svc["device"] == "prov-edge-01"


def test_client_network_without_gateway_is_unlocated_honest():
    adapter = FakeAdapter([], prefixes=[_pfx("203.0.113.0/28", desc="Ghost client")])
    svc = _join(adapter, FakeSession()).services[0]
    assert svc["kind"] == "network" and svc["located"] is False
    assert svc["location_method"] == "none"


def test_untagged_and_inactive_prefixes_stay_out():
    adapter = FakeAdapter([], prefixes=[
        _pfx("198.51.100.0/30", desc="infra p2p", tags=()),              # no tag
        _pfx("198.51.100.4/30", desc="old client", status="deprecated"),  # inactive
    ])
    assert _join(adapter, FakeSession()).services == []


def test_host_rows_are_stamped_kind_host():
    adapter = FakeAdapter([_ip("198.51.100.26/28", dns="cam-lobby-01")])
    svc = _join(adapter, FakeSession()).services[0]
    assert svc["kind"] == "host"


# ── s17 fix: role-aware host attachment (switch owns the VLAN, not the gw) ────

def test_switch_beats_gateway_that_only_routes():
    # A firewall ARPs the host (it IS the VLAN gateway); the services switch
    # owns the same VLAN subnet. The host hangs on the SWITCH.
    adapter = FakeAdapter([_ip("198.51.100.50/24", dns="server-a")])
    session = FakeSession(
        arp={"198.51.100.50": [
            {"device": "fw-01", "interface": "vlan200", "mac": "aa:aa:aa:aa:aa:aa"}]},
        subnets=[
            {"device": "svc-sw-01", "interface": "Vl200", "ip": "198.51.100.254", "prefix_length": 24},
            {"device": "fw-01", "interface": "vlan200", "ip": "198.51.100.1", "prefix_length": 24}],
        roles={"fw-01": "firewall", "svc-sw-01": "services_switch"},
    )
    svc = _join(adapter, session).services[0]
    assert svc["device"] == "svc-sw-01"          # switch, not the routing firewall
    assert svc["location_method"] == "subnet"


def test_arp_fdb_on_switch_still_wins_over_a_gateway_arp():
    # Even role-first, an exact switch edge port (arp+fdb) is the best answer.
    adapter = FakeAdapter([_ip("198.51.100.51/24", dns="server-b")])
    session = FakeSession(
        arp={"198.51.100.51": [
            {"device": "fw-01", "interface": "vlan200", "mac": "bb:bb:bb:bb:bb:bb"}]},
        mac={"bb:bb:bb:bb:bb:bb": [
            {"device": "acc-sw-02", "interface": "Gi1/0/7", "vlan": "200"}]},
        roles={"fw-01": "firewall", "acc-sw-02": "access_switch"},
    )
    svc = _join(adapter, session).services[0]
    assert svc["location_method"] == "arp+fdb"
    assert svc["device"] == "acc-sw-02" and svc["interface"] == "Gi1/0/7"


def test_gateway_only_host_still_locates_on_the_gateway():
    # No switch owns the subnet → the firewall is the honest, only answer.
    adapter = FakeAdapter([_ip("198.51.100.60/24", dns="dmz-host")])
    session = FakeSession(
        arp={"198.51.100.60": [
            {"device": "fw-01", "interface": "dmz", "mac": "cc:cc:cc:cc:cc:cc"}]},
        roles={"fw-01": "firewall"},
    )
    svc = _join(adapter, session).services[0]
    assert svc["located"] is True and svc["device"] == "fw-01"


# ── s17 fix: deterministic VLAN co-location ──────────────────────────────────

def test_unobserved_host_colocates_with_its_vlan_neighbour():
    # vcenter is observed on the services switch; host-b (same /24, never seen)
    # has NO switch SVI — only the firewall's gateway SVI. It must follow its
    # VLAN neighbour onto the switch, not sit on the firewall.
    adapter = FakeAdapter([
        _ip("198.51.100.10/24", dns="vcenter"),
        _ip("198.51.100.11/24", dns="host-b")])
    session = FakeSession(
        arp={"198.51.100.10": [
            {"device": "svc-sw-01", "interface": "Vl210", "mac": "aa:aa:aa:aa:aa:10"}]},
        mac={"aa:aa:aa:aa:aa:10": [
            {"device": "svc-sw-01", "interface": "Gi1/0/3", "vlan": "210"}]},
        # only the firewall has an L3 interface in this subnet (no switch SVI)
        subnets=[{"device": "fw-01", "interface": "vlan210", "ip": "198.51.100.1",
                  "prefix_length": 24}],
        roles={"svc-sw-01": "services_switch", "fw-01": "firewall"},
    )
    svcs = {s["name"]: s for s in _join(adapter, session).services}
    assert svcs["vcenter"]["location_method"] == "arp+fdb"
    assert svcs["vcenter"]["device"] == "svc-sw-01"
    # host-b: firewall was its only subnet owner → co-located to the switch
    assert svcs["host-b"]["device"] == "svc-sw-01"
    assert svcs["host-b"]["location_method"] == "colocated"


def test_gateway_only_vlan_stays_on_gateway_when_no_neighbour_observed():
    # No host of the VLAN was ever seen on a switch → nothing to co-locate to;
    # the firewall is the honest, only answer.
    adapter = FakeAdapter([_ip("198.51.100.20/24", dns="lonely")])
    session = FakeSession(
        subnets=[{"device": "fw-01", "interface": "vlan99", "ip": "198.51.100.1",
                  "prefix_length": 24}],
        roles={"fw-01": "firewall"},
    )
    svc = _join(adapter, session).services[0]
    assert svc["device"] == "fw-01" and svc["location_method"] == "subnet"


# ── s19: deterministic virtualization from the ESXi compute layer ────────────

def test_esxi_ip_match_stamps_virtualized_even_when_unlocated(monkeypatch):
    # The money case: an idle VM the network never saw (no ARP → unlocated) is
    # still classified virtual, because ESXi reports its guest IP directly.
    monkeypatch.setattr(
        "netcopilot.declared_state.services._esxi_vms",
        lambda rid: [{"name": "SYNTH-APP-01", "power_state": "poweredOn",
                      "host": "esxi-node-1", "macs": ["00:50:56:00:00:01"],
                      "ips": ["198.51.100.50"]}])
    adapter = FakeAdapter([_ip("198.51.100.50/24", dns="app-01")])
    svc = _join(adapter, FakeSession()).services[0]
    assert svc["located"] is False           # the network never saw it
    assert svc["virtualized"] is True         # ESXi did
    assert svc["host"] == "esxi-node-1"
    assert svc["vm_name"] == "SYNTH-APP-01"


def test_esxi_mac_bridge_when_tools_absent(monkeypatch):
    # Tools-less VM: ESXi reports no guest IP, only the vNIC MAC. The service's
    # observed ARP MAC matches it (case-insensitively) → virtual via the bridge.
    monkeypatch.setattr(
        "netcopilot.declared_state.services._esxi_vms",
        lambda rid: [{"name": "SYNTH-DB-01", "power_state": "poweredOn",
                      "host": "esxi-node-2", "macs": ["00:0c:29:ab:cd:ef"], "ips": []}])
    adapter = FakeAdapter([_ip("198.51.100.60/24", dns="db-01")])
    session = FakeSession(arp={"198.51.100.60": [
        {"device": "acc-sw", "interface": "Vlan200", "mac": "00:0C:29:AB:CD:EF"}]})
    svc = _join(adapter, session).services[0]
    assert svc["located"] is True and svc["mac"] == "00:0C:29:AB:CD:EF"
    assert svc["virtualized"] is True and svc["host"] == "esxi-node-2"


def test_bare_metal_not_in_esxi_inventory_not_virtualized(monkeypatch):
    # A DNA/appliance IP absent from every VM inventory is never virtualized —
    # no collision is possible (bare-metal is not in ESXi).
    monkeypatch.setattr(
        "netcopilot.declared_state.services._esxi_vms",
        lambda rid: [{"name": "SYNTH-APP-01", "host": "esxi-node-1",
                      "macs": ["00:50:56:00:00:01"], "ips": ["198.51.100.50"]}])
    adapter = FakeAdapter([_ip("198.51.100.20/24", dns="dnac1")])
    session = FakeSession(arp={"198.51.100.20": [
        {"device": "svc-sw", "interface": "Vlan200", "mac": "3c:fd:fe:00:00:01"}]})
    svc = _join(adapter, session).services[0]
    assert "virtualized" not in svc


def test_no_esxi_layer_leaves_virtualization_unknown():
    # Default (no ESXi facts for the run) → nothing is stamped virtual, even a
    # host the network saw. Honest 'unknown', never a bare-metal guess.
    adapter = FakeAdapter([_ip("198.51.100.11/24", dns="splunk")])
    session = FakeSession(arp={"198.51.100.11": [
        {"device": "svc-sw", "interface": "Vlan200", "mac": "00:50:56:00:00:02"}]})
    svc = _join(adapter, session).services[0]
    assert svc["located"] is True
    assert "virtualized" not in svc


def test_midpull_ip_failure_raises_and_never_deletes():
    # Audit A1: ping() succeeds, then the IP pull dies mid-pagination. The
    # join must raise ServiceSourceUnavailable and MUST NOT touch the graph —
    # a masked [] here used to DELETE the previous service layer and report
    # it as honestly empty.
    class MidPullAdapter(FakeAdapter):
        def get_ip_addresses(self, *, strict=False):
            raise TimeoutError("page 2 of ip_addresses timed out")

    session = FakeSession()
    with pytest.raises(ServiceSourceUnavailable, match="unknown, not empty"):
        _join(MidPullAdapter([]), session)
    assert session.writes == []          # no DETACH DELETE, nothing persisted


def test_midpull_prefix_failure_raises_and_never_deletes():
    # Audit A2: a failed prefix pull must fail loud — degrading to [] would
    # silently disable site scoping (cross-site mixing) and drop every
    # client network.
    class MidPullAdapter(FakeAdapter):
        def get_prefixes(self, *, strict=False):
            raise ConnectionError("prefixes endpoint reset")

    session = FakeSession()
    with pytest.raises(ServiceSourceUnavailable, match="unknown, not empty"):
        _join(MidPullAdapter([_ip("198.51.100.50/24", dns="app-01")]), session)
    assert session.writes == []


def test_truly_empty_netbox_is_a_trustworthy_empty_layer():
    # Contrast with the mid-pull cases: a SUCCESSFUL pull with zero named IPs
    # is a legitimate empty layer — stale rows from a previous join are
    # deleted (delete-then-reload), nothing new written.
    session = FakeSession()
    report = _join(FakeAdapter([]), session)
    assert report.services == []
    assert any("DETACH DELETE" in q for q, _ in session.writes)


def test_ip_of_another_site_is_skipped_not_mixed():
    # s19: one NetBox, several sites. An IP inside a prefix scoped to ANOTHER
    # site must not appear in this run's lens (the "mixing sites" bug).
    adapter = FakeAdapter(
        [_ip("198.51.100.26/28", dns="other-site-cam"),
         _ip("203.0.113.50/32", dns="unscoped-svc")],
        prefixes=[{"prefix": "198.51.100.0/24", "vrf": None, "netbox_id": 5,
                   "description": None, "status_value": "active", "role": None,
                   "tags": [], "site": "branch-b"}])
    report = _join(adapter, FakeSession())
    names = [s["name"] for s in report.services]
    assert "other-site-cam" not in names            # scoped to branch-b → skipped
    assert "unscoped-svc" in names                  # no scoped prefix → joins (honest)
    assert any("branch-b" in line for line in report.skipped_other_site)


def test_ip_of_this_site_joins_and_most_specific_prefix_wins():
    # Nested scopes: /24 → other site, /28 → THIS site. Longest match decides.
    adapter = FakeAdapter(
        [_ip("198.51.100.26/28", dns="cam-lobby-01")],
        prefixes=[
            {"prefix": "198.51.100.0/24", "vrf": None, "netbox_id": 5,
             "description": None, "status_value": "active", "role": None,
             "tags": [], "site": "branch-b"},
            {"prefix": "198.51.100.16/28", "vrf": None, "netbox_id": 6,
             "description": None, "status_value": "active", "role": None,
             "tags": [], "site": SITE},
        ])
    report = _join(adapter, FakeSession())
    assert [s["name"] for s in report.services] == ["cam-lobby-01"]
    assert report.skipped_other_site == []


def test_client_network_of_another_site_is_skipped():
    adapter = FakeAdapter(
        [],
        prefixes=[
            {**_pfx("198.51.100.0/27", desc="their clients"), "site": "branch-b"},
            {**_pfx("198.51.100.32/27", desc="our clients"), "site": SITE},
        ])
    report = _join(adapter, FakeSession())
    names = [s["name"] for s in report.services]
    assert "our clients" in names and "their clients" not in names
    assert any("branch-b" in line for line in report.skipped_other_site)


def test_esxi_readers_from_disk_single_endpoint(monkeypatch, tmp_path):
    # The real file-reading path (not monkeypatched): one endpoint → labels
    # pass through untouched.
    import json
    from netcopilot.declared_state.services import _esxi_hosts, _esxi_vms
    d = tmp_path / "r9" / "facts" / "synth-vc-01"
    d.mkdir(parents=True)
    (d / "esxi_vms.json").write_text(json.dumps(
        [{"name": "SYNTH-01", "host": "node-1", "macs": [], "ips": ["198.51.100.9"]}]))
    (d / "esxi_hosts.json").write_text(json.dumps(
        [{"name": "node-1", "health": "green", "vm_count": 1}]))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    assert _esxi_vms("r9")[0]["host"] == "node-1"
    assert _esxi_hosts("r9")[0]["name"] == "node-1"
    assert _esxi_vms("missing-run") == [] and _esxi_hosts("missing-run") == []


def test_esxi_readers_namespace_labels_across_two_endpoints(monkeypatch, tmp_path):
    # Two VMware endpoints in one run: node-N is only unique per endpoint —
    # readers namespace labels so host-health can never cross endpoints.
    import json
    from netcopilot.declared_state.services import _esxi_hosts, _esxi_vms
    for ep in ("vc-a", "vc-b"):
        d = tmp_path / "r9" / "facts" / ep
        d.mkdir(parents=True)
        (d / "esxi_vms.json").write_text(json.dumps(
            [{"name": f"SYNTH-{ep}", "host": "node-1", "macs": [], "ips": []}]))
        (d / "esxi_hosts.json").write_text(json.dumps(
            [{"name": "node-1", "health": "green"}]))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    vms = {v["name"]: v["host"] for v in _esxi_vms("r9")}
    assert vms == {"SYNTH-vc-a": "vc-a:node-1", "SYNTH-vc-b": "vc-b:node-1"}
    assert sorted(h["name"] for h in _esxi_hosts("r9")) == ["vc-a:node-1", "vc-b:node-1"]


def test_demo_esxi_fixture_reads_through_the_real_path(monkeypatch):
    # S19-4: the shipped demo carries a recorded VMware fixture — prove the
    # REAL disk-reader path consumes it (not a mock), so the feature is
    # demonstrable offline.
    from pathlib import Path
    from netcopilot.declared_state.services import _esxi_hosts, _esxi_vms
    repo_demo = Path(__file__).resolve().parents[1] / "demo"
    monkeypatch.setenv("RUNS_DIR", str(repo_demo))
    vms = _esxi_vms("campus")
    hosts = _esxi_hosts("campus")
    assert {h["name"] for h in hosts} == {"node-1", "node-2"}
    assert all(v["name"].startswith("SYNTH-") for v in vms)
    assert any(v["ips"] for v in vms)            # IP-match path exercisable
    assert any(not v["ips"] and v["macs"] for v in vms)   # MAC-bridge path too


def test_esxi_health_and_host_stamped(monkeypatch):
    # s19-6: a matched VM carries its own health/info + its node's health.
    monkeypatch.setattr(
        "netcopilot.declared_state.services._esxi_vms",
        lambda rid: [{"name": "SYNTH-APP-01", "power_state": "poweredOn", "host": "node-1",
                      "macs": [], "ips": ["198.51.100.50"], "guest_os": "Ubuntu Linux (64-bit)",
                      "tools_status": "toolsOk", "cpu_mhz": 371, "mem_mb": 12400, "health": "green"}])
    monkeypatch.setattr(
        "netcopilot.declared_state.services._esxi_hosts",
        lambda rid: [{"name": "node-1", "health": "green", "cpu_mhz": 500,
                      "cpu_capacity_mhz": 32000, "mem_mb": 40000, "mem_capacity_mb": 64000,
                      "vm_count": 6, "version": "8.0.2"}])
    adapter = FakeAdapter([_ip("198.51.100.50/24", dns="app-01")])
    svc = _join(adapter, FakeSession()).services[0]
    assert svc["virtualized"] is True and svc["host"] == "node-1"
    assert svc["guest_os"] == "Ubuntu Linux (64-bit)" and svc["tools_status"] == "toolsOk"
    assert svc["vm_cpu_mhz"] == 371 and svc["vm_mem_mb"] == 12400 and svc["vm_health"] == "green"
    assert svc["host_health"] == "green" and svc["host_vm_count"] == 6
    assert svc["host_cpu_capacity_mhz"] == 32000 and svc["host_version"] == "8.0.2"
