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

    def get_ip_addresses(self):
        return list(self._ips)

    def get_prefixes(self):
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
        self.port_macs = {}               # (device, interface) → [mac]  (s18)
        self.descriptions = {}            # (device, interface) → desc   (s18)
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
        if "DISTINCT m.mac AS mac" in q:   # s18: _port_endpoint_macs
            macs = self.port_macs.get((params["device"], params["interface"]), [])
            return [{"mac": m} for m in macs]
        if "i.description AS description" in q:   # s18: _interface_descriptions
            return [{"device": d, "interface": i, "description": v}
                    for (d, i), v in self.descriptions.items()]
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


# ── s18: deterministic virtualization host detection ─────────────────────────

def test_hypervisor_oui_and_multiendpoint_detection():
    from netcopilot.declared_state.services import _hypervisor_for
    assert _hypervisor_for(["00:50:56:aa:bb:cc"]) == "VMware"
    assert _hypervisor_for(["52:54:00:11:22:33"]) == "KVM/QEMU"
    assert _hypervisor_for(["3c:fd:fe:00:00:01"]) is None   # bare-metal NIC


def test_vms_group_by_server_across_ports(monkeypatch):
    # Two VMs on DIFFERENT ports of the SAME server (per description) group into
    # one node; endpoint count sums across the server's ports.
    adapter = FakeAdapter([
        _ip("198.51.100.10/24", dns="vcenter"),
        _ip("198.51.100.11/24", dns="splunk")])
    session = FakeSession(
        arp={"198.51.100.10": [{"device": "svc-sw", "interface": "Vl200", "mac": "00:50:56:00:00:01"}],
             "198.51.100.11": [{"device": "svc-sw", "interface": "Vl200", "mac": "00:0c:29:00:00:02"}]},
        mac={"00:50:56:00:00:01": [{"device": "svc-sw", "interface": "Te1/1/5", "vlan": "200"}],
             "00:0c:29:00:00:02": [{"device": "svc-sw", "interface": "Te1/1/6", "vlan": "200"}]},
        roles={"svc-sw": "services_switch"},
    )
    session.port_macs = {("svc-sw", "Te1/1/5"): ["00:50:56:00:00:01", "00:50:56:00:00:aa"],
                         ("svc-sw", "Te1/1/6"): ["00:0c:29:00:00:02", "00:0c:29:00:00:bb"]}
    monkeypatch.setattr("netcopilot.declared_state.services._interface_descriptions",
                        lambda rid: {("svc-sw", "Te1/1/5"): "Link to SYNTH-SRV-ESX-01",
                                     ("svc-sw", "Te1/1/6"): "Link to SYNTH-SRV-ESX-01"})
    svcs = {s["name"]: s for s in _join(adapter, session).services}
    for name in ("vcenter", "splunk"):
        assert svcs[name]["server"] == "SYNTH-SRV-ESX-01"   # SAME node, both ports
        assert svcs[name]["hypervisor"] == "VMware"
        assert svcs[name]["server_endpoint_count"] == 4      # 2 ports x 2 MACs


def test_bare_metal_single_mac_port_not_stamped(monkeypatch):
    adapter = FakeAdapter([_ip("198.51.100.20/24", dns="dnac1")])
    session = FakeSession(
        arp={"198.51.100.20": [{"device": "svc-sw", "interface": "Vl200", "mac": "3c:fd:fe:00:00:01"}]},
        mac={"3c:fd:fe:00:00:01": [{"device": "svc-sw", "interface": "Te1/1/1", "vlan": "200"}]},
        roles={"svc-sw": "services_switch"},
    )
    session.port_macs = {("svc-sw", "Te1/1/1"): ["3c:fd:fe:00:00:01"]}   # one MAC
    monkeypatch.setattr("netcopilot.declared_state.services._interface_descriptions",
                        lambda rid: {("svc-sw", "Te1/1/1"): "SYNTH-SRV-APP-01 (Enterprise port)"})
    svc = _join(adapter, session).services[0]
    assert "server" not in svc and svc["location_method"] == "arp+fdb"
