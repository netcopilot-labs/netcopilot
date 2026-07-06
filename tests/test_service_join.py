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
    def __init__(self, ips, ping_exc=None):
        self._ips = ips
        self._ping_exc = ping_exc

    def ping(self):
        if self._ping_exc:
            raise self._ping_exc

    def get_ip_addresses(self):
        return list(self._ips)


class FakeSession:
    """Routes the join's queries by substring to canned rows; records writes."""

    def __init__(self, *, infra=(), subnets=(), uplinks=(), arp=None, mac=None):
        self.infra = list(infra)          # rows: {device, interface, ip}
        self.subnets = list(subnets)      # rows: {device, interface, ip} (cidr)
        self.uplinks = list(uplinks)      # rows: {a, ai, b, bi}
        self.arp = arp or {}              # ip → rows {device, interface, mac}
        self.mac = mac or {}              # mac → rows {device, interface, vlan}
        self.writes: list[tuple[str, dict]] = []

    def run(self, query, **params):
        q = " ".join(query.split())
        if "DETACH DELETE" in q or "CREATE (s:Service)" in q or "REACHED_VIA" in q:
            self.writes.append((q, params))
            return []
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
