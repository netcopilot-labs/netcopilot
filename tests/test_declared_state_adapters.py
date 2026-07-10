"""S11-1: declared-state adapters — contract, factory, write gate, YAML source.

The NetBox adapter's pynetbox surface is mocked (unit level; the gated
integration tests against a real demo NetBox live in the compose-profile
story). RFC 5737 IPs, synthetic names.
"""

import sys
import types

import pytest

from netcopilot.declared_state import (
    DeclaredStateSource,
    ImproperlyConfigured,
    WritesDisabled,
    YAMLInventoryAdapter,
    get_source,
    require_write_enabled,
    write_enabled,
)

INVENTORY = """\
devices:
  - name: acc-sw-01
    mgmt_ip: 192.0.2.11
    os: ios-xe
    role: access_switch
    site: demo
  - name: edge-fw-01
    mgmt_ip: 192.0.2.1
    os: fortios
    role: firewall
    site: demo
"""


@pytest.fixture()
def inv_path(tmp_path):
    p = tmp_path / "lab.yaml"
    p.write_text(INVENTORY)
    return p


# ── write gate (Constitution Art. I) ─────────────────────────────────────────

def test_write_gate_defaults_off(monkeypatch):
    monkeypatch.delenv("NETBOX_WRITE_ENABLED", raising=False)
    assert write_enabled() is False
    with pytest.raises(WritesDisabled):
        require_write_enabled("test write")


def test_write_gate_explicit_optin(monkeypatch):
    monkeypatch.setenv("NETBOX_WRITE_ENABLED", "true")
    assert write_enabled() is True
    require_write_enabled("test write")  # no raise


def test_write_gate_rejects_non_true_values(monkeypatch):
    for v in ("1", "yes", "TRUE ", "on"):  # only the literal "true" opts in
        monkeypatch.setenv("NETBOX_WRITE_ENABLED", v)
        if v.strip().lower() == "true" and v == v.strip():
            continue
        assert write_enabled() is False


# ── YAML adapter ─────────────────────────────────────────────────────────────

def test_yaml_adapter_contract(inv_path):
    a = YAMLInventoryAdapter(inventory_path=inv_path)
    assert isinstance(a, DeclaredStateSource)
    devices = a.get_devices()
    assert [d["name"] for d in devices] == ["acc-sw-01", "edge-fw-01"]
    assert a.get_device("edge-fw-01")["mgmt_ip"] == "192.0.2.1"
    assert a.get_device("nope") is None
    assert a.get_sites() == [{"slug": "demo", "name": "demo"}]
    assert a.get_interfaces("acc-sw-01") == []   # YAML declares no interfaces


def test_yaml_adapter_missing_file_raises(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        YAMLInventoryAdapter(inventory_path=tmp_path / "absent.yaml")


# ── factory ──────────────────────────────────────────────────────────────────

def test_factory_yaml(inv_path):
    a = get_source("yaml", inventory_path=inv_path)
    assert isinstance(a, YAMLInventoryAdapter)


def test_factory_unknown_name():
    with pytest.raises(ValueError, match="Unknown declared-state source"):
        get_source("servicenow")


# ── NetBox adapter (pynetbox mocked) ─────────────────────────────────────────

def _install_fake_pynetbox(monkeypatch, devices=()):
    """Install a minimal fake pynetbox module; returns the fake api object."""
    class Rec:
        def __init__(self, **kw):
            self.__dict__.update(kw)
        def __str__(self):
            return str(getattr(self, "name", ""))

    class Endpoint:
        def __init__(self, items):
            self._items = list(items)
        def all(self):
            return list(self._items)
        def get(self, **kw):
            for it in self._items:
                if all(str(getattr(it, k, None)) == str(v) for k, v in kw.items()):
                    return it
            return None
        def filter(self, **kw):
            return [it for it in self._items
                    if all(str(getattr(it, k, None)) == str(v) for k, v in kw.items())]

    api = types.SimpleNamespace()
    api.http_session = types.SimpleNamespace(verify=None, timeout=None)
    api.dcim = types.SimpleNamespace(
        devices=Endpoint([Rec(id=1, name="acc-sw-01", primary_ip4=Rec(name="192.0.2.11/24"),
                              role=Rec(name="access_switch", slug="access-switch"),
                              platform=Rec(name="iosxe", slug="cisco-ios-xe"),
                              site=Rec(name="demo", slug="demo"),
                              status=Rec(name="active", value="active"),
                              config_context={"netcopilot": {"ssh_only": True}})] + list(devices)),
        sites=Endpoint([Rec(id=1, slug="demo", name="demo")]),
        interfaces=Endpoint([Rec(id=7, name="Gi1/0/1", device=Rec(name="acc-sw-01"),
                                 enabled=True, type=Rec(name="1000base-t"),
                                 mtu=1500, mac_address="00:00:5E:00:53:01")]),
    )
    api.virtualization = types.SimpleNamespace(clusters=Endpoint([]))

    fake = types.ModuleType("pynetbox")
    fake.api = lambda url, token=None: api
    monkeypatch.setitem(sys.modules, "pynetbox", fake)
    return api


def test_netbox_adapter_requires_config(monkeypatch):
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_API_TOKEN", raising=False)
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    with pytest.raises(ImproperlyConfigured, match="NETBOX_URL"):
        NetBoxAdapter()


def test_netbox_adapter_reads(monkeypatch):
    _install_fake_pynetbox(monkeypatch)
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    a = NetBoxAdapter(url="https://netbox.example.test", token="nbt_x.y")
    devs = a.get_devices()
    assert devs[0]["name"] == "acc-sw-01"
    assert devs[0]["mgmt_ip"] == "192.0.2.11"    # /24 stripped
    assert devs[0]["role"] == "access_switch"
    # s15 slug/value forms for the inventory source
    assert devs[0]["platform_slug"] == "cisco-ios-xe"
    assert devs[0]["role_slug"] == "access-switch"
    assert devs[0]["site_slug"] == "demo"
    assert devs[0]["status_value"] == "active"
    assert devs[0]["virtual_chassis"] is None and devs[0]["cluster"] is None
    assert devs[0]["config_context"] == {"netcopilot": {"ssh_only": True}}
    # server-side site scoping (fake filter compares str(site) == value)
    assert [d["name"] for d in a.get_devices(site="demo")] == ["acc-sw-01"]
    assert a.get_devices(site="other") == []
    assert a.get_device("nope") is None
    assert a.get_sites()[0]["slug"] == "demo"
    ifaces = a.get_interfaces("acc-sw-01")
    assert ifaces[0]["name"] == "Gi1/0/1" and ifaces[0]["mtu"] == 1500


def test_netbox_adapter_ip_addresses_carry_operator_meaning(monkeypatch):
    # s16: dns_name/description/tenant/assigned-object travel; bare-minimum
    # records (no enrichment) degrade to None fields, never KeyError.
    api = _install_fake_pynetbox(monkeypatch)
    class Rec:
        def __init__(self, **kw): self.__dict__.update(kw)
        def __str__(self): return str(getattr(self, "name", ""))
    rich = Rec(id=9, address="198.51.100.26/28", dns_name="cam-lobby-01.branch.example",
               description="Lobby camera", status=Rec(name="active", value="active"),
               role=None, tenant=Rec(name="facilities"), tags=[Rec(name="cctv", slug="cctv")],
               vrf=None,
               assigned_object=Rec(name="Vlan10", device=Rec(name="acc-sw-03")))
    bare = Rec(id=10, address="198.51.100.27/28")
    class EP:
        def all(self): return [rich, bare]
    api.ipam = types.SimpleNamespace(ip_addresses=EP())
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    a = NetBoxAdapter(url="https://netbox.example.test", token="nbt_x.y")
    ips = a.get_ip_addresses()
    r = ips[0]
    assert r["address"] == "198.51.100.26/28" and r["netbox_id"] == 9
    assert r["dns_name"] == "cam-lobby-01.branch.example"
    assert r["description"] == "Lobby camera"
    assert r["status_value"] == "active" and r["tenant"] == "facilities"
    assert r["tags"] == ["cctv"]
    assert r["assigned_device"] == "acc-sw-03" and r["assigned_interface"] == "Vlan10"
    b = ips[1]
    assert b["address"] == "198.51.100.27/28"
    assert b["dns_name"] is None and b["assigned_device"] is None and b["tags"] == []


def test_netbox_adapter_prefixes_site_scope_mapping(monkeypatch):
    # s19: NetBox 4.2 generic `scope` accepted only when scope_type is a SITE;
    # a Region/SiteGroup scope must NOT masquerade as a site. Legacy 3.x
    # direct `site` still honored. Unscoped → site None.
    api = _install_fake_pynetbox(monkeypatch)
    class Rec:
        def __init__(self, **kw): self.__dict__.update(kw)
        def __str__(self): return str(getattr(self, "name", ""))
    base = dict(status=Rec(name="active", value="active"), role=None,
                vrf=None, description=None, tags=[])
    scoped_site = Rec(id=1, prefix="198.51.100.0/28",
                      scope=Rec(slug="branch-a"), scope_type="dcim.site", **base)
    scoped_region = Rec(id=2, prefix="198.51.100.16/28",
                        scope=Rec(slug="emea"), scope_type="dcim.region", **base)
    legacy_site = Rec(id=3, prefix="198.51.100.32/28",
                      site=Rec(slug="branch-b"), **base)
    unscoped = Rec(id=4, prefix="198.51.100.48/28", **base)
    class EP:
        def all(self): return [scoped_site, scoped_region, legacy_site, unscoped]
    api.ipam = types.SimpleNamespace(prefixes=EP())
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    a = NetBoxAdapter(url="https://netbox.example.test", token="nbt_x.y")
    sites = {p["netbox_id"]: p["site"] for p in a.get_prefixes()}
    assert sites == {1: "branch-a", 2: None, 3: "branch-b", 4: None}


def test_netbox_adapter_strict_reads_raise_default_swallows(monkeypatch):
    # Audit A1/A2: the default read path degrades to [] (dedup-hint
    # consumers); strict=True re-raises so correctness consumers (the service
    # join) can refuse to wipe on a mid-pull failure.
    api = _install_fake_pynetbox(monkeypatch)
    class BoomEP:
        def all(self): raise TimeoutError("page 2 timed out")
    api.ipam = types.SimpleNamespace(ip_addresses=BoomEP(), prefixes=BoomEP())
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    a = NetBoxAdapter(url="https://netbox.example.test", token="nbt_x.y")
    assert a.get_ip_addresses() == []
    assert a.get_prefixes() == []
    with pytest.raises(TimeoutError):
        a.get_ip_addresses(strict=True)
    with pytest.raises(TimeoutError):
        a.get_prefixes(strict=True)


def test_ensure_infrastructure_is_write_gated(monkeypatch):
    # Empty NetBox + writes disabled → the first create attempt raises
    # WritesDisabled BEFORE any API call (Constitution Art. I).
    api = _install_fake_pynetbox(monkeypatch)
    api.virtualization.cluster_types = api.virtualization.clusters  # empty endpoint
    monkeypatch.delenv("NETBOX_WRITE_ENABLED", raising=False)
    from netcopilot.declared_state.netbox_adapter import NetBoxAdapter
    a = NetBoxAdapter(url="https://netbox.example.test", token="nbt_x.y")
    with pytest.raises(WritesDisabled):
        a.ensure_infrastructure()
