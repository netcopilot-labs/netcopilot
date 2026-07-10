"""S19-1/5/6: read-only VMware (vCenter / ESXi) adapter. pyvmomi faked.

``_extract`` consumes flat property maps (pure dicts) — fakes are trivial.
``_fetch_inventory`` is driven end-to-end against a FAKE pyvmomi module
injected into ``sys.modules``: the test records every call made to the
"wire" and asserts the surface is retrieval-only (the read-only invariant),
that the session is always disconnected, and that continuation pages are
followed. Host identity is a generic ``node-N`` label — no real FQDN.
"""

import json
import sys
import types
from types import SimpleNamespace

import pytest

from netcopilot.collect import EsxiAdapter, applicable_strategies
from netcopilot.collect.esxi import (
    HOST_PROPS,
    VM_PROPS,
    EsxiUnavailable,
    _extract,
    _is_routable_ip,
)

DEVICE = {"name": "synth-vc-01", "mgmt_ip": "203.0.113.5", "os": "vcenter"}


def _nic(mac, ips=()):
    return SimpleNamespace(macAddress=mac, ipAddress=list(ips))


def _host_row(name, moid, *, status="green", cpu=None, mem=None, cores=16,
              hz=2_000_000_000, mem_bytes=None, version="8.0.2", vms=()):
    return {
        "moId": moid, "name": name,
        "summary.overallStatus": status,
        "summary.quickStats.overallCpuUsage": cpu,
        "summary.quickStats.overallMemoryUsage": mem,
        "summary.config.product.version": version,
        "hardware.cpuInfo.hz": hz,
        "hardware.cpuInfo.numCpuCores": cores,
        "hardware.memorySize": mem_bytes,
        "vm": list(vms),
    }


def _vm_row(name, power, host_moid, *, guest_nics=(), hw_macs=(), guest_os=None,
            tools=None, cpu=None, mem=None, health=None):
    return {
        "moId": f"vm-{name}",
        "summary.config.name": name,
        "summary.config.guestFullName": guest_os,
        "summary.runtime.powerState": power,
        "summary.overallStatus": health,
        "summary.quickStats.overallCpuUsage": cpu,
        "summary.quickStats.guestMemoryUsage": mem,
        "runtime.host": host_moid,
        "guest.net": list(guest_nics),
        "guest.toolsStatus": tools,
        "config.hardware.device": [SimpleNamespace(macAddress=m) for m in hw_macs]
        + [SimpleNamespace(label="disk-0")],   # non-NIC device ignored
    }


# ── selection ────────────────────────────────────────────────────────────

def test_supports_esxi_and_vcenter():
    a = EsxiAdapter()
    assert a.supports({"os": "esxi"}) is True
    assert a.supports({"os": "vcenter"}) is True
    assert a.supports({"os": "ios-xe"}) is False
    assert [s.name for s in applicable_strategies(DEVICE)] == ["esxi"]


# ── extraction (pure, flat property maps) ────────────────────────────────

def test_extract_vm_enriched_fields():
    nic = _nic("00:50:56:AA:BB:CC", ["203.0.113.10", "fe80::1", "169.254.1.2"])
    vm = _vm_row("SYNTH-APP-01", "poweredOn", "host-1", guest_nics=[nic],
                 hw_macs=["00:50:56:aa:bb:cc"], guest_os="Ubuntu Linux (64-bit)",
                 tools="toolsOk", cpu=371, mem=12400, health="green")
    _, (out,) = _extract([_host_row("esxi-a.example", "host-1")], [vm], None)
    assert out["name"] == "SYNTH-APP-01"
    assert out["power_state"] == "poweredOn"
    assert out["host"] == "node-1"               # generic label, not the FQDN
    assert out["macs"] == ["00:50:56:aa:bb:cc"]  # lowercased + deduped
    assert out["ips"] == ["203.0.113.10"]        # link-local dropped
    assert out["guest_os"] == "Ubuntu Linux (64-bit)"
    assert out["tools_status"] == "toolsOk"
    assert out["cpu_mhz"] == 371 and out["mem_mb"] == 12400
    assert out["health"] == "green"


def test_extract_host_fields_generic_label():
    row = _host_row("esxi-a.example", "host-1", status="green", cpu=500, mem=8000,
                    cores=16, hz=2_000_000_000, mem_bytes=64 * 1024 * 1024 * 1024,
                    version="8.0.2", vms=[object(), object()])
    (h,), _ = _extract([row], [], None)
    assert h["name"] == "node-1"                 # never the real FQDN
    assert h["health"] == "green"
    assert h["cpu_mhz"] == 500 and h["mem_mb"] == 8000
    assert h["cpu_capacity_mhz"] == 2000 * 16    # hz→MHz × cores
    assert h["mem_capacity_mb"] == 64 * 1024
    assert h["version"] == "8.0.2" and h["vm_count"] == 2


def test_extract_generic_labels_by_sorted_name():
    # Two hosts → node-1/node-2 by SORTED real name; a VM on the 2nd maps to it.
    h1 = _host_row("esxi-zeta.example", "host-Z")
    h2 = _host_row("esxi-alpha.example", "host-A")   # sorts first → node-1
    vm = _vm_row("SYNTH-DB", "poweredOn", "host-Z")  # on zeta → node-2
    hosts, (out,) = _extract([h1, h2], [vm], None)
    assert {h["name"] for h in hosts} == {"node-1", "node-2"}
    assert out["host"] == "node-2"


def test_extract_standalone_single_label():
    # A standalone host keeps the operator's inventory name.
    hosts, vms = _extract([_host_row("esxi-a.example", "host-1")],
                          [_vm_row("SYNTH-01", "poweredOn", "host-1")],
                          "esxi-node-1")
    assert hosts[0]["name"] == "esxi-node-1" and vms[0]["host"] == "esxi-node-1"


def test_extract_toolsless_mac_bridge():
    vm = _vm_row("SYNTH-DB-01", "poweredOn", "host-1", guest_nics=[],
                 hw_macs=["00:0C:29:11:22:33"])
    _, (out,) = _extract([_host_row("h", "host-1")], [vm], None)
    assert out["ips"] == []
    assert out["macs"] == ["00:0c:29:11:22:33"]


def test_extract_transient_vm_skipped_not_fatal():
    # Mid-clone VM: summary.config not yet populated → that ROW is skipped,
    # the rest of the endpoint survives (audit A4).
    good = _vm_row("SYNTH-OK", "poweredOn", "host-1")
    transient = {"moId": "vm-x", "runtime.host": "host-1"}   # no config name
    _, vms = _extract([_host_row("h", "host-1")], [transient, good], None)
    assert [v["name"] for v in vms] == ["SYNTH-OK"]


def test_extract_orphan_vm_maps_to_unknown():
    # Mid-vMotion: runtime.host missing → honest "unknown", never a guess.
    vm = _vm_row("SYNTH-MOVING", "poweredOn", None)
    vm.pop("runtime.host")
    _, (out,) = _extract([_host_row("h", "host-1")], [vm], None)
    assert out["host"] == "unknown"


def test_extract_output_sorted_by_vm_name():
    rows = [_vm_row("SYNTH-B", "poweredOn", "h1"), _vm_row("SYNTH-A", "poweredOn", "h1")]
    _, vms = _extract([_host_row("h", "h1")], rows, None)
    assert [v["name"] for v in vms] == ["SYNTH-A", "SYNTH-B"]


def test_is_routable_ip():
    assert _is_routable_ip("203.0.113.10") is True
    assert _is_routable_ip("") is False
    assert _is_routable_ip("169.254.9.9") is False
    assert _is_routable_ip("fe80::1") is False


# ── _fetch_inventory against a FAKE pyvmomi (the wire surface) ─────────────

class _FakeVim:
    class HostSystem:
        def __init__(self, moid): self._moId = moid

    class VirtualMachine:
        def __init__(self, moid): self._moId = moid


def _install_fake_pyvmomi(monkeypatch, *, pages):
    """Inject fake pyVim/pyVmomi into sys.modules; record every wire call.

    ``pages`` is a list of result pages; each page is a list of
    (managed_obj, {prop: val}) pairs. Returns the recorder dict.
    """
    rec = {"calls": [], "disconnected": False, "view_destroyed": False}

    class _Result:
        def __init__(self, objs, token):
            self.objects = [
                SimpleNamespace(obj=o, propSet=[SimpleNamespace(name=k, val=v)
                                                for k, v in props.items()])
                for o, props in objs
            ]
            self.token = token

    class _PC:
        def RetrievePropertiesEx(self, specs, opts):
            rec["calls"].append("RetrievePropertiesEx")
            rec["filter_specs"] = specs
            return _Result(pages[0], token="t1" if len(pages) > 1 else None)

        def ContinueRetrievePropertiesEx(self, token):
            rec["calls"].append("ContinueRetrievePropertiesEx")
            return _Result(pages[1], token=None)

    class _View:
        view = []

        def Destroy(self):
            rec["view_destroyed"] = True

    content = SimpleNamespace(
        rootFolder=object(),
        viewManager=SimpleNamespace(
            CreateContainerView=lambda root, types_, rec_: _View()),
        propertyCollector=_PC(),
    )
    si = SimpleNamespace(RetrieveContent=lambda: content)

    def smart_connect(**kw):
        rec["calls"].append("SmartConnect")
        rec["connect_kwargs"] = kw
        return si

    def disconnect(s):
        rec["disconnected"] = True

    qs = SimpleNamespace(
        TraversalSpec=lambda **kw: SimpleNamespace(**kw),
        ObjectSpec=lambda **kw: SimpleNamespace(**kw),
        PropertySpec=lambda **kw: SimpleNamespace(**kw),
        FilterSpec=lambda **kw: SimpleNamespace(**kw),
        RetrieveOptions=lambda: SimpleNamespace(),
    )
    fake_pyvim = types.ModuleType("pyVim")
    fake_connect = types.ModuleType("pyVim.connect")
    fake_connect.SmartConnect = smart_connect
    fake_connect.Disconnect = disconnect
    fake_pyvim.connect = fake_connect
    fake_pyvmomi = types.ModuleType("pyVmomi")
    fake_pyvmomi.vim = _FakeVim
    fake_pyvmomi.vmodl = SimpleNamespace(query=SimpleNamespace(PropertyCollector=qs))
    monkeypatch.setitem(sys.modules, "pyVim", fake_pyvim)
    monkeypatch.setitem(sys.modules, "pyVim.connect", fake_connect)
    monkeypatch.setitem(sys.modules, "pyVmomi", fake_pyvmomi)
    return rec


def test_fetch_inventory_is_retrieval_only_and_always_disconnects(monkeypatch):
    host_obj = _FakeVim.HostSystem("host-1")
    vm_obj = _FakeVim.VirtualMachine("vm-1")
    rec = _install_fake_pyvmomi(monkeypatch, pages=[
        [(host_obj, {"name": "esxi-a.example"}),
         (vm_obj, {"summary.config.name": "SYNTH-01",
                   "runtime.host": SimpleNamespace(_moId="host-1")})],
    ])
    host_rows, vm_rows = EsxiAdapter()._fetch_inventory("203.0.113.5", "u", "p")

    # The complete wire surface — retrieval only, nothing else ever called.
    assert rec["calls"] == ["SmartConnect", "RetrievePropertiesEx"]
    assert rec["view_destroyed"] is True         # session-side view cleanup
    assert rec["disconnected"] is True           # Disconnect in finally
    # Bounded connect: a hung endpoint fails the device, not the run.
    assert rec["connect_kwargs"]["httpConnectionTimeout"] > 0
    # Rows landed in the right buckets; moref flattened to its id.
    assert host_rows == [{"moId": "host-1", "name": "esxi-a.example"}]
    assert vm_rows == [{"moId": "vm-1", "summary.config.name": "SYNTH-01",
                        "runtime.host": "host-1"}]
    # The batch asks for every documented property path.
    specs = rec["filter_specs"][0].propSet
    assert specs[0].pathSet == HOST_PROPS and specs[1].pathSet == VM_PROPS


def test_fetch_inventory_follows_continuation_pages(monkeypatch):
    h = _FakeVim.HostSystem("host-1")
    v1, v2 = _FakeVim.VirtualMachine("vm-1"), _FakeVim.VirtualMachine("vm-2")
    rec = _install_fake_pyvmomi(monkeypatch, pages=[
        [(h, {"name": "a"}), (v1, {"summary.config.name": "SYNTH-1"})],
        [(v2, {"summary.config.name": "SYNTH-2"})],
    ])
    host_rows, vm_rows = EsxiAdapter()._fetch_inventory("203.0.113.5", "u", "p")
    assert rec["calls"] == ["SmartConnect", "RetrievePropertiesEx",
                            "ContinueRetrievePropertiesEx"]
    assert len(host_rows) == 1 and len(vm_rows) == 2
    assert rec["disconnected"] is True


def test_fetch_inventory_without_pyvmomi_raises_esxi_unavailable(monkeypatch):
    for mod in ("pyVim", "pyVim.connect", "pyVmomi"):
        monkeypatch.setitem(sys.modules, mod, None)   # import → ImportError
    with pytest.raises(EsxiUnavailable, match=r"\.\[esxi\]"):
        EsxiAdapter()._fetch_inventory("203.0.113.5", "u", "p")


# ── collect() wiring (fetch monkeypatched — no connection) ─────────────────

def test_missing_credentials_fails_clearly(monkeypatch, tmp_path):
    monkeypatch.delenv("ESXi_USERNAME", raising=False)
    monkeypatch.delenv("ESXi_PASSWORD", raising=False)
    res = EsxiAdapter().collect({"name": "esxi-1", "mgmt_ip": "203.0.113.5", "os": "esxi"},
                                [], str(tmp_path), {})
    assert res.success is False
    assert "credentials not set" in res.error


def test_collect_writes_both_facts_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ESXi_USERNAME", "ro-user")
    monkeypatch.setenv("ESXi_PASSWORD", "ro-pass")
    a = EsxiAdapter()
    monkeypatch.setattr(a, "_fetch_inventory", lambda ip, u, p: (
        [_host_row("esxi-a.example", "host-1", vms=[object()])],
        [_vm_row("SYNTH-APP-01", "poweredOn", "host-1",
                 guest_nics=[_nic("00:50:56:aa:bb:cc", ["203.0.113.10"])])],
    ))

    raw = tmp_path / "raw"
    raw.mkdir()
    res = a.collect(DEVICE, [], str(raw), {})

    assert res.success is True
    vfile = tmp_path / "facts" / "synth-vc-01" / "esxi_vms.json"
    hfile = tmp_path / "facts" / "synth-vc-01" / "esxi_hosts.json"
    vms = json.loads(vfile.read_text())
    hosts = json.loads(hfile.read_text())
    assert vms[0]["name"] == "SYNTH-APP-01" and vms[0]["host"] == "node-1"
    assert hosts[0]["name"] == "node-1" and hosts[0]["vm_count"] == 1
    assert str(vfile) in res.files_created and str(hfile) in res.files_created


def test_per_device_username_used(monkeypatch, tmp_path):
    # vCenter uses its SSO user (per-device), not the env user.
    monkeypatch.setenv("ESXi_USERNAME", "node-root")
    monkeypatch.setenv("ESXi_PASSWORD", "ro-pass")
    seen = {}
    a = EsxiAdapter()

    def _capture(ip, user, pwd):
        seen["user"] = user
        return ([], [])

    monkeypatch.setattr(a, "_fetch_inventory", _capture)
    dev = {**DEVICE, "username": "administrator@vsphere.example"}
    a.collect(dev, [], str(tmp_path), {})
    assert seen["user"] == "administrator@vsphere.example"


def test_pyvmomi_missing_surfaces_via_collect(monkeypatch, tmp_path):
    monkeypatch.setenv("ESXi_USERNAME", "u")
    monkeypatch.setenv("ESXi_PASSWORD", "p")
    a = EsxiAdapter()

    def _unavailable(*_a):
        raise EsxiUnavailable("install the extra: pip install -e '.[esxi]'")

    monkeypatch.setattr(a, "_fetch_inventory", _unavailable)
    res = a.collect(DEVICE, [], str(tmp_path), {})
    assert res.success is False and "esxi" in res.error.lower()


def test_connection_error_captured_not_raised(monkeypatch, tmp_path):
    monkeypatch.setenv("ESXi_USERNAME", "u")
    monkeypatch.setenv("ESXi_PASSWORD", "p")
    a = EsxiAdapter()

    def _boom(*_a):
        raise OSError("host 203.0.113.5 unreachable")

    monkeypatch.setattr(a, "_fetch_inventory", _boom)
    res = a.collect(DEVICE, [], str(tmp_path), {})
    assert res.success is False and "unreachable" in res.error
