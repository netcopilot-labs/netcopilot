"""Read-only VMware (vCenter / standalone ESXi) inventory collection.

Reads the virtual-machine and host inventory over the vSphere Web Services API
(``/sdk``) via ``pyvmomi``. One endpoint, two modes, same code:

* ``os: vcenter`` — one connection returns **every** host and VM in the
  cluster, with the authoritative VM→host placement. The complete story.
* ``os: esxi`` — a standalone host returns its own VMs (no vCenter needed).

For each VM: name, power state, the host it runs on, vNIC MACs, guest IPs
(VMware Tools), plus health/quickStats (guest OS, tools status, CPU/mem,
overall status). For each host: overall health, CPU/mem usage vs capacity,
version, VM count. This is the *deterministic* source for whether a service
IP is virtualised — the network alone cannot see an idle VM.

**Batched retrieval.** All properties are fetched in a single
``PropertyCollector.RetrievePropertiesEx`` call (plus continuation pages) —
one round-trip for the whole inventory. The naive per-attribute access is a
SOAP round-trip *per property per object*; at ~20 properties × N VMs it took
minutes for even a small cluster.

**Leak discipline.** Host identity is emitted as a **generic** label
(``node-1``, ``node-2``, … deterministic by sorted real host name) — the real
ESXi FQDN never enters the fact file, graph, panel, or a commit. The label is
stable only *within* a collection: renaming or adding a host shifts the sort,
so ``node-2`` in one run and ``node-2`` in another are not comparable. VM
names come from the guest and are the operator's own data.

**Read-only.** The only vSphere calls are session setup, view creation, and
property *retrieval* — never a power/reconfigure/migrate/destroy method.
:func:`_extract` consumes plain property maps and is structurally incapable
of a wire call; :mod:`tests.test_collect_esxi` drives
:meth:`EsxiAdapter._fetch_inventory` against a fake pyvmomi and asserts no
managed-object method is ever invoked.

**Opt-in.** ``pyvmomi`` is the ``[esxi]`` extra, imported lazily inside
:meth:`EsxiAdapter._fetch_inventory`, so the chain and the test suite load on
a plain install; an ``os: esxi``/``vcenter`` device then collects with a
clear "install .[esxi]" error instead of a silent absence.

Guest-IP caveat, handled honestly: guest IPs exist only when VMware Tools
runs in the guest. A VM without Tools still exposes its vNIC MAC(s) — the
service join bridges those MACs to an IP through the observed ARP table.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from netcopilot.collect.base import CollectionResult, CollectionStrategy, expand_env_ref

logger = logging.getLogger(__name__)

#: Inventory os-families this adapter collects (a vCenter or a standalone host).
SUPPORTED_OS_FAMILIES = {"esxi", "vcenter"}

#: Environment variables holding the read-only credentials (kept out of the
#: inventory file). A per-device ``username``/``password`` (literal or
#: ``${ENV}``) overrides them — a vCenter uses a different user
#: (e.g. ``administrator@vsphere.example``) than the hosts, same password.
USERNAME_ENV_VAR = "ESXi_USERNAME"
PASSWORD_ENV_VAR = "ESXi_PASSWORD"

#: Canonical output filenames written under ``facts/<endpoint>/``.
VMS_FILENAME = "esxi_vms.json"
HOSTS_FILENAME = "esxi_hosts.json"

#: Seconds before an unreachable/hung endpoint fails the connection — a
#: black-holed management IP must fail the device, not hang the run's
#: worker thread indefinitely.
CONNECT_TIMEOUT = 30

#: Batched property paths — the full set both modes need, retrieved in ONE
#: PropertyCollector call. Extend here, never with per-object attribute reads.
HOST_PROPS = [
    "name",
    "summary.overallStatus",
    "summary.quickStats.overallCpuUsage",
    "summary.quickStats.overallMemoryUsage",
    "summary.config.product.version",
    "hardware.cpuInfo.hz",
    "hardware.cpuInfo.numCpuCores",
    "hardware.memorySize",
    "vm",
]
VM_PROPS = [
    "summary.config.name",
    "summary.config.guestFullName",
    "summary.runtime.powerState",
    "summary.overallStatus",
    "summary.quickStats.overallCpuUsage",
    "summary.quickStats.guestMemoryUsage",
    "runtime.host",
    "guest.net",
    "guest.toolsStatus",
    "config.hardware.device",
]


class EsxiUnavailable(RuntimeError):
    """The ``[esxi]`` extra (pyvmomi) is not installed."""


def _dedup(seq: list[str]) -> list[str]:
    """Order-preserving de-duplication."""
    return list(dict.fromkeys(seq))


def _is_routable_ip(ip: str) -> bool:
    """Drop empty / link-local addresses that never identify a service."""
    if not ip:
        return False
    low = ip.lower()
    return not (low.startswith("169.254.") or low.startswith("fe80:"))


def _str_or_none(v: Any) -> str | None:
    s = str(v) if v is not None else ""
    return s or None


def _extract(host_rows: list[dict], vm_rows: list[dict],
             single_label: str | None) -> tuple[list, list]:
    """Extract (hosts, vms) canonical dicts from flat property maps.

    Each row is ``{"moId": str, "<property.path>": value, ...}`` as returned
    by :meth:`EsxiAdapter._fetch_inventory` (missing properties absent — the
    PropertyCollector omits unset values). NIC/device entries under
    ``guest.net`` / ``config.hardware.device`` are vSphere *data* objects
    (local attribute access, no wire) — read defensively with ``getattr``.

    Pure and pyvmomi-free: it consumes dicts and never touches a managed
    object, so it is unit-testable with plain fakes and structurally cannot
    mutate anything.

    Host identity is a **generic** label — ``single_label`` when given (a
    standalone host keeps its inventory name), else ``node-N`` assigned by
    sorted real host name (a vCenter's several hosts). The real FQDN is
    never stored.

    A malformed VM row (e.g. mid-clone, ``summary.config`` transiently unset)
    is skipped with a warning — one transient VM must not fail the endpoint.
    """
    real_names = sorted({r.get("name") for r in host_rows if r.get("name")})
    if single_label is not None and len(real_names) <= 1:
        label_by_name = {n: single_label for n in real_names}
    else:
        label_by_name = {n: f"node-{i + 1}" for i, n in enumerate(real_names)}
    label_by_moid = {r["moId"]: label_by_name[r["name"]]
                     for r in host_rows if r.get("name")}

    hosts: list[dict[str, Any]] = []
    for r in host_rows:
        if not r.get("name"):
            continue
        hz = r.get("hardware.cpuInfo.hz")
        cores = r.get("hardware.cpuInfo.numCpuCores")
        mem_bytes = r.get("hardware.memorySize")
        hosts.append({
            "name": label_by_name[r["name"]],
            "health": _str_or_none(r.get("summary.overallStatus")),
            "cpu_mhz": r.get("summary.quickStats.overallCpuUsage"),
            "cpu_capacity_mhz": int(hz // 1_000_000 * cores) if hz and cores else None,
            "mem_mb": r.get("summary.quickStats.overallMemoryUsage"),
            "mem_capacity_mb": int(mem_bytes // (1024 * 1024)) if mem_bytes else None,
            "version": _str_or_none(r.get("summary.config.product.version")),
            "vm_count": len(r.get("vm") or []),
        })
    hosts.sort(key=lambda x: x["name"])

    vms: list[dict[str, Any]] = []
    skipped = 0
    for r in vm_rows:
        name = r.get("summary.config.name")
        if not name:
            # Transient (mid-clone/mid-create): config not yet populated.
            skipped += 1
            continue
        try:
            macs: list[str] = []
            ips: list[str] = []
            for nic in (r.get("guest.net") or []):
                mac = getattr(nic, "macAddress", None)
                if mac:
                    macs.append(mac.lower())
                for ip in (getattr(nic, "ipAddress", None) or []):
                    if _is_routable_ip(ip):
                        ips.append(ip)
            for dev in (r.get("config.hardware.device") or []):
                mac = getattr(dev, "macAddress", None)
                if mac:
                    macs.append(mac.lower())
            vms.append({
                "name": str(name),
                "power_state": _str_or_none(r.get("summary.runtime.powerState")),
                "host": label_by_moid.get(r.get("runtime.host"),
                                          single_label or "unknown"),
                "macs": _dedup(macs),
                "ips": _dedup(ips),
                "guest_os": _str_or_none(r.get("summary.config.guestFullName")),
                "tools_status": _str_or_none(r.get("guest.toolsStatus")),
                "cpu_mhz": r.get("summary.quickStats.overallCpuUsage"),
                "mem_mb": r.get("summary.quickStats.guestMemoryUsage"),
                "health": _str_or_none(r.get("summary.overallStatus")),
            })
        except (AttributeError, TypeError) as exc:  # one bad VM ≠ dead endpoint
            skipped += 1
            logger.warning("Skipping malformed VM record %r: %s", str(name), exc)
    if skipped:
        logger.warning("VMware inventory: skipped %d transient/malformed VM record(s)",
                       skipped)
    vms.sort(key=lambda v: v["name"])   # stable fact files (no view-order churn)
    return hosts, vms


class EsxiAdapter(CollectionStrategy):
    """Collect VMware inventory from a vCenter or standalone ESXi host (read-only)."""

    name = "esxi"

    def supports(self, device: dict[str, Any]) -> bool:
        return device.get("os") in SUPPORTED_OS_FAMILIES

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """Read the VM + host inventory → ``facts/<endpoint>/esxi_vms.json`` +
        ``esxi_hosts.json``.

        Credentials: a per-device ``username``/``password`` (literal or
        ``${ENV}``) wins — a vCenter needs its SSO user (e.g.
        ``administrator@vsphere.example``) — else the ``ESXi_USERNAME``/
        ``ESXi_PASSWORD`` env vars (the FortiGate-token pattern), keeping
        secrets out of the inventory file.
        """
        inventory_name = device.get("name", device.get("mgmt_ip", "unknown"))
        mgmt_ip = device["mgmt_ip"]
        multi_host = device.get("os") == "vcenter"

        try:
            dev_user = device.get("username")
            user = expand_env_ref(str(dev_user)) if dev_user else os.getenv(USERNAME_ENV_VAR)
            dev_pwd = device.get("password")
            pwd = expand_env_ref(str(dev_pwd)) if dev_pwd else os.getenv(PASSWORD_ENV_VAR)
        except ValueError as exc:
            return CollectionResult(
                success=False, strategy_name=self.name, hostname=inventory_name,
                error=f"VMware credential {exc}",
            )
        if not user or not pwd:
            return CollectionResult(
                success=False, strategy_name=self.name, hostname=inventory_name,
                error=(f"VMware credentials not set — a per-device username/password "
                       f"or {USERNAME_ENV_VAR}/{PASSWORD_ENV_VAR} (read-only account)"),
            )

        single_label = None if multi_host else inventory_name
        try:
            host_rows, vm_rows = self._fetch_inventory(mgmt_ip, user, pwd)
        except EsxiUnavailable as exc:
            return CollectionResult(
                success=False, strategy_name=self.name, hostname=inventory_name,
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 — connection/auth error, per contract
            logger.warning("VMware collection failed for '%s': %s", inventory_name, exc)
            return CollectionResult(
                success=False, strategy_name=self.name, hostname=inventory_name,
                error=f"{type(exc).__name__}: {exc}",
            )

        hosts, vms = _extract(host_rows, vm_rows, single_label)

        # facts/<endpoint>/ — sibling of raw/, same derivation pyATS uses
        # (facts_dir = Path(output_dir).parent / "facts" / <name>).
        facts_dir = Path(output_dir).parent / "facts" / inventory_name
        facts_dir.mkdir(parents=True, exist_ok=True)
        vms_file = facts_dir / VMS_FILENAME
        hosts_file = facts_dir / HOSTS_FILENAME
        vms_file.write_text(json.dumps(vms, indent=2), encoding="utf-8")
        hosts_file.write_text(json.dumps(hosts, indent=2), encoding="utf-8")

        return CollectionResult(
            success=True, strategy_name=self.name, hostname=inventory_name,
            files_created=[str(vms_file), str(hosts_file)],
            commands=[{
                "command": "vSphere:RetrievePropertiesEx (read-only host+VM inventory)",
                "output_file": str(vms_file),
                "status": "success",
                "error": None,
            }],
        )

    def _fetch_inventory(self, host: str, user: str, pwd: str) -> tuple[list, list]:
        """Connect and return (host_rows, vm_rows) flat property maps.

        pyvmomi is imported here (lazily) so the module and tests load without
        the ``[esxi]`` extra. One ``RetrievePropertiesEx`` batch (plus
        continuation pages) fetches every property for every host and VM —
        no per-object round-trips.
        """
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim, vmodl
        except ImportError as exc:  # [esxi] extra not installed
            raise EsxiUnavailable(
                "VMware collection needs pyvmomi — install the extra: pip install -e '.[esxi]'"
            ) from exc

        # disableSslCertValidation: vCenter/ESXi management endpoints present
        # self-signed certs; this is read-only collection over management.
        # httpConnectionTimeout: a hung endpoint fails the device instead of
        # hanging the run's worker thread forever.
        si = SmartConnect(host=host, user=user, pwd=pwd,
                          disableSslCertValidation=True,
                          httpConnectionTimeout=CONNECT_TIMEOUT)
        try:
            content = si.RetrieveContent()
            view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.HostSystem, vim.VirtualMachine], True)
            try:
                pc = content.propertyCollector
                qs = vmodl.query.PropertyCollector
                traversal = qs.TraversalSpec(name="view", path="view",
                                             skip=False, type=type(view))
                filter_spec = qs.FilterSpec(
                    objectSet=[qs.ObjectSpec(obj=view, skip=True,
                                             selectSet=[traversal])],
                    propSet=[
                        qs.PropertySpec(type=vim.HostSystem, pathSet=HOST_PROPS),
                        qs.PropertySpec(type=vim.VirtualMachine, pathSet=VM_PROPS),
                    ],
                )
                host_rows: list[dict] = []
                vm_rows: list[dict] = []
                result = pc.RetrievePropertiesEx([filter_spec], qs.RetrieveOptions())
                while result is not None:
                    for obj in result.objects:
                        row: dict[str, Any] = {"moId": obj.obj._moId}
                        for prop in obj.propSet:
                            # A managed-object *reference* value (runtime.host)
                            # is flattened to its moId string; data objects
                            # (guest.net entries, hardware devices) pass
                            # through for local attribute reads.
                            val = prop.val
                            if prop.name == "runtime.host":
                                val = getattr(val, "_moId", None)
                            row[prop.name] = val
                        if isinstance(obj.obj, vim.HostSystem):
                            host_rows.append(row)
                        else:
                            vm_rows.append(row)
                    token = getattr(result, "token", None)
                    result = pc.ContinueRetrievePropertiesEx(token) if token else None
                return host_rows, vm_rows
            finally:
                # Destroy the *view* helper object (session-side), not any VM
                # or host — read-only w.r.t. the managed infrastructure.
                try:
                    view.Destroy()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
        finally:
            Disconnect(si)
