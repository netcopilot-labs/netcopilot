"""The service layer join (s16, ADR-0019): declared meaning × observed truth.

An operator names an IP in NetBox (``dns_name`` / ``description`` — "the lobby
camera", "the vision mixer"). The network observes that IP somewhere (ARP on a
gateway, a MAC on an access port). This module joins the two into per-run
``:Service`` nodes so every consumer — find_service, blast_radius, trace_path,
the Service topology view, the LLM — can answer *where services live and what
they depend on*.

Architecture (the s13 drift twin): the join runs OUTSIDE the hermetic
pipeline, on demand, against an already-loaded run. It deletes and reloads
only its own ``:Service`` rows (site + run scoped); model, findings and
goldens are untouched. Reloading a run wipes Service nodes with everything
else (the label-agnostic per-run delete) — re-running the join restores them.

Location ladder (most→least precise, each tier honest about itself):

1. ``arp+fdb`` — an ArpEntry resolves IP→MAC→gateway, and the MAC-table shows
   that MAC on exactly one physical **edge** port (a port with no
   device-to-device link) → port-precise: RESIDES_ON that switch,
   REACHED_VIA that interface.
2. ``arp``     — ArpEntry only → the service hangs off the device that
   resolved it (deterministic pick on ties, observers counted).
3. ``subnet``  — no ARP, but an interface subnet contains the IP → the
   gateway device, approximate.
4. ``none``    — the operator named an IP the network has never seen.
   ``located: false`` — a first-class honest answer, never dropped.

Infrastructure exclusion: an IP that IS a collected device interface is the
network, not a service on it — skipped and counted, with a warning naming it.
"""
from __future__ import annotations

import ipaddress as ipaddr_mod
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netcopilot.declared_state import get_source
from netcopilot.graph.client import get_driver, get_site_for_run
from netcopilot.graph.schema import (
    ARP_ENTRY,
    DEVICE,
    HAS_INTERFACE,
    INTERFACE,
    MAC_ENTRY,
    REACHED_VIA,
    RESIDES_ON,
    SERVICE,
)

log = logging.getLogger(__name__)

#: NetBox prefix tag that marks a CLIENT NETWORK (s17): a range the operator
#: serves without knowing its inner hosts ("I'm their ISP — I know where it
#: connects"). Tagged prefixes join as ``kind: network`` services located at
#: their gateway; untagged prefixes (infrastructure subnets) stay out.
CLIENT_NETWORK_TAG = "client-network"

# An L3 gateway (firewall / router) ROUTES for a subnet; the host still
# ATTACHES to the access/services switch that owns the VLAN. When both could
# locate a host, prefer the switch — a firewall ARPing a host means "I'm its
# gateway", not "it hangs off me" (found live: VLAN-200 servers the FortiGate
# ARP'd as the gateway are physically on the services switch).
_GATEWAY_ROLES = {"firewall", "border_router", "router"}


def _gateway_rank(role: str | None) -> int:
    """0 for an access/L2 device (preferred host attachment), 1 for an L3
    gateway (routes for the subnet, isn't where the host hangs)."""
    return 1 if (role or "").lower() in _GATEWAY_ROLES else 0


class ServiceSourceUnavailable(RuntimeError):
    """NetBox is unreachable — the service layer is unknown, not empty."""


@dataclass
class ServiceJoinReport:
    run_id: str
    site: str
    services: list[dict] = field(default_factory=list)
    skipped_infrastructure: list[str] = field(default_factory=list)
    skipped_other_site: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def counts_by_method(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.services:
            out[s["location_method"]] = out.get(s["location_method"], 0) + 1
        return out

    def format_summary(self) -> str:
        by = self.counts_by_method()
        located = sum(n for m, n in by.items() if m != "none")
        lines = [
            f"Service join for run {self.run_id} (site {self.site}): "
            f"{len(self.services)} service(s) from NetBox-named IPs — "
            f"{located} located ({', '.join(f'{m}: {n}' for m, n in sorted(by.items()) if m != 'none') or 'none'}), "
            f"{by.get('none', 0)} never seen by the network."
        ]
        if self.skipped_infrastructure:
            lines.append(
                f"{len(self.skipped_infrastructure)} named IP(s) are device interfaces "
                "(infrastructure, not services) — skipped."
            )
        if self.skipped_other_site:
            lines.append(
                f"{len(self.skipped_other_site)} entrie(s) belong to another site "
                "(prefix scope) — skipped."
            )
        lines.extend(self.warnings)
        return "\n".join(lines)


# ── Observation queries ──────────────────────────────────────────────────────


def _infra_ips(session, site: str, run_id: str) -> dict[str, tuple[str, str]]:
    """bare-ip → (device, interface) for every collected interface address."""
    rows = session.run(
        f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}})"
        f"-[:{HAS_INTERFACE}]->(i:{INTERFACE}) "
        "WHERE i.ip IS NOT NULL "
        "RETURN d.name AS device, i.name AS interface, i.ip AS ip "
        "ORDER BY d.name, i.name",
        site=site, run_id=run_id,
    )
    out: dict[str, tuple[str, str]] = {}
    for r in rows:
        bare = str(r["ip"]).split("/")[0]
        out.setdefault(bare, (r["device"], r["interface"]))
    return out


def _interface_subnets(session, site: str, run_id: str) -> list[tuple[Any, str, str]]:
    """(network, device, interface) for every interface address with a mask.

    Interface nodes store the address bare in ``ip`` with the mask in
    ``prefix_length`` (a few sources embed it in ``ip`` instead — both
    accepted; found live, the CONTAINS '/' assumption matched 4 of 71).
    """
    rows = session.run(
        f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}})"
        f"-[:{HAS_INTERFACE}]->(i:{INTERFACE}) "
        "WHERE i.ip IS NOT NULL AND (i.prefix_length IS NOT NULL OR i.ip CONTAINS '/') "
        "RETURN d.name AS device, i.name AS interface, i.ip AS ip, "
        "i.prefix_length AS prefix_length",
        site=site, run_id=run_id,
    )
    subnets = []
    for r in rows:
        cidr = str(r["ip"])
        if "/" not in cidr and r["prefix_length"] is not None:
            cidr = f"{cidr}/{r['prefix_length']}"
        try:
            net = ipaddr_mod.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen >= 32:
            continue
        subnets.append((net, r["device"], r["interface"]))
    return subnets


def _link_endpoint_ports(session, site: str, run_id: str) -> set[tuple[str, str]]:
    """(device, interface) pairs that terminate a device-to-device link —
    uplinks/backbone, never a host edge port."""
    rows = session.run(
        f"MATCH (a:{DEVICE} {{site: $site, run_id: $run_id}})-[l]->"
        f"(b:{DEVICE} {{site: $site, run_id: $run_id}}) "
        "WHERE l.local_interface IS NOT NULL "
        "RETURN a.name AS a, l.local_interface AS ai, b.name AS b, l.remote_interface AS bi",
        site=site, run_id=run_id,
    )
    ports: set[tuple[str, str]] = set()
    for r in rows:
        if r["ai"]:
            ports.add((r["a"], r["ai"]))
        if r["b"] and r["bi"]:
            ports.add((r["b"], r["bi"]))
    return ports


def _esxi_read(run_id: str, filename: str, label_key: str) -> list[dict]:
    """Read one ESXi fact file across the run's endpoints, deterministically.

    Endpoint dirs are iterated SORTED, and when the run holds more than one
    VMware endpoint the generic ``node-N`` labels — unique only within one
    endpoint's file — are namespaced ``<endpoint>:<label>`` on read. Without
    that, two vCenters both emitting ``node-1`` would collide in the join's
    ``hosts_by_name`` index and a VM could be stamped with the OTHER
    endpoint's host health, decided by filesystem iteration order.
    """
    import json
    import os
    from pathlib import Path

    facts = Path(os.environ.get("RUNS_DIR", "runs")) / run_id / "facts"
    if not facts.is_dir():
        return []
    endpoint_dirs = sorted(
        d for d in facts.iterdir()
        if (d / "esxi_vms.json").is_file() or (d / "esxi_hosts.json").is_file()
    )
    multi = len(endpoint_dirs) > 1
    out: list[dict] = []
    for dev_dir in endpoint_dirs:
        f = dev_dir / filename
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            if multi and entry.get(label_key):
                entry[label_key] = f"{dev_dir.name}:{entry[label_key]}"
            out.append(entry)
    return out


def _esxi_vms(run_id: str) -> list[dict]:
    """Every VM across the run's ESXi endpoints (s19: the compute layer).

    Reads ``facts/<endpoint>/esxi_vms.json`` (written by the read-only ESXi
    adapter) — each entry ``{name, power_state, host, macs, ips, ...}``. This
    is the deterministic source for virtualization: it knows a VM regardless
    of whether the network ever saw it talk. An absent file means the run has
    no ESXi layer (virtualization unknown, never guessed).
    """
    return _esxi_read(run_id, "esxi_vms.json", "host")


def _esxi_hosts(run_id: str) -> list[dict]:
    """ESXi hosts across the run (s19-6: node health), from esxi_hosts.json —
    written by the VMware adapter alongside esxi_vms.json. Generic ``node-N``
    labels; each carries overall health + CPU/mem + VM count."""
    return _esxi_read(run_id, "esxi_hosts.json", "name")


_SVI_RE = re.compile(r"[Vv]l(?:an)?(\d+)")


def _vlan_of_svi(interface: str | None) -> str | None:
    """'Vl301' / 'Vlan301' → '301'."""
    if not interface:
        return None
    m = _SVI_RE.fullmatch(interface)
    return m.group(1) if m else None


def _vlan_access_ports(run_id: str) -> dict:
    """vlan_id → [(device, port)] — the L2 access member ports of each VLAN,
    read from the run's VLAN databases. A client VLAN's access ports are where
    its clients physically plug in (on the access switch), even though the L3
    SVI/gateway lives on the core.
    """
    import json
    import os
    from pathlib import Path

    from netcopilot.model.interface_normalizer import normalize_interface_name

    facts = Path(os.environ.get("RUNS_DIR", "runs")) / run_id / "facts"
    out: dict = {}
    if not facts.is_dir():
        return out
    for dev_dir in facts.iterdir():
        gv = dev_dir / "genie_vlan.json"
        if not gv.is_file():
            continue
        try:
            data = json.loads(gv.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for vid, vd in (data.get("vlans") or {}).items():
            for port in (vd.get("interfaces") or []):
                out.setdefault(str(vid), []).append(
                    (dev_dir.name, normalize_interface_name(port)))
    return out


def _portchannel_members(run_id: str) -> dict:
    """(device, 'PoN') → [member ports], from each device's genie_lag.json.

    A client VLAN's access port is often a port-channel; the info panel shows
    its physical member links. Read from the LAG database (like the VLAN DB),
    normalized to the graph-wide abbreviated interface form.
    """
    import json
    import os
    from pathlib import Path

    from netcopilot.model.interface_normalizer import normalize_interface_name

    facts = Path(os.environ.get("RUNS_DIR", "runs")) / run_id / "facts"
    out: dict = {}
    if not facts.is_dir():
        return out
    for dev_dir in facts.iterdir():
        gl = dev_dir / "genie_lag.json"
        if not gl.is_file():
            continue
        try:
            data = json.loads(gl.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for po, pd in (data.get("interfaces") or {}).items():
            members = list((pd.get("members") or {}).keys())
            if members:
                key = (dev_dir.name, normalize_interface_name(po))
                out[key] = [normalize_interface_name(m) for m in members]
    return out


def _device_roles(session, site: str, run_id: str) -> dict:
    """device name → role, for role-aware host attachment."""
    rows = session.run(
        f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}}) "
        "RETURN d.name AS name, d.role AS role",
        site=site, run_id=run_id,
    )
    return {r["name"]: r["role"] for r in rows}


def _arp_observers(session, site: str, run_id: str, ip: str) -> list[dict]:
    rows = session.run(
        f"MATCH (a:{ARP_ENTRY} {{site: $site, run_id: $run_id, ip: $ip}}) "
        "RETURN a.device AS device, a.interface AS interface, a.mac AS mac "
        "ORDER BY a.device, a.interface, a.mac",
        site=site, run_id=run_id, ip=ip,
    )
    return [dict(r) for r in rows]


def _edge_ports_for_mac(session, site: str, run_id: str, mac: str,
                        uplinks: set[tuple[str, str]]) -> list[dict]:
    """Physical, non-uplink MAC-table sightings of ``mac``."""
    rows = session.run(
        f"MATCH (m:{MAC_ENTRY} {{site: $site, run_id: $run_id, mac: $mac}}) "
        "RETURN m.device AS device, m.interface AS interface, m.vlan AS vlan "
        "ORDER BY m.device, m.interface",
        site=site, run_id=run_id, mac=mac,
    )
    out = []
    for r in rows:
        intf = str(r["interface"] or "")
        # MacEntry.interface uses the graph-wide abbreviated form (Vl50,
        # Po35, Gi1/0/5 — same as Interface.name and link properties).
        if intf.startswith(("Vl", "vl", "Po", "po")):
            continue  # SVIs / aggregates locate nothing physical
        if (r["device"], intf) in uplinks:
            continue  # transit sighting, not the host's port
        out.append(dict(r))
    return out


# ── The join ─────────────────────────────────────────────────────────────────


def run_service_join(
    run_id: str,
    *,
    adapter=None,
    driver=None,
    site: str | None = None,
) -> ServiceJoinReport:
    """Join NetBox-named IPs against the run's observations → ``:Service`` rows.

    Raises:
        ServiceSourceUnavailable: NetBox unreachable (never an empty layer).
        ValueError: the run is not loaded in Neo4j (nothing to join against).
    """
    if adapter is None:
        adapter = get_source("netbox")
    try:
        adapter.ping()
    except Exception as exc:
        raise ServiceSourceUnavailable(
            f"Declared-state source unreachable — the service layer is unknown, "
            f"not empty: {exc}"
        ) from exc

    if driver is None:
        driver = get_driver()
    if site is None:
        site = get_site_for_run(run_id)
    if site is None:
        raise ValueError(
            f"Run {run_id!r} is not loaded in Neo4j — load it first "
            "(netcopilot run / Run Now), then re-run the service join."
        )

    report = ServiceJoinReport(run_id=run_id, site=site)
    joined_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # STRICT source reads (audit A1/A2): the join delete-then-reloads, so a
    # mid-pull failure masked as [] would WIPE the previous service layer and
    # report it as honestly empty — and an empty prefix list would silently
    # disable site scoping (cross-site mixing). ping() only covers total
    # outage; the reads themselves must fail loud. Nothing is deleted unless
    # both pulls succeeded.
    try:
        all_ips = adapter.get_ip_addresses(strict=True)
        all_prefixes = adapter.get_prefixes(strict=True)
    except Exception as exc:
        raise ServiceSourceUnavailable(
            f"Declared-state read failed mid-pull — the service layer is "
            f"unknown, not empty (previous rows kept): {exc}"
        ) from exc

    candidates = [
        ip for ip in all_ips
        if (ip.get("dns_name") or ip.get("description"))
        and (ip.get("status_value") in (None, "active"))
    ]

    # ── Site scoping (s19) ──────────────────────────────────────────────────
    # NetBox IPs carry no site; a prefix carries a site scope. An IP's site is
    # the site of the LONGEST scoped prefix containing it (most-specific wins,
    # the NetBox containment model). One NetBox serving several sites would
    # otherwise mix every site's services into every run's lens. An IP inside
    # no scoped prefix has an unknown site and honestly joins every run —
    # single-site setups that never scope prefixes are unaffected.
    scoped_nets: list[tuple] = []
    for p in all_prefixes:
        if p.get("site"):
            try:
                scoped_nets.append(
                    (ipaddr_mod.ip_network(str(p["prefix"]), strict=False), p["site"]))
            except ValueError:
                continue

    def _ip_site(addr) -> str | None:
        # Longest prefix wins; equal-length overlaps (a NetBox modeling error,
        # but possible) tie-break on (site, prefix) lexicographically so the
        # answer never depends on NetBox result order.
        best = None
        for net, pfx_site in scoped_nets:
            if addr in net:
                key = (-net.prefixlen, pfx_site, str(net))
                if best is None or key < best[0]:
                    best = (key, pfx_site)
        return best[1] if best else None

    with driver.session() as session:
        infra = _infra_ips(session, site, run_id)
        subnets = _interface_subnets(session, site, run_id)
        uplinks = _link_endpoint_ports(session, site, run_id)
        roles = _device_roles(session, site, run_id)

        for cand in candidates:
            bare = str(cand["address"]).split("/")[0]
            name = cand.get("dns_name") or cand.get("description")

            try:
                cand_addr = ipaddr_mod.ip_address(bare)
            except ValueError:
                report.warnings.append(
                    f"{name}: {cand['address']!r} is not a valid address — skipped")
                continue
            ip_site = _ip_site(cand_addr)
            if ip_site is not None and ip_site != site:
                report.skipped_other_site.append(
                    f"{name} ({bare}) belongs to site {ip_site!r}, not {site!r}")
                continue

            if bare in infra:
                dev, intf = infra[bare]
                report.skipped_infrastructure.append(
                    f"{name} ({bare}) is {dev}/{intf} — a device interface, not a service"
                )
                continue

            svc: dict[str, Any] = {
                "name": name,
                "kind": "host",
                "ip": bare,
                "address": cand["address"],
                "dns_name": cand.get("dns_name"),
                "description": cand.get("description"),
                "tenant": cand.get("tenant"),
                "role": cand.get("role"),
                "vrf": cand.get("vrf"),
                "tags": cand.get("tags") or [],
                "netbox_id": cand.get("netbox_id"),
                "located": False,
                "location_method": "none",
                "device": None,
                "interface": None,
                "mac": None,
                "observer_count": 0,
                "joined_at": joined_at,
                "site": site,
                "run_id": run_id,
            }

            addr = cand_addr   # parsed (and site-checked) above

            # Gather every candidate location, then pick role-first: a switch
            # that owns the VLAN beats a gateway that merely routes for it,
            # even when the gateway is the only device that ARP'd the host.
            # Within a role, precision wins (arp+fdb > arp > subnet), then the
            # most-specific subnet, then name (deterministic).
            # Key = (gateway_rank, precision, -prefixlen, device, interface).
            observers = _arp_observers(session, site, run_id, bare)
            cands: list[tuple] = []
            for o in observers:
                cands.append((_gateway_rank(roles.get(o["device"])), 1, -32,
                              o["device"], o["interface"], "arp", o["mac"]))
                edge = _edge_ports_for_mac(session, site, run_id, o["mac"], uplinks)
                if len(edge) == 1:
                    e = edge[0]
                    cands.append((_gateway_rank(roles.get(e["device"])), 0, -32,
                                  e["device"], e["interface"], "arp+fdb", o["mac"]))
            for net, dev, intf in subnets:
                if addr in net:
                    cands.append((_gateway_rank(roles.get(dev)), 2, -net.prefixlen,
                                  dev, intf, "subnet", None))

            if cands:
                cands.sort(key=lambda c: c[:5])
                _, _, _, dev, intf, method, mac = cands[0]
                svc.update(located=True, location_method=method, device=dev,
                           interface=intf, mac=mac, observer_count=len(observers))

            report.services.append(svc)

        # ── Deterministic VLAN co-location ──────────────────────────────────
        # A subnet is one L2 broadcast domain = one VLAN = ONE access switch.
        # If any host of a subnet was directly observed on a switch (arp/
        # arp+fdb), that VLAN lives on that switch — so its OTHER hosts attach
        # there too, even ones no device individually observed. This makes a
        # VLAN's placement consistent regardless of which hosts were powered
        # on, and keeps the L3 gateway (firewall/router) from being mistaken
        # for the attachment point. Deterministic: most-observed switch wins,
        # then device name.
        gw_devices = {d for d, role in roles.items() if _gateway_rank(role)}
        subnet_obs: dict = {}   # network → {switch: observed_count}
        host_svcs = [s for s in report.services
                     if s.get("kind") == "host" and s.get("located")]
        for s in host_svcs:
            if s["location_method"] in ("arp", "arp+fdb") and s["device"] not in gw_devices:
                a = ipaddr_mod.ip_address(s["ip"])
                for net, dev, intf in subnets:
                    if a in net:
                        subnet_obs.setdefault(net, {})
                        subnet_obs[net][s["device"]] = subnet_obs[net].get(s["device"], 0) + 1
        subnet_switch = {
            net: sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            for net, counts in subnet_obs.items()
        }
        for s in host_svcs:
            if s["device"] in gw_devices:   # sitting on an L3 gateway → relocate
                a = ipaddr_mod.ip_address(s["ip"])
                # Most-specific containing subnet; equal-length ties break on
                # the prefix string, never on dict iteration order.
                best_net = None
                for net in subnet_switch:
                    if a in net and (
                        best_net is None
                        or (-net.prefixlen, str(net)) < (-best_net.prefixlen, str(best_net))
                    ):
                        best_net = net
                if best_net is not None:
                    s.update(device=subnet_switch[best_net], interface=None,
                             mac=None, location_method="colocated")

        # ── Virtualization from the ESXi compute layer (s19) ────────────────
        # Deterministic: a service is virtualized iff its IP is a known VM guest
        # IP, OR its observed ARP MAC is a known VM vNIC MAC (the bridge for VMs
        # without VMware Tools). The network alone cannot see an idle VM — ESXi
        # can. No ESXi facts for the run ⇒ virtualization stays unknown, never
        # guessed as bare-metal. This replaces the s18 network-inferred guess
        # (MAC-OUI + port-description grouping), which mislabelled idle VMs.
        vms = _esxi_vms(run_id)
        hosts_by_name = {h.get("name"): h for h in _esxi_hosts(run_id)}
        ip_to_vm: dict[str, dict] = {}
        mac_to_vm: dict[str, dict] = {}
        for vm in vms:
            for ip in (vm.get("ips") or []):
                ip_to_vm.setdefault(ip, vm)
            for mac in (vm.get("macs") or []):
                mac_to_vm.setdefault(str(mac).lower(), vm)
        for s in report.services:
            if s.get("kind") == "network":
                continue
            vm = ip_to_vm.get(s["ip"])
            if vm is None and s.get("mac"):
                vm = mac_to_vm.get(str(s["mac"]).lower())
            if vm is not None:
                s["virtualized"] = True
                s["host"] = vm.get("host")
                s["vm_name"] = vm.get("name")
                # s19-6: VM health/info for the info panel.
                s["guest_os"] = vm.get("guest_os")
                s["tools_status"] = vm.get("tools_status")
                s["power_state"] = vm.get("power_state")
                s["vm_cpu_mhz"] = vm.get("cpu_mhz")
                s["vm_mem_mb"] = vm.get("mem_mb")
                s["vm_health"] = vm.get("health")
                # Host (node) health, denormalized onto the VM for the panel's
                # node section (Neo4j has no nested values; the host label ties
                # them). Only present with a vCenter host inventory.
                host = hosts_by_name.get(vm.get("host"))
                if host:
                    s["host_health"] = host.get("health")
                    s["host_cpu_mhz"] = host.get("cpu_mhz")
                    s["host_cpu_capacity_mhz"] = host.get("cpu_capacity_mhz")
                    s["host_mem_mb"] = host.get("mem_mb")
                    s["host_mem_capacity_mb"] = host.get("mem_capacity_mb")
                    s["host_vm_count"] = host.get("vm_count")
                    s["host_version"] = host.get("version")

        # ── Client networks (s17): tagged prefixes located at their gateway ──
        vlan_access = _vlan_access_ports(run_id)   # s18: VLAN → access ports
        pc_members = _portchannel_members(run_id)  # s19: PoN → member links
        # Site scoping (s19): a client-network prefix carries its own site
        # scope — join it only into that site's runs (unscoped = every run).
        net_candidates = []
        for p in all_prefixes:
            if CLIENT_NETWORK_TAG not in (p.get("tags") or []):
                continue
            if p.get("status_value") not in (None, "active"):
                continue
            if p.get("site") is not None and p["site"] != site:
                report.skipped_other_site.append(
                    f"client network {p.get('description') or p['prefix']} "
                    f"({p['prefix']}) belongs to site {p['site']!r}, not {site!r}")
                continue
            net_candidates.append(p)
        for cand in net_candidates:
            try:
                pfx_net = ipaddr_mod.ip_network(str(cand["prefix"]), strict=False)
            except ValueError:
                report.warnings.append(
                    f"client network {cand.get('prefix')!r}: not a valid prefix — skipped"
                )
                continue
            name = cand.get("description") or str(cand["prefix"])

            # Gateway ladder: an interface whose connected subnet IS the
            # prefix (exact) — else one strictly inside it (the operator
            # declared an aggregate). Every matching gateway attaches
            # (redundant gateways are real, not a tie to break).
            exact = sorted(
                ((dev, intf) for net, dev, intf in subnets if net == pfx_net),
                key=lambda t: (t[0], t[1]),
            )
            containing = sorted(
                ((dev, intf) for net, dev, intf in subnets
                 if net != pfx_net and net.subnet_of(pfx_net)),
                key=lambda t: (t[0], t[1]),
            ) if not exact else []
            gateways = exact or containing
            method = "gateway" if exact else ("gateway-containing" if containing else "none")

            # s18: the client physically lands on the ACCESS switch — the L2
            # member ports of its VLAN — while the L3 SVI/gateway is on the
            # core. Derive the VLAN from the gateway SVI, then its access ports.
            vlan_id = _vlan_of_svi(gateways[0][1]) if gateways else None
            access = vlan_access.get(vlan_id, []) if vlan_id else []
            # s19: for each access port that is a port-channel, its member links
            # ("Po101=Twe1/0/1,Twe2/0/1") — flat strings (Neo4j has no nested
            # list values); the info panel parses them.
            access_members = [
                f"{p}={','.join(pc_members[(d, p)])}"
                for d, p in access if (d, p) in pc_members
            ]

            svc = {
                "name": name,
                "kind": "network",
                "ip": str(pfx_net),                      # the CIDR is the key
                "address": str(pfx_net),
                "description": cand.get("description"),
                "role": cand.get("role"),
                "vrf": cand.get("vrf"),
                "tags": cand.get("tags") or [],
                "netbox_id": cand.get("netbox_id"),
                "located": bool(gateways),
                "location_method": method,
                "device": gateways[0][0] if gateways else None,
                "interface": gateways[0][1] if gateways else None,
                "gateways": [f"{d}/{i}" for d, i in gateways],
                "vlan_id": vlan_id,
                "access_ports": [f"{d}/{p}" for d, p in access],
                "access_members": access_members,
                "joined_at": joined_at,
                "site": site,
                "run_id": run_id,
            }
            report.services.append(svc)

        _persist(session, report)

    log.info(
        "Service join %s/%s: %d services (%s), %d infra-skipped",
        site, run_id, len(report.services), report.counts_by_method(),
        len(report.skipped_infrastructure),
    )
    return report


def _persist(session, report: ServiceJoinReport) -> None:
    """Delete-then-reload this run's Service rows (only ours — findings,
    model nodes and everything else untouched)."""
    session.run(
        f"MATCH (s:{SERVICE} {{site: $site, run_id: $run_id}}) DETACH DELETE s",
        site=report.site, run_id=report.run_id,
    )
    if not report.services:
        return

    # None-valued properties are dropped (Neo4j has no null property values).
    rows = [{k: v for k, v in s.items() if v is not None} for s in report.services]
    networks = [r for r in rows if r.get("kind") == "network"]
    host_rows = [r for r in rows if r.get("kind") != "network"]
    located = [r for r in host_rows if r.get("device")]
    unlocated = [r for r in host_rows if not r.get("device")]

    if located:
        session.run(
            f"""
            UNWIND $rows AS r
            MATCH (d:{DEVICE} {{site: r.site, run_id: r.run_id, name: r.device}})
            CREATE (s:{SERVICE})
            SET s = r
            CREATE (s)-[:{RESIDES_ON}]->(d)
            """,
            rows=located,
        )
        # Port-precise services also point at their interface. Interface nodes
        # key on (device, name) within the run.
        precise = [r for r in located if r.get("interface") and r["location_method"] == "arp+fdb"]
        if precise:
            session.run(
                f"""
                UNWIND $rows AS r
                MATCH (s:{SERVICE} {{site: r.site, run_id: r.run_id, ip: r.ip}})
                MATCH (d:{DEVICE} {{site: r.site, run_id: r.run_id, name: r.device}})
                      -[:{HAS_INTERFACE}]->(i:{INTERFACE} {{name: r.interface}})
                CREATE (s)-[:{REACHED_VIA}]->(i)
                """,
                rows=precise,
            )
    if unlocated:
        session.run(
            f"UNWIND $rows AS r CREATE (s:{SERVICE}) SET s = r",
            rows=unlocated,
        )

    # Client networks (s17): the node first, then one RESIDES_ON+REACHED_VIA
    # per gateway — a network with redundant gateways attaches to ALL of them.
    if networks:
        session.run(
            f"UNWIND $rows AS r CREATE (s:{SERVICE}) SET s = r",
            rows=networks,
        )
        attach = []
        for r in networks:
            for gw in r.get("gateways") or []:
                dev, _, intf = gw.partition("/")
                attach.append({"site": r["site"], "run_id": r["run_id"],
                               "ip": r["ip"], "device": dev, "interface": intf})
        if attach:
            session.run(
                f"""
                UNWIND $rows AS r
                MATCH (s:{SERVICE} {{site: r.site, run_id: r.run_id, ip: r.ip}})
                MATCH (d:{DEVICE} {{site: r.site, run_id: r.run_id, name: r.device}})
                CREATE (s)-[:{RESIDES_ON}]->(d)
                WITH s, d, r
                OPTIONAL MATCH (d)-[:{HAS_INTERFACE}]->(i:{INTERFACE} {{name: r.interface}})
                FOREACH (_ IN CASE WHEN i IS NULL THEN [] ELSE [1] END |
                    CREATE (s)-[:{REACHED_VIA}]->(i))
                """,
                rows=attach,
            )
