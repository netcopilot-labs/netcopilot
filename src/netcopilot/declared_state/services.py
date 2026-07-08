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
        lines.extend(self.warnings)
        return "\n".join(lines)


# ── Observation queries ──────────────────────────────────────────────────────


def _infra_ips(session, site: str, run_id: str) -> dict[str, tuple[str, str]]:
    """bare-ip → (device, interface) for every collected interface address."""
    rows = session.run(
        f"MATCH (d:{DEVICE} {{site: $site, run_id: $run_id}})"
        f"-[:{HAS_INTERFACE}]->(i:{INTERFACE}) "
        "WHERE i.ip IS NOT NULL "
        "RETURN d.name AS device, i.name AS interface, i.ip AS ip",
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


# Known hypervisor / VM MAC OUIs — a MAC in one of these is deterministic
# proof of virtualization (no heuristic). Extend as new platforms appear.
_HYPERVISOR_OUIS = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware", "00:1c:14": "VMware",
    "00:15:5d": "Hyper-V", "52:54:00": "KVM/QEMU", "00:16:3e": "Xen", "0a:00:27": "VirtualBox",
}


def _hypervisor_for(macs) -> str | None:
    for m in macs:
        vendor = _HYPERVISOR_OUIS.get((m or "")[:8].lower())
        if vendor:
            return vendor
    return None


# A physical server is named in its switch-port description ("Link to
# <HOST>", "<HOST> (Enterprise port)", "CIMC <HOST>"). The deterministic host
# identity is the hostname-shaped token — ≥3 hyphen-separated segments, so
# role labels like "STACK-DAD" don't match. Ports sharing that token are the
# same physical node (multiple NICs of one server).
_SERVER_RE = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,}")


def _server_from_description(desc: str | None) -> str | None:
    if not desc:
        return None
    m = _SERVER_RE.search(desc)
    return m.group(0) if m else None


def _interface_descriptions(run_id: str) -> dict:
    """(device, interface) → port description, read from the run's facts.

    The model only carries descriptions for L3 interfaces; the L2 access ports
    that face the servers (where the host-grouping description lives) lose them.
    So read genie_interface.json directly (drift.py reads run facts too) and
    normalize the interface name to the graph-wide abbreviated form.
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
        gi = dev_dir / "genie_interface.json"
        if not gi.is_file():
            continue
        try:
            data = json.loads(gi.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for raw_name, d in (data or {}).items():
            desc = (d or {}).get("description")
            if desc:
                out[(dev_dir.name, normalize_interface_name(raw_name))] = desc
    return out


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


def _port_endpoint_macs(session, site: str, run_id: str, device: str, interface: str) -> list[str]:
    """Distinct endpoint MACs learned on one physical port (FDB)."""
    rows = session.run(
        f"MATCH (m:{MAC_ENTRY} {{site: $site, run_id: $run_id, "
        "device: $device, interface: $interface}) "
        "RETURN DISTINCT m.mac AS mac",
        site=site, run_id=run_id, device=device, interface=interface,
    )
    return [r["mac"] for r in rows]


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
        "ORDER BY a.device, a.interface",
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

    candidates = [
        ip for ip in adapter.get_ip_addresses()
        if (ip.get("dns_name") or ip.get("description"))
        and (ip.get("status_value") in (None, "active"))
    ]

    with driver.session() as session:
        infra = _infra_ips(session, site, run_id)
        subnets = _interface_subnets(session, site, run_id)
        uplinks = _link_endpoint_ports(session, site, run_id)
        roles = _device_roles(session, site, run_id)

        for cand in candidates:
            bare = str(cand["address"]).split("/")[0]
            name = cand.get("dns_name") or cand.get("description")

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

            try:
                addr = ipaddr_mod.ip_address(bare)
            except ValueError:
                report.warnings.append(f"{name}: {cand['address']!r} is not a valid address — skipped")
                continue

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
                best_net = None
                for net in subnet_switch:
                    if a in net and (best_net is None or net.prefixlen > best_net.prefixlen):
                        best_net = net
                if best_net is not None:
                    s.update(device=subnet_switch[best_net], interface=None,
                             mac=None, location_method="colocated")

        # ── Virtualization host detection (s18) ─────────────────────────────
        # A physical access port is a virtualization uplink when it carries ≥2
        # endpoint MACs OR any MAC with a known hypervisor OUI. But a physical
        # HOST has MULTIPLE uplink NICs — so the deterministic grouping into
        # nodes is the SERVER named in the port description (e.g. two ports both
        # "Link to <HOST>" are the same node). We group a server's virtualized
        # ports into one host, summing endpoints across them, and stamp each VM
        # with its server + hypervisor. Ports without a server description fall
        # back to the port itself (honest — we can't name the node). Bare-metal
        # ports (single non-hypervisor MAC) are left alone: the appliance IS the
        # service, drawn directly.
        descriptions = _interface_descriptions(run_id)
        port_info: dict = {}     # (device, port) → {virt, hypervisor, count, server}
        for s in report.services:
            if (s.get("kind") == "host" and s.get("location_method") == "arp+fdb"
                    and s.get("interface")):
                key = (s["device"], s["interface"])
                if key not in port_info:
                    macs = _port_endpoint_macs(session, site, run_id, *key)
                    hv = _hypervisor_for(macs)
                    port_info[key] = {
                        "virt": len(macs) >= 2 or bool(hv),
                        "hypervisor": hv, "count": len(macs),
                        "server": _server_from_description(descriptions.get(key)),
                    }
        # Aggregate a server's virtualized ports into one node (fall back to the
        # port id when the port has no server description).
        server_agg: dict = {}    # server_key → {hypervisor, count, label}
        for key, pi in port_info.items():
            if not pi["virt"]:
                continue
            server_key = pi["server"] or f"{key[0]}:{key[1]}"
            agg = server_agg.setdefault(server_key, {"hypervisor": None, "count": 0,
                                                     "named": pi["server"]})
            agg["hypervisor"] = agg["hypervisor"] or pi["hypervisor"]
            agg["count"] += pi["count"]
        for s in report.services:
            key = (s.get("device"), s.get("interface"))
            pi = port_info.get(key)
            if pi and pi["virt"]:
                server_key = pi["server"] or f"{key[0]}:{key[1]}"
                agg = server_agg[server_key]
                s["server"] = server_key
                s["server_name"] = agg["named"] or server_key
                s["hypervisor"] = agg["hypervisor"] or "multi-endpoint"
                s["server_endpoint_count"] = agg["count"]

        # ── Client networks (s17): tagged prefixes located at their gateway ──
        vlan_access = _vlan_access_ports(run_id)   # s18: VLAN → access ports
        net_candidates = [
            p for p in adapter.get_prefixes()
            if CLIENT_NETWORK_TAG in (p.get("tags") or [])
            and (p.get("status_value") in (None, "active"))
        ]
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
