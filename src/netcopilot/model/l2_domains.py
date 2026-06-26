"""L2 broadcast-domain discovery.

A broadcast domain is the *connected* set of switches reachable for a VLAN over
L2 **bridging** links — trunk/access endpoints that both carry the VLAN. This is
connectivity-based, unlike ``_discover_shared_vlans`` which groups purely by
"VLAN N appears on >=2 devices" regardless of whether an L2 path exists.

Two switches that both carry VLAN 10 but are only *routed* between each other are
**separate** broadcast domains — each legitimately its own STP root. The ID-based
grouping conflates them, which is what produces the ``STP_ROOT_BRIDGE_CONFLICT``
false positive on routed networks (verified on the demo: ``acc-sw-01`` has zero L2
links yet was flagged dual-root with ``acc-sw-03``).

This module only *computes* the domains; the cross-device rules consume them in a
later step. ``discover_l2_domains`` is a pure function of (interfaces, links):
output is fully sorted and deterministic (independent of input order), per the
R1/R2 determinism invariant.

Hazards handled (found by inspecting real ``link["l2"]`` data, 2026-06-26):
  - ``vlans_carried`` are **strings** ("10") while interface ``trunk_vlans`` /
    ``access_vlan`` are **ints** (10) — everything is normalized to int.
  - an ``svi`` endpoint is the L3 gateway INTO a domain, **not** a bridging edge.
  - a device that carries a VLAN but has no L2 bridging edge for it is its own
    **singleton** domain.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

#: SVI interface name, e.g. "Vl10" or "Vlan10" -> VLAN 10 (the L3 gateway).
_SVI_RE = re.compile(r"^Vl(?:an)?(\d+)$", re.IGNORECASE)


def _as_int(value: Any) -> int | None:
    """Coerce a VLAN id to int; None if not an integer (str/int tolerant)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _carried_vlans(side: dict | None) -> set[int]:
    """VLANs an ``l2`` endpoint carries as an L2-**bridging** port.

    The link's ``vlans_carried`` is the *resolved* forwarding set computed during
    ``enrich_l2_metadata`` — authoritative even when the interface's own
    ``trunk_vlans`` is ``None`` (an allow-all trunk with no explicit prune list,
    common on real inter-switch trunks). Seeding membership from this, not from
    interface ``trunk_vlans``, is what makes allow-all trunks form real domains.

    A ``svi`` (or any non-trunk/access) endpoint is the L3 gateway, NOT a
    bridging port — it carries nothing for domain purposes.
    """
    if not side:
        return set()
    mode = side.get("mode")
    if mode == "trunk":
        carried = (side.get("trunk") or {}).get("vlans_carried") or []
        return {v for v in (_as_int(x) for x in carried) if v is not None}
    if mode == "access":
        v = _as_int((side.get("vlan") or {}).get("id"))
        return {v} if v is not None else set()
    return set()


class _UnionFind:
    """Union-find whose component root is always the minimum hostname, so the
    grouping is independent of edge insertion order (determinism)."""

    def __init__(self, items: set[str]) -> None:
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        # smaller hostname wins -> component root is the global min member.
        if rb < ra:
            ra, rb = rb, ra
        self.parent[rb] = ra


def _vlan_names(links: list[dict[str, Any]]) -> dict[int, str]:
    """Deterministic VLAN-id -> name map from any ``l2`` endpoint that names it
    (min name when sources disagree)."""
    candidates: dict[int, set[str]] = defaultdict(set)
    for link in links:
        l2 = link.get("l2") or {}
        for side in (l2.get("local"), l2.get("remote")):
            vlan = (side or {}).get("vlan") or {}
            vid, name = _as_int(vlan.get("id")), vlan.get("name")
            if vid is not None and name:
                candidates[vid].add(name)
    return {vid: sorted(names)[0] for vid, names in candidates.items()}


def discover_l2_domains(
    interfaces: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compute connectivity-based L2 broadcast domains.

    Returns a sorted list of domain dicts::

        {"id": "vlan10-dom0", "vlan_id": 10, "name": "USERS-A" | None,
         "member_devices": [...], "access_ports": [...],
         "trunk_links": [...], "svis": [...]}

    One domain per connected component of switches for each VLAN. A device with
    the VLAN but no bridging edge for it forms its own singleton domain.
    """
    # --- 1. Access-port + SVI membership, from interfaces ------------------
    # Access ports define VLAN membership directly (an access port to a host has
    # no inter-switch link). SVIs are the L3 gateway into a VLAN. Trunk VLANs are
    # NOT read here — interface ``trunk_vlans`` is None on allow-all trunks; the
    # resolved set lives on the link (step 2).
    member_devices: dict[int, set[str]] = defaultdict(set)
    access_ports: dict[int, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    svis: dict[int, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for intf in interfaces:
        dev = intf.get("device_id")
        iid = intf.get("interface_id") or f"{dev}:{intf.get('name')}"
        if intf.get("switchport_mode") == "access":
            v = _as_int(intf.get("access_vlan"))
            if v is not None:
                member_devices[v].add(dev)
                access_ports[v][dev].append(iid)
        m = _SVI_RE.match(str(intf.get("name") or ""))
        if m:
            svis[int(m.group(1))][dev].append(iid)

    # --- 2. Trunk membership + bridging edges, from link l2 ----------------
    # The link's resolved ``vlans_carried`` is authoritative (handles allow-all
    # trunks). A device carrying VLAN V on a trunk endpoint is a member of V; an
    # edge exists where BOTH endpoints carry V (and both are bridging ports).
    edges: dict[int, list[tuple[str, str, str]]] = defaultdict(list)
    for link in links:
        l2 = link.get("l2")
        da, db = link.get("local_device_id"), link.get("remote_device_id")
        if not l2 or not da or not db:
            continue
        carried_a = _carried_vlans(l2.get("local"))
        carried_b = _carried_vlans(l2.get("remote"))
        for v in carried_a:
            member_devices[v].add(da)
        for v in carried_b:
            member_devices[v].add(db)
        link_id = link.get("link_id") or (
            f"{link.get('local_interface_id')}__{link.get('remote_interface_id')}"
        )
        for v in carried_a & carried_b:
            edges[v].append((da, db, link_id))

    # --- 3. connected components per VLAN ----------------------------------
    names = _vlan_names(links)
    domains: list[dict[str, Any]] = []
    for v in sorted(member_devices):
        members = member_devices[v]
        uf = _UnionFind(members)
        for da, db, _lid in edges[v]:
            if da in uf.parent and db in uf.parent:
                uf.union(da, db)

        comps: dict[str, set[str]] = defaultdict(set)
        for dev in members:
            comps[uf.find(dev)].add(dev)

        comp_links: dict[str, set[str]] = defaultdict(set)
        for da, db, lid in edges[v]:
            if da in uf.parent and db in uf.parent and uf.find(da) == uf.find(db):
                comp_links[uf.find(da)].add(lid)

        for n, comp in enumerate(sorted(comps.values(), key=lambda s: sorted(s))):
            comp_devs = sorted(comp)
            root = uf.find(comp_devs[0])
            domains.append({
                "id": f"vlan{v}-dom{n}",
                "vlan_id": v,
                "name": names.get(v),
                "member_devices": comp_devs,
                "access_ports": sorted(
                    iid for dev in comp_devs for iid in access_ports[v].get(dev, [])
                ),
                "trunk_links": sorted(comp_links.get(root, set())),
                "svis": sorted(
                    iid for dev in comp_devs for iid in svis[v].get(dev, [])
                ),
            })
    return domains
