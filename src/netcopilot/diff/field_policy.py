"""Field policy for the run-to-run diff — the "what counts as a change" contract.

This module is the make-or-break part of the drift feature. It answers three
questions for the engine:

1. **How is each entity identified across runs?** (``STABLE_KEYS``) — a stable
   key so "the same interface in run A and run B" is matched, not mistaken for
   an add + a remove.

2. **Which model collections do we diff, and are they node/link/other for the
   topology?** (``ENTITY_TYPES``, ``element_ref``).

3. **When two versions of the same entity differ, does that difference count as
   drift, as an info-tier signal, or as nothing at all?** (``VOLATILE_FIELDS``,
   ``INFO_FIELDS``, ``classify_field_changes``).

The three field buckets, and why the split matters:

- **VOLATILE** — wall-clock / per-run metadata and pure counters
  (bytes/packets/messages). These change on *every* re-collection of an
  unchanged network, so a diff of them is pure noise → they produce **no
  change at all**. Seeded from the golden-master ``_VOLATILE_KEYS``
  (``scripts/golden_master.py``) so the drift view and the determinism
  snapshot agree on what "content" means.

- **INFO** — semi-volatile operational signals an operator sometimes *does*
  want to see, but which are not configuration/state drift: BGP prefix counts,
  ARP/FDB/MAC table sizes, DHCP lease counts, session uptime/flap. When the
  *only* differences on an entity are info fields, the entity lands in the
  **info** tier (summarised, no topology halo), not in drift.

- **drift (everything else)** — configuration and operational *state*
  (admin/oper status, IPs, VLAN membership, neighbor up/down, ACLs, …). Any
  drift-field difference makes the entity a **changed** drift entry.

Keep both sets **explicit, not regex** — a new volatile or info field should be
a deliberate, reviewable addition (same discipline as the golden master).
"""

from __future__ import annotations

import json
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Bucket 1 — VOLATILE: differences here produce NO change (ignored entirely).
# ---------------------------------------------------------------------------
#: Mirrors ``scripts/golden_master.py``'s ``_VOLATILE_KEYS`` (detected_at,
#: spf_runs, lsa_count) and extends it with per-run metadata and pure
#: traffic/message counters. Pure-counter deltas (bytes/packets/msg_sent)
#: change on every collection of an unchanged network → not drift, not even
#: info. Keep in sync with the golden master's set for the shared keys.
VOLATILE_FIELDS: frozenset[str] = frozenset(
    {
        # --- golden-master _VOLATILE_KEYS (shared contract) ---
        "detected_at",  # finding creation timestamp
        "spf_runs",  # OSPF SPF-runs-since-boot counter
        "lsa_count",  # OSPF LSA-database size (runtime)
        # --- per-run / wall-clock metadata ---
        "generated_at",
        "collection_timestamp",
        "timestamp",
        "last_updated",
        # --- pure traffic / message counters (bytes/packets/messages) ---
        "in_octets",
        "out_octets",
        "in_bytes",
        "out_bytes",
        "in_packets",
        "out_packets",
        "in_pkts",
        "out_pkts",
        "in_unicast",
        "out_unicast",
        "in_errors",
        "out_errors",
        "in_discards",
        "out_discards",
        "in_rate",
        "out_rate",
        "msg_sent",
        "msg_rcvd",
        "messages_sent",
        "messages_received",
    }
)

# ---------------------------------------------------------------------------
# Bucket 2 — INFO: differences here land in the info tier (not drift).
# ---------------------------------------------------------------------------
#: The four semi-volatile signal families from the sprint plan:
#: BGP prefix counts, ARP/FDB/MAC table sizes, DHCP leases, session
#: uptime/flap. Surfaced (summarised) so an operator can see churn, but never
#: haloed on the topology as configuration/state drift.
INFO_FIELDS: frozenset[str] = frozenset(
    {
        # --- BGP prefix counts ---
        "prefixes_received",
        "prefixes_sent",
        "prefixes_advertised",
        "accepted_prefixes",
        # --- session uptime / flap ---
        "uptime",
        "up_time",
        "up_down",  # BGP Up/Down duration (e.g. "2d21h") — advances every run
        "session_uptime",
        "connection_uptime",
        "last_flap",
        "flap_count",
        "flaps",
        "resets",
        "connection_resets",
        # --- ARP / FDB / MAC table sizes ---
        "arp_count",
        "arp_entries",
        "mac_count",
        "mac_entries",
        "fdb_count",
        "fdb_entries",
        "neighbor_count",
        # --- DHCP leases ---
        "dhcp_leases",
        "lease_count",
        "active_leases",
        "bindings",
    }
)


# ---------------------------------------------------------------------------
# Entity identity — stable keys per model collection.
# ---------------------------------------------------------------------------
def _adjacency_key(a: dict[str, Any]) -> str:
    """Composite stable key for an adjacency (no single id field).

    Adjacencies are protocol sessions with an ``a``/``b`` endpoint pair
    (``device_a`` is often a neighbor IP/router-id, ``device_b`` the local
    hostname). The endpoints are sorted so orientation never flips the key.
    Scoped by protocol, vrf, process_id, and area to keep parallel sessions
    distinct.
    """
    endpoints = sorted(str(a.get("device_a", "")) + "|" + str(a.get("device_b", "")))
    pair = "~".join(sorted([str(a.get("device_a", "")), str(a.get("device_b", ""))]))
    return "|".join(
        [
            str(a.get("protocol", "")),
            pair,
            str(a.get("vrf", "")),
            str(a.get("process_id", "")),
            str(a.get("area", "")),
        ]
    )


def _shared_service_key(s: dict[str, Any]) -> str:
    """Composite stable key for a shared service.

    ``service_type`` + ``identifier`` is not unique on its own: multiple
    ``ospf_area`` services legitimately share ``identifier`` "0.0.0.0",
    distinguished only by ``process_id`` + ``vrf`` (verified on real runs).
    Include both discriminators (empty for services like ``vlan`` that don't
    carry them).
    """
    return ":".join(
        [
            str(s.get("service_type", "")),
            str(s.get("identifier", "")),
            str(s.get("process_id", "")),
            str(s.get("vrf", "")),
        ]
    )


def _ospf_lsdb_key(l: dict[str, Any]) -> str:
    """Composite stable key for an OSPF LSA (area + type + id + adv-router)."""
    return "|".join(
        [
            str(l.get("area_id", "")),
            str(l.get("lsa_type", "")),
            str(l.get("lsa_id", "")),
            str(l.get("adv_router", "")),
            str(l.get("process_id", "")),
            str(l.get("vrf", "")),
        ]
    )


#: entity_type -> callable(entity_dict) -> hashable stable key. The order of
#: this dict is the deterministic order in which entity types are diffed.
STABLE_KEYS: dict[str, Callable[[dict[str, Any]], str]] = {
    "devices": lambda d: str(d["device_id"]),
    "interfaces": lambda i: str(i["interface_id"]),
    "links": lambda k: str(k["link_id"]),
    "adjacencies": _adjacency_key,
    "shared_services": _shared_service_key,
    "l2_domains": lambda x: str(x["id"]),
    "ospf_lsdb": _ospf_lsdb_key,
}

#: The model collections the engine diffs, in deterministic order.
ENTITY_TYPES: tuple[str, ...] = tuple(STABLE_KEYS.keys())


def finding_key(f: dict[str, Any]) -> str:
    """Stable key for a finding: its ``finding_id`` (== ``rule_id::element_id``)."""
    return str(f["finding_id"])


# ---------------------------------------------------------------------------
# Topology addressing — how a diff entry maps onto a node / link / neither.
# ---------------------------------------------------------------------------
#: entity_type -> ("device" | "link" | None, key_field_or_None). Tells the UI
#: what to halo: devices + interfaces halo their owning node; links halo the
#: edge; everything else (services, l2 domains, LSAs, findings) has no direct
#: topology element and is list-only.
_ELEMENT_REF: dict[str, tuple[str | None, str | None]] = {
    "devices": ("device", "device_id"),
    "interfaces": ("device", "device_id"),  # an interface halos its node
    "links": ("link", "link_id"),
    "adjacencies": (None, None),
    "shared_services": (None, None),
    "l2_domains": (None, None),
    "ospf_lsdb": (None, None),
}


def element_ref(entity_type: str, entity: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return ``(element_type, element_id)`` for topology halo/ghost, or
    ``(None, None)`` if the entity has no direct topology element."""
    kind, key_field = _ELEMENT_REF.get(entity_type, (None, None))
    if kind is None or key_field is None:
        return (None, None)
    return (kind, str(entity.get(key_field, "")))


# ---------------------------------------------------------------------------
# Canonicalisation + field-level classification.
# ---------------------------------------------------------------------------
def canonicalize(obj: Any) -> Any:
    """Order-independent, volatile-free canonical form for value comparison.

    Mirrors ``scripts/golden_master.py``'s ``_canon``: dicts are key-sorted
    with :data:`VOLATILE_FIELDS` dropped (recursively), lists are sorted by
    each element's canonical JSON so production *ordering* never shows up as a
    spurious change. Used to decide field equality; the *reported* before/after
    values are the raw ones, not the canonical ones.
    """
    if isinstance(obj, dict):
        return {k: canonicalize(obj[k]) for k in sorted(obj) if k not in VOLATILE_FIELDS}
    if isinstance(obj, list):
        items = [canonicalize(x) for x in obj]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return obj


def _equal(a: Any, b: Any) -> bool:
    return canonicalize(a) == canonicalize(b)


def field_bucket(field: str) -> str:
    """Classify a field name into ``"volatile"`` / ``"info"`` / ``"drift"``.

    Adjacency fields are **bilateral** — the same signal appears as ``<name>_a``
    and ``<name>_b`` (``msg_sent_a``/``msg_sent_b``, ``cost_a``/``cost_b``, …).
    So a field matches a bucket if either its exact name OR its ``_a``/``_b``-
    stripped base is in the set. Volatile wins over info wins over drift. The
    base check only ever *reclassifies* a field whose base is explicitly in a
    curated set, so drift fields like ``router_id_a`` (base ``router_id``, in no
    set) correctly stay drift.
    """
    base = field[:-2] if field.endswith(("_a", "_b")) else field
    if field in VOLATILE_FIELDS or base in VOLATILE_FIELDS:
        return "volatile"
    if field in INFO_FIELDS or base in INFO_FIELDS:
        return "info"
    return "drift"


# ---------------------------------------------------------------------------
# Granular field paths — so a changed list-of-dicts or nested dict reports the
# *element/leaf* that changed (``vlans[30].name: X -> Y``) instead of the whole
# opaque blob. Without this, a VLAN rename shows as ``vlans: [ ...huge list... ]``
# and the operator can't see what actually changed.
# ---------------------------------------------------------------------------
#: Field name -> the per-element key for list-of-dict fields we diff by element.
#: Explicit (not auto-detected) so a new keyed list is a deliberate addition.
_LIST_ELEMENT_KEYS: dict[str, str] = {
    "vlans": "vlan_id",
}


def _leaf_field(path: str) -> str:
    """Last segment of a granular path, for bucket classification.

    ``vlans[30].name`` -> ``name``; ``evidence.key_facts.count`` -> ``count``;
    ``msg_sent_b`` -> ``msg_sent_b``; ``vlans[40]`` -> ``vlans``.
    """
    last = path.rsplit(".", 1)[-1]
    return last.split("[", 1)[0]


def _granular_diffs(path: str, before: Any, after: Any, out: list[dict[str, Any]]) -> None:
    """Collect readable ``{field, before, after}`` diffs under ``path``.

    Recurses into dicts (by key) and into keyed lists of dicts (by element key,
    per :data:`_LIST_ELEMENT_KEYS`); everything else (scalars, string lists,
    non-keyed lists) is emitted as a single leaf entry. Volatile keys are
    dropped during dict recursion. Deterministic: keys sorted, element keys
    sorted by string form.
    """
    if _equal(before, after):
        return

    if isinstance(before, dict) and isinstance(after, dict):
        for k in sorted(set(before) | set(after)):
            if k in VOLATILE_FIELDS:
                continue
            _granular_diffs(f"{path}.{k}", before.get(k), after.get(k), out)
        return

    key_field = _LIST_ELEMENT_KEYS.get(_leaf_field(path))
    if (
        key_field
        and isinstance(before, list)
        and isinstance(after, list)
        and all(isinstance(x, dict) and key_field in x for x in before)
        and all(isinstance(x, dict) and key_field in x for x in after)
    ):
        b_idx = {x[key_field]: x for x in before}
        a_idx = {x[key_field]: x for x in after}
        for k in sorted(set(b_idx) | set(a_idx), key=lambda v: str(v)):
            _granular_diffs(f"{path}[{k}]", b_idx.get(k), a_idx.get(k), out)
        return

    out.append({"field": path, "before": before, "after": after})


def classify_field_changes(
    old: dict[str, Any], new: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compare two versions of the same entity, field by field.

    Returns ``(drift_fields, info_fields)`` — two lists of
    ``{"field", "before", "after"}`` dicts. Changed list-of-dict fields and
    nested dicts are expanded to granular paths (``vlans[30].name``) so each
    entry is readable; each is bucketed by its **leaf** field name. Volatile
    fields are ignored entirely. A field present on only one side counts as a
    change (``None`` on the missing side).

    The caller decides the entity's tier: any ``drift_fields`` → *changed*;
    else any ``info_fields`` → *info*; else no change.
    """
    drift: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []
    for field in sorted(set(old) | set(new)):
        if field_bucket(field) == "volatile":
            continue
        before = old.get(field)
        after = new.get(field)
        if _equal(before, after):
            continue
        entries: list[dict[str, Any]] = []
        _granular_diffs(field, before, after, entries)
        for entry in entries:
            bucket = field_bucket(_leaf_field(entry["field"]))
            if bucket == "volatile":
                continue
            (info if bucket == "info" else drift).append(entry)
    return drift, info
