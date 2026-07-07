"""Staging machinery for NetBox write candidates (s11, ADR-0013).

Every NetBox write goes through this staging surface before any API call is
made — the non-bypassable pipeline Constitution Art. I requires. The pattern
is uniform across sources:

    bootstrap / excel_import / drift / manual
        |
        v
    stage_candidate(...)  -> :NetBoxPendingWrite node in Neo4j
        |
        v
    operator reviews (Reconcile UI, `list_netbox_pending_writes` tool, CLI)
        |
        +-- approve(id)  -> NetBox API write + :NetBoxWrite audit node
        +-- reject(id)   -> :NetBoxWrite audit row + :NetBoxPendingWrite deleted
        +-- modify(id, payload) -> :NetBoxPendingWrite.payload_json updated

Schema (Cypher CREATE-on-MERGE semantics — no migrations script needed):

    (:NetBoxPendingWrite {
        id: <uuid>,
        created_at: <iso datetime>,
        source: 'bootstrap' | 'excel_import' | 'drift' | 'manual',
        netbox_object_type: 'device' | 'interface' | 'manufacturer' |
                            'platform' | 'site' | 'vlan' | 'ipaddress' |
                            'cluster' | 'virtual_chassis' | 'inventory_item',
        payload_json: <serialised target NetBox payload>,
        reason: <human prose explaining why this candidate exists>,
        before_json: <null if creating; serialised existing object if updating>,
        priority: int 1-100
    })

Relationships (set when the related Neo4j node exists; warning logged if not —
the candidate still stages without the orphaned edge):

    (:NetBoxPendingWrite)-[:AFFECTS_DEVICE]->(:Device)
    (:NetBoxPendingWrite)-[:AFFECTS_INTERFACE]->(:Interface)
    (:NetBoxPendingWrite)-[:FROM_FINDING]->(:Finding)   — drift candidates
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from netcopilot.declared_state.gate import require_write_enabled
from netcopilot.graph.client import get_driver

log = logging.getLogger(__name__)


# ── Allowed enum values ──────────────────────────────────────────────────────

VALID_SOURCES = frozenset({"bootstrap", "excel_import", "drift", "manual", "manual_reject"})
VALID_OBJECT_TYPES = frozenset(
    {
        "device", "interface", "manufacturer", "platform", "site",
        "vlan", "ipaddress",
        "vrf", "prefix",    # s14: IPAM (ipam.vrfs / ipam.prefixes)
        "cable",            # s14: dcim.Cable from high-confidence links
        "cluster",          # dcim.Cluster for firewall HA pairs
        "virtual_chassis",  # dcim.VirtualChassis for switch stacks
        "inventory_item",   # dcim.InventoryItem for transceivers/SFPs
        "device_primary_ip",  # s15: PATCH device.primary_ip4 (the mgmt IP collection used)
    }
)

# ── Priority defaults ────────────────────────────────────────────────────────
#
# bootstrap / excel_import / manual default to 50; drift candidates derive
# their priority from the originating :Finding severity. Operators can
# override per-row in the Reconcile UI.

_DEFAULT_PRIORITY = 50

_DRIFT_SEVERITY_PRIORITY = {
    "critical": 80,
    "high": 70,
    "warning": 60,
    "info": 40,
}


def priority_for_drift(severity: str | None) -> int:
    """Return the default priority for a drift candidate.

    Falls back to :data:`_DEFAULT_PRIORITY` for unknown / missing severity
    so a malformed finding doesn't crash the staging path.
    """
    if not severity:
        return _DEFAULT_PRIORITY
    return _DRIFT_SEVERITY_PRIORITY.get(severity.lower(), _DEFAULT_PRIORITY)


# ── Index bootstrap ──────────────────────────────────────────────────────────

_INDEX_CYPHER = (
    "CREATE INDEX netbox_pending_write_id_idx IF NOT EXISTS "
    "FOR (p:NetBoxPendingWrite) ON (p.id)"
)


def ensure_index() -> None:
    """Create the (id) index on :NetBoxPendingWrite if missing (idempotent)."""
    with get_driver().session() as session:
        session.run(_INDEX_CYPHER)


_index_ensured = False


def _ensure_index_once() -> None:
    global _index_ensured
    if not _index_ensured:
        ensure_index()
        _index_ensured = True


# ── Public API ───────────────────────────────────────────────────────────────


def stage_candidate(
    *,
    source: str,
    object_type: str,
    payload: dict[str, Any],
    reason: str,
    before: dict[str, Any] | None = None,
    priority: int | None = None,
    drift_severity: str | None = None,
    affects_device_name: str | None = None,
    affects_device_site: str | None = None,
    affects_interface_id: str | None = None,
    from_finding_id: str | None = None,
    from_finding_run_id: str | None = None,
) -> str:
    """Create a :NetBoxPendingWrite node + wire its outgoing edges.

    Args:
        source: One of :data:`VALID_SOURCES`.
        object_type: One of :data:`VALID_OBJECT_TYPES`.
        payload: The intended NetBox payload for the eventual write
            (serialised to ``payload_json``).
        reason: Human-readable string explaining why this candidate exists.
        before: Pre-write NetBox object state (None if creating).
        priority: 1-100, higher = more urgent. If ``None``, defaults to
            :data:`_DEFAULT_PRIORITY`; for ``source='drift'``, derives from
            ``drift_severity``.
        drift_severity: Used when ``priority`` is None and ``source='drift'``.
        affects_device_name: If set, creates an ``AFFECTS_DEVICE`` edge to the
            LATEST :Device snapshot with this name (ordered by ``run_id``
            DESC). Pass ``affects_device_site`` alongside in multi-site
            graphs to avoid attaching to a same-named device elsewhere.
        affects_interface_id: If set, creates an ``AFFECTS_INTERFACE`` edge.
        from_finding_id: If set, creates a ``FROM_FINDING`` edge. Pass
            ``from_finding_run_id`` alongside to pin the edge to the exact
            run's Finding snapshot (finding_id repeats across runs); without
            it the LATEST snapshot is used — same convention as
            ``affects_device_name``/``affects_device_site``.

    Missing edge targets log WARN and the candidate stages without the edge.

    Returns:
        The new candidate's ``id`` (uuid string).

    Raises:
        ValueError: On invalid ``source`` / ``object_type`` / ``priority``.
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"Invalid source={source!r}. Valid: {sorted(VALID_SOURCES)}")
    if object_type not in VALID_OBJECT_TYPES:
        raise ValueError(
            f"Invalid object_type={object_type!r}. Valid: {sorted(VALID_OBJECT_TYPES)}"
        )

    if priority is None:
        if source == "drift":
            priority = priority_for_drift(drift_severity)
        else:
            priority = _DEFAULT_PRIORITY

    if not (1 <= priority <= 100):
        raise ValueError(f"priority must be in 1..100, got {priority}")

    _ensure_index_once()

    candidate_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    payload_json = json.dumps(payload, sort_keys=True, default=str)
    before_json = json.dumps(before, sort_keys=True, default=str) if before is not None else None

    with get_driver().session() as session:
        # Create the candidate node first; edges go in separate Cypher calls
        # so missing target nodes don't roll back the whole stage.
        session.run(
            """
            CREATE (p:NetBoxPendingWrite {
                id: $id,
                created_at: $created_at,
                source: $source,
                netbox_object_type: $object_type,
                payload_json: $payload_json,
                reason: $reason,
                before_json: $before_json,
                priority: $priority
            })
            """,
            id=candidate_id,
            created_at=now_iso,
            source=source,
            object_type=object_type,
            payload_json=payload_json,
            reason=reason,
            before_json=before_json,
            priority=priority,
        )

        if affects_device_name:
            # Pick the LATEST Device snapshot for this name (ordered by
            # run_id DESC) — Neo4j retains one :Device per pipeline run, so
            # an unconstrained MATCH would attach N edges per candidate.
            if affects_device_site:
                edge_cypher = (
                    "MATCH (p:NetBoxPendingWrite {id: $cid}) "
                    "MATCH (d:Device {name: $name, site: $site}) "
                    "WITH p, d ORDER BY d.run_id DESC LIMIT 1 "
                    "CREATE (p)-[:AFFECTS_DEVICE]->(d) RETURN count(d) AS n"
                )
                params = {"cid": candidate_id, "name": affects_device_name, "site": affects_device_site}
                desc = f"Device name={affects_device_name!r} site={affects_device_site!r}"
            else:
                edge_cypher = (
                    "MATCH (p:NetBoxPendingWrite {id: $cid}) "
                    "MATCH (d:Device {name: $name}) "
                    "WITH p, d ORDER BY d.run_id DESC LIMIT 1 "
                    "CREATE (p)-[:AFFECTS_DEVICE]->(d) RETURN count(d) AS n"
                )
                params = {"cid": candidate_id, "name": affects_device_name}
                desc = f"Device name={affects_device_name!r}"
            _attach_edge_or_warn(
                session, candidate_id, edge_cypher, params,
                edge_label="AFFECTS_DEVICE", target_desc=desc,
            )

        if affects_interface_id:
            _attach_edge_or_warn(
                session,
                candidate_id,
                "MATCH (p:NetBoxPendingWrite {id: $cid}), (i:Interface {id: $iid}) "
                "CREATE (p)-[:AFFECTS_INTERFACE]->(i) RETURN count(i) AS n",
                {"cid": candidate_id, "iid": affects_interface_id},
                edge_label="AFFECTS_INTERFACE",
                target_desc=f"Interface id={affects_interface_id!r}",
            )

        if from_finding_id:
            # Finding nodes carry `finding_id` (RULE::element), which repeats
            # across runs — pin to the caller's run when known, else the
            # LATEST snapshot (AFFECTS_DEVICE convention). (s13 fix: the
            # original Cypher matched a nonexistent `id` property, so the
            # edge never attached — latent since s11 because drift is the
            # first from_finding_id producer.)
            if from_finding_run_id:
                edge_cypher = (
                    "MATCH (p:NetBoxPendingWrite {id: $cid}) "
                    "MATCH (f:Finding {finding_id: $fid, run_id: $frun}) "
                    "WITH p, f LIMIT 1 "
                    "CREATE (p)-[:FROM_FINDING]->(f) RETURN count(f) AS n"
                )
            else:
                edge_cypher = (
                    "MATCH (p:NetBoxPendingWrite {id: $cid}) "
                    "MATCH (f:Finding {finding_id: $fid}) "
                    "WITH p, f ORDER BY f.run_id DESC LIMIT 1 "
                    "CREATE (p)-[:FROM_FINDING]->(f) RETURN count(f) AS n"
                )
            _attach_edge_or_warn(
                session,
                candidate_id,
                edge_cypher,
                {"cid": candidate_id, "fid": from_finding_id,
                 "frun": from_finding_run_id},
                edge_label="FROM_FINDING",
                target_desc=f"Finding finding_id={from_finding_id!r} run={from_finding_run_id!r}",
            )

    return candidate_id


def _attach_edge_or_warn(session, candidate_id: str, cypher: str, params: dict, edge_label: str, target_desc: str) -> None:
    """Attempt to create an edge; log WARN + skip if no target node."""
    result = session.run(cypher, **params).single()
    if not result or result["n"] == 0:
        log.warning(
            "stage_candidate(%s): no target node for %s edge to %s — candidate stages without the edge",
            candidate_id, edge_label, target_desc,
        )


def list_pending(
    *,
    source: str | None = None,
    object_type: str | None = None,
    min_priority: int | None = None,
) -> list[dict[str, Any]]:
    """Return pending candidates matching optional filters.

    Returns dicts mirroring the node's property set with ``payload`` and
    ``before`` deserialised from JSON. Sorted by priority DESC, created_at
    DESC (the Reconcile UI default).
    """
    where_clauses: list[str] = []
    params: dict[str, Any] = {}
    if source is not None:
        where_clauses.append("p.source = $source")
        params["source"] = source
    if object_type is not None:
        where_clauses.append("p.netbox_object_type = $object_type")
        params["object_type"] = object_type
    if min_priority is not None:
        where_clauses.append("p.priority >= $min_priority")
        params["min_priority"] = min_priority

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cypher = (
        f"MATCH (p:NetBoxPendingWrite) {where} "
        "RETURN p ORDER BY p.priority DESC, p.created_at DESC"
    )

    rows: list[dict[str, Any]] = []
    with get_driver().session() as session:
        for record in session.run(cypher, **params):
            node = record["p"]
            row = dict(node)
            row["payload"] = json.loads(row.pop("payload_json", "null"))
            before_json = row.pop("before_json", None)
            row["before"] = json.loads(before_json) if before_json else None
            rows.append(row)
    return rows


def modify(candidate_id: str, new_payload: dict[str, Any]) -> bool:
    """Update a candidate's payload + bump ``last_modified``.

    Returns True if a candidate was updated, False if not found.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(new_payload, sort_keys=True, default=str)

    with get_driver().session() as session:
        result = session.run(
            "MATCH (p:NetBoxPendingWrite {id: $id}) "
            "SET p.payload_json = $payload_json, p.last_modified = $last_modified "
            "RETURN count(*) AS n",
            id=candidate_id,
            payload_json=payload_json,
            last_modified=now_iso,
        ).single()
    return bool(result and result["n"] > 0)


# ─────────────────────────────────────────────────────────────────────────────
# Approve path + :NetBoxWrite audit + reject audit
# ─────────────────────────────────────────────────────────────────────────────

# NetBox object_type → (pynetbox app, endpoint attribute)
_NETBOX_ENDPOINT_MAP = {
    "site":            ("dcim",           "sites"),
    "cluster":         ("virtualization", "clusters"),
    "virtual_chassis": ("dcim",           "virtual_chassis"),
    "manufacturer":    ("dcim",           "manufacturers"),
    "platform":        ("dcim",           "platforms"),
    "device":          ("dcim",           "devices"),
    "interface":       ("dcim",           "interfaces"),
    "inventory_item":  ("dcim",           "inventory_items"),
    "vrf":             ("ipam",           "vrfs"),
    "vlan":            ("ipam",           "vlans"),
    "prefix":          ("ipam",           "prefixes"),
    "ipaddress":       ("ipam",           "ip_addresses"),
    "cable":           ("dcim",           "cables"),
    "device_primary_ip": ("dcim",         "devices"),  # s15: PATCHes the Device record
}

# Bulk approve writes parents before dependents. virtual_chassis precedes
# device so member Devices can reference it via FK; inventory_item comes last
# (depends on device + interface existing).
_TOPOLOGICAL_ORDER = (
    "site", "vrf", "vlan", "prefix",
    "cluster", "virtual_chassis", "manufacturer", "platform",
    "device", "interface", "ipaddress", "device_primary_ip", "inventory_item", "cable",
)

# Mirror of bootstrap's dedup-key fields — kept in sync but local to avoid
# the circular import bootstrap → staging would create.
_AUDIT_DEDUP_KEY_FIELD = {
    "site": "slug",
    "manufacturer": "name",
    "platform": "slug",
    "device": "name",
    "interface": "dedup_key",
    "cluster": "name",
    "virtual_chassis": "name",
    "vrf": "name",
    "vlan": "dedup_key",        # "<site>::<vid>"
    "prefix": "dedup_key",      # "<vrf-or-global>::<cidr>"
    "ipaddress": "address",     # CIDR string is globally unique enough here
    "cable": "dedup_key",       # order-independent "<a>--<b>" termination pair
    "inventory_item": "dedup_key",  # device::iface::serial (set at stage time)
    "device_primary_ip": "device",  # one primary IP per (member) device (s15)
}

# Hardcoded operator until multi-user has a real driver.
_DEFAULT_OPERATOR = "admin"

_AUDIT_INDEX_DEDUP = (
    "CREATE INDEX idx_netbox_write_dedup IF NOT EXISTS "
    "FOR (w:NetBoxWrite) ON (w.netbox_object_type, w.dedup_key)"
)
_AUDIT_INDEX_TIMESTAMP = (
    "CREATE INDEX idx_netbox_write_timestamp IF NOT EXISTS "
    "FOR (w:NetBoxWrite) ON (w.timestamp)"
)

_audit_index_ensured = False


def ensure_audit_index() -> None:
    """Create the :NetBoxWrite indexes (idempotent)."""
    with get_driver().session() as session:
        session.run(_AUDIT_INDEX_DEDUP)
        session.run(_AUDIT_INDEX_TIMESTAMP)


def _ensure_audit_index_once() -> None:
    global _audit_index_ensured
    if not _audit_index_ensured:
        ensure_audit_index()
        _audit_index_ensured = True


class AuthAbortError(RuntimeError):
    """Raised on NetBox 401/403 — caller MUST abort the bulk run.

    Continuing after auth failure would flood the audit log with identical
    failure rows. The bulk approve loop catches this and stops.
    """


class AlreadyApprovedError(RuntimeError):
    """Raised when the candidate is no longer pending (raced approve)."""


def _read_pending(candidate_id: str) -> dict[str, Any] | None:
    """Read a :NetBoxPendingWrite as a dict, or None if it doesn't exist."""
    with get_driver().session() as session:
        result = session.run(
            "MATCH (p:NetBoxPendingWrite {id: $id}) RETURN p",
            id=candidate_id,
        ).single()
    if not result:
        return None
    return dict(result["p"])


def _atomic_delete_pending(candidate_id: str) -> bool:
    """Atomically detach-delete the pending node.

    Returns True iff the node existed and was deleted by THIS call. False
    means a concurrent approve/reject already cleaned it up — caller treats
    this as "lost the race; the audit row is still the durable record".
    """
    with get_driver().session() as session:
        result = session.run(
            "MATCH (p:NetBoxPendingWrite {id: $id}) DETACH DELETE p RETURN count(*) AS n",
            id=candidate_id,
        ).single()
    return bool(result and result["n"] > 0)


def _dedup_key_for_audit(object_type: str, payload: dict[str, Any]) -> str:
    """Derive the natural-key string for :NetBoxWrite(netbox_object_type, dedup_key)."""
    field = _AUDIT_DEDUP_KEY_FIELD.get(object_type)
    if not field:
        return ""
    value = payload.get(field)
    return str(value) if value is not None else ""


def _create_audit_row(
    pending: dict[str, Any],
    write_result: dict[str, Any],
    *,
    source_override: str | None = None,
) -> str:
    """Create a :NetBoxWrite audit node.

    Append-only: never mutate existing rows. Failure writes also produce a
    row so the operator can see what was attempted.
    """
    _ensure_audit_index_once()
    audit_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        payload = json.loads(pending.get("payload_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        payload = {}

    dedup_key = _dedup_key_for_audit(pending["netbox_object_type"], payload)

    reason_base = pending.get("reason", "") or ""
    reason_append = write_result.get("reason_append", "") or ""
    reason_final = (reason_base + reason_append).strip()

    with get_driver().session() as session:
        session.run(
            """
            CREATE (w:NetBoxWrite {
                id: $id,
                timestamp: $timestamp,
                operator: $operator,
                source: $source,
                netbox_object_type: $object_type,
                netbox_object_id: $netbox_object_id,
                dedup_key: $dedup_key,
                before_json: $before_json,
                after_json: $after_json,
                api_method: $api_method,
                api_response_status: $api_response_status,
                pending_id: $pending_id,
                finding_id: $finding_id,
                reason: $reason
            })
            """,
            id=audit_id,
            timestamp=now_iso,
            operator=_DEFAULT_OPERATOR,
            source=source_override or pending["source"],
            object_type=pending["netbox_object_type"],
            netbox_object_id=write_result.get("netbox_object_id"),
            dedup_key=dedup_key,
            before_json=pending.get("before_json"),
            after_json=write_result.get("after_json"),
            api_method=write_result.get("api_method"),
            api_response_status=write_result.get("api_response_status"),
            pending_id=pending["id"],
            finding_id=None,  # drift (s13) wires this for source=drift
            reason=reason_final,
        )
    return audit_id


def _get_pynetbox_endpoint(adapter, object_type: str):
    """Return the pynetbox endpoint object for a NetBox object_type."""
    if object_type not in _NETBOX_ENDPOINT_MAP:
        raise ValueError(
            f"object_type={object_type!r} has no NetBox endpoint mapping. "
            f"Known: {sorted(_NETBOX_ENDPOINT_MAP)}"
        )
    app, endpoint = _NETBOX_ENDPOINT_MAP[object_type]
    nb = adapter._nb  # NetBoxAdapter exposes pynetbox.api as ._nb
    return getattr(getattr(nb, app), endpoint)


def _extract_http_status(exc) -> int | None:
    """Best-effort HTTP status extraction from a pynetbox.RequestError."""
    for attr_chain in (
        ("req", "status_code"),
        ("response", "status_code"),
        ("status_code",),
    ):
        target = exc
        ok = True
        for attr in attr_chain:
            if hasattr(target, attr):
                target = getattr(target, attr)
            else:
                ok = False
                break
        if ok and isinstance(target, int):
            return target
    return None


def _extract_error_body(exc) -> str:
    """Best-effort error body extraction from a pynetbox.RequestError."""
    for attr in ("error", "message"):
        if hasattr(exc, attr):
            value = getattr(exc, attr)
            if value:
                return str(value)
    return str(exc)


def _record_to_after_json(record) -> str:
    """Convert a pynetbox record (after-write state) to a JSON string."""
    try:
        if hasattr(record, "serialize"):  # pynetbox 7.x
            return json.dumps(record.serialize(), sort_keys=True, default=str)
        return json.dumps(dict(record), sort_keys=True, default=str)
    except Exception:
        return json.dumps({"_unserialisable": True, "repr": repr(record)})


def _write_to_netbox(
    adapter,
    object_type: str,
    payload: dict[str, Any],
    *,
    is_update: bool = False,
    existing_id: int | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Single NetBox POST/PATCH with the locked 5-class failure taxonomy.

    THE write choke point — gated by ``NETBOX_WRITE_ENABLED`` (Constitution
    Art. I): raises ``WritesDisabled`` before any API interaction when the
    deployment has not opted in.

    Returns a result dict regardless of outcome:
        {
            "api_method": "POST" | "PATCH",
            "api_response_status": int,           # HTTP status or 0 on network
            "netbox_object_id": int | None,
            "after_json": str | None,
            "reason_append": str,                 # appended to audit row's reason
        }

    Behavior matrix:
        * 2xx success     → success result
        * 409 Conflict    → GET by natural key → wrap as auto-resolved success
        * 400 "already exists" (NetBox 4.6 unique collision) → same auto-resolve
        * Other 4xx       → failure result (no retry)
        * 5xx / network   → retry once with 2s backoff; then failure result
        * 401/403 auth    → raise AuthAbortError (bulk caller stops)
    """
    import time

    require_write_enabled(f"NetBox {'PATCH' if is_update else 'POST'} ({object_type})")

    endpoint = _get_pynetbox_endpoint(adapter, object_type)
    api_method = "PATCH" if is_update else "POST"

    # inventory_item writes need the parent Interface's NetBox id resolved at
    # write time so the InventoryItem attaches to the right interface, not
    # just the device. The candidate carries `_resolve_interface_name` as a
    # non-NetBox hint field; translate it to component_type + component_id
    # here, then drop the hint before POST.
    if object_type == "inventory_item" and not is_update:
        payload = dict(payload)  # don't mutate caller's dict
        iface_name = payload.pop("_resolve_interface_name", None)
        if iface_name and "component_id" not in payload:
            device_name = payload.get("_resolve_device_name") or payload.pop("_resolve_device_name", None)
            if not device_name:
                dev = payload.get("device") or {}
                device_name = dev.get("name") if isinstance(dev, dict) else dev
            iface = _resolve_interface_for_inventory_item(adapter, device_name, iface_name)
            if iface is not None:
                payload["component_type"] = "dcim.interface"
                payload["component_id"] = iface.id
        payload.pop("_resolve_device_name", None)

    # ipaddress writes assign to an Interface: resolve the FK from the
    # `device::interface` hint at write time (same pattern as inventory_item).
    if object_type == "ipaddress" and not is_update:
        payload = dict(payload)
        dev_name = payload.pop("_resolve_device_name", None)
        iface_name = payload.pop("_resolve_interface_name", None)
        if dev_name and iface_name and "assigned_object_id" not in payload:
            iface = _resolve_interface_for_inventory_item(adapter, dev_name, iface_name)
            if iface is None:
                # An unassigned IP silently loses the assignment intent —
                # fail retryably instead (interfaces write first in bulk, so
                # this only happens when the interface candidate is missing).
                return {
                    "api_method": "POST",
                    "api_response_status": 422,
                    "netbox_object_id": None,
                    "after_json": None,
                    "reason_append": (
                        f" — interface {dev_name}/{iface_name} not found in NetBox; "
                        "approve the interface candidate first, then retry"
                    ),
                }
            payload["assigned_object_type"] = "dcim.interface"
            payload["assigned_object_id"] = iface.id

    # cable writes terminate on two Interfaces: resolve both FKs from hints.
    # An unresolvable end is a hard skip (a mis-terminated cable is worse
    # than a failed candidate) — returned as a 4xx-style failed outcome.
    if object_type == "cable" and not is_update:
        payload = dict(payload)
        ends = {}
        for side in ("a", "b"):
            dev_name = payload.pop(f"_resolve_{side}_device", None)
            iface_name = payload.pop(f"_resolve_{side}_interface", None)
            if dev_name and iface_name:
                iface = _resolve_interface_for_inventory_item(adapter, dev_name, iface_name)
                if iface is not None:
                    ends[side] = [{"object_type": "dcim.interface", "object_id": iface.id}]
        if "a_terminations" not in payload or "b_terminations" not in payload:
            if "a" in ends and "b" in ends:
                payload["a_terminations"] = ends["a"]
                payload["b_terminations"] = ends["b"]
            else:
                missing = [side for side in ("a", "b") if side not in ends]
                return {
                    "api_method": "POST",
                    "api_response_status": 422,
                    "netbox_object_id": None,
                    "after_json": None,
                    "reason_append": (
                        f" — cable termination(s) {missing} could not be resolved "
                        "to NetBox interfaces; approve the device/interface "
                        "candidates first, then retry"
                    ),
                }

    # device_primary_ip (s15) PATCHes an existing Device's primary_ip4 with the
    # NetBox id of an already-written IPAddress. Both FKs resolve at write time
    # (same pattern as ipaddress/cable hints); unresolvable → retryable 422.
    # Non-destructive by construction: a primary IP already present in NetBox
    # is KEPT — the candidate completes as a no-op with the reason recorded.
    if object_type == "device_primary_ip":
        payload = dict(payload)
        dev_name = payload.pop("device", None)
        address = payload.pop("address", None)
        if not dev_name or not address:
            return {
                "api_method": "PATCH", "api_response_status": 400,
                "netbox_object_id": None, "after_json": None,
                "reason_append": " — malformed candidate: needs device + address",
            }
        try:
            dev_rec = adapter._nb.dcim.devices.get(name=dev_name)
        except Exception:
            dev_rec = None
        if dev_rec is None:
            return {
                "api_method": "PATCH", "api_response_status": 422,
                "netbox_object_id": None, "after_json": None,
                "reason_append": (
                    f" — device {dev_name!r} not found in NetBox; approve the "
                    "device candidate first, then retry"
                ),
            }
        if getattr(dev_rec, "primary_ip4", None) is not None:
            return {
                "api_method": "PATCH", "api_response_status": 200,
                "netbox_object_id": dev_rec.id,
                "after_json": _record_to_after_json(dev_rec),
                "reason_append": (
                    f" — primary_ip4 is already {dev_rec.primary_ip4} in NetBox; "
                    "kept (an operator's value is never overwritten)"
                ),
            }
        try:
            ip_candidates = list(adapter._nb.ipam.ip_addresses.filter(address=address))
        except Exception:
            ip_candidates = []
        own, foreign_owner = None, None
        for rec in ip_candidates:
            assigned = getattr(rec, "assigned_object", None)
            owner_rec = getattr(assigned, "device", None) if assigned is not None else None
            owner = str(getattr(owner_rec, "name", "")) if owner_rec is not None else None
            if owner == dev_name:
                own = rec
                break
            if owner:
                foreign_owner = owner
        if own is None:
            if foreign_owner:
                hint = (
                    f" — {address} is assigned to {foreign_owner!r}, not {dev_name!r}; "
                    "fix the assignment in NetBox, then retry"
                )
            elif ip_candidates:
                hint = (
                    f" — {address} exists in NetBox but is not assigned to an "
                    f"interface of {dev_name!r} (NetBox requires the assignment); "
                    "approve/fix the ipaddress candidate first, then retry"
                )
            else:
                hint = (
                    f" — {address} not found in NetBox; approve the ipaddress "
                    "candidate first, then retry"
                )
            return {
                "api_method": "PATCH", "api_response_status": 422,
                "netbox_object_id": None, "after_json": None,
                "reason_append": hint,
            }
        is_update, existing_id = True, dev_rec.id
        api_method = "PATCH"
        payload = {"primary_ip4": own.id}

    def _attempt() -> dict[str, Any]:
        """Single write attempt — returns a result dict OR re-raises pynetbox/network errors."""
        if is_update:
            existing = endpoint.get(existing_id) if existing_id else None
            if existing is None:
                return {
                    "api_method": "PATCH",
                    "api_response_status": 404,
                    "netbox_object_id": None,
                    "after_json": None,
                    "reason_append": f" — PATCH target id={existing_id!r} not found in NetBox",
                }
            existing.update(payload)
            return {
                "api_method": "PATCH",
                "api_response_status": 200,
                "netbox_object_id": existing.id,
                "after_json": _record_to_after_json(existing),
                "reason_append": "",
            }
        created = endpoint.create(**payload)
        return {
            "api_method": "POST",
            "api_response_status": 201,
            "netbox_object_id": created.id,
            "after_json": _record_to_after_json(created),
            "reason_append": "",
        }

    for attempt in (1, 2):
        try:
            return _attempt()
        except Exception as exc:  # noqa: BLE001 — branch by type below
            status = _extract_http_status(exc)
            body = _extract_error_body(exc)

            # 401 / 403 → abort whole bulk
            if status in (401, 403):
                raise AuthAbortError(
                    f"NetBox returned HTTP {status} — token is invalid or lacks permission. {body}"
                ) from exc

            # 409 → auto-resolve via natural-key GET
            if status == 409:
                dedup_key = _dedup_key_for_audit(object_type, payload)
                try:
                    existing = _resolve_by_natural_key(adapter, object_type, dedup_key, payload)
                except Exception as resolve_exc:
                    return {
                        "api_method": api_method,
                        "api_response_status": 409,
                        "netbox_object_id": None,
                        "after_json": json.dumps({"error": body, "resolve_error": str(resolve_exc)}),
                        "reason_append": " — 409 conflict, natural-key resolution failed",
                    }
                if existing is not None:
                    return {
                        "api_method": api_method,
                        "api_response_status": 200,
                        "netbox_object_id": existing.id,
                        "after_json": _record_to_after_json(existing),
                        "reason_append": " — 409 auto-resolved via natural-key GET",
                    }
                return {
                    "api_method": api_method,
                    "api_response_status": 409,
                    "netbox_object_id": None,
                    "after_json": json.dumps({"error": body}),
                    "reason_append": " — 409 conflict, natural key not found",
                }

            # Other 4xx → NetBox 4.6 signals unique collisions as 400 + "already
            # exists" in the body; auto-resolve those, fail the rest (no retry).
            if status is not None and 400 <= status < 500:
                if status == 400 and "already exists" in body.lower():
                    dedup_key = _dedup_key_for_audit(object_type, payload)
                    try:
                        existing = _resolve_by_natural_key(adapter, object_type, dedup_key, payload)
                    except Exception:
                        existing = None
                    if existing is not None:
                        return {
                            "api_method": api_method,
                            "api_response_status": 200,
                            "netbox_object_id": existing.id,
                            "after_json": _record_to_after_json(existing),
                            "reason_append": " — 400 'already exists' auto-resolved via natural-key GET",
                        }
                return {
                    "api_method": api_method,
                    "api_response_status": status,
                    "netbox_object_id": None,
                    "after_json": json.dumps({"error": body}),
                    "reason_append": f" — HTTP {status} client error (no retry)",
                }

            # 5xx / network / timeout → retry once then fail
            if attempt == 1:
                log.warning(
                    "NetBox %s %s attempt 1 failed (status=%s): %s — retrying after 2s",
                    api_method, object_type, status, body,
                )
                time.sleep(2.0)
                continue
            return {
                "api_method": api_method,
                "api_response_status": status if status is not None else 0,
                "netbox_object_id": None,
                "after_json": json.dumps({"error": body, "phase": "after_retry"}),
                "reason_append": " — retried once, still failing (transient or NetBox down)",
            }

    # Unreachable in normal flow; defensive return for type checkers.
    return {
        "api_method": api_method,
        "api_response_status": 0,
        "netbox_object_id": None,
        "after_json": None,
        "reason_append": " — unexpected loop exit",
    }


def _resolve_interface_for_inventory_item(adapter, device_name: str, iface_name: str):
    """Find a NetBox Interface on ``device_name`` matching ``iface_name``.

    Strategies in order: (1) exact ``name=`` match; (2) case-insensitive
    contains; (3) Cisco short-form expansion (``Te1/1/1`` → walk the device's
    interfaces, match prefix family + slot-path suffix). Returns the pynetbox
    Interface record or None — in which case the InventoryItem still writes,
    just attached at Device level (no component link).
    """
    nb = adapter._nb

    # 1. Exact match
    try:
        iface = nb.dcim.interfaces.get(device=device_name, name=iface_name)
        if iface is not None:
            return iface
    except Exception:
        pass

    # 2. Case-insensitive contains (NetBox name__ic filter)
    try:
        candidates = list(nb.dcim.interfaces.filter(device=device_name, name__ic=iface_name))
        if len(candidates) == 1:
            return candidates[0]
    except Exception:
        pass

    # 3. Short-form expansion
    import re as _re
    m = _re.match(r"^([A-Za-z]+)([\d/]+)$", iface_name)
    if not m:
        return None
    short_prefix, slot_path = m.group(1), m.group(2)

    family_starts = {
        "te": ("teng", "tenge"),       # TenGigE / TenGigabitEthernet
        "hu": ("hundredgig",),         # HundredGigE / HundredGigabitEthernet
        "tw": ("twentyfivegig",),      # TwentyFiveGigE
        "fo": ("fortygig",),           # FortyGigE
        "gi": ("gigabitethernet",),    # GigabitEthernet
        "fa": ("fastethernet",),       # FastEthernet
        "et": ("ethernet",),           # Ethernet
        "fou": ("fourhundredgig",),    # FourHundredGigE
    }
    family = family_starts.get(short_prefix.lower())
    if not family:
        return None

    try:
        all_ifaces = list(nb.dcim.interfaces.filter(device=device_name))
    except Exception:
        return None

    for cand in all_ifaces:
        name_lower = str(cand.name).lower()
        if not name_lower.startswith(family):
            continue
        if name_lower.endswith(slot_path):
            return cand
    return None


def _resolve_by_natural_key(adapter, object_type: str, dedup_key: str, payload: dict[str, Any]):
    """Return the existing NetBox record matching the natural key, or None."""
    endpoint = _get_pynetbox_endpoint(adapter, object_type)
    field = _AUDIT_DEDUP_KEY_FIELD.get(object_type)
    if not field or not dedup_key:
        return None

    if object_type == "site":
        return endpoint.get(slug=dedup_key)
    if object_type == "manufacturer":
        return endpoint.get(name=dedup_key)
    if object_type == "platform":
        return endpoint.get(slug=dedup_key)
    if object_type == "cluster":
        return endpoint.get(name=dedup_key)
    if object_type == "virtual_chassis":
        return endpoint.get(name=dedup_key)
    if object_type == "device":
        return endpoint.get(name=dedup_key)
    if object_type == "interface":
        # interface dedup_key is "<device>::<name>"; split + filter by both
        if "::" in dedup_key:
            device, iface_name = dedup_key.split("::", 1)
            return endpoint.get(device=device, name=iface_name)
        return endpoint.get(name=dedup_key)
    if object_type == "inventory_item":
        # inventory_item dedup_key is "<device>::<iface>::<serial>"
        parts = dedup_key.split("::", 2)
        if len(parts) == 3:
            device, _iface, serial = parts
            try:
                return endpoint.get(device=device, serial=serial)
            except Exception:
                return None
        return None
    if object_type == "vrf":
        return endpoint.get(name=dedup_key)
    if object_type == "vlan":
        # vlan dedup_key is "<site>::<vid>"
        if "::" in dedup_key:
            site, vid = dedup_key.split("::", 1)
            try:
                return endpoint.get(site=site, vid=int(vid))
            except Exception:
                return None
        return None
    if object_type == "prefix":
        # prefix dedup_key is "<vrf-or-global>::<cidr>"
        if "::" in dedup_key:
            vrf, cidr = dedup_key.split("::", 1)
            try:
                if vrf == "global":
                    return endpoint.get(prefix=cidr, vrf_id="null")
                return endpoint.get(prefix=cidr, vrf=vrf)
            except Exception:
                return None
        return None
    if object_type == "ipaddress":
        return endpoint.get(address=dedup_key)
    # cable: no reliable natural-key GET (terminations aren't filterable by
    # a simple key) — a duplicate surfaces as a failed outcome, not silently.
    return None


def approve(candidate_id: str, *, adapter=None) -> dict[str, Any] | None:
    """Approve one pending candidate: write to NetBox + audit + delete pending.

    Args:
        candidate_id: The :NetBoxPendingWrite.id to approve.
        adapter: Optional :class:`NetBoxAdapter`. If None, constructed from
            env vars.

    Returns:
        A result dict on terminal outcome:
            {"outcome": "success" | "auto_resolved" | "failed",
             "audit_id": str,
             "api_response_status": int,
             "netbox_object_id": int | None}
        OR None if the candidate is no longer pending (race / already
        rejected — not an error).

    Raises:
        WritesDisabled: when ``NETBOX_WRITE_ENABLED`` is not ``true``.
        AuthAbortError: on NetBox 401/403. Bulk caller MUST stop.
    """
    pending = _read_pending(candidate_id)
    if pending is None:
        return None

    if adapter is None:
        from netcopilot.declared_state import get_source
        adapter = get_source("netbox")

    object_type = pending["netbox_object_type"]
    payload = json.loads(pending["payload_json"])
    is_update = bool(pending.get("before_json"))
    existing_id = None
    if is_update:
        before = json.loads(pending["before_json"])
        existing_id = before.get("id") if isinstance(before, dict) else None

    write_result = _write_to_netbox(
        adapter, object_type, payload,
        is_update=is_update, existing_id=existing_id,
    )

    audit_id = _create_audit_row(pending, write_result)
    status = write_result["api_response_status"]
    is_success = 200 <= status < 300

    if is_success:
        # Delete pending atomically; a lost race is fine — the audit row is
        # the durable record.
        _atomic_delete_pending(candidate_id)
        outcome = "auto_resolved" if "auto-resolved" in (write_result.get("reason_append") or "") else "success"
    else:
        outcome = "failed"  # pending stays; operator can modify + retry
        # Stamp WHY it failed onto the candidate so the Reconcile row can show
        # it inline — the NetBox error otherwise only lived in the audit log.
        _stamp_pending_failure(candidate_id, write_result)

    return {
        "outcome": outcome,
        "audit_id": audit_id,
        "api_response_status": status,
        "netbox_object_id": write_result.get("netbox_object_id"),
    }


def _humanize_netbox_error(write_result: dict[str, Any]) -> str:
    """A one-line, operator-readable rendering of a failed write.

    NetBox nests validation errors as JSON-in-JSON
    (``{"error": "{\\"__all__\\": [\\"Duplicate termination …\\"]}"}``); flatten
    them to ``HTTP 400: Duplicate termination found for dcim.interface 1086:
    cable 53``. Falls back to the reason_append when there's no structured body.
    """
    status = write_result.get("api_response_status")
    body = write_result.get("after_json")
    parts: list[str] = []
    if body:
        try:
            outer = json.loads(body)
            err = outer.get("error", outer) if isinstance(outer, dict) else outer
            if isinstance(err, str):
                try:
                    err = json.loads(err)
                except (ValueError, TypeError):
                    pass
            if isinstance(err, dict):
                for field, msgs in err.items():
                    msgs = msgs if isinstance(msgs, list) else [msgs]
                    label = "" if field in ("__all__", "error", "detail") else f"{field}: "
                    parts.extend(f"{label}{m}" for m in msgs)
            elif isinstance(err, list):
                parts.extend(str(m) for m in err)
            else:
                parts.append(str(err))
        except (ValueError, TypeError):
            parts.append(str(body)[:200])
    msg = "; ".join(str(p) for p in parts if p)
    if not msg:
        msg = (write_result.get("reason_append") or "").strip(" —") or "no detail"
    return f"HTTP {status}: {msg}"


def _stamp_pending_failure(candidate_id: str, write_result: dict[str, Any]) -> None:
    """Record the last failed-write reason on the pending node (Reconcile UI)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_driver().session() as session:
        session.run(
            "MATCH (p:NetBoxPendingWrite {id: $id}) "
            "SET p.last_write_status = $status, "
            "    p.last_write_error = $error, "
            "    p.last_attempt_at = $at",
            id=candidate_id,
            status=write_result.get("api_response_status"),
            error=_humanize_netbox_error(write_result),
            at=now_iso,
        )


def approve_bulk(
    *,
    source: str | None = None,
    object_type: str | None = None,
    min_priority: int | None = None,
    ids: list[str] | None = None,
    adapter=None,
    progress_callback=None,
) -> dict[str, Any]:
    """Approve multiple pending candidates in topological order.

    Args:
        source / object_type / min_priority: filters (mirror :func:`list_pending`).
        ids: Optional explicit id list; overrides the filter set.
        adapter: Optional :class:`NetBoxAdapter`.
        progress_callback: Optional ``callable(event_dict)`` invoked once per
            candidate AND once for ``"complete"`` / ``"aborted"`` — drives the
            SSE stream in the routes layer (s12).

    Returns:
        Summary dict:
            {"written": int, "auto_resolved": int, "failed": int,
             "aborted": bool, "abort_reason": str | None,
             "failed_ids": [str], "duration_ms": int, "total": int}

    Never raises :class:`AuthAbortError` — returns ``aborted=True`` with
    ``abort_reason`` instead, so callers handle uniformly.
    """
    import time as _time

    if adapter is None:
        from netcopilot.declared_state import get_source
        adapter = get_source("netbox")

    if ids:
        candidates = [_read_pending(cid) for cid in ids]
        candidates = [c for c in candidates if c is not None]
    else:
        rows = list_pending(source=source, object_type=object_type, min_priority=min_priority)
        # list_pending deserialises payloads; re-read by id for the raw shape.
        candidates = [_read_pending(r["id"]) for r in rows]
        candidates = [c for c in candidates if c is not None]

    # Topological sort: parents before dependents
    ordering = {t: i for i, t in enumerate(_TOPOLOGICAL_ORDER)}
    candidates.sort(
        key=lambda c: (
            ordering.get(c["netbox_object_type"], 99),
            -int(c.get("priority", 50)),
            c.get("created_at", ""),
        )
    )

    started = _time.monotonic()
    written = 0
    auto_resolved = 0
    failed = 0
    failed_ids: list[str] = []
    aborted = False
    abort_reason: str | None = None
    total = len(candidates)

    for position, pending in enumerate(candidates, start=1):
        if progress_callback:
            progress_callback({
                "event": "progress",
                "data": {
                    "candidate_id": pending["id"],
                    "dedup_key": _dedup_key_for_audit(
                        pending["netbox_object_type"],
                        json.loads(pending.get("payload_json") or "{}"),
                    ),
                    "object_type": pending["netbox_object_type"],
                    "status": "writing",
                    "position": position,
                    "total": total,
                },
            })

        try:
            result = approve(pending["id"], adapter=adapter)
        except AuthAbortError as exc:
            aborted = True
            abort_reason = f"auth_{_extract_http_status(exc) or '401_or_403'}"
            if progress_callback:
                progress_callback({
                    "event": "aborted",
                    "data": {
                        "reason": abort_reason,
                        "written_before_abort": written + auto_resolved,
                        "remaining": total - position + 1,
                    },
                })
            break

        if result is None:
            # raced — someone else already approved/rejected
            failed += 1
            failed_ids.append(pending["id"])
            status = "raced"
            netbox_object_id = None
        else:
            status_code = result["api_response_status"]
            netbox_object_id = result.get("netbox_object_id")
            if result["outcome"] == "success":
                written += 1
                status = "success"
            elif result["outcome"] == "auto_resolved":
                auto_resolved += 1
                status = "auto_resolved_409"
            else:
                failed += 1
                failed_ids.append(pending["id"])
                if status_code and 400 <= status_code < 500:
                    status = "failed_4xx"
                elif status_code and 500 <= status_code < 600:
                    status = "failed_5xx"
                else:
                    status = "failed_unknown"

        if progress_callback:
            progress_callback({
                "event": "progress",
                "data": {
                    "candidate_id": pending["id"],
                    "object_type": pending["netbox_object_type"],
                    "status": status,
                    "netbox_object_id": netbox_object_id,
                    "position": position,
                    "total": total,
                },
            })

    duration_ms = int((_time.monotonic() - started) * 1000)
    summary = {
        "written": written,
        "auto_resolved": auto_resolved,
        "failed": failed,
        "aborted": aborted,
        "abort_reason": abort_reason,
        "failed_ids": failed_ids,
        "duration_ms": duration_ms,
        "total": total,
    }

    if progress_callback and not aborted:
        progress_callback({"event": "complete", "data": summary})

    return summary


def reject(candidate_id: str) -> bool:
    """Delete a pending candidate + write a :NetBoxWrite audit row.

    The audit row (source=``manual_reject``, api_method=None,
    api_response_status=None) keeps the operator-decision record complete
    even for rejected candidates; drift queries filter to 2xx statuses so
    rejection rows never pollute the "what's in NetBox" view. Rejects are
    NOT write-gated — no NetBox API call is made.

    Returns:
        True iff a candidate was deleted, False if not found.
    """
    pending = _read_pending(candidate_id)
    if pending is None:
        return False

    # Audit first so the record survives even if the DELETE races.
    _create_audit_row(
        pending,
        write_result={
            "api_method": None,
            "api_response_status": None,
            "netbox_object_id": None,
            "after_json": None,
            "reason_append": " — rejected by operator (no NetBox API call made)",
        },
        source_override="manual_reject",
    )

    return _atomic_delete_pending(candidate_id)


def reject_bulk(
    *,
    source: str | None = None,
    object_type: str | None = None,
    min_priority: int | None = None,
    ids: list[str] | None = None,
) -> dict[str, Any]:
    """Reject multiple pending candidates. Each writes a :NetBoxWrite row.

    Returns:
        Summary dict: ``{"rejected": int, "not_found": int, "total": int}``.
    """
    if ids:
        target_ids = list(ids)
    else:
        rows = list_pending(source=source, object_type=object_type, min_priority=min_priority)
        target_ids = [r["id"] for r in rows]

    rejected = 0
    not_found = 0
    for cid in target_ids:
        if reject(cid):
            rejected += 1
        else:
            not_found += 1

    return {"rejected": rejected, "not_found": not_found, "total": len(target_ids)}
