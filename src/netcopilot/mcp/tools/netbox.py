"""NetBox declared-state tools (s11, ADR-0013).

Four tools over the L0 declared-state layer:

    get_netbox_device / get_netbox_site   — read live NetBox (adapter)
    list_netbox_pending_writes            — staged candidates awaiting approval (Neo4j)
    get_netbox_write_history              — the :NetBoxWrite append-only audit log (Neo4j)

All four are read-only; the write path (approve/reject) is CLI/route-driven and
gated by NETBOX_WRITE_ENABLED (Constitution Art. I). Absent NetBox
configuration → honest ``error`` (Article III), never a fake-empty answer.
"""

import json
import logging

from netcopilot.graph.client import get_driver, is_available
from netcopilot.mcp.result import ToolResult

log = logging.getLogger(__name__)


def _adapter_or_error() -> tuple[object | None, ToolResult | None]:
    """Build a NetBoxAdapter, or return the honest error ToolResult."""
    try:
        from netcopilot.declared_state import get_source
        return get_source("netbox"), None
    except Exception as exc:
        return None, ToolResult("error", (
            "NetBox is not available: "
            f"{exc} — set NETBOX_URL + NETBOX_API_TOKEN (and install the "
            "[netbox] extra) to enable declared-state queries."
        ))


async def get_netbox_device(*, name: str, context: dict) -> ToolResult:
    """Look up one device in NetBox (declared state) by name."""
    adapter, err = _adapter_or_error()
    if err:
        return err

    dev = adapter.get_device(name)
    if dev is None:
        return ToolResult("not_found", (
            f"Device '{name}' not found in NetBox. Declared state may not be "
            "populated yet — run the bootstrap, or check the exact device name."
        ))

    lines = [f"NetBox device: {dev['name']}"]
    for label, key in (
        ("Management IP", "mgmt_ip"), ("Role", "role"), ("Platform", "platform"),
        ("Site", "site"), ("Status", "status"), ("NetBox ID", "netbox_id"),
    ):
        if dev.get(key) is not None:
            lines.append(f"  {label}: {dev[key]}")
    return ToolResult("ok", "\n".join(lines), highlight={"device": dev["name"]})


async def get_netbox_site(*, slug: str, context: dict) -> ToolResult:
    """Look up one site in NetBox (declared state) by slug."""
    adapter, err = _adapter_or_error()
    if err:
        return err

    sites = adapter.get_sites()
    match = next((s for s in sites if s.get("slug") == slug), None)
    if match is None:
        known = ", ".join(sorted(s.get("slug", "?") for s in sites)) or "none"
        return ToolResult("not_found", (
            f"Site '{slug}' not found in NetBox. Known sites: {known}."
        ))
    return ToolResult("ok", (
        f"NetBox site: {match['name']} (slug: {match['slug']}, "
        f"NetBox ID: {match['netbox_id']})"
    ))


async def list_netbox_pending_writes(
    *,
    source: str | None = None,
    object_type: str | None = None,
    min_priority: int | None = None,
    limit: int = 25,
    context: dict,
) -> ToolResult:
    """List staged NetBox write candidates awaiting operator approval."""
    if not is_available():
        return ToolResult("error", "Neo4j is unavailable. Pending writes live in the graph database.")

    from netcopilot.declared_state.staging import list_pending

    rows = list_pending(source=source, object_type=object_type, min_priority=min_priority)
    if not rows:
        filters = " matching the filters" if (source or object_type or min_priority) else ""
        return ToolResult("no_data", (
            f"No pending NetBox writes{filters}. Either nothing is staged, or "
            "everything staged has been approved/rejected."
        ))

    shown = rows[:limit]
    lines = [f"Pending NetBox writes: {len(rows)} candidate(s)" +
             (f" (showing first {limit})" if len(rows) > limit else "")]
    for r in shown:
        name = ""
        payload = r.get("payload") or {}
        for key in ("name", "slug", "dedup_key", "address", "vid"):
            if payload.get(key):
                name = str(payload[key])
                break
        lines.append(
            f"  [{r.get('priority', '?'):>3}] {r.get('netbox_object_type', '?'):<16} "
            f"{name:<30} source={r.get('source', '?')} id={r.get('id', '?')[:8]}…"
        )
    lines.append("")
    lines.append("Approve/reject via the CLI (`netcopilot netbox approve <id> | --all`).")
    return ToolResult("ok", "\n".join(lines))


async def get_netbox_write_history(
    *,
    source: str | None = None,
    object_type: str | None = None,
    device: str | None = None,
    success_only: bool = False,
    since: str | None = None,
    limit: int = 20,
    context: dict,
) -> ToolResult:
    """Query the :NetBoxWrite append-only audit log (what NetCopilot wrote,
    when, and whether NetBox accepted it — failures and rejections included)."""
    if not is_available():
        return ToolResult("error", "Neo4j is unavailable. The NetBox write history lives in the graph database.")

    conditions: list[str] = []
    params: dict = {"limit": max(1, min(int(limit), 200))}
    if source:
        conditions.append("w.source = $source")
        params["source"] = source
    if object_type:
        conditions.append("w.netbox_object_type = $object_type")
        params["object_type"] = object_type
    if device:
        conditions.append("toLower(w.dedup_key) CONTAINS toLower($device)")
        params["device"] = device
    if success_only:
        conditions.append("w.api_response_status >= 200 AND w.api_response_status < 300")
    if since:
        conditions.append("w.timestamp >= $since")
        params["since"] = since

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    cypher = (
        f"MATCH (w:NetBoxWrite) {where} "
        "RETURN w ORDER BY w.timestamp DESC LIMIT $limit"
    )

    with get_driver().session() as session:
        rows = [dict(rec["w"]) for rec in session.run(cypher, **params)]

    if not rows:
        filters = " matching the filters" if conditions else ""
        return ToolResult("no_data", (
            f"No NetBox writes recorded{filters}. NetCopilot has not written "
            "to NetBox yet (or the writes were outside the filter window)."
        ))

    lines = [f"NetBox write history: {len(rows)} row(s), newest first"]
    for w in rows:
        status = w.get("api_response_status")
        if w.get("source") == "manual_reject":
            outcome = "REJECTED"
        elif status is not None and 200 <= int(status) < 300:
            outcome = f"OK {status}"
        else:
            outcome = f"FAILED {status}"
        lines.append(
            f"  {w.get('timestamp', '?')[:19]}  {outcome:<10} "
            f"{w.get('api_method') or '—':<5} {w.get('netbox_object_type', '?'):<16} "
            f"{w.get('dedup_key', '')} (source={w.get('source', '?')})"
        )
    return ToolResult("ok", "\n".join(lines))
