"""get_security_policies — Cisco ACLs, IOS XE route-maps / IOS XR route-policies, and prefix-lists / prefix-sets.

Cousin to `get_security_posture` (CIS-style settings) and `get_firewall_policies`
(FortiGate zone-based rules). Covers the Cisco slice the dashboard Security tab
renders for IOS XR border routers — ACLs with ACE detail (incl. DENY rows),
route-policies with their inline bodies, and prefix-sets with their CIDR entries.

Data source: Neo4j is the source of truth (same nodes the dashboard Security tab
reads). Works on both Cisco platforms (IOS XR via running-config; IOS XE via
genie ACL + parsed route-policy + parsed prefix-list facts).
"""

import logging

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_security_policies(
    *,
    device: str,
    kind: str = "all",
    name: str | None = None,
    context: dict,
) -> str:
    """Get ACLs, route-policies, and prefix-sets for a Cisco device.

    Args:
        device: device hostname (substring match, fuzzy resolution).
        kind: filter — "acl" | "route-policy" | "prefix-set" | "all" (default).
        name: optional substring match on the policy/ACL/prefix-set name.
        context: agent context (must contain run_id).

    Returns plain-English summary with sequence/action/source/dest detail
    for ACLs (DENY rows highlighted), inline body for IOS XR route-policies
    (or match/set clauses for IOS XE route-maps), and CIDR entries for
    prefix-sets/lists. Empty kinds are surfaced explicitly so the agent
    can tell "no ACLs configured" apart from "no data collected".
    """
    run_id = context.get("run_id", "")
    if not run_id:
        return "Error: run_id missing from context."

    if not is_available():
        return "Neo4j is unavailable. Cannot resolve device."

    # ── Device resolution (fuzzy match against Neo4j) ────────────────────
    driver = get_driver()
    import re
    filt = device.lower()
    if "-" not in filt:
        filt = re.sub(r"([a-z]{2,})(\d)", r"\1-\2", filt)
    with driver.session() as session:
        rec = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE toLower(d.name) CONTAINS $filt "
            "RETURN d.name AS name, d.os_type AS os, d.role AS role "
            "LIMIT 1",
            run_id=run_id, filt=filt,
        ).single()
    if not rec:
        return f"Device '{device}' not found. Use query_topology to list devices."
    resolved = rec["name"]
    os_type = rec["os"] or ""
    role = rec["role"] or ""

    # ── Data fetch: Neo4j is the source of truth ─────────────────────────
    # ACLs are :FirewallPolicy nodes (one per ACE, grouped by name);
    # route-policies are :RoutePolicy nodes; prefix-sets/lists are
    # :PrefixSetEntry nodes (one per entry, grouped by name). All three
    # were loaded by the graph loader. Same data the frontend Security tab renders.
    acls = _query_acls(driver, run_id, resolved)
    route_maps = _query_route_policies(driver, run_id, resolved)
    prefix_lists = _query_prefix_sets(driver, run_id, resolved)

    # ── Optional name-substring filter ───────────────────────────────────
    if name:
        n = name.lower()
        acls = [a for a in acls if n in a.get("name", "").lower()]
        route_maps = [r for r in route_maps if n in r.get("name", "").lower()]
        prefix_lists = [p for p in prefix_lists if n in p.get("name", "").lower()]

    # ── Render ───────────────────────────────────────────────────────────
    show_acls = kind in ("all", "acl")
    show_rp = kind in ("all", "route-policy", "route-map")
    show_ps = kind in ("all", "prefix-set", "prefix-list")

    lines: list[str] = [f"Security policies — {resolved} ({role} · {os_type})"]
    if name:
        lines.append(f"Filter: name contains '{name}'")
    lines.append("")

    if show_acls:
        lines.extend(_render_acls(acls))
    if show_rp:
        lines.extend(_render_route_policies(route_maps, os_type))
    if show_ps:
        lines.extend(_render_prefix_sets(prefix_lists))

    return "\n".join(lines).rstrip()


# ── Neo4j query helpers ───────────────────────────────────────────────────


def _query_acls(driver, run_id: str, device: str) -> list[dict]:
    """Return ACLs grouped by name, with ACE detail + applied_to bindings.
    Reads :FirewallPolicy nodes (one per ACE); `applied_to` is duplicated
    across ACEs sharing the same name (set during load), so we de-dup."""
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_POLICY]->(p:FirewallPolicy) "
            "WHERE p.acl_type IS NOT NULL "
            "RETURN p.name AS name, p.acl_type AS acl_type, p.policyid AS seq, "
            "p.action AS action, p.srcaddr AS source, p.dstaddr AS destination, "
            "p.service AS protocol, p.applied_to AS applied_to "
            "ORDER BY p.name, p.policyid",
            run_id=run_id, device=device,
        )
        by_name: dict[str, dict] = {}
        for rec in result:
            n = rec["name"]
            if n not in by_name:
                by_name[n] = {
                    "name": n,
                    "type": rec["acl_type"] or "?",
                    "aces": [],
                    "applied_to": list(rec["applied_to"] or []),
                }
            by_name[n]["aces"].append({
                "seq": rec["seq"],
                "action": rec["action"] or "?",
                "source": rec["source"] or "any",
                "destination": rec["destination"] or "any",
                "protocol": rec["protocol"] or "",
                "port": "",
            })
    return list(by_name.values())


def _query_route_policies(driver, run_id: str, device: str) -> list[dict]:
    """Return :RoutePolicy nodes for the device, incl. applied_to bindings."""
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_ROUTE_POLICY]->(rp:RoutePolicy) "
            "RETURN rp.name AS name, rp.body AS body, rp.applied_to AS applied_to "
            "ORDER BY rp.name",
            run_id=run_id, device=device,
        )
        return [
            {
                "name": rec["name"],
                "body": list(rec["body"] or []),
                "applied_to": list(rec["applied_to"] or []),
            }
            for rec in result
        ]


def _query_prefix_sets(driver, run_id: str, device: str) -> list[dict]:
    """Return prefix-sets / prefix-lists, grouping :PrefixSetEntry by name."""
    with driver.session() as session:
        result = session.run(
            "MATCH (d:Device {run_id: $run_id, name: $device})-[:HAS_PREFIX_ENTRY]->(e:PrefixSetEntry) "
            "RETURN e.name AS name, e.seq AS seq, e.action AS action, e.prefix AS prefix, "
            "e.referenced_by AS referenced_by "
            "ORDER BY e.name, e.seq",
            run_id=run_id, device=device,
        )
        by_name: dict[str, dict] = {}
        for rec in result:
            n = rec["name"]
            if n not in by_name:
                by_name[n] = {
                    "name": n,
                    "entries": [],
                    "referenced_by": list(rec["referenced_by"] or []),
                }
            by_name[n]["entries"].append({
                "seq": rec["seq"],
                "action": rec["action"] or "permit",
                "prefix": rec["prefix"] or "",
            })
    return list(by_name.values())


def _render_acls(acls: list[dict]) -> list[str]:
    if not acls:
        return ["ACLs: none configured (or no genie_acl.json for this device).", ""]
    out = [f"ACLs ({len(acls)}):"]
    for acl in acls:
        aces = acl.get("aces", [])
        deny_count = sum(1 for a in aces if a.get("action") == "deny")
        applied = acl.get("applied_to", [])
        # applied_to is list[str] from Neo4j (pre-formatted by loader).
        # Legacy tests may pass list[dict] (interface/direction); support both.
        applied_strs: list[str] = []
        for b in applied:
            if isinstance(b, dict):
                applied_strs.append(f"{b.get('intf', b.get('interface','?'))} {b.get('direction','?')}")
            else:
                applied_strs.append(str(b))
        applied_str = ", ".join(applied_strs) or "not applied to any interface"
        out.append(
            f"  - {acl['name']} [{acl.get('type','?')}, {len(aces)} ACEs, {deny_count} deny] — applied to: {applied_str}"
        )
        for ace in aces:
            seq = ace.get("seq", "?")
            action = ace.get("action", "?")
            src = ace.get("source", "any")
            dst = ace.get("destination", "any")
            proto = ace.get("protocol", "")
            port = ace.get("port", "")
            marker = "🛑" if action == "deny" else " "
            out.append(f"      {marker} seq {seq:>4} {action:<6} {proto:<5} src={src} dst={dst}{(' port=' + port) if port else ''}")
    out.append("")
    return out


def _render_route_policies(rps: list[dict], os_type: str) -> list[str]:
    if not rps:
        return ["Route-policies / route-maps: none configured.", ""]
    out = [f"Route-policies / route-maps ({len(rps)}):"]
    for rp in rps:
        applied = rp.get("applied_to", [])
        # applied_to is list[str] from Neo4j (pre-formatted by loader: "BGP <ip>
        # (<desc>) <dir>"). Support legacy list[dict] for backward-compat tests.
        applied_strs: list[str] = []
        for b in applied:
            if isinstance(b, dict):
                applied_strs.append(
                    f"BGP neighbor {b.get('peer', b.get('context','?'))} {b.get('direction','?')}"
                )
            else:
                applied_strs.append(str(b))
        applied_str = ", ".join(applied_strs) or "not applied to any BGP neighbor"
        out.append(f"  - {rp['name']} — applied to: {applied_str}")
        # IOS XR: inline body
        if rp.get("body"):
            for line in rp["body"]:
                out.append(f"      {line}")
        # IOS XE: structured sequences
        elif rp.get("sequences"):
            for seq in rp["sequences"]:
                out.append(f"      seq {seq.get('seq','?')} {seq.get('action','?')} match={seq.get('match',{})} set={seq.get('set',{})}")
    out.append("")
    return out


def _render_prefix_sets(pls: list[dict]) -> list[str]:
    if not pls:
        return ["Prefix-sets / prefix-lists: none configured.", ""]
    out = [f"Prefix-sets / prefix-lists ({len(pls)}):"]
    for pl in pls:
        refs = pl.get("referenced_by", [])
        refs_str = ", ".join(refs) or "not referenced by any route-policy"
        entries = pl.get("entries", [])
        out.append(f"  - {pl['name']} ({len(entries)} entries) — referenced by: {refs_str}")
        for entry in entries[:50]:  # cap to keep output manageable
            seq = entry.get("seq", "?")
            action = entry.get("action", "permit")
            prefix = entry.get("prefix", "?")
            out.append(f"      seq {seq:>4} {action:<6} {prefix}")
        if len(entries) > 50:
            out.append(f"      ... and {len(entries) - 50} more entries")
    out.append("")
    return out
