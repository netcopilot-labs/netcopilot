"""Findings helpers — load rule-engine findings from Neo4j and derive their device.

Neo4j-only in this build. The disk-ingestion path, synthetic DEVICE_UNREACHABLE
enrichment, and deprecated-rule filtering from the source live in later phases.
"""

from __future__ import annotations

import json
import logging
import re

from .graph.client import get_driver, get_site_for_run, is_available

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "low": 2, "cis": 3, "info": 4}


def _devices_from_element_id(element_id: str) -> list[str]:
    """Extract the device names referenced by a finding's element_id.

    Handles the documented element_id formats:
      "DEVICE/bgp/vrf/peer"      -> ["DEVICE"]
      "DEVICE:Interface"         -> ["DEVICE"]
      "DEVICE:Intf--DEVICE2:Intf"-> ["DEVICE", "DEVICE2"]
      "ntp::reason::D1,D2,D3"    -> ["D1", "D2", "D3"]
      "stp_..."                  -> []  (global)
      "fdb_mgmt_DEVICE_m2"       -> ["DEVICE"]
    """
    if not element_id:
        return []
    if element_id.startswith("stp_"):
        return []
    if element_id.startswith("ntp::"):
        parts = element_id.split("::")
        return [d.strip() for d in parts[2].split(",") if d.strip()] if len(parts) >= 3 else []
    if element_id.startswith("fdb_mgmt_"):
        core = element_id[len("fdb_mgmt_"):]
        if core.endswith(("_m1", "_m2")):
            core = core[:-3]
        return [core] if core else []
    if "--" in element_id:
        devices: list[str] = []
        for part in element_id.split("--"):
            if ":" in part:
                dev = part.split(":")[0]
                if dev and dev not in devices:
                    devices.append(dev)
        return devices
    if ":" in element_id and "/" in element_id:
        before_colon = element_id.split(":")[0]
        return [before_colon] if "/" not in before_colon else [element_id.split("/")[0]]
    if "/" in element_id:
        return [element_id.split("/")[0]]
    if ":" in element_id:
        dp = element_id.split(":")[0]
        return [dp] if dp else []
    return [element_id]


def device_from_finding(finding: dict) -> str | None:
    """Primary device for a finding (first device in its element_id), or None."""
    eid = finding.get("evidence", {}).get("element_id", "")
    if not eid:
        fid = finding.get("finding_id", "")
        if "::" in fid:
            eid = fid.split("::", 1)[1]
    devices = _devices_from_element_id(eid)
    return devices[0] if devices else None


# ── Device resolution helpers (used by MCP tools) ───────────────────────────


def resolve_device(name: str, run_id: str) -> str | None:
    """Resolve a device name with multiple strategies.

    Tries raw lowercase substring → regex-normalized (fwl01 → fwl-01) → raw
    substring. Works for any naming convention.
    """
    if not is_available():
        return None

    driver = get_driver()
    with driver.session() as session:
        filt = name.lower()
        rec = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE toLower(d.name) CONTAINS $filt "
            "RETURN d.name AS name LIMIT 1",
            run_id=run_id, filt=filt,
        ).single()
        if rec:
            return rec["name"]

        if '-' not in filt:
            filt2 = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
            rec = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt "
                "RETURN d.name AS name LIMIT 1",
                run_id=run_id, filt=filt2,
            ).single()
            if rec:
                return rec["name"]

        rec = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE toLower(d.name) CONTAINS toLower($name) "
            "RETURN d.name AS name LIMIT 1",
            run_id=run_id, name=name,
        ).single()
        if rec:
            return rec["name"]

    return None


def suggest_devices(name: str, run_id: str) -> str:
    """Return a helpful suggestion string when device resolution fails."""
    if not is_available():
        return ""
    try:
        with get_driver().session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) WHERE d.role IS NOT NULL "
                "RETURN d.name AS name ORDER BY d.name LIMIT 10",
                run_id=run_id,
            )
            names = [rec["name"] for rec in result]
        if names:
            return f" Available devices: {', '.join(names[:8])}{'...' if len(names) > 8 else ''}"
    except Exception:
        pass
    return ""


_role_cache: dict[tuple[str, str], str] = {}


def get_device_role(device: str, run_id: str) -> str:
    """Get a device's role from Neo4j (cached per (run_id, device))."""
    cache_key = (run_id, device)
    if cache_key in _role_cache:
        return _role_cache[cache_key]
    if not is_available():
        return "unknown"
    try:
        with get_driver().session() as session:
            rec = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $name}) RETURN d.role AS role",
                run_id=run_id, name=device,
            ).single()
            role = rec["role"] if rec and rec["role"] else "unknown"
    except Exception as exc:
        log.warning("Failed to get role for %s: %s", device, exc)
        role = "unknown"
    _role_cache[cache_key] = role
    return role


def is_security_device(device: str, run_id: str) -> bool:
    """True if a device is a security appliance (role-based, not hardcoded names)."""
    role = get_device_role(device, run_id).lower()
    return any(kw in role for kw in ("firewall", "fw", "security", "ips", "ids"))


def is_default_route(prefix: str) -> bool:
    """True if a prefix is a default route (IPv4 or IPv6)."""
    return prefix in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0")


# ── OS-family resolution (used by remediation lookup) ───────────────────────

_OS_FAMILY_MAP = {
    "iosxe": "ios_xe", "ios-xe": "ios_xe", "ios_xe": "ios_xe",
    "ios": "ios_xe",  # Plain "ios" defaults to ios_xe
    "iosxr": "iosxr", "ios-xr": "iosxr", "ios_xr": "iosxr",
    "nxos": "nxos", "nx-os": "nxos",
    "fortios": "fortios", "fortigate": "fortios",
    "eos": "eos",      # Arista (future)
    "junos": "junos",  # Juniper (future)
}

_os_cache: dict[tuple[str, str], str] = {}


def get_os_family(device: str, run_id: str) -> str:
    """Get the OS family for a device (cached). Returns 'generic' if unknown."""
    cache_key = (run_id, device)
    if cache_key in _os_cache:
        return _os_cache[cache_key]
    if not is_available():
        return "generic"
    os_family = "generic"
    try:
        with get_driver().session() as session:
            rec = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $name}) RETURN d.os_type AS os_type",
                run_id=run_id, name=device,
            ).single()
            if rec and rec["os_type"]:
                raw = (rec["os_type"] or "").lower()
                os_family = _OS_FAMILY_MAP.get(raw, raw) or "generic"
    except Exception as exc:
        log.warning("Failed to get OS family for %s: %s", device, exc)
    _os_cache[cache_key] = os_family
    return os_family


def get_os_map(run_id: str) -> dict[str, str]:
    """Get the OS family for ALL devices in a run (cached, batch query)."""
    if not is_available():
        return {}
    # If any device from this run is cached, assume all are.
    for key in _os_cache:
        if key[0] == run_id:
            return {k[1]: v for k, v in _os_cache.items() if k[0] == run_id}
    os_map: dict[str, str] = {}
    try:
        with get_driver().session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) RETURN d.name AS name, d.os_type AS os_type",
                run_id=run_id,
            )
            for rec in result:
                raw = (rec["os_type"] or "").lower()
                family = _OS_FAMILY_MAP.get(raw, raw) or "generic"
                os_map[rec["name"]] = family
                _os_cache[(run_id, rec["name"])] = family
    except Exception as exc:
        log.warning("Failed to batch load OS families: %s", exc)
    return os_map


def _finding_node_to_dict(rec: dict) -> dict:
    """Convert a Neo4j Finding node's properties to the dict shape consumers expect."""
    key_facts = {k[3:]: v for k, v in rec.items() if k.startswith("kf_") and v is not None}
    involved = rec.get("involved_devices")
    if involved:
        try:
            key_facts["involved_devices"] = (
                json.loads(involved) if isinstance(involved, str) else involved
            )
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "finding_id": rec.get("finding_id", ""),
        "rule_id": rec.get("rule_id", ""),
        "severity": rec.get("severity", "info"),
        "title": rec.get("title", ""),
        "message": rec.get("message", ""),
        "recommendation": rec.get("recommendation", ""),
        "detected_at": rec.get("detected_at", ""),
        "evidence": {
            "element_type": rec.get("element_type", "device"),
            "element_id": rec.get("element_id", ""),
            "key_facts": key_facts,
        },
        "acknowledged": rec.get("ack_reason") is not None,
        "acknowledged_reason": rec.get("ack_reason", ""),
        "cross_device": rec.get("cross_device", False),
    }


def _strip_deprecated_rules(findings: list[dict] | None) -> list[dict] | None:
    """Filter out findings whose rule has been retired (``is_enabled() → False``
    in code, listed in ``netcopilot.deprecated_rules.DEPRECATED_RULE_IDS``).

    Pre-existing findings from when the rule was still active remain in
    Neo4j / JSON for forensic purposes; this filter hides them from every
    dashboard surface that uses ``load_findings_enriched``.
    """
    if not findings:
        return findings
    from netcopilot.deprecated_rules import DEPRECATED_RULE_IDS
    return [f for f in findings if f.get("rule_id") not in DEPRECATED_RULE_IDS]


def load_findings_enriched(run_id: str) -> list[dict] | None:
    """Load Finding nodes for a run from Neo4j, with acknowledgement enrichment.

    Retired-rule findings (``DEPRECATED_RULE_IDS``) are filtered out.
    Returns None if Neo4j is unavailable, [] if the run has no findings.
    """
    if not is_available():
        return None
    try:
        site = get_site_for_run(run_id)
        with get_driver().session() as session:
            # Scope by (run_id, site): both are part of the multi-site node key, so a
            # run_id reused across sites cannot bleed findings between them.
            result = session.run(
                "MATCH (f:Finding {run_id: $run_id, site: $site}) "
                "OPTIONAL MATCH (a:Acknowledgement {site: $site, finding_id: f.finding_id}) "
                "RETURN properties(f) AS props, a.reason AS ack_reason",
                run_id=run_id,
                site=site or "",
            )
            findings = []
            for rec in result:
                props = dict(rec["props"])
                props["ack_reason"] = rec["ack_reason"]
                findings.append(_finding_node_to_dict(props))
            return _strip_deprecated_rules(findings)
    except Exception as exc:
        log.warning("Neo4j findings query failed: %s", exc)
        return None
