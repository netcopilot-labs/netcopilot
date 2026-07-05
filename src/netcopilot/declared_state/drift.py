"""Drift detection: declared state (NetBox) vs observed state (a collected run).

s13 (ADR-0015). Compares what the declared-state source says the network is
against what a collected run shows, and emits ``INTENT_*`` findings in the
standard :class:`~netcopilot.rules.finding.Finding` shape.

Architecture: drift runs OUTSIDE the rules engine. ``run_rules`` is hermetic
over the run directory — that property backs the golden-master harness — so a
check that reads a live external source cannot live inside it. Drift is an
on-demand post-load step (CLI ``netcopilot netbox drift`` / MCP
``run_drift_check``): it writes a ``drift/drift_findings.json`` artifact into
the run directory and loads ``:Finding`` nodes for the run via the same
loader path engine findings use (``load_findings_list``), after deleting only
the previous ``INTENT_*`` rows — re-running drift refreshes, never duplicates,
and never touches engine findings.

The observed side is derived from the same inputs bootstrap uses (inventory +
``device_facts.json`` + ``genie_interface.json``) via bootstrap's own helper
functions — one derivation, two consumers, so drift compares like-for-like
with what bootstrap would stage.

Honesty rule (s08 discipline): the declared source is probed first
(``adapter.ping()``); an unreachable NetBox raises
:class:`DriftSourceUnavailable` — it is never reported as "0 drift".
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netcopilot.declared_state import get_source
from netcopilot.declared_state.bootstrap import (
    _INTERFACE_NAME_KEY_PATTERN,
    _OS_TO_PLATFORM,
    _attribute_interface_to_position,
    _is_cisco_stack,
    _is_fortigate_ha,
    _load_cluster_members,
    _master_position,
    _member_device_name,
    _runs_dir,
)
from netcopilot.inventory.base import normalize_os
from netcopilot.rules.finding import Finding

log = logging.getLogger(__name__)


class DriftSourceUnavailable(RuntimeError):
    """The declared-state source cannot be read — drift is UNKNOWN, not zero."""


# Interface attributes compared by INTENT_INTERFACE_ATTR_DRIFT. ``type`` is
# deliberately excluded: NetBox returns the display label ("1000BASE-T (1GE)")
# while bootstrap stages the slug value ("1000base-t") — comparing them would
# manufacture permanent false drift.
_IFACE_ATTRS = ("enabled", "description", "mtu", "mac_address")


@dataclass
class DriftReport:
    """Result of one drift check."""

    run_id: str
    declared_source: str
    findings: list[Finding] = field(default_factory=list)
    devices_checked: int = 0
    interfaces_checked: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def counts_by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.rule_id] = out.get(f.rule_id, 0) + 1
        return out

    @property
    def quiet(self) -> bool:
        return not self.findings

    def format_summary(self) -> str:
        if self.quiet:
            return (
                f"No drift: declared state matches run {self.run_id!r} "
                f"({self.devices_checked} devices, {self.interfaces_checked} interfaces checked)."
            )
        lines = [
            f"Drift detected: {len(self.findings)} finding(s) against run {self.run_id!r} "
            f"({self.devices_checked} devices, {self.interfaces_checked} interfaces checked):"
        ]
        for rule_id, n in sorted(self.counts_by_rule.items()):
            lines.append(f"  {rule_id}: {n}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────── observed side


def _derive_observed(run_id: str, inventory_path: str | Path, warnings: list[str]) -> dict[str, Any]:
    """Derive the observed per-physical-device view from inventory + run facts.

    Mirrors bootstrap's derivation (member expansion, interface attribution,
    field sourcing) by calling its helpers — the comparison must be
    like-for-like with what bootstrap would stage.

    Returns ``{"devices": {name: {...}}, "interfaces": {device: {iface: {...}}},
    "sites": set[str]}``.
    """
    yaml_adapter = get_source("yaml", inventory_path=inventory_path)
    yaml_devices = yaml_adapter.get_devices()

    facts_dir = _runs_dir() / run_id / "facts"
    if not facts_dir.is_dir():
        raise FileNotFoundError(f"facts dir not found for run {run_id!r} at {facts_dir}")

    devices: dict[str, dict[str, Any]] = {}
    interfaces: dict[str, dict[str, dict[str, Any]]] = {}
    sites: set[str] = set()

    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue

        os_name = normalize_os(dev.get("os") or "")
        members = _load_cluster_members(name, run_id)
        is_stack = _is_cisco_stack(os_name, members)
        is_ha = _is_fortigate_ha(os_name, members)

        yaml_site = dev.get("site")
        site_slug = yaml_site.lower() if isinstance(yaml_site, str) else None
        if site_slug:
            sites.add(site_slug)
        platform_name = _OS_TO_PLATFORM.get(os_name, (None, None))[1]

        info_serial = None
        info_platform = None
        facts_file = facts_dir / name / "device_facts.json"
        if facts_file.is_file():
            try:
                _d = json.loads(facts_file.read_text(encoding="utf-8"))
                info = _d.get("device_info") or {}
                info_serial = info.get("serial")
                info_platform = info.get("platform")
            except json.JSONDecodeError:
                warnings.append(f"{name}: device_facts.json malformed — serial/platform not compared")

        if not is_stack and not is_ha:
            devices[name] = {
                "inventory_name": name,
                "site": site_slug,
                "platform": platform_name,
                "serial": info_serial,
            }
        else:
            for idx, member in enumerate(members):
                position = idx + 1
                member_name = _member_device_name(name, position)
                devices[member_name] = {
                    "inventory_name": name,
                    "site": site_slug,
                    "platform": platform_name,
                    "serial": member.get("serial_number"),
                }

        # Interfaces — same attribution rule as bootstrap
        iface_file = facts_dir / name / "genie_interface.json"
        if not iface_file.is_file():
            warnings.append(f"{name}: genie_interface.json missing — interfaces not compared")
            continue
        try:
            data = json.loads(iface_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            warnings.append(f"{name}: genie_interface.json malformed ({exc}) — interfaces not compared")
            continue
        if not isinstance(data, dict):
            continue

        for iface_name, iface_data in data.items():
            if not _INTERFACE_NAME_KEY_PATTERN.match(iface_name):
                continue
            if is_stack:
                target = _member_device_name(name, _attribute_interface_to_position(iface_name, members))
            elif is_ha:
                target = _member_device_name(name, _master_position(members))
            else:
                target = name
            interfaces.setdefault(target, {})[iface_name] = {
                "enabled": bool(iface_data.get("enabled", True)),
                "description": iface_data.get("description") or "",
                "mtu": iface_data.get("mtu"),
                "mac_address": iface_data.get("mac_address") or iface_data.get("phys_address"),
            }

    return {"devices": devices, "interfaces": interfaces, "sites": sites}


# ─────────────────────────────────────────────────────────────── comparators


def _norm_mac(mac: str | None) -> str | None:
    """Normalise a MAC to bare lowercase hex — NetBox stores AA:BB:…, genie aabb.ccdd.…"""
    if not mac:
        return None
    hexonly = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    return hexonly or None


def _finding(rule_id: str, severity: str, title: str, message: str,
             element_id: str, key_facts: dict[str, Any], recommendation: str) -> Finding:
    return Finding(
        finding_id=f"{rule_id}::{element_id}",
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        evidence={"element_type": "device", "element_id": element_id, "key_facts": key_facts},
        recommendation=recommendation,
        detected_at=datetime.now(timezone.utc).isoformat(),
    )


def _compare_devices(observed: dict[str, Any], declared_devices: list[dict],
                     report: DriftReport) -> None:
    obs = observed["devices"]
    sites = observed["sites"]
    decl = {d["name"]: d for d in declared_devices}
    # MISSING_IN_NETWORK is scoped to the inventory's site(s): a multi-site
    # NetBox must not flood a single-site run with noise. Name matches stay
    # site-agnostic — a device declared at the wrong site is SITE_DRIFT,
    # not UNKNOWN_IN_NETBOX.
    decl_in_scope = {
        n for n, d in decl.items()
        if (d.get("site") or "").lower() in sites or not sites
    }

    report.devices_checked = len(set(obs) | decl_in_scope)

    for name in sorted(set(obs) - set(decl)):
        report.findings.append(_finding(
            "INTENT_DEVICE_UNKNOWN_IN_NETBOX", "low",
            "Device not documented in NetBox",
            f"Device '{name}' was collected from the network but has no NetBox record.",
            name,
            {"device": name, "inventory_name": obs[name]["inventory_name"]},
            "Stage it via bootstrap (Reconcile tab → Bootstrap from run) or add it in NetBox.",
        ))

    for name in sorted(decl_in_scope - set(obs)):
        report.findings.append(_finding(
            "INTENT_DEVICE_MISSING_IN_NETWORK", "high",
            "Declared device absent from the network",
            f"NetBox declares device '{name}' (site {decl[name].get('site')}), "
            f"but it does not appear in the collected run.",
            name,
            {"device": name, "declared_site": decl[name].get("site"),
             "declared_platform": decl[name].get("platform")},
            "Verify the device is up and reachable, and that the inventory covers it. "
            "If it was decommissioned, retire it in NetBox.",
        ))

    for name in sorted(set(obs) & set(decl)):
        o, d = obs[name], decl[name]

        if d.get("serial") and o.get("serial") and d["serial"] != o["serial"]:
            report.findings.append(_finding(
                "INTENT_SERIAL_DRIFT", "high",
                "Serial number drift (possible hardware swap)",
                f"Device '{name}': NetBox declares serial {d['serial']!r}, "
                f"the network shows {o['serial']!r}.",
                name,
                {"device": name, "declared": d["serial"], "observed": o["serial"]},
                "Confirm whether the chassis was replaced; update NetBox to the observed serial.",
            ))

        if d.get("platform") and o.get("platform") and d["platform"] != o["platform"]:
            report.findings.append(_finding(
                "INTENT_PLATFORM_DRIFT", "low",
                "Platform drift",
                f"Device '{name}': NetBox declares platform {d['platform']!r}, "
                f"observed OS maps to {o['platform']!r}.",
                name,
                {"device": name, "declared": d["platform"], "observed": o["platform"]},
                "Update the NetBox platform to match the observed operating system.",
            ))

        if d.get("site") and o.get("site") and d["site"].lower() != o["site"].lower():
            report.findings.append(_finding(
                "INTENT_SITE_DRIFT", "low",
                "Site drift",
                f"Device '{name}': NetBox places it at site {d['site']!r}, "
                f"the inventory says {o['site']!r}.",
                name,
                {"device": name, "declared": d["site"], "observed": o["site"]},
                "Move the device to the correct site in NetBox (or fix the inventory).",
            ))


def _compare_interfaces(observed: dict[str, Any], adapter, declared_names: set[str],
                        report: DriftReport) -> None:
    for device, obs_ifaces in sorted(observed["interfaces"].items()):
        if device not in declared_names:
            # Device-level finding already covers it; per-interface noise helps nobody.
            continue
        decl_ifaces = {i["name"]: i for i in adapter.get_interfaces(device)}
        report.interfaces_checked += len(set(obs_ifaces) | set(decl_ifaces))

        missing = sorted(set(decl_ifaces) - set(obs_ifaces))
        unknown = sorted(set(obs_ifaces) - set(decl_ifaces))
        drifted: dict[str, dict[str, Any]] = {}

        for iface in sorted(set(obs_ifaces) & set(decl_ifaces)):
            o, d = obs_ifaces[iface], decl_ifaces[iface]
            diffs: dict[str, Any] = {}
            for attr in _IFACE_ATTRS:
                ov, dv = o.get(attr), d.get(attr)
                if attr == "mac_address":
                    ov, dv = _norm_mac(ov), _norm_mac(dv)
                if attr == "description":
                    ov, dv = ov or "", dv or ""
                if ov is None or dv is None:
                    continue  # one side undeclared → nothing to compare
                if ov != dv:
                    diffs[attr] = {"declared": d.get(attr), "observed": o.get(attr)}
            if diffs:
                drifted[iface] = diffs

        if missing:
            report.findings.append(_finding(
                "INTENT_INTERFACE_MISSING_IN_NETWORK", "low",
                "Declared interfaces absent from the network",
                f"Device '{device}': {len(missing)} interface(s) declared in NetBox "
                f"were not observed in the run: {', '.join(missing[:10])}"
                + (" …" if len(missing) > 10 else "") + ".",
                device,
                {"device": device, "interfaces": json.dumps(missing)},
                "Verify the interfaces exist (module removed?); retire stale records in NetBox.",
            ))
        if unknown:
            report.findings.append(_finding(
                "INTENT_INTERFACE_UNKNOWN_IN_NETBOX", "info",
                "Observed interfaces not documented in NetBox",
                f"Device '{device}': {len(unknown)} observed interface(s) have no NetBox "
                f"record: {', '.join(unknown[:10])}" + (" …" if len(unknown) > 10 else "") + ".",
                device,
                {"device": device, "interfaces": json.dumps(unknown)},
                "Stage them via bootstrap (idempotent) to complete the documentation.",
            ))
        if drifted:
            report.findings.append(_finding(
                "INTENT_INTERFACE_ATTR_DRIFT", "info",
                "Interface attribute drift",
                f"Device '{device}': {len(drifted)} interface(s) differ from their NetBox "
                f"record on {', '.join(sorted({a for d_ in drifted.values() for a in d_}))}.",
                device,
                {"device": device, "drift": json.dumps(drifted)},
                "Review each attribute; use [Update NetBox] to stage the observed values.",
            ))


# ─────────────────────────────────────────────────────────────── entry point


def run_drift_check(
    run_id: str,
    inventory_path: str | Path,
    *,
    adapter=None,
    load: bool = True,
    driver=None,
) -> DriftReport:
    """Compare declared state against a collected run and emit INTENT_* findings.

    Args:
        run_id: Run directory under ``RUNS_DIR`` to compare against.
        inventory_path: Inventory YAML the run was collected from.
        adapter: Optional :class:`DeclaredStateSource` (defaults to NetBox
            from env). Must expose ``ping()`` — unreachability raises
            :class:`DriftSourceUnavailable`, never "0 drift".
        load: When True, persist findings: write
            ``<run>/drift/drift_findings.json`` and reload the run's
            ``INTENT_*`` :Finding rows in Neo4j (delete-then-load, engine
            findings untouched).
        driver: Optional Neo4j driver (defaults to the shared client).

    Returns:
        :class:`DriftReport`.
    """
    if adapter is None:
        adapter = get_source("netbox")

    try:
        adapter.ping()
    except Exception as exc:
        raise DriftSourceUnavailable(
            f"Declared-state source unreachable — drift is unknown, not zero: {exc}"
        ) from exc

    warnings: list[str] = []
    observed = _derive_observed(run_id, inventory_path, warnings)

    report = DriftReport(run_id=run_id, declared_source=type(adapter).__name__)
    report.warnings = warnings

    declared_devices = adapter.get_devices()
    _compare_devices(observed, declared_devices, report)
    declared_names = {d["name"] for d in declared_devices}
    _compare_interfaces(observed, adapter, declared_names, report)

    log.info("Drift check for %s: %d findings", run_id, len(report.findings))

    if load:
        _persist(report)

    return report


class NotCorrectable(ValueError):
    """The finding carries no NetBox correction NetCopilot can stage."""


# Rules whose observed value can be staged as a NetBox correction. The rest
# are informational: MISSING_IN_NETWORK means NetBox is right or the network
# is broken (a write would paper over it); the UNKNOWN/MISSING interface and
# device rules are creates already covered by the idempotent bootstrap.
_CORRECTABLE_RULES = {
    "INTENT_SERIAL_DRIFT",
    "INTENT_PLATFORM_DRIFT",
    "INTENT_SITE_DRIFT",
    "INTENT_INTERFACE_ATTR_DRIFT",
}

_PLATFORM_NAME_TO_SLUG = {name: slug for slug, name in _OS_TO_PLATFORM.values()}


def stage_correction(finding_id: str, run_id: str, *, adapter=None) -> dict[str, Any]:
    """Stage the NetBox correction(s) for one INTENT_* drift finding.

    Reads the loaded :Finding row, re-reads the declared object live (fresh
    NetBox ids, guards stale findings), and stages update candidate(s) with
    ``source='drift'``, priority derived from the finding severity, and a
    ``FROM_FINDING`` edge. Idempotent: an already-pending candidate for the
    same object is skipped, not duplicated.

    Returns:
        ``{"staged": int, "skipped": int, "candidate_ids": [str, ...]}``

    Raises:
        KeyError: finding not found for the run.
        NotCorrectable: the rule has no stageable correction.
        DriftSourceUnavailable: NetBox unreachable.
    """
    from netcopilot.declared_state.staging import (
        _dedup_key_for_audit,
        list_pending,
        stage_candidate,
    )
    from netcopilot.graph.client import get_driver

    with get_driver().session() as session:
        record = session.run(
            "MATCH (f:Finding {finding_id: $fid, run_id: $run_id}) RETURN f LIMIT 1",
            fid=finding_id, run_id=run_id,
        ).single()
    if record is None:
        raise KeyError(f"No finding {finding_id!r} for run {run_id!r}")
    f = dict(record["f"])

    rule_id = f.get("rule_id", "")
    if rule_id not in _CORRECTABLE_RULES:
        raise NotCorrectable(
            f"{rule_id or finding_id} has no stageable NetBox correction — "
            "creates go through bootstrap; MISSING_IN_NETWORK needs a human decision."
        )

    device = f.get("device") or f.get("element_id")
    site = f.get("site")
    severity = f.get("severity")

    if adapter is None:
        adapter = get_source("netbox")
    try:
        adapter.ping()
    except Exception as exc:
        raise DriftSourceUnavailable(
            f"Declared-state source unreachable — cannot stage a correction: {exc}"
        ) from exc

    pending_keys = {
        (r["netbox_object_type"],
         _dedup_key_for_audit(r["netbox_object_type"], r.get("payload") or {}))
        for r in list_pending(source="drift")
    }

    staged: list[str] = []
    skipped = 0

    def _stage(object_type: str, payload: dict, before: dict, reason: str,
               affects_interface_id: str | None = None) -> None:
        nonlocal skipped
        key = (object_type, _dedup_key_for_audit(object_type, payload))
        if key in pending_keys:
            skipped += 1
            return
        staged.append(stage_candidate(
            source="drift",
            object_type=object_type,
            payload=payload,
            before=before,
            reason=reason,
            drift_severity=severity,
            affects_device_name=device,
            affects_device_site=site,
            affects_interface_id=affects_interface_id,
            from_finding_id=finding_id,
            from_finding_run_id=run_id,
        ))

    if rule_id in ("INTENT_SERIAL_DRIFT", "INTENT_PLATFORM_DRIFT", "INTENT_SITE_DRIFT"):
        declared = adapter.get_device(device)
        if declared is None:
            raise KeyError(f"Device {device!r} no longer exists in NetBox — re-run the drift check.")
        observed = f.get("kf_observed")
        if observed is None:
            raise NotCorrectable(f"{finding_id}: finding carries no observed value.")

        payload: dict[str, Any] = {"name": device}
        if rule_id == "INTENT_SERIAL_DRIFT":
            payload["serial"] = observed
        elif rule_id == "INTENT_PLATFORM_DRIFT":
            slug = _PLATFORM_NAME_TO_SLUG.get(observed)
            if slug is None:
                raise NotCorrectable(
                    f"{finding_id}: observed platform {observed!r} maps to no known slug."
                )
            payload["platform"] = {"slug": slug}
        else:
            payload["site"] = {"slug": observed.lower()}

        _stage(
            "device", payload,
            before={**declared, "id": declared["netbox_id"]},
            reason=f"{rule_id}: update NetBox to the observed value ({observed!r})",
        )

    else:  # INTENT_INTERFACE_ATTR_DRIFT
        try:
            drifted: dict[str, dict] = json.loads(f.get("kf_drift") or "{}")
        except json.JSONDecodeError as exc:
            raise NotCorrectable(f"{finding_id}: malformed drift evidence: {exc}") from exc
        if not drifted:
            raise NotCorrectable(f"{finding_id}: finding carries no per-interface drift detail.")

        decl_ifaces = {i["name"]: i for i in adapter.get_interfaces(device)}
        for iface_name, attrs in drifted.items():
            decl = decl_ifaces.get(iface_name)
            if decl is None:
                skipped += 1
                continue  # interface gone from NetBox since detection
            payload = {
                "device": {"name": device},
                "name": iface_name,
                "dedup_key": f"{device}::{iface_name}",
            }
            for attr, vals in attrs.items():
                payload[attr] = vals.get("observed")
            _stage(
                "interface", payload,
                before={**decl, "id": decl["netbox_id"]},
                reason=(f"{rule_id}: {iface_name} — update "
                        f"{', '.join(sorted(attrs))} to the observed value(s)"),
            )

    return {"staged": len(staged), "skipped": skipped, "candidate_ids": staged}


def _persist(report: DriftReport) -> None:
    """Write the drift artifact + refresh the run's INTENT_* :Finding rows."""
    run_dir = _runs_dir() / report.run_id
    drift_dir = run_dir / "drift"
    drift_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "run_id": report.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "declared_source": report.declared_source,
            "devices_checked": report.devices_checked,
            "interfaces_checked": report.interfaces_checked,
            "total_findings": len(report.findings),
            "counts_by_rule": report.counts_by_rule,
            "warnings": report.warnings,
        },
        "findings": [f.to_dict() for f in report.findings],
    }
    (drift_dir / "drift_findings.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )

    from netcopilot.graph.client import get_driver, get_site_for_run, is_available
    from netcopilot.graph.loader import (
        _SEVERITY_MAP,
        _clean_properties,
        _derive_category,
        _flatten_key_facts,
        load_findings_list,
    )

    if not is_available():
        report.warnings.append(
            "Neo4j unavailable — drift findings written to the run artifact only, "
            "not visible in the dashboard until loaded."
        )
        return

    driver = get_driver()
    site = get_site_for_run(report.run_id)
    if site is None:
        report.warnings.append(
            f"Run {report.run_id!r} is not loaded in Neo4j — drift findings written "
            "to the run artifact only. Load the run first (netcopilot run / load)."
        )
        return

    # MISSING_IN_NETWORK findings describe devices that by definition have no
    # :Device node in the run — the shared loader's MATCH would silently drop
    # them. They load as standalone :Finding nodes (the read path queries
    # Finding {run_id, site} directly, so they stay visible everywhere).
    attached = [f.to_dict() for f in report.findings
                if f.rule_id != "INTENT_DEVICE_MISSING_IN_NETWORK"]
    unattached = [f for f in report.findings
                  if f.rule_id == "INTENT_DEVICE_MISSING_IN_NETWORK"]

    with driver.session() as session:
        session.run(
            "MATCH (f:Finding {run_id: $run_id, site: $site}) "
            "WHERE f.rule_id STARTS WITH 'INTENT_' "
            "DETACH DELETE f",
            run_id=report.run_id,
            site=site,
        )

    loaded = load_findings_list(driver, attached, site, report.run_id)

    if unattached:
        params = []
        for f in unattached:
            props = {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "severity": _SEVERITY_MAP.get(f.severity, f.severity),
                "title": f.title,
                "message": f.message,
                "element_id": f.evidence.get("element_id", ""),
                "element_type": f.evidence.get("element_type", "device"),
                "recommendation": f.recommendation,
                "detected_at": f.detected_at,
                "category": _derive_category(f.rule_id),
                "device": f.evidence.get("element_id", ""),
                "site": site,
                "run_id": report.run_id,
            }
            props.update(_flatten_key_facts(f.evidence.get("key_facts")))
            params.append(_clean_properties(props))
        with driver.session() as session:
            session.run(
                "UNWIND $findings AS f CREATE (fin:Finding) SET fin = f",
                findings=params,
            )
        loaded += len(params)

    log.info("Drift findings loaded to Neo4j: %d (site=%s)", loaded, site)
