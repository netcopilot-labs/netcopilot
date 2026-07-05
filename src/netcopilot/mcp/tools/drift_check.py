"""Declared-vs-observed drift tools (s13, ADR-0015).

Two tools over :mod:`netcopilot.declared_state.drift`:

    run_drift_check             — full run-level check, INTENT_* findings
    compare_declared_vs_actual  — structured per-field diff for one device

Both need the declared source (NetBox) reachable AND the inventory the run
was collected from (``NETBOX_BOOTSTRAP_INVENTORY``). Missing either →
honest ``error`` (Article III) — drift is then UNKNOWN, never "zero".
"""
import json
import logging
import os

from netcopilot.mcp.result import ToolResult

log = logging.getLogger(__name__)


def _inventory_or_error() -> tuple[str | None, ToolResult | None]:
    inv = os.environ.get("NETBOX_BOOTSTRAP_INVENTORY")
    if not inv:
        return None, ToolResult("error", (
            "No inventory configured for drift comparison — set "
            "NETBOX_BOOTSTRAP_INVENTORY to the inventory YAML the runs are "
            "collected from (drift derives the observed side from it)."
        ))
    return inv, None


def _resolve_run(run_id: str | None, context: dict) -> str | None:
    return run_id or context.get("run_id")


async def run_drift_check(*, run_id: str | None = None, context: dict) -> ToolResult:
    """Compare declared state (NetBox) against a collected run → INTENT_* findings."""
    from netcopilot.declared_state.drift import DriftSourceUnavailable
    from netcopilot.declared_state.drift import run_drift_check as _run

    rid = _resolve_run(run_id, context)
    if not rid:
        return ToolResult("error", "No run selected — pass run_id or select a run first.")

    inv, err = _inventory_or_error()
    if err:
        return err

    try:
        report = _run(rid, inv)
    except DriftSourceUnavailable as exc:
        return ToolResult("error", str(exc))
    except FileNotFoundError as exc:
        return ToolResult("not_found", f"Run data not found: {exc}")
    except Exception as exc:
        log.error("run_drift_check(%r) failed: %s", rid, exc)
        return ToolResult("error", f"Drift check failed: {exc}")

    lines = [report.format_summary()]
    for f in report.findings:
        lines.append(f"  [{f.severity.upper():>4}] {f.rule_id} — {f.evidence['element_id']}: {f.title}")
    if report.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {w}" for w in report.warnings)
    if not report.quiet:
        lines.append(
            "Findings are loaded for this run — see the Audit tab (category: intent), "
            "or stage corrections from the drift findings."
        )

    drifted_devices = sorted({
        f.evidence["element_id"] for f in report.findings
        if f.rule_id != "INTENT_DEVICE_MISSING_IN_NETWORK"
    })
    verdict = {
        "result": "clean" if report.quiet else "drift",
        "total_findings": len(report.findings),
        "counts_by_rule": report.counts_by_rule,
        "devices_checked": report.devices_checked,
        "interfaces_checked": report.interfaces_checked,
    }
    return ToolResult(
        "ok", "\n".join(lines),
        verdict=verdict,
        highlight={"devices": drifted_devices} if drifted_devices else None,
    )


async def compare_declared_vs_actual(
    *, device: str, run_id: str | None = None, context: dict,
) -> ToolResult:
    """Structured declared-vs-observed diff for one device."""
    from netcopilot.declared_state import get_source
    from netcopilot.declared_state.drift import (
        _IFACE_ATTRS,
        _derive_observed,
        _norm_mac,
    )

    rid = _resolve_run(run_id, context)
    if not rid:
        return ToolResult("error", "No run selected — pass run_id or select a run first.")

    inv, err = _inventory_or_error()
    if err:
        return err

    try:
        adapter = get_source("netbox")
        adapter.ping()
    except Exception as exc:
        return ToolResult("error", (
            f"NetBox is not available: {exc} — declared state cannot be read, "
            "so the comparison is unknown (not empty)."
        ))

    try:
        warnings: list[str] = []
        observed = _derive_observed(rid, inv, warnings)
    except FileNotFoundError as exc:
        return ToolResult("not_found", f"Run data not found: {exc}")

    obs_dev = observed["devices"].get(device)
    decl_dev = adapter.get_device(device)

    if obs_dev is None and decl_dev is None:
        known = ", ".join(sorted(observed["devices"])[:12])
        return ToolResult("not_found", (
            f"Device '{device}' is neither in the collected run nor in NetBox. "
            f"Devices in run {rid!r}: {known}."
        ))

    lines = [f"Declared vs observed — {device} (run {rid}):"]
    if decl_dev is None:
        lines.append("  NetBox: NOT DOCUMENTED (observed in the network)")
    elif obs_dev is None:
        lines.append("  Network: NOT OBSERVED in this run (declared in NetBox)")

    if decl_dev and obs_dev:
        for label, key in (("Serial", "serial"), ("Platform", "platform"), ("Site", "site")):
            d, o = decl_dev.get(key), obs_dev.get(key)
            if key == "site":
                match = (d or "").lower() == (o or "").lower() if d and o else None
            else:
                match = (d == o) if d and o else None
            marker = "=" if match else ("≠ DRIFT" if match is False else "— (one side undeclared)")
            lines.append(f"  {label}: declared={d!r} observed={o!r} {marker}")

        decl_ifaces = {i["name"]: i for i in adapter.get_interfaces(device)}
        obs_ifaces = observed["interfaces"].get(device, {})
        both = sorted(set(decl_ifaces) & set(obs_ifaces))
        drift_rows = []
        for name in both:
            for attr in _IFACE_ATTRS:
                dv, ov = decl_ifaces[name].get(attr), obs_ifaces[name].get(attr)
                if attr == "mac_address":
                    dv_c, ov_c = _norm_mac(dv), _norm_mac(ov)
                else:
                    dv_c, ov_c = dv, ov
                if attr == "description":
                    dv_c, ov_c = dv_c or "", ov_c or ""
                if dv_c is None or ov_c is None:
                    continue
                if dv_c != ov_c:
                    drift_rows.append(f"    {name}.{attr}: declared={dv!r} observed={ov!r}")
        lines.append(
            f"  Interfaces: {len(obs_ifaces)} observed / {len(decl_ifaces)} declared / "
            f"{len(both)} matched by name"
        )
        missing = sorted(set(decl_ifaces) - set(obs_ifaces))
        unknown = sorted(set(obs_ifaces) - set(decl_ifaces))
        if missing:
            lines.append(f"    declared-only: {', '.join(missing[:10])}" + (" …" if len(missing) > 10 else ""))
        if unknown:
            lines.append(f"    observed-only: {', '.join(unknown[:10])}" + (" …" if len(unknown) > 10 else ""))
        if drift_rows:
            lines.append("  Attribute drift:")
            lines.extend(drift_rows[:20])
            if len(drift_rows) > 20:
                lines.append(f"    … {len(drift_rows) - 20} more")
        elif both:
            lines.append("  Attribute drift: none")

    return ToolResult("ok", "\n".join(lines), highlight={"device": device})
