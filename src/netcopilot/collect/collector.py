"""Collection orchestrator.

Drives the strategy chain over an :class:`~netcopilot.inventory.base.InventorySource`:
validate the inventory, pick a command profile and credentials per device, run
the applicable strategies in priority order until one succeeds, and write a
``manifest.json`` describing exactly what was collected.

Read-only throughout. One device's failure never aborts the run — it is recorded
as an error entry in the manifest, not raised.
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netcopilot.collect.base import CollectionStrategy, expand_env_ref
from netcopilot.collect.chain import applicable_strategies, default_chain
from netcopilot.collect.profiles import commands_for
from netcopilot.collect.roles import validate_role, validate_site
from netcopilot.inventory.base import InventorySource

#: OS families the pipeline recognises. A device may be valid inventory yet have
#: no applicable strategy in a given chain — that surfaces as an error manifest
#: entry, never a silent skip.
KNOWN_OS = frozenset({"ios-xe", "ios-xr", "fortios"})

#: Strategies that authenticate with SSH-style username/password credentials.
#: (FortiGate REST uses an API token from the environment instead.)
_CRED_STRATEGIES = frozenset({"ssh", "netconf", "restconf"})
_NO_CREDS = {"username": None, "password": None, "enable_password": None}


def get_env_credentials() -> dict[str, Any]:
    """Load base SSH credentials from the environment.

    Reads ``NETCOPILOT_SSH_USERNAME`` / ``NETCOPILOT_SSH_PASSWORD`` (required)
    and ``NETCOPILOT_ENABLE_PASSWORD`` (optional). Credentials are never stored
    in code or inventory files.
    """
    username = os.getenv("NETCOPILOT_SSH_USERNAME")
    password = os.getenv("NETCOPILOT_SSH_PASSWORD")
    if not username or not password:
        raise ValueError(
            "NETCOPILOT_SSH_USERNAME and NETCOPILOT_SSH_PASSWORD must be set"
        )
    return {
        "username": username,
        "password": password,
        "enable_password": os.getenv("NETCOPILOT_ENABLE_PASSWORD"),
    }


def resolve_credentials(device: dict, base: dict[str, Any]) -> dict[str, Any]:
    """Layer per-device credential overrides on top of the run-level base.

    A device may declare ``username`` / ``password`` / ``enable_password``.
    Values are resolved via :func:`~netcopilot.collect.base.expand_env_ref`, so
    the documented ``${ENV_VAR}`` style in inventory files resolves from the
    environment (keeping literal secrets out of the inventory). A ``${ENV_VAR}``
    that names an unset variable raises ``ValueError`` rather than silently
    passing through as a bogus credential.
    """
    creds = dict(base)
    for key in ("username", "password", "enable_password"):
        value = device.get(key)
        if value:
            creds[key] = expand_env_ref(str(value))
    return creds


def _validate_devices(devices: list[dict]) -> list[dict]:
    """Validate required fields, OS support, and name uniqueness."""
    seen: set[str] = set()
    for idx, dev in enumerate(devices):
        name, mgmt_ip, os_family = dev.get("name"), dev.get("mgmt_ip"), dev.get("os")
        if not name or not mgmt_ip or not os_family:
            raise ValueError(
                f"inventory device at index {idx} missing required name/mgmt_ip/os"
            )
        if os_family not in KNOWN_OS:
            raise ValueError(
                f"device '{name}' has unsupported os '{os_family}' "
                f"(known: {sorted(KNOWN_OS)})"
            )
        if name in seen:
            raise ValueError(f"duplicate device name in inventory: '{name}'")
        seen.add(name)
    return devices


def _manifest_entry(
    device: dict,
    *,
    role: str,
    site: str,
    hostname: str,
    strategy: str,
    status: str,
    error: str | None,
    commands: list,
) -> dict[str, Any]:
    return {
        "inventory_name": device["name"],
        "target": device["mgmt_ip"],
        "hostname": hostname,
        "os": device["os"],
        "role": role,
        "site": site,
        "collection_strategy": strategy,
        # Inventory-declared cluster ({name, size}); model_builder derives
        # cluster_declared_size from cluster.size to drive stack/HA member-id
        # attribution. Dropping it leaves every cable un-attributed to a member.
        "cluster": device.get("cluster"),
        "status": status,
        "error": error,
        "commands": commands,
    }


def collect_device(
    device: dict,
    raw_base: Path,
    base_credentials: dict[str, Any],
    chain: list[CollectionStrategy],
) -> dict[str, Any]:
    """Collect from one device, returning its manifest entry (never raises)."""
    role, _ = validate_role(device.get("role"))
    site, _ = validate_site(device.get("site"))
    try:
        strategies = applicable_strategies(device, chain)
        if not strategies:
            return _manifest_entry(
                device, role=role, site=site, hostname=device["name"],
                strategy="none", status="error",
                error=f"no applicable collection strategy for os '{device['os']}'",
                commands=[],
            )

        commands = commands_for(device["os"])
        creds = resolve_credentials(device, base_credentials)
        result = None
        for strategy in strategies:
            result = strategy.collect(device, commands, str(raw_base), creds)
            if result.success:
                break

        return _manifest_entry(
            device, role=role, site=site, hostname=result.hostname,
            strategy=result.strategy_name,
            status="success" if result.success else "error",
            error=result.error, commands=result.commands,
        )
    except Exception as exc:  # noqa: BLE001 — isolate one device; record, don't abort
        return _manifest_entry(
            device, role=role, site=site, hostname=device["name"],
            strategy="unknown", status="error", error=str(exc), commands=[],
        )


def run_collection(
    source: InventorySource,
    *,
    dry_run: bool = False,
    run_prefix: str | None = None,
    parallel: bool = True,
    max_workers: int = 10,
    runs_dir: str | Path = "runs",
    chain: list[CollectionStrategy] | None = None,
) -> str:
    """Collect from every device in ``source`` and write a run manifest.

    Args:
        source: Where devices come from (e.g. ``YAMLInventory``).
        dry_run: Print what would be collected without connecting; returns ``""``.
        run_prefix: Optional prefix for the run folder (``<prefix>_<timestamp>``).
        parallel: Collect devices concurrently (threads); each writes its own
            ``raw/<name>/`` directory, so there are no write conflicts.
        max_workers: Thread pool cap when ``parallel``.
        runs_dir: Base directory for run folders.
        chain: Strategy chain override (defaults to :func:`default_chain`).

    Returns:
        The ``run_id`` (folder name), or ``""`` for a dry run.
    """
    devices = _validate_devices(source.get_devices())
    chain = default_chain() if chain is None else chain

    if dry_run:
        for dev in devices:
            strategies = applicable_strategies(dev, chain)
            label = strategies[0].name if strategies else "none"
            print(f"[DRY-RUN] {dev['name']} ({dev['mgmt_ip']}, os={dev['os']}, strategy={label})")
        return ""

    # Only require SSH credentials when some device will actually use a
    # credential-based strategy. A FortiGate-only run (REST/token auth) needs none.
    needs_ssh_creds = any(
        any(s.name in _CRED_STRATEGIES for s in applicable_strategies(dev, chain))
        for dev in devices
    )
    base_credentials = get_env_credentials() if needs_ssh_creds else dict(_NO_CREDS)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    run_id = f"{run_prefix}_{timestamp}" if run_prefix else timestamp
    base_run = Path(runs_dir) / run_id
    raw_base = base_run / "raw"
    raw_base.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    if parallel and len(devices) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            entries = list(
                pool.map(lambda d: collect_device(d, raw_base, base_credentials, chain), devices)
            )
        mode = "parallel_threads"
    else:
        entries = [collect_device(d, raw_base, base_credentials, chain) for d in devices]
        mode = "sequential"
    elapsed = round(time.monotonic() - start, 1)

    manifest = {
        "run_id": run_id,
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_count": len(devices),
        "collection_mode": mode,
        "collection_seconds": elapsed,
        "devices": entries,
    }
    (base_run / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_id
