"""FortiGate REST collection strategy (httpx).

Fetches structured JSON from FortiGate (FortiOS) over its REST API — the
responses are already structured evidence, so there is no CLI parsing step.
FortiGate authenticates with a **Bearer API token** (from the environment), not
SSH credentials, and there is no SSH fallback for it.

Read-only: GET requests only. Raw JSON is saved per endpoint as
``raw/<name>/<fortigate_*.json>`` for the parse layer.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

from netcopilot.collect.base import CollectionResult, CollectionStrategy, expand_env_ref

logger = logging.getLogger(__name__)

SUPPORTED_OS_FAMILIES = frozenset({"fortios"})

#: Environment variable holding the FortiGate REST API token.
API_TOKEN_ENV_VAR = "NETCOPILOT_FORTIGATE_API_TOKEN"

REQUEST_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# FortiOS throttles bursts of REST calls with HTTP 429. Back off and retry rather
# than dropping the endpoint (which would silently lose the whole firewall).
_RETRY_STATUSES = {429, 503}
_MAX_RETRIES = 5


def _get_with_retry(client: "httpx.Client", url: str, params):
    """GET with exponential backoff on 429/503 (honours Retry-After when present)."""
    delay = 1.0
    for attempt in range(_MAX_RETRIES + 1):
        resp = client.get(url, params=params)
        if resp.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
            wait = delay
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    wait = float(ra)
                except ValueError:
                    pass
            time.sleep(min(wait, 10.0))
            delay = min(delay * 2, 10.0)
            continue
        return resp
    return resp

# (output filename, REST API path). All filenames use the fortigate_ prefix so
# the parse layer can tell them apart from Cisco evidence. system_status MUST be
# first — hostname extraction depends on it. Grouped by CIS domain for clarity;
# the set is a security/config baseline, not exhaustive.
FORTIGATE_ENDPOINTS = [
    ("fortigate_system_status.json", "/api/v2/monitor/system/status"),
    ("fortigate_ha_peer.json", "/api/v2/monitor/system/ha-peer"),
    ("fortigate_web_ui_state.json", "/api/v2/monitor/web-ui/state"),
    ("fortigate_system_interface.json", "/api/v2/cmdb/system/interface"),
    ("fortigate_monitor_interface.json", "/api/v2/monitor/system/interface"),
    ("fortigate_interface_transceivers.json", "/api/v2/monitor/system/interface/transceivers"),
    # Firmware & auto-install/update
    ("fortigate_auto_install.json", "/api/v2/cmdb/system/auto-install"),
    ("fortigate_autoupdate_schedule.json", "/api/v2/cmdb/system.autoupdate/schedule"),
    # System global / DNS / NTP
    ("fortigate_system_global.json", "/api/v2/cmdb/system/global"),
    ("fortigate_system_dns.json", "/api/v2/cmdb/system/dns"),
    ("fortigate_system_ntp.json", "/api/v2/cmdb/system/ntp"),
    # Password & crypto
    ("fortigate_password_policy.json", "/api/v2/cmdb/system/password-policy"),
    # SNMP
    ("fortigate_snmp_sysinfo.json", "/api/v2/cmdb/system.snmp/sysinfo"),
    ("fortigate_snmp_community.json", "/api/v2/cmdb/system.snmp/community"),
    ("fortigate_snmp_user.json", "/api/v2/cmdb/system.snmp/user"),
    # Admin & access
    ("fortigate_system_admin.json", "/api/v2/cmdb/system/admin"),
    ("fortigate_system_accprofile.json", "/api/v2/cmdb/system/accprofile"),
    # HA & security fabric
    ("fortigate_system_ha.json", "/api/v2/cmdb/system/ha"),
    ("fortigate_system_csf.json", "/api/v2/cmdb/system/csf"),
    # Firewall policies & security profiles
    ("fortigate_firewall_policy.json", "/api/v2/cmdb/firewall/policy"),
    ("fortigate_local_in_policy.json", "/api/v2/cmdb/firewall/local-in-policy"),
    ("fortigate_system_zone.json", "/api/v2/cmdb/system/zone"),
    # Address & service objects (policy resolution)
    ("fortigate_firewall_address.json", "/api/v2/cmdb/firewall/address"),
    ("fortigate_firewall_addrgrp.json", "/api/v2/cmdb/firewall/addrgrp"),
    ("fortigate_firewall_service_custom.json", "/api/v2/cmdb/firewall.service/custom"),
    ("fortigate_firewall_service_group.json", "/api/v2/cmdb/firewall.service/group"),
    ("fortigate_firewall_vip.json", "/api/v2/cmdb/firewall/vip"),
    ("fortigate_ips_sensor.json", "/api/v2/cmdb/ips/sensor"),
    ("fortigate_antivirus_profile.json", "/api/v2/cmdb/antivirus/profile"),
    ("fortigate_application_list.json", "/api/v2/cmdb/application/list"),
    ("fortigate_dnsfilter_profile.json", "/api/v2/cmdb/dnsfilter/profile"),
    # VPN / SSL
    ("fortigate_vpn_ssl.json", "/api/v2/cmdb/vpn.ssl/settings"),
    # User settings
    ("fortigate_user_setting.json", "/api/v2/cmdb/user/setting"),
    # Logging
    ("fortigate_fortianalyzer.json", "/api/v2/cmdb/log.fortianalyzer/setting"),
    ("fortigate_eventfilter.json", "/api/v2/cmdb/log/eventfilter"),
    # ARP (HA member cable attribution)
    ("fortigate_arp.json", "/api/v2/monitor/network/arp"),
    # Routing
    ("fortigate_static_route.json", "/api/v2/cmdb/router/static"),
    ("fortigate_routing.json", "/api/v2/monitor/router/ipv4"),
    # Internet Service Database (ISDB) name→id catalog. Global FortiGuard data
    # (identical across VDOMs) — left unscoped. Feeds policy ISDB-reference
    # resolution; the id→ranges detail is fetched dynamically (see
    # ``_resolve_isdb_services``) only for services policies actually reference.
    ("fortigate_internet_service_name.json", "/api/v2/cmdb/firewall/internet-service-name"),
]

# The monitor endpoint that resolves an ISDB service id to its IP-range entries.
# Undocumented publicly but a stable API surface (present in Fortinet's own
# ``fortios_monitor_fact`` Ansible module); verified live on FortiOS 7.0.19.
_ISDB_DETAILS_PATH = "/api/v2/monitor/firewall/internet-service-details"
# Entries per page for the paged detail fetch (verified: server honours count=500).
_ISDB_PAGE_SIZE = 500
# Safety cap on pages per service — large feeds (e.g. malicious-server lists)
# can run to many thousands of ranges. Truncation is flagged, never silent.
_ISDB_MAX_PAGES = int(os.environ.get("NETCOPILOT_ISDB_MAX_PAGES", "40"))
# Policy fields that carry ISDB references (dst + src families).
_ISDB_POLICY_FIELDS = (
    "internet-service-name", "internet-service-custom", "internet-service-group",
    "internet-service-src-name", "internet-service-src-custom", "internet-service-src-group",
    "internet-service-id", "internet-service-src-id",
)

# Endpoints that return per-VDOM data and accept a ``?vdom=`` filter. When a
# device declares a ``vdom``, these are scoped to it; global endpoints (HA,
# admin, SNMP, logging, ...) return config that applies across all VDOMs and
# are left unscoped.
_VDOM_SCOPED_PATHS = frozenset({
    "/api/v2/cmdb/system/interface",
    "/api/v2/monitor/system/interface",
    "/api/v2/monitor/system/interface/transceivers",
    "/api/v2/cmdb/firewall/policy",
    "/api/v2/cmdb/firewall/local-in-policy",
    "/api/v2/cmdb/system/zone",
    "/api/v2/cmdb/firewall/address",
    "/api/v2/cmdb/firewall/addrgrp",
    "/api/v2/cmdb/firewall.service/custom",
    "/api/v2/cmdb/firewall.service/group",
    "/api/v2/cmdb/system/dns",
    "/api/v2/cmdb/system/ntp",
    "/api/v2/cmdb/ips/sensor",
    "/api/v2/cmdb/antivirus/profile",
    "/api/v2/cmdb/application/list",
    "/api/v2/cmdb/dnsfilter/profile",
    "/api/v2/cmdb/firewall/vip",
    "/api/v2/monitor/network/arp",
    "/api/v2/cmdb/router/static",
})


def _determine_hostname(status_data: dict | None, fallback: str) -> str:
    """Extract the hostname from the system/status response (``results.hostname``)."""
    if not status_data:
        return fallback
    try:
        hostname = status_data.get("results", {}).get("hostname")
        if hostname and isinstance(hostname, str):
            return hostname.strip()
    except (AttributeError, TypeError):
        pass
    return fallback


def _build_isdb_name_index(name_table: dict | None) -> dict[str, int]:
    """Map ISDB service name → id from the ``internet-service-name`` catalog."""
    index: dict[str, int] = {}
    if not name_table:
        return index
    results = name_table.get("results")
    if not isinstance(results, list):
        return index
    for entry in results:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        sid = entry.get("internet-service-id")
        if name and isinstance(sid, int):
            index[name] = sid
    return index


def _extract_referenced_isdb(policies: dict | None, name_index: dict[str, int]) -> dict[int, str]:
    """Collect the ISDB service ids (→ name) that any policy references.

    Scans every policy's ISDB reference fields (dst + src families). References
    by id are taken directly; references by name are resolved via the catalog
    index. Returns ``{id: name}`` — only these services get their ranges
    fetched, so collection cost stays proportional to what the config uses.
    """
    referenced: dict[int, str] = {}
    if not policies:
        return referenced
    results = policies.get("results")
    if not isinstance(results, list):
        return referenced
    id_to_name = {v: k for k, v in name_index.items()}
    for policy in results:
        if not isinstance(policy, dict):
            continue
        for field in _ISDB_POLICY_FIELDS:
            for ref in policy.get(field, []) or []:
                if not isinstance(ref, dict):
                    continue
                sid = ref.get("id")
                name = ref.get("name")
                if isinstance(sid, int):
                    referenced[sid] = name or id_to_name.get(sid, str(sid))
                elif name and name in name_index:
                    referenced[name_index[name]] = name
    return referenced


def _fetch_isdb_ranges(client, base_url: str, service_id: int, name: str) -> dict | None:
    """Resolve one ISDB service id to its IP ranges via the monitor endpoint.

    Returns ``{"name", "total", "truncated", "ranges": [...]}`` or ``None`` when
    the endpoint is unavailable (older FortiOS / restricted token profile) — the
    caller degrades to names-only and logs it, never fabricates ranges.
    """
    try:
        summary = _get_with_retry(
            client, f"{base_url}{_ISDB_DETAILS_PATH}",
            {"id": service_id, "summary_only": True},
        )
        summary.raise_for_status()
        total = summary.json().get("results", {}).get("total", 0)
    except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as exc:
        logger.warning("ISDB summary for id %s (%s) failed: %s", service_id, name, exc)
        return None

    ranges: list[str] = []
    truncated = False
    fetched = 0  # raw entry rows seen (before de-dup) — the coverage measure
    for page in range(_ISDB_MAX_PAGES):
        start = page * _ISDB_PAGE_SIZE
        if start >= total:
            break
        try:
            resp = _get_with_retry(
                client, f"{base_url}{_ISDB_DETAILS_PATH}",
                {"id": service_id, "start": start, "count": _ISDB_PAGE_SIZE},
            )
            resp.raise_for_status()
            entries = resp.json().get("results", {}).get("entry", []) or []
        except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as exc:
            logger.warning("ISDB page %d for id %s (%s) failed: %s", page, service_id, name, exc)
            truncated = True
            break
        if not entries:
            break
        fetched += len(entries)
        for e in entries:
            ipr = e.get("ip_range") or {}
            start_ip, end_ip = ipr.get("start_ip"), ipr.get("end_ip")
            if not start_ip:
                continue
            ranges.append(start_ip if start_ip == end_ip else f"{start_ip}-{end_ip}")
    else:
        # Loop exhausted the page cap. Compare RAW rows fetched (not de-duped
        # ranges) to total — de-dup legitimately shrinks the list below total.
        if fetched < total:
            truncated = True
            logger.warning(
                "ISDB service %s (%s): capped at %d pages (%d/%d rows)",
                service_id, name, _ISDB_MAX_PAGES, fetched, total,
            )

    # De-dup across proto rows (TCP/UDP duplicate the same range), keep order.
    ranges = list(dict.fromkeys(ranges))
    return {"name": name, "total": total, "truncated": truncated, "ranges": ranges}


class RestAdapter(CollectionStrategy):
    """Collect structured JSON from a FortiGate over its REST API using httpx."""

    name = "rest"

    def supports(self, device: dict[str, Any]) -> bool:
        return device.get("os") in SUPPORTED_OS_FAMILIES

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """Collect via REST. ``commands``/``credentials`` ignored (token from env)."""
        inventory_name = device.get("name", device.get("mgmt_ip", "unknown"))
        mgmt_ip = device["mgmt_ip"]

        # Per-device token (``api_token: ${FW_X_TOKEN}`` in the inventory) lets one
        # run target many FortiGates — each with its own token — while the secrets
        # stay in .env. Falls back to the global env var for the single-FortiGate
        # case, so existing single-token setups are unchanged.
        device_token = device.get("api_token")
        if device_token:
            try:
                api_token = expand_env_ref(str(device_token))
            except ValueError as exc:
                return CollectionResult(
                    success=False, strategy_name=self.name, hostname=inventory_name,
                    error=f"FortiGate api_token {exc}",
                )
        else:
            api_token = os.getenv(API_TOKEN_ENV_VAR)
        if not api_token:
            return CollectionResult(
                success=False, strategy_name=self.name, hostname=inventory_name,
                error=(
                    f"API token not set — set the device's 'api_token' (e.g. ${{FW_TOKEN}}) "
                    f"or the '{API_TOKEN_ENV_VAR}' environment variable"
                ),
            )

        base_url = f"https://{mgmt_ip}"
        # When the device declares a VDOM, per-VDOM endpoints are scoped to it.
        target_vdom = device.get("vdom")
        collected: dict[str, Any] = {}
        command_entries: list[dict[str, Any]] = []
        first_error: str | None = None

        # verify=False: FortiGate management endpoints commonly present
        # self-signed certs; this is read-only collection.
        client = httpx.Client(
            headers={"Authorization": f"Bearer {api_token}"},
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        try:
            for filename, api_path in FORTIGATE_ENDPOINTS:
                cmd_status = "success"
                cmd_error: str | None = None
                params = (
                    {"vdom": target_vdom}
                    if target_vdom and api_path in _VDOM_SCOPED_PATHS
                    else None
                )
                try:
                    response = _get_with_retry(client, f"{base_url}{api_path}", params)
                    response.raise_for_status()
                    collected[filename] = response.json()
                except httpx.HTTPStatusError as exc:
                    # 4xx/5xx — missing/empty evidence is valid (e.g. a profile
                    # not configured is itself a finding); record, keep going.
                    cmd_status = "error"
                    cmd_error = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
                    if first_error is None:
                        first_error = cmd_error
                except httpx.RequestError as exc:
                    cmd_status = "error"
                    cmd_error = f"{type(exc).__name__}: {exc}"
                    if first_error is None:
                        first_error = cmd_error
                    logger.warning("REST '%s' failed for '%s': %s", api_path, inventory_name, cmd_error)
                except ValueError as exc:  # invalid JSON
                    cmd_status = "error"
                    cmd_error = f"Invalid JSON response: {exc}"
                    if first_error is None:
                        first_error = cmd_error

                command_entries.append({
                    "command": f"REST:GET {api_path}",
                    "output_file": None,
                    "status": cmd_status,
                    "error": cmd_error,
                })

            # ── ISDB range resolution (referenced services only) ──────────
            # The name catalog + policies are now collected; resolve the ISDB
            # ids the policies reference to their IP ranges. Degrades to
            # names-only (no ranges file) if the monitor endpoint is absent.
            name_index = _build_isdb_name_index(collected.get("fortigate_internet_service_name.json"))
            referenced = _extract_referenced_isdb(
                collected.get("fortigate_firewall_policy.json"), name_index,
            )
            if referenced:
                isdb_ranges: dict[str, Any] = {}
                for sid, sname in sorted(referenced.items()):
                    resolved = _fetch_isdb_ranges(client, base_url, sid, sname)
                    if resolved is not None:
                        isdb_ranges[str(sid)] = resolved
                if isdb_ranges:
                    collected["fortigate_isdb_ranges.json"] = isdb_ranges
                    command_entries.append({
                        "command": f"REST:GET {_ISDB_DETAILS_PATH} (x{len(isdb_ranges)} referenced services)",
                        "output_file": None, "status": "success", "error": None,
                    })
                else:
                    logger.warning(
                        "ISDB: %d services referenced but none resolved "
                        "(monitor endpoint unavailable) — names-only", len(referenced),
                    )
        finally:
            client.close()

        real_hostname = _determine_hostname(collected.get("fortigate_system_status.json"), inventory_name)

        host_path = Path(output_dir) / inventory_name
        host_path.mkdir(parents=True, exist_ok=True)
        files_created: list[str] = []
        for i, (filename, _) in enumerate(FORTIGATE_ENDPOINTS):
            data = collected.get(filename)
            if data is not None:
                output_file = host_path / filename
                output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                files_created.append(str(output_file))
                command_entries[i]["output_file"] = str(output_file)

        # Dynamic ISDB ranges file (not part of the static endpoint list).
        isdb_data = collected.get("fortigate_isdb_ranges.json")
        if isdb_data is not None:
            isdb_file = host_path / "fortigate_isdb_ranges.json"
            isdb_file.write_text(json.dumps(isdb_data, indent=2), encoding="utf-8")
            files_created.append(str(isdb_file))

        # Success if any endpoint returned data — partial evidence is still useful.
        return CollectionResult(
            success=bool(collected), strategy_name=self.name, hostname=real_hostname,
            files_created=files_created, error=first_error, commands=command_entries,
        )
