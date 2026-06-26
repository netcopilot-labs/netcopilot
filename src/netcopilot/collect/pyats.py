"""pyATS collection strategy — the primary Cisco transport (Unicon + Genie).

The richest Cisco strategy: pyATS/Unicon manages the SSH session and Genie's
``device.learn()`` / ``device.parse()`` turn show output into structured
per-protocol JSON. It produces the ``genie_*.json`` files the model layer reads,
so it sits ahead of NETCONF/RESTCONF/SSH in the chain. Cisco IOS XE / IOS XR
only; FortiGate and ``ssh_only`` devices are not supported (they fall to the
REST and SSH strategies).

Two-phase ``collect()`` over a single Unicon session::

    generate_testbed() ─► device.connect() (learns hostname from the prompt)
      │
      ├─ Phase 1 — profile commands
      │    device.execute(cmd) ─► raw/<name>/<cmd>.txt   (same filenames as SSH)
      │
      └─ Phase 2 — Genie evidence ─► facts/<name>/
           execute('show running-config')   ─► running_config.txt
           discover_protocols(config)        ─► which families to learn
           device.learn(family) × N          ─► genie_<family>.json
           device.learn('lag')               ─► genie_lag.json   (LACP partner data)
           config parsers                    ─► security_config.json, parsed_*.json
           stack / StackWise-Virtual parses  ─► genie_stack_ports.json | genie_svl_*.json
           policy-map parses                 ─► genie_policy_map[_interface].json

Design notes:

* Per-family isolation — one failed ``learn()`` never aborts the rest.
* Facts-primary — the Genie JSON under ``facts/<name>/`` is the canonical store;
  the model layer (link/model builders) reads it directly.
* Hybrid discovery — six core families always, plus config-detected extras, so a
  device is never queried for a protocol it does not run.
* Never raises for device-level errors — failures land in the CollectionResult.

The module imports pyATS at top level (via :mod:`testbed_generator`), so it is
only importable with the optional ``[pyats]`` extra installed; the strategy
chain imports it behind ``try/except ImportError``.
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.collect.base import CollectionResult, CollectionStrategy
from netcopilot.collect.config_parser import (
    parse_management,
    parse_prefix_lists,
    parse_route_policies,
    parse_security_config,
    parse_stack_ports_summary,
)
from netcopilot.collect.protocol_discovery import discover_protocols
from netcopilot.collect.testbed_generator import generate_testbed

# -------------------------------------------------------------------------
# Suppress pyATS/Genie/Unicon logging
# -------------------------------------------------------------------------
# These frameworks generate extremely verbose logs at DEBUG/INFO level (every
# SSH command, parser step, schema validation). Suppressing to CRITICAL keeps
# console output readable when collecting from many devices.
for _logger_name in ("pyats", "genie", "unicon", "ats"):
    logging.getLogger(_logger_name).setLevel(logging.CRITICAL)

# -------------------------------------------------------------------------
# Module logger
# -------------------------------------------------------------------------
log = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------
# OS families that pyATS can collect from.
# SSH-only devices (ssh_only: true) are excluded at supports() time.
SUPPORTED_OS_FAMILIES = {"ios-xe", "ios-xr"}

# Strategy name recorded in manifest.json under collection_strategy.
# This is what the SSH_FALLBACK rule and reporting checks for.
STRATEGY_NAME = "pyats"


# -------------------------------------------------------------------------
# Private helpers
# -------------------------------------------------------------------------

def _count_bgp_prefixes(bgp_summary: dict) -> int:
    """Count total received prefixes from a BGP summary (genie_bgp.json).

    Works with both IOS XR summary format (state_pfxrcd in AF blocks)
    and IOS XE full learn format (prefixes.total_entries).
    """
    total = 0
    for inst in bgp_summary.get("instance", {}).values():
        for vrf in inst.get("vrf", {}).values():
            for nbr in vrf.get("neighbor", {}).values():
                for af in nbr.get("address_family", {}).values():
                    # IOS XR summary: state_pfxrcd is a string count
                    spfx = af.get("state_pfxrcd", "")
                    if spfx:
                        try:
                            total += int(spfx)
                        except (ValueError, TypeError):
                            pass
                    # IOS XE: prefixes → total_entries
                    pfx = af.get("prefixes", {})
                    if "total_entries" in pfx:
                        total += pfx["total_entries"]
    return total


def _count_route_summary(route_summary: dict) -> int:
    """Count total routes from a route summary (genie_routing.json).

    IOS XR 'show route summary' has route_source → protocol → routes.
    """
    total = 0
    for proto, proto_data in route_summary.get("route_source", {}).items():
        if isinstance(proto_data, dict):
            if "routes" in proto_data:
                total += proto_data["routes"]
            else:
                # Nested sub-key (e.g., bgp → AS-number → routes)
                for sub in proto_data.values():
                    if isinstance(sub, dict) and "routes" in sub:
                        total += sub["routes"]
    return total


def _parse_bgp_peer_routes_text(raw: str) -> list[dict]:
    """Parse IOS XR/XE 'show bgp neighbors <ip> routes' text output.

    Example IOS XR format:
    *> 203.0.113.0/24       198.51.100.108           0    100      0 64512 i
    *>i0.0.0.0/0            198.51.100.2                   100      0 i

    Example IOS XE format:
    *>  203.0.113.0/24  198.51.100.108   0         100     0 64512 i
    """
    routes = []
    for line in raw.splitlines():
        stripped = line.rstrip()
        # BGP route lines start with status codes: *, r, s, h, etc.
        if not stripped or stripped[0] not in "*>rshdSR ":
            continue
        # Skip header lines
        if "Network" in stripped and "Next Hop" in stripped:
            continue
        # IOS XR/XE BGP table format (fixed-width columns):
        # Status(3) Network(~18) NextHop(~20) Metric(~6) LocPrf(~6) Weight(~6) Path Origin
        # Use positional parsing: find prefix and next-hop, then split remainder
        m = re.match(
            r"^([*>srhdSRi ]{1,5})"  # status codes (1-5 chars)
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # prefix
            r"(\d+\.\d+\.\d+\.\d+)"  # next_hop
            r"\s+(.*)",  # remainder: metric locprf weight path origin
            stripped,
        )
        if not m:
            continue
        status = m.group(1).strip()
        prefix = m.group(2)
        next_hop = m.group(3)
        remainder = m.group(4).strip()
        # Split remainder into fields — last char is origin code (i/e/?)
        origin = ""
        if remainder and remainder[-1] in "ie?":
            origin = remainder[-1]
            remainder = remainder[:-1].strip()
        # Remaining tokens: up to 3 numbers (metric, locprf, weight) + AS path
        tokens = remainder.split()
        # Walk from the end: AS path numbers are typically > 100 (AS numbers)
        # Weight is usually 0 or small; locprf is 100; metric varies
        # Heuristic: last group of numbers before AS path
        # Simpler: IOS XR columns are fixed — split by whitespace groups
        metric = None
        local_pref = None
        weight = None
        path = ""
        if tokens:
            # All tokens are numbers — need to distinguish columns from AS path
            # IOS XR: empty metric/locprf show as gaps. Weight is always present.
            # Format: [metric] [locprf] weight [AS-path-numbers]
            # Weight is typically 0. AS path numbers are AS numbers (> 0).
            # Best approach: weight is the first number after gaps, path is rest
            # Actually just store all tokens as path — the key data is prefix/next_hop
            path = " ".join(tokens)

        routes.append({
            "prefix": prefix,
            "next_hop": next_hop,
            "metric": metric,
            "local_pref": local_pref,
            "weight": weight,
            "path": path,
            "origin": origin,
            "status": status,
        })
    return routes


def _extract_peer_prefix_counts(bgp_summary: dict) -> dict[str, int]:
    """Extract per-peer received prefix counts from a BGP summary.

    Returns {peer_ip: prefix_count} for each neighbor.
    """
    result: dict[str, int] = {}
    for inst in bgp_summary.get("instance", {}).values():
        for vrf in inst.get("vrf", {}).values():
            for nbr_ip, nbr in vrf.get("neighbor", {}).items():
                pfx = 0
                for af in nbr.get("address_family", {}).values():
                    spfx = af.get("state_pfxrcd", "")
                    if spfx:
                        try:
                            pfx += int(spfx)
                        except (ValueError, TypeError):
                            pass
                    pfx_info = af.get("prefixes", {})
                    if "total_entries" in pfx_info:
                        pfx += pfx_info["total_entries"]
                result[nbr_ip] = pfx
    return result


def _sanitize_command_to_filename(command: str) -> str:
    """
    Convert a CLI command into a safe .txt filename.

    This MUST produce identical output to SSHAdapter._sanitize_command_to_filename()
    because downstream parsers locate raw evidence files by name.

    Examples:
        "show version"                           → "show_version.txt"
        "show ip interface brief"                → "show_ip_interface_brief.txt"
        "show running-config | include hostname" → "show_running-config__include_hostname.txt"

    Args:
        command: The CLI command string

    Returns:
        Safe filename with .txt extension (no path, just the filename)
    """
    name = command.lower().replace(" ", "_")

    # Remove characters that are invalid in filenames (Windows-safe subset)
    forbidden = '/\\:*?"<>|'
    for ch in forbidden:
        name = name.replace(ch, "")

    return f"{name}.txt"


def _capture_raw_cli(pyats_device: Any, host_path: Path, cmd: str) -> Optional[Path]:
    """
    Preserve the raw CLI output of a command whose Genie parse failed.

    When ``device.parse(cmd)`` raises (schema mismatch, platform-token routing
    miss, unsupported on this image), the parsed JSON is never written and the
    raw output is lost — so the failure can only be diagnosed by re-running a
    live collection. This helper captures the raw text via ``device.execute()``
    and writes it next to the other raw evidence, so the *next* collection has
    the actual output to diagnose the parser mismatch against. No-silent-loss
    companion to the Genie parse path.

    Returns the written path, or None if execute() produced nothing or itself
    failed (the device may not support the command at all — e.g. a non-stack
    platform — in which case there is genuinely nothing to preserve).
    """
    try:
        raw = pyats_device.execute(cmd)
    except Exception as exc:  # noqa: BLE001
        log.debug("raw capture of '%s' failed: %s", cmd, type(exc).__name__)
        return None
    if not raw or not str(raw).strip():
        return None
    path = host_path / _sanitize_command_to_filename(cmd)
    path.write_text(str(raw), encoding="utf-8")
    return path


def _get_real_hostname(device: Any, fallback: str) -> str:
    """
    Extract the actual hostname that pyATS learned from the device prompt.

    When device.connect(learn_hostname=True) is used, Unicon captures the
    hostname from the CLI prompt and stores it in device.hostname.

    Args:
        device:   Connected pyATS Device object
        fallback: Value to use if pyATS did not learn a hostname

    Returns:
        Hostname string (pyATS-learned or fallback)
    """
    learned = getattr(device, "hostname", None)
    if learned and learned.strip():
        return learned.strip()
    return fallback


# -------------------------------------------------------------------------
# pyATS Adapter
# -------------------------------------------------------------------------

class PyATSAdapter(CollectionStrategy):
    """
    pyATS-based collection strategy — primary for Cisco IOS XE and IOS XR.

    Uses pyATS/Unicon for SSH session management and Genie device.learn()
    for comprehensive per-protocol structured evidence. Raw text files are
    written with the same filenames as SSHAdapter so all downstream parsers
    work unchanged (Phase 1). Evidence JSON is the primary structured output
    (Phase 2).

    Usage by orchestrator:
        adapter = PyATSAdapter()
        if adapter.supports(device):
            result = adapter.collect(device, commands, output_dir, credentials)
    """

    name = STRATEGY_NAME

    def supports(self, device: dict[str, Any]) -> bool:
        """
        Check if pyATS collection is available for the given device.

        Returns True only for Cisco IOS XE and IOS XR devices that are NOT
        flagged as ssh_only. SSH-only devices (IOSv, IOSvL2) fall through to
        SSHAdapter.

        Args:
            device: Device dict with at least "os" and optionally "ssh_only" fields.

        Returns:
            True if pyATS can collect from this device, False otherwise.
        """
        os_family = device.get("os", "")
        if os_family not in SUPPORTED_OS_FAMILIES:
            return False
        # ssh_only devices have no Genie parser support — fall through to SSHAdapter
        if device.get("ssh_only", False):
            return False
        return True

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """
        Collect evidence from a Cisco device via pyATS/Unicon and Genie learn().

        Two-phase collection:

        Phase 1 (profile commands) — same raw text as the SSH strategy:
            For each command in the OS profile, runs device.execute() and writes
            raw text to raw/<hostname>/<cmd>.txt. All downstream parsers
            (the IOS XE / IOS XR text parsers) read these files unchanged.

        Phase 2 (Genie learn() evidence):
            Fetches show running-config, discovers active protocol families, then
            calls device.learn(family) for each. Results go to facts/<hostname>/.
            Per-family isolation: one failed learn() does not abort the rest.

        This method never raises for device-level errors — all failures are
        captured and returned in the CollectionResult.

        Args:
            device:      Device dict with "name", "mgmt_ip", "os" fields.
            commands:    List of CLI commands to execute from the OS profile.
            output_dir:  Base path for raw output files (runs/<id>/raw/).
                         Phase 1 writes to output_dir/<hostname>/<cmd>.txt.
                         Phase 2 writes to output_dir/../facts/<hostname>/.
            credentials: Dict with "username", "password", optional "enable_password".

        Returns:
            CollectionResult with standard fields plus dynamic attributes:
                - strategy_name = "pyats"
                - hostname: actual hostname learned from device prompt
                - files_created: .txt and .json evidence files written
                - commands: per-command status for the manifest
                - success: False + error if connection failed
                - families_discovered: list from discover_protocols()
                - families_collected: families where learn() succeeded
                - families_failed: families where learn() raised (or empty result)
                - facts_dir: path to facts/<hostname>/ directory
        """
        # Use inventory_name for directory naming (stable, deterministic).
        # Real hostname is still collected for metadata but not used for paths.
        device_hostname: str = device.get("name", device.get("mgmt_ip", "unknown"))
        real_hostname: str = device_hostname  # Updated after successful connect
        device_success: bool = True
        device_error: Optional[str] = None
        command_entries: list[dict[str, Any]] = []
        files_created: list[str] = []

        # Track per-family learn() outcomes for manifest metadata.
        # Initialised here so they survive device-level exceptions (e.g. auth failure)
        # and are always present on the returned CollectionResult.
        families_discovered: list[str] = []
        families_collected: list[str] = []
        families_failed: list[str] = []
        facts_dir: Optional[Path] = None

        pyats_device = None
        testbed = None

        try:
            # -----------------------------------------------------------------
            # Build a single-device testbed for this collection call
            # -----------------------------------------------------------------
            # We build a per-device testbed rather than a shared one because:
            # - The orchestrator calls collect() sequentially per device
            # - A shared testbed would require lifecycle management across calls
            # - Per-device testbeds are simpler and perfectly adequate here
            testbed = generate_testbed([device], credentials)

            # The device name in the testbed matches device["name"] from inventory
            device_name_in_testbed = device["name"]
            if device_name_in_testbed not in testbed.devices:
                return CollectionResult(
                    success=False,
                    strategy_name=self.name,
                    hostname=device_hostname,
                    error=(
                        f"Device '{device_name_in_testbed}' not found in generated testbed. "
                        f"Available: {list(testbed.devices.keys())}"
                    ),
                )

            pyats_device = testbed.devices[device_name_in_testbed]

            # -----------------------------------------------------------------
            # Connect via Unicon SSH
            # -----------------------------------------------------------------
            # learn_hostname=True: Unicon reads the hostname from the CLI prompt
            # and stores it in pyats_device.hostname — avoids show run | include hostname
            # log_stdout=False: suppress Unicon's connection debug output to console
            pyats_device.connect(
                learn_hostname=True,
                log_stdout=False,
                connection_timeout=30,
                init_config_commands=[],
                init_exec_commands=[
                    "terminal length 0",
                    "terminal width 512",
                ],
            )

            # Get the real hostname that Unicon learned from the prompt (metadata only)
            real_hostname = _get_real_hostname(pyats_device, fallback=device_hostname)

            # Create the device-specific output folder using inventory_name
            host_path = Path(output_dir) / device_hostname
            host_path.mkdir(parents=True, exist_ok=True)

            # -----------------------------------------------------------------
            # Execute each command in the profile
            # -----------------------------------------------------------------
            for cmd in commands:
                output_file: Optional[Path] = None
                cmd_status = "success"
                cmd_error: Optional[str] = None

                try:
                    # Execute the command and capture raw text output.
                    # device.execute() is Unicon's command executor — it handles
                    # prompt detection and paging (terminal length 0 equivalent).
                    raw_output: str = pyats_device.execute(cmd)

                    # Write raw text with the same filename convention as SSHAdapter.
                    # Downstream parsers (the IOS XE / IOS XR text parsers) rely
                    # on these filenames to locate evidence — MUST NOT change.
                    filename = _sanitize_command_to_filename(cmd)
                    output_file = host_path / filename
                    output_file.write_text(raw_output, encoding="utf-8")
                    files_created.append(str(output_file))

                except Exception as cmd_exc:  # noqa: BLE001
                    # Command execution failed — record and continue to next command.
                    # A per-command failure (e.g. "show interfaces status" not supported
                    # on IOSv classic) does NOT fail the whole device collection — the
                    # device connected successfully and other commands may have worked.
                    # device_success stays True; the failure is visible in command_entries.
                    cmd_status = "error"
                    cmd_error = str(cmd_exc)
                    log.warning(
                        "Command '%s' failed on %s: %s",
                        cmd,
                        device_hostname,
                        cmd_exc.__class__.__name__,
                    )

                # Record per-command result for the manifest
                command_entries.append(
                    {
                        "command": cmd,
                        "output_file": str(output_file) if output_file else None,
                        "status": cmd_status,
                        "error": cmd_error,
                    }
                )

            # -----------------------------------------------------------------
            # Phase 2: Genie learn() evidence collection
            # -----------------------------------------------------------------
            # This phase runs after all profile commands, on the same open
            # connection. It writes to facts/<hostname>/ (sibling of raw/).
            #
            # output_dir = runs/<run-id>/raw/
            # facts_dir = runs/<run-id>/facts/<hostname>/
            facts_dir = Path(output_dir).parent / "facts" / device_hostname
            facts_dir.mkdir(parents=True, exist_ok=True)

            # -----------------------------------------------------------------
            # Step 2a: Capture running config
            # -----------------------------------------------------------------
            # Running config drives protocol discovery (which learn() calls to make)
            # and is stored as structured evidence.
            # If it fails, we fall back to the ALWAYS_COLLECT core set via
            # discover_protocols("") — no exception propagates upward.
            running_config_text = ""
            try:
                running_config_text = pyats_device.execute("show running-config")
                rc_file = facts_dir / "running_config.txt"
                rc_file.write_text(running_config_text, encoding="utf-8")
                files_created.append(str(rc_file))
                log.debug(
                    "Captured running-config for %s (%d chars)",
                    device_hostname,
                    len(running_config_text),
                )
            except Exception as rc_exc:  # noqa: BLE001
                # Running config fetch failed (rare — device is connected and
                # responding). Log and continue; discovery returns core set only.
                log.warning(
                    "Failed to capture running-config for %s: %s",
                    device_hostname,
                    rc_exc.__class__.__name__,
                )

            # -----------------------------------------------------------------
            # Step 2b: Hybrid protocol discovery
            # -----------------------------------------------------------------
            # discover_protocols() scans running config text for protocol keywords.
            # Always returns the 6 ALWAYS_COLLECT families + any detected extras.
            # Empty string → core 6 only (safe fallback if running config failed).
            families_discovered = discover_protocols(running_config_text)

            # Filter out families explicitly skipped in inventory (e.g. bgp/routing
            # on border routers with ~1M internet routes — learn() would OOM).
            # For bgp and routing, run lightweight summary parse commands instead
            # so BGP cross-device rules still have neighbor/prefix-count data.
            skip_families = set(device.get("skip_families", []))
            if skip_families:
                families_discovered = [f for f in families_discovered if f not in skip_families]
                log.info(
                    "%s: skipping families per inventory: %s",
                    device_hostname,
                    ", ".join(sorted(skip_families)),
                )

                # Smart skip: collect BGP/routing summary first to assess RIB
                # size.  If total received prefixes are below a safe threshold,
                # promote the family back to full learn() — this gives us the
                # complete neighbor detail + full RIB without OOM risk.
                # Only transit peers with 100K+ routes are dangerous.
                _SAFE_PREFIX_THRESHOLD = 50_000  # prefixes — safe for learn()
                _SAFE_ROUTE_THRESHOLD = 50_000   # routes — safe for learn()

                _SUMMARY_COMMANDS: dict[str, list[tuple[str, str]]] = {
                    "bgp": [
                        ("show bgp summary", "genie_bgp.json"),
                        ("show bgp ipv4 unicast neighbors", "genie_bgp_neighbors.json"),
                    ],
                    "routing": [
                        ("show route summary", "genie_routing.json"),
                    ],
                }
                for family, cmd_list in _SUMMARY_COMMANDS.items():
                    if family not in skip_families:
                        continue
                    summary_data = {}
                    for cmd, filename in cmd_list:
                        try:
                            parsed = pyats_device.parse(cmd)
                            if parsed:
                                out = facts_dir / filename
                                out.write_text(json.dumps(parsed, indent=2))
                                files_created.append(str(out))
                                summary_data[filename] = parsed
                                log.info("%s: saved summary-only %s → %s", device_hostname, cmd, filename)
                        except Exception as exc:
                            log.debug("%s: summary parse '%s' skipped: %s", device_hostname, cmd, exc)

                    # Guardrail: check if full learn() is safe based on summary
                    promote = False
                    if family == "bgp" and "genie_bgp.json" in summary_data:
                        total_pfx = _count_bgp_prefixes(summary_data["genie_bgp.json"])
                        if total_pfx < _SAFE_PREFIX_THRESHOLD:
                            promote = True
                            log.info(
                                "%s: BGP prefix count %d < %d threshold — promoting to full learn",
                                device_hostname, total_pfx, _SAFE_PREFIX_THRESHOLD,
                            )
                    elif family == "routing" and "genie_routing.json" in summary_data:
                        total_routes = _count_route_summary(summary_data["genie_routing.json"])
                        if total_routes < _SAFE_ROUTE_THRESHOLD:
                            promote = True
                            log.info(
                                "%s: route count %d < %d threshold — promoting to full learn",
                                device_hostname, total_routes, _SAFE_ROUTE_THRESHOLD,
                            )

                    if promote:
                        # Put back into families_discovered for full learn()
                        families_discovered.append(family)
                        skip_families.discard(family)
                        log.info("%s: %s promoted from summary-only to full learn", device_hostname, family)

                    # Per-peer received routes: for devices staying in summary
                    # mode, collect routes from peers with small prefix counts.
                    # "show bgp neighbors <ip> routes" is safe — returns only
                    # that peer's prefixes, not the full RIB.
                    # No Genie parser exists, so we use device.execute() + text parsing.
                    _PER_PEER_PREFIX_LIMIT = 1_000
                    if family == "bgp" and not promote and "genie_bgp.json" in summary_data:
                        peer_prefixes = _extract_peer_prefix_counts(summary_data["genie_bgp.json"])
                        for peer_ip, pfx_count in peer_prefixes.items():
                            if 0 < pfx_count <= _PER_PEER_PREFIX_LIMIT:
                                # IOS XR: "show bgp neighbors <ip> routes"
                                # IOS XE: "show ip bgp neighbors <ip> routes"
                                os_type = device.get("os", "ios-xr")
                                cmd = (
                                    f"show bgp neighbors {peer_ip} routes"
                                    if os_type == "ios-xr"
                                    else f"show ip bgp neighbors {peer_ip} routes"
                                )
                                filename = f"bgp_peer_routes_{peer_ip.replace('.', '_')}.txt"
                                try:
                                    raw_output = pyats_device.execute(cmd)
                                    if raw_output:
                                        out = facts_dir / filename
                                        out.write_text(raw_output)
                                        files_created.append(str(out))
                                        # Parse text into structured JSON
                                        routes = _parse_bgp_peer_routes_text(raw_output)
                                        if routes:
                                            json_file = facts_dir / f"genie_bgp_routes_{peer_ip.replace('.', '_')}.json"
                                            json_file.write_text(json.dumps({"routes": routes}, indent=2))
                                            files_created.append(str(json_file))
                                        log.info(
                                            "%s: collected %d routes from peer %s → %s",
                                            device_hostname, len(routes), peer_ip, filename,
                                        )
                                except Exception as exc:
                                    log.debug(
                                        "%s: per-peer routes '%s' skipped: %s",
                                        device_hostname, cmd, exc,
                                    )

            log.info(
                "%s: discovered %d protocol families — %s",
                device_hostname,
                len(families_discovered),
                ", ".join(families_discovered),
            )

            # -----------------------------------------------------------------
            # Step 2c: device.learn(family) per discovered family
            # -----------------------------------------------------------------
            # Per-family isolation: catching Exception per iteration means one
            # failed family (e.g. 'fdb' on a pure-L3 IOS XR router) does NOT
            # abort the loop — remaining families are still collected.
            #
            # Two exception categories:
            #   SchemaEmptyParserError — protocol present but returned no data
            #     (e.g. 'fdb' on routers, 'stp' on IOS XR) — expected, DEBUG log
            #   Any other Exception — unexpected Genie/device failure — WARNING log
            for family in families_discovered:
                family_file = facts_dir / f"genie_{family}.json"
                try:
                    ops = pyats_device.learn(family)

                    # ops.info is the plain dict we want. The ops object itself is
                    # NOT JSON-serialisable — always extract .info before dumping.
                    # default=str handles any residual non-JSON types (datetime, etc.)
                    data = ops.info if hasattr(ops, "info") and ops.info else {}
                    family_file.write_text(
                        json.dumps(data, indent=2, default=str),
                        encoding="utf-8",
                    )
                    files_created.append(str(family_file))
                    families_collected.append(family)
                    log.debug(
                        "%s: learned '%s' — %d top-level keys",
                        device_hostname,
                        family,
                        len(data),
                    )

                except Exception as learn_exc:  # noqa: BLE001
                    exc_name = type(learn_exc).__name__
                    # SchemaEmptyParserError = Genie has a parser but device
                    # returned no output for this family — expected for unconfigured
                    # protocols and L2-only families on L3-only devices.
                    if "SchemaEmptyParserError" in exc_name or "Empty" in exc_name:
                        log.debug(
                            "%s: '%s' — empty result (SchemaEmptyParserError)",
                            device_hostname,
                            family,
                        )
                    elif exc_name in (
                        "NotImplementedError",
                        "SchemaMissingKeyError",
                        "SchemaUnsupportedKeyError",
                    ):
                        # Harmless: Genie doesn't support this family on
                        # this platform, or the device returned unexpected
                        # schema keys. Not a real failure.
                        log.info(
                            "%s: '%s' — skipped (unsupported on this platform)",
                            device_hostname,
                            family,
                        )
                    else:
                        log.warning(
                            "%s: '%s' — learn() failed: %s: %s",
                            device_hostname,
                            family,
                            exc_name,
                            learn_exc,
                        )
                    families_failed.append(family)

            # -----------------------------------------------------------------
            # Step 2d: LAG / Link Aggregation via Genie learn('lag')
            # -----------------------------------------------------------------
            # LACP: switch from single parse commands to full
            # Genie Ops learn('lag') which includes LACP partner data.
            #
            # IOS XE learn('lag') executes:
            #   show lacp sys-id, show etherchannel summary,
            #   show lacp neighbor (partner_id!), show lacp counters,
            #   show pagp neighbor, show pagp counters
            #
            # IOS XR learn('lag') executes:
            #   show lacp system-id, show bundle,
            #   show lacp (partner_id + partner_port_num!)
            #
            # Produces: facts/<hostname>/genie_lag.json (superset of old
            # parsed_lag.json — backward compat via facts_loader fallback)
            #
            # Gating: only collect on devices with LAG config keywords.
            os_family = device.get("os", "")

            has_lag_config = (
                (os_family == "ios-xe" and re.search(r"channel-group \d+", running_config_text))
                or (os_family == "ios-xr" and re.search(r"bundle id \d+", running_config_text))
            )

            if has_lag_config:
                try:
                    lag_ops = pyats_device.learn("lag")
                    # Genie Ops → dict via .info attribute
                    lag_data = getattr(lag_ops, "info", None) or {}
                    lag_file = facts_dir / "genie_lag.json"
                    lag_file.write_text(
                        json.dumps(lag_data, indent=2, default=str),
                        encoding="utf-8",
                    )
                    files_created.append(str(lag_file))
                    log.debug("%s: learned LAG (Genie Ops) — %s", device_hostname, os_family)
                except Exception as lag_exc:  # noqa: BLE001
                    # Fallback: try the old parse-only approach
                    log.debug(
                        "%s: learn('lag') failed (%s: %s), trying parse fallback",
                        device_hostname,
                        type(lag_exc).__name__,
                        lag_exc,
                    )
                    try:
                        if os_family == "ios-xe":
                            lag_raw = pyats_device.execute("show etherchannel summary")
                            lag_parsed = pyats_device.parse(
                                "show etherchannel summary", output=lag_raw
                            )
                        else:
                            lag_raw = pyats_device.execute("show bundle")
                            lag_parsed = pyats_device.parse("show bundle", output=lag_raw)
                        lag_file = facts_dir / "parsed_lag.json"
                        lag_file.write_text(
                            json.dumps(lag_parsed, indent=2, default=str),
                            encoding="utf-8",
                        )
                        files_created.append(str(lag_file))
                        log.debug("%s: parsed LAG (fallback) — %s", device_hostname, os_family)
                    except Exception as fb_exc:  # noqa: BLE001
                        log.debug(
                            "%s: LAG parse fallback skipped: %s: %s",
                            device_hostname,
                            type(fb_exc).__name__,
                            fb_exc,
                        )

            # -----------------------------------------------------------------
            # Step 2e: Running config structured parsers
            # -----------------------------------------------------------------
            # Four pure-function parsers convert running config text into
            # structured JSON evidence. Each is isolated — one failure does
            # not block the others or Phase 1 / learn() evidence.
            #
            # security_config.json is always written (even if mostly empty).
            # parsed_management, parsed_route_policy, parsed_prefix_list are
            # only written when the parser returns non-empty results.
            # parse_security_config needs os_family for cdp_lldp and password_policy
            # sections where XE opt-out / XR opt-in semantics differ.
            config_parsers = [
                (parse_security_config, "security_config.json",    True,  os_family),
                (parse_management,      "parsed_management.json",   False, None),
                (parse_route_policies,  "parsed_route_policy.json", False, None),
                (parse_prefix_lists,    "parsed_prefix_list.json",  False, None),
            ]
            for parser_fn, filename, always_write, extra_arg in config_parsers:
                try:
                    data = parser_fn(running_config_text, extra_arg) if extra_arg else parser_fn(running_config_text)
                    # Skip writing empty dicts for optional files (saves disk
                    # and makes 'ls facts/<hostname>/' cleaner on simple devices)
                    if not always_write and not data:
                        log.debug(
                            "%s: %s — no data, skipping write",
                            device_hostname,
                            filename,
                        )
                        continue
                    out_file = facts_dir / filename
                    out_file.write_text(
                        json.dumps(data, indent=2, default=str),
                        encoding="utf-8",
                    )
                    files_created.append(str(out_file))
                    log.debug("%s: wrote %s", device_hostname, filename)
                except Exception as cfg_exc:  # noqa: BLE001
                    log.warning(
                        "%s: %s parse failed: %s: %s",
                        device_hostname,
                        filename,
                        type(cfg_exc).__name__,
                        cfg_exc,
                    )

            # -----------------------------------------------------------------
            # Step 2f: Stack interconnect collection
            # -----------------------------------------------------------------
            # Collect stack interconnect data from stacked IOS XE devices.
            # Gating: device must have cluster config (cluster.size >= 2 in
            # inventory) AND be IOS XE. Non-stacked and non-iosxe devices
            # skip this step entirely.
            #
            # Two stacking technologies exist on Catalyst 9K:
            #   - C9500 StackWise Virtual (SVL): show stackwise-virtual link/
            #     bandwidth/dual-active-detection → 3 JSON files
            #   - C9300 traditional StackWise: show switch stack-ports summary
            #     → 1 JSON file
            #
            # Strategy: try SVL first (C9500). If SVL command fails (invalid
            # input on non-SVL platforms), fall back to traditional stack-ports
            # (C9300). CML virtual devices have no real stack hardware, so
            # both may fail — handled gracefully.
            #
            # Output: genie_svl_link.json + genie_svl_bandwidth.json +
            #         genie_svl_dad.json (SVL) OR genie_stack_ports.json
            cluster_info = device.get("cluster") or {}
            cluster_size = cluster_info.get("size", 0)

            if os_family == "ios-xe" and cluster_size >= 2:
                svl_detected = False
                # Track whether ANY stack/SVL topology was captured. A clustered
                # IOS XE device (SVL pair or traditional stack) that yields none
                # is the genuinely-unexpected case — surfaced as a warning below
                # rather than swallowed at debug level (no-silent-fallback).
                stack_svl_captured = False

                # --- Try C9500 StackWise Virtual first ---
                try:
                    svl_link = pyats_device.parse(
                        "show stackwise-virtual link"
                    )
                    if svl_link:
                        svl_detected = True
                        stack_svl_captured = True
                        svl_file = facts_dir / "genie_svl_link.json"
                        svl_file.write_text(
                            json.dumps(svl_link, indent=2, default=str),
                            encoding="utf-8",
                        )
                        files_created.append(str(svl_file))
                        log.debug(
                            "%s: SVL detected — collected svl link",
                            device_hostname,
                        )
                except Exception as svl_exc:  # noqa: BLE001
                    # Parse failed: either not a C9500 SVL device (→ stack-ports
                    # fallback below handles it) OR a Genie schema/platform-token
                    # mismatch on a real SVL device. We cannot tell apart from a
                    # frozen run, so preserve the raw output for the next
                    # collection to diagnose against (the parsed JSON is lost on
                    # a parse failure — the raw text is the only evidence).
                    log.debug(
                        "%s: SVL link parse failed (%s) — capturing raw, trying stack-ports",
                        device_hostname,
                        type(svl_exc).__name__,
                    )
                    raw_path = _capture_raw_cli(
                        pyats_device, host_path, "show stackwise-virtual link"
                    )
                    if raw_path:
                        files_created.append(str(raw_path))

                # --- Collect remaining SVL commands if SVL detected ---
                if svl_detected:
                    for svl_cmd, svl_filename in [
                        ("show stackwise-virtual bandwidth", "genie_svl_bandwidth.json"),
                        ("show stackwise-virtual dual-active-detection", "genie_svl_dad.json"),
                    ]:
                        try:
                            svl_data = pyats_device.parse(svl_cmd)
                            if svl_data:
                                out = facts_dir / svl_filename
                                out.write_text(
                                    json.dumps(svl_data, indent=2, default=str),
                                    encoding="utf-8",
                                )
                                files_created.append(str(out))
                                log.debug(
                                    "%s: collected %s", device_hostname, svl_filename
                                )
                        except Exception as svl2_exc:  # noqa: BLE001
                            log.info(
                                "%s: SVL command '%s' parse failed: %s: %s — capturing raw",
                                device_hostname,
                                svl_cmd,
                                type(svl2_exc).__name__,
                                svl2_exc,
                            )
                            raw_path = _capture_raw_cli(pyats_device, host_path, svl_cmd)
                            if raw_path:
                                files_created.append(str(raw_path))


                # --- Fall back to C9300 traditional stack-ports ---
                if not svl_detected:
                    stack_empty = False
                    try:
                        stack_parsed = pyats_device.parse(
                            "show switch stack-ports summary"
                        )
                        if stack_parsed:
                            stack_svl_captured = True
                            stack_file = facts_dir / "genie_stack_ports.json"
                            stack_file.write_text(
                                json.dumps(stack_parsed, indent=2, default=str),
                                encoding="utf-8",
                            )
                            files_created.append(str(stack_file))
                            log.debug(
                                "%s: collected stack-ports summary",
                                device_hostname,
                            )
                        else:
                            stack_empty = True
                            log.debug(
                                "%s: stack-ports summary returned empty",
                                device_hostname,
                            )
                    except Exception as stack_exc:  # noqa: BLE001
                        stack_empty = True
                        log.info(
                            "%s: stack-ports parse produced no data (%s) — capturing raw",
                            device_hostname,
                            type(stack_exc).__name__,
                        )

                    # Within this block the device is ALWAYS clustered (cluster
                    # size >= 2), so an empty/unparseable stack-ports is
                    # suspicious — it may be a real traditional stack (C9300)
                    # whose `show switch stack-ports summary` output Genie cannot
                    # parse, NOT "no stack hardware". Preserve the raw output so
                    # the next collection can diagnose the parser/command
                    # mismatch instead of silently concluding the stack is
                    # absent (a non-stacked pair legitimately yields an empty
                    # banner here, which is itself useful evidence).
                    if stack_empty:
                        raw_path = _capture_raw_cli(
                            pyats_device, host_path, "show switch stack-ports summary"
                        )
                        if raw_path:
                            files_created.append(str(raw_path))
                            # Genie's ShowSwitchStackPortsSummary parser raises on
                            # valid C9300 output (observed on real services-tier
                            # stacks), so recover the stack topology with a text
                            # parse — written in the Genie schema so the model
                            # consumer is unchanged. Keeps traditional-stack health
                            # monitored instead of silently dark.
                            recovered = parse_stack_ports_summary(
                                raw_path.read_text(encoding="utf-8")
                            )
                            if recovered.get("stackports"):
                                stack_svl_captured = True
                                stack_file = facts_dir / "genie_stack_ports.json"
                                stack_file.write_text(
                                    json.dumps(recovered, indent=2, default=str),
                                    encoding="utf-8",
                                )
                                files_created.append(str(stack_file))
                                log.info(
                                    "%s: stack-ports recovered via text fallback "
                                    "(%d ports) — Genie parser failed",
                                    device_hostname,
                                    len(recovered["stackports"]),
                                )

                # De-silence: a clustered IOS XE device that produced no SVL and
                # no stack-ports topology is unexpected (the very gap that hid
                # a real SVL parse failure at debug level for months). Warn so
                # it is visible; the raw CLI output captured above is the
                # evidence to diagnose the Genie mismatch on the next collection.
                if not stack_svl_captured:
                    log.warning(
                        "%s: clustered IOS XE device (cluster size %d) produced no "
                        "StackWise/SVL topology — Genie parse failed for all stack "
                        "commands. Raw CLI output captured under raw/%s/ for diagnosis.",
                        device_hostname,
                        cluster_size,
                        device_hostname,
                    )

            # -----------------------------------------------------------------
            # Step 2g: QoS policy collection
            # -----------------------------------------------------------------
            # Collect QoS policy definitions and per-interface operational
            # counters from IOS XE devices. Uses device.parse() with Genie
            # ShowPolicyMap and ShowPolicyMapInterface parsers.
            #
            # Collected unconditionally for all IOS XE devices — every IOS XE
            # device has at least system-cpp-policy, and devices without user
            # QoS produce minimal output that the parser handles gracefully.
            #
            # Output:
            #   genie_policy_map.json           ← policy definitions (types, rates, burst)
            #   genie_policy_map_interface.json  ← per-interface counters (conform/exceed)
            if os_family == "ios-xe":
                qos_commands = [
                    ("show policy-map", "genie_policy_map.json"),
                    ("show policy-map interface", "genie_policy_map_interface.json"),
                ]
                for qos_cmd, qos_filename in qos_commands:
                    try:
                        qos_parsed = pyats_device.parse(qos_cmd)
                        if qos_parsed:
                            qos_file = facts_dir / qos_filename
                            qos_file.write_text(
                                json.dumps(qos_parsed, indent=2, default=str),
                                encoding="utf-8",
                            )
                            files_created.append(str(qos_file))
                            log.debug(
                                "%s: collected QoS — %s",
                                device_hostname,
                                qos_filename,
                            )
                    except Exception as qos_exc:  # noqa: BLE001
                        exc_name = type(qos_exc).__name__
                        if "SchemaEmptyParserError" in exc_name or "Empty" in exc_name:
                            log.debug(
                                "%s: QoS '%s' — empty result (no QoS data)",
                                device_hostname,
                                qos_cmd,
                            )
                        else:
                            log.warning(
                                "%s: QoS '%s' parse failed: %s: %s",
                                device_hostname,
                                qos_cmd,
                                exc_name,
                                qos_exc,
                            )

        except Exception as dev_exc:  # noqa: BLE001
            # Device-level failure: connection refused, authentication error,
            # timeout, testbed generation failure, etc.
            device_success = False
            device_error = str(dev_exc)
            log.error("pyATS collection failed for %s: %s", device_hostname, device_error)

        finally:
            # -----------------------------------------------------------------
            # Always disconnect, even if errors occurred
            # -----------------------------------------------------------------
            if pyats_device is not None:
                try:
                    pyats_device.disconnect()
                except Exception:  # noqa: BLE001
                    pass  # Ignore disconnect errors

        # Build the result.  CollectionResult is the standard schema understood
        # by collector.py and the manifest builder.  The adapter adds family
        # metadata as dynamic attributes — the dataclass does not use __slots__
        # so attribute assignment is safe.  The collector reads these
        # to include them in manifest.json under each device's collection entry.
        result = CollectionResult(
            success=device_success,
            strategy_name=self.name,
            hostname=real_hostname,
            files_created=files_created,
            error=device_error,
            commands=command_entries,
        )
        result.families_discovered = families_discovered
        result.families_collected = families_collected
        result.families_failed = families_failed
        result.facts_dir = str(facts_dir) if facts_dir else None
        return result
