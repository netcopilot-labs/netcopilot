"""Facts builder — turn collected raw evidence into canonical device facts.

Reads a run's ``manifest.json``, and for each device routes its raw output (by
collection strategy + OS) to the matching parsers, assembling one canonical
``device_facts.json`` per device under ``runs/<run-id>/facts/<name>/``. This is
the bridge between "what we collected" and "what the graph loads".

The canonical per-device schema is transport-independent — an interface parsed
from SSH text, NETCONF YANG, or RESTCONF JSON lands in the same ``interfaces``
shape — so downstream layers never care how a device was reached.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netcopilot.parse.iosxe import show_cdp_neighbors as iosxe_cdp
from netcopilot.parse.iosxe import show_ip_interface_brief as iosxe_intf
from netcopilot.parse.iosxe import show_version as iosxe_version
from netcopilot.parse.iosxr import show_cdp_neighbors as iosxr_cdp
from netcopilot.parse.iosxr import show_inventory as iosxr_inventory
from netcopilot.parse.iosxr import show_ipv4_interface_brief as iosxr_intf
from netcopilot.parse.iosxr import show_version as iosxr_version
from netcopilot.parse.cisco_native import cdp as native_cdp
from netcopilot.parse.cisco_native import system as native_system
from netcopilot.parse.cisco_native.bgp_config import parse_bgp_process_config
from netcopilot.parse.openconfig import interfaces as oc_interfaces
from netcopilot.parse.openconfig import lldp as oc_lldp
from netcopilot.parse.restconf import cdp as rc_cdp
from netcopilot.parse.restconf import interfaces as rc_interfaces
from netcopilot.parse.restconf import lldp as rc_lldp
from netcopilot.parse.restconf import system as rc_system
from netcopilot.parse.fortigate import interfaces as fg_interfaces
from netcopilot.parse.fortigate import system as fg_system

PARSER_VERSION = "0.1.0"

# Strategies that produce CLI ``show`` text parsed by the text parsers.
_TEXT_STRATEGIES = frozenset({"ssh", "pyats"})


def _empty_facts(device: dict, run_id: str, timestamp: str | None) -> dict:
    """Canonical per-device facts skeleton (transport-independent)."""
    return {
        "hostname": device.get("hostname") or device["inventory_name"],
        "os": device["os"],
        "collection_strategy": device.get("collection_strategy"),
        "source_run_id": run_id,
        "collection_timestamp": timestamp,
        "device_info": None,
        "interfaces": [],
        "cdp_neighbors": [],
        "cluster_members": [],
        "fortigate": {},  # raw FortiGate REST evidence (fortios only; for the rules layer)
        "genie": {},  # Genie Ops JSON keyed by family (pyATS strategy only; for the model layer)
        "_metadata": {"parser_version": PARSER_VERSION, "warnings": []},
    }


def _parse_iosxe_text(raw_dir: Path, facts: dict) -> bool:
    """Fill facts from IOS XE ``show`` text. Returns True if any data parsed."""
    got = False
    version = iosxe_version.parse(str(raw_dir / "show_version.txt"))
    if version:
        got = True
        facts["device_info"] = {
            "hostname": version.get("hostname"),
            "version": version.get("version"),
            "platform": version.get("platform"),
            "serial": version.get("serial"),
            "uptime_text": version.get("uptime_text"),
            "mac_address": version.get("mac_address"),
            "role": facts.get("_role"),
            "site": facts.get("_site"),
        }
        facts["cluster_members"] = version.get("cluster_members", [])
        facts["_metadata"]["warnings"] += version.get("_warnings", [])

    intf = iosxe_intf.parse(str(raw_dir / "show_ip_interface_brief.txt"))
    if intf:
        got = True
        facts["interfaces"] = intf.get("interfaces", [])

    cdp = iosxe_cdp.parse(str(raw_dir / "show_cdp_neighbors.txt"))
    if cdp:
        got = True
        facts["cdp_neighbors"] = cdp.get("neighbors", [])

    return got


def _parse_iosxr_text(raw_dir: Path, facts: dict) -> bool:
    """Fill facts from IOS XR ``show`` text. Returns True if any data parsed."""
    got = False
    version = iosxr_version.parse(str(raw_dir / "show_version.txt"))
    inventory = iosxr_inventory.parse(str(raw_dir / "show_inventory.txt"))
    if version or inventory:
        got = True
        facts["device_info"] = {
            "hostname": facts["hostname"],  # XR show version has no hostname; use manifest
            "version": (version or {}).get("version"),
            "platform": (version or {}).get("platform"),
            "serial": (inventory or {}).get("serial"),
            "uptime_text": (version or {}).get("uptime_text"),
            "mac_address": None,
            "role": facts.get("_role"),
            "site": facts.get("_site"),
        }
        facts["_metadata"]["warnings"] += (version or {}).get("_warnings", [])

    intf = iosxr_intf.parse(str(raw_dir / "show_ipv4_interface_brief.txt"))
    if intf:
        got = True
        facts["interfaces"] = intf.get("interfaces", [])

    cdp = iosxr_cdp.parse(str(raw_dir / "show_cdp_neighbors.txt"))
    if cdp:
        got = True
        facts["cdp_neighbors"] = cdp.get("neighbors", [])

    return got


def _merge_neighbors(cdp: dict | None, lldp: dict | None) -> list[dict]:
    """CDP neighbors first, then LLDP ones not already seen (by local-intf + neighbor)."""
    neighbors = list((cdp or {}).get("neighbors", []))
    seen = {(n.get("local_interface"), n.get("neighbor_hostname")) for n in neighbors}
    for n in (lldp or {}).get("neighbors", []):
        key = (n.get("local_interface"), n.get("neighbor_hostname"))
        if key not in seen:
            neighbors.append(n)
            seen.add(key)
    return neighbors


def _assemble_structured(facts: dict, system, intf, cdp, lldp) -> bool:
    """Fill facts from already-parsed structured results (shared by NETCONF + RESTCONF)."""
    got = False
    if system:
        got = True
        facts["device_info"] = {
            "hostname": system.get("hostname") or facts["hostname"],
            "version": system.get("version"),
            "platform": system.get("platform"),
            "serial": system.get("serial"),
            "uptime_text": system.get("uptime_text"),
            "mac_address": None,
            "role": facts.get("_role"),
            "site": facts.get("_site"),
        }
        facts["cluster_members"] = system.get("cluster_members", [])
        facts["_metadata"]["warnings"] += system.get("_warnings", [])
    if intf:
        got = True
        facts["interfaces"] = intf.get("interfaces", [])
    if cdp or lldp:
        got = True
        facts["cdp_neighbors"] = _merge_neighbors(cdp, lldp)
    return got


def _parse_netconf(raw_dir: Path, facts: dict, os_family: str) -> bool:
    """Fill facts from NETCONF YANG XML (Cisco-native system/CDP + OpenConfig)."""
    if os_family == "ios-xe":
        system = native_system.parse_iosxe(str(raw_dir))
        cdp = native_cdp.parse_iosxe(str(raw_dir / "netconf_cdp.xml"))
    else:
        system = native_system.parse_iosxr(str(raw_dir))
        cdp = native_cdp.parse_iosxr(str(raw_dir / "netconf_cdp.xml"))
    intf = oc_interfaces.parse(str(raw_dir / "netconf_interfaces.xml"))
    lldp = oc_lldp.parse(str(raw_dir / "netconf_lldp.xml"))
    return _assemble_structured(facts, system, intf, cdp, lldp)


def _parse_restconf(raw_dir: Path, facts: dict) -> bool:
    """Fill facts from RESTCONF JSON (IOS XE only)."""
    system = rc_system.parse(str(raw_dir))
    intf = rc_interfaces.parse(str(raw_dir / "restconf_interfaces.json"))
    cdp = rc_cdp.parse(str(raw_dir / "restconf_cdp.json"))
    lldp = rc_lldp.parse(str(raw_dir / "restconf_lldp.json"))
    return _assemble_structured(facts, system, intf, cdp, lldp)


def _load_genie_evidence(facts_device_dir: Path) -> dict:
    """Load every ``genie_*.json`` in a device's facts dir, keyed by family.

    The pyATS strategy writes ``genie_<family>.json`` into ``facts/<name>/``
    during collection. We embed each into ``facts["genie"][family]`` so the
    model layer can read structured Genie data (LAG/LACP partner data, the
    interface table, StackWise-Virtual links) straight from ``device_facts.json``
    without re-reading files. ``"genie_interface.json"`` → key ``"interface"``;
    ``"genie_svl_link.json"`` → key ``"svl_link"``. Empty (``{}``) for strategies
    that produce no Genie output. Unreadable files are skipped, not fatal.
    """
    genie: dict = {}
    for json_file in sorted(facts_device_dir.glob("genie_*.json")):
        family = json_file.stem[len("genie_"):]  # "genie_interface" → "interface"
        try:
            genie[family] = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return genie


def _load_fortigate_evidence(raw_dir: Path) -> dict:
    """Load every collected ``fortigate_*.json`` keyed by endpoint name.

    Carries the raw FortiGate REST evidence (firewall policy, SNMP, NTP, ...)
    forward so the rules/analysis layer can consume it — otherwise that
    collected data would be stranded. FortiGate has no CLI parse step.
    """
    evidence: dict = {}
    for f in sorted(raw_dir.glob("fortigate_*.json")):
        try:
            evidence[f.stem[len("fortigate_"):]] = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return evidence


def _parse_fortigate(raw_dir: Path, facts: dict) -> bool:
    """Fill facts from FortiGate REST JSON (device_info, interfaces, raw evidence)."""
    got = False
    system = fg_system.parse(str(raw_dir))
    if system and system.get("_parse_status") != "failed":
        got = True
        facts["device_info"] = {
            "hostname": system.get("hostname") or facts["hostname"],
            "version": system.get("version"),
            "platform": system.get("platform"),
            "serial": system.get("serial"),
            "uptime_text": system.get("uptime_text"),
            "mac_address": None,
            "role": facts.get("_role"),
            "site": facts.get("_site"),
        }
        facts["cluster_members"] = system.get("cluster_members", [])
        facts["_metadata"]["warnings"] += system.get("_warnings", [])

    intf = fg_interfaces.parse(str(raw_dir))
    if intf:
        got = True
        facts["interfaces"] = intf.get("interfaces", [])

    # FortiGate has no CDP/LLDP — link discovery (FDB/LACP) is a model-layer concern.
    evidence = _load_fortigate_evidence(raw_dir)
    if evidence:
        got = True
        facts["fortigate"] = evidence
    return got


def build_device_facts(device: dict, run_path: Path, run_id: str, timestamp: str | None) -> dict | None:
    """Build canonical facts for one manifest device, or ``None`` if unparseable."""
    name = device["inventory_name"]
    os_family = device["os"]
    strategy = device.get("collection_strategy")
    raw_dir = run_path / "raw" / name

    facts = _empty_facts(device, run_id, timestamp)
    facts["_role"] = device.get("role")
    facts["_site"] = device.get("site")

    parsed = False
    if strategy in _TEXT_STRATEGIES and os_family == "ios-xe":
        parsed = _parse_iosxe_text(raw_dir, facts)
    elif strategy in _TEXT_STRATEGIES and os_family == "ios-xr":
        parsed = _parse_iosxr_text(raw_dir, facts)
    elif strategy == "netconf" and os_family in ("ios-xe", "ios-xr"):
        parsed = _parse_netconf(raw_dir, facts, os_family)
    elif strategy == "restconf" and os_family == "ios-xe":
        parsed = _parse_restconf(raw_dir, facts)
    elif strategy == "rest" and os_family == "fortios":
        parsed = _parse_fortigate(raw_dir, facts)

    # Embed Genie evidence written by the pyATS strategy into facts/<name>/.
    # The model layer reads facts["genie"]["lag"/"interface"/"svl_link"/...];
    # empty for non-pyATS strategies (no genie_*.json present).
    facts["genie"] = _load_genie_evidence(run_path / "facts" / name)

    facts.pop("_role", None)
    facts.pop("_site", None)
    return facts if parsed else None


def build_facts(run_id: str, runs_base: str | Path = "runs") -> dict:
    """Parse a whole run into per-device ``device_facts.json`` files.

    Returns a summary: ``{"devices": [...], "success_count": N, "error_count": N}``.
    """
    run_path = Path(runs_base) / run_id
    manifest_path = run_path / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    timestamp = manifest.get("timestamp_utc")
    facts_root = run_path / "facts"
    facts_root.mkdir(exist_ok=True)

    summary: dict[str, Any] = {"devices": [], "success_count": 0, "error_count": 0}
    for device in manifest["devices"]:
        name = device["inventory_name"]
        facts = build_device_facts(device, run_path, run_id, timestamp)
        if facts is not None:
            device_dir = facts_root / name
            device_dir.mkdir(parents=True, exist_ok=True)
            # BGP route-reflector / cluster-id are config-only — genie's operational
            # `show bgp` never exposes them. Parse them from the running-config into
            # a fact so the cross-device BGP rules (and the model) can see the
            # route-reflector topology. Absent for devices with no running-config.
            # A parse failure on one device must not abort the whole facts build,
            # but it is recorded in the device's warnings (not silently dropped).
            bgp_cfg = None
            rc_path = device_dir / "running_config.txt"
            if rc_path.exists():
                try:
                    bgp_cfg = parse_bgp_process_config(
                        rc_path.read_text(encoding="utf-8", errors="replace")
                    )
                except Exception as exc:  # noqa: BLE001 — recorded, not swallowed
                    facts["_metadata"]["warnings"].append(
                        f"bgp_config parse failed: {exc}"
                    )
            (device_dir / "device_facts.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
            # FortiGate: also emit one facts/<dev>/fortigate_<endpoint>.json per
            # REST endpoint. The cis_fg_* rules discover FortiGate devices by
            # globbing these files (cis_fg_helpers.find_fortigate_devices) and read
            # them per-endpoint; without them every CIS_FG_* rule silently yields 0.
            for endpoint, data in (facts.get("fortigate") or {}).items():
                (device_dir / f"fortigate_{endpoint}.json").write_text(
                    json.dumps(data, indent=2), encoding="utf-8"
                )
            if bgp_cfg:
                (device_dir / "bgp_config.json").write_text(
                    json.dumps(bgp_cfg, indent=2), encoding="utf-8"
                )
            summary["devices"].append({"hostname": name, "status": "success"})
            summary["success_count"] += 1
        else:
            summary["devices"].append({"hostname": name, "status": "error"})
            summary["error_count"] += 1
    return summary
