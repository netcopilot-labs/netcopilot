"""
Static Route Health Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines genie_static_routing.json and genie_interface.json to detect
    static route misconfigurations: missing redundancy, unreachable next-hops,
    and VRF leaking.

Rule IDs: STATIC_ROUTE_NO_REDUNDANCY, STATIC_ROUTE_NEXT_HOP_UNREACHABLE,
          STATIC_ROUTE_VRF_LEAK
Severity: varies

Static Routing Enrichment.
"""

from typing import Any

import ipaddress

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_static_routes(data: dict):
    """Yield (vrf, af, prefix, route) tuples from genie_static_routing.json."""
    for vrf_name, vrf in data.get("vrf", {}).items():
        if not isinstance(vrf, dict):
            continue
        for af_name, af in vrf.get("address_family", {}).items():
            if not isinstance(af, dict):
                continue
            for prefix, route in af.get("routes", {}).items():
                if not isinstance(route, dict):
                    continue
                yield vrf_name, af_name, prefix, route


def _extract_next_hops(route: dict) -> list[dict]:
    """Extract next-hop entries from a static route."""
    results = []
    nh = route.get("next_hop", {})
    # next_hop_list: {index: {next_hop, outgoing_interface, ...}}
    for _idx, entry in nh.get("next_hop_list", {}).items():
        if isinstance(entry, dict):
            results.append({
                "ip": entry.get("next_hop", ""),
                "interface": entry.get("outgoing_interface", ""),
            })
    # outgoing_interface: {intf_name: {outgoing_interface, ...}}
    for intf_name, entry in nh.get("outgoing_interface", {}).items():
        if isinstance(entry, dict):
            results.append({
                "ip": "",
                "interface": entry.get("outgoing_interface", intf_name),
            })
    return results


def _is_null_interface(intf: str) -> bool:
    return "null" in intf.lower() if intf else False


def _build_connected_subnets(run_path: str, hostname: str) -> dict[str, list]:
    """Build VRF → list of IPv4Network from genie_interface.json.

    Returns {vrf: [IPv4Network, ...]} for all interfaces with IP addresses.
    """
    intfs = load_device_facts(run_path, hostname, "genie_interface")
    if not intfs:
        return {}

    subnets: dict[str, list] = {}
    for intf_name, intf_data in intfs.items():
        if not isinstance(intf_data, dict):
            continue
        vrf = intf_data.get("vrf", "default") or "default"
        ipv4 = intf_data.get("ipv4", {})
        if not isinstance(ipv4, dict):
            continue
        for addr_str, addr_data in ipv4.items():
            if not isinstance(addr_data, dict):
                continue
            ip = addr_data.get("ip", "")
            pfx = addr_data.get("prefix_length")
            if not ip or pfx is None:
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{pfx}", strict=False)
                subnets.setdefault(vrf, []).append(net)
            except (ValueError, TypeError):
                pass

    return subnets


# ---------------------------------------------------------------------------
# STATIC_ROUTE_NO_REDUNDANCY
# ---------------------------------------------------------------------------

class StaticRouteNoRedundancyRule(BaseRule):
    """Flags static route prefixes with only one next-hop (no ECMP or floating backup).

    DISABLED: A static route with a single next-hop is a valid design when
    there is only one L3 path (one link, one subnet, one next-hop IP).
    The rule cannot determine whether a backup is physically possible,
    so it produces false positives on every intentionally single-path route.
    45 findings of noise on the test network. Re-enable only if the rule can check
    whether an alternative next-hop actually exists.
    """

    rule_id = "STATIC_ROUTE_NO_REDUNDANCY"
    severity = "low"
    title = "Static Route No Redundancy"
    description = "Static route has a single next-hop with no backup path"

    def is_enabled(self) -> bool:
        return False

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_static_routing")
            if not data:
                continue

            # Group next-hops by (vrf, prefix)
            prefix_hops: dict[tuple[str, str], list[dict]] = {}
            prefix_af: dict[tuple[str, str], str] = {}
            for vrf, af, prefix, route in _iter_static_routes(data):
                key = (vrf, prefix)
                hops = _extract_next_hops(route)
                prefix_hops.setdefault(key, []).extend(hops)
                prefix_af[key] = af

            for (vrf, prefix), hops in prefix_hops.items():
                # Skip default route (often intentionally single-homed)
                if prefix == "0.0.0.0/0":
                    continue
                # Skip Null0 aggregates
                if all(_is_null_interface(h["interface"]) for h in hops):
                    continue
                # Skip interface-only routes (directly connected statics)
                if all(h["ip"] == "" for h in hops):
                    continue
                # Only flag if exactly 1 next-hop
                if len(hops) == 1:
                    nh = hops[0]
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/static/{vrf}/{prefix}/no-redundancy",
                        message=(
                            f"Static route {prefix} in VRF {vrf} has a single "
                            f"next-hop {nh['ip'] or nh['interface']} with no backup"
                        ),
                        key_facts={
                            "prefix": prefix, "vrf": vrf,
                            "next_hop": nh["ip"] or nh["interface"],
                        },
                        recommendation=(
                            "Add a floating static route with higher AD as backup, "
                            "or add ECMP next-hop for redundancy"
                        ),
                    ))

        return findings


# ---------------------------------------------------------------------------
# STATIC_ROUTE_NEXT_HOP_UNREACHABLE
# ---------------------------------------------------------------------------

class StaticRouteNextHopUnreachableRule(BaseRule):
    """Flags static routes whose next-hop IP is not in any connected subnet."""

    rule_id = "STATIC_ROUTE_NEXT_HOP_UNREACHABLE"
    severity = "high"
    title = "Static Route Next-Hop Unreachable"
    description = "Static route next-hop IP is not reachable via any connected interface"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_static_routing")
            if not data:
                continue

            connected = _build_connected_subnets(run_path, hostname)
            if not connected:
                continue

            # Build flat list of all connected subnets (across VRFs)
            # Static routes use recursive lookup, so next-hop can be in any VRF
            all_subnets = []
            for nets in connected.values():
                all_subnets.extend(nets)

            for vrf, af, prefix, route in _iter_static_routes(data):
                for nh in _extract_next_hops(route):
                    nh_ip = nh["ip"]
                    if not nh_ip:
                        continue  # Interface-only route
                    try:
                        addr = ipaddress.ip_address(nh_ip)
                    except ValueError:
                        continue
                    # Check if next-hop is in any connected subnet
                    reachable = any(addr in net for net in all_subnets)
                    if not reachable:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/static/{vrf}/{prefix}/nh-unreachable",
                            message=(
                                f"Static route {prefix} next-hop {nh_ip} is not in "
                                f"any connected subnet on {hostname}"
                            ),
                            key_facts={
                                "prefix": prefix, "vrf": vrf,
                                "next_hop": nh_ip,
                            },
                            recommendation=(
                                "Verify next-hop is reachable — check interface "
                                "IP configuration or add a connected route"
                            ),
                        ))

        return findings


# ---------------------------------------------------------------------------
# STATIC_ROUTE_VRF_LEAK
# ---------------------------------------------------------------------------

class StaticRouteVrfLeakRule(BaseRule):
    """Flags static routes whose next-hop belongs to a different VRF's subnet."""

    rule_id = "STATIC_ROUTE_VRF_LEAK"
    severity = "low"
    title = "Static Route VRF Leak"
    description = "Static route next-hop IP belongs to a different VRF's connected subnet"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_static_routing")
            if not data:
                continue

            connected = _build_connected_subnets(run_path, hostname)
            # Only relevant for multi-VRF devices
            if len(connected) < 2:
                continue

            for vrf, af, prefix, route in _iter_static_routes(data):
                for nh in _extract_next_hops(route):
                    nh_ip = nh["ip"]
                    if not nh_ip:
                        continue
                    try:
                        addr = ipaddress.ip_address(nh_ip)
                    except ValueError:
                        continue
                    # Check if next-hop is in a DIFFERENT VRF's subnet
                    for other_vrf, nets in connected.items():
                        if other_vrf == vrf:
                            continue
                        for net in nets:
                            if addr in net:
                                findings.append(Finding.create_from_rule(
                                    rule=self, element_type="device",
                                    element_id=f"{hostname}/static/{vrf}/{prefix}/vrf-leak",
                                    message=(
                                        f"Static route {prefix} in VRF {vrf} has "
                                        f"next-hop {nh_ip} in VRF {other_vrf}'s "
                                        f"subnet {net}"
                                    ),
                                    key_facts={
                                        "prefix": prefix, "vrf": vrf,
                                        "next_hop": nh_ip,
                                        "other_vrf": other_vrf,
                                        "other_subnet": str(net),
                                    },
                                    recommendation=(
                                        "Verify inter-VRF routing is intended — "
                                        "configure route leaking or move route to correct VRF"
                                    ),
                                ))

        return findings
