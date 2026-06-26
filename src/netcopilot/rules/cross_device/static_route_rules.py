"""
Cross-Device Static Route Rules — Phase 3 bilateral static route analysis.

Detection Logic:
    For each link, loads static routes from both endpoints and detects
    asymmetric routing (same prefix, different AD/metric) between neighbors.

Rule IDs: XD_STATIC_ROUTE_ASYMMETRIC
Severity: medium

Static Routing Enrichment.
"""

import ipaddress
import logging
from typing import Any

from netcopilot.rules.cross_device.helpers import (
    make_finding,
    safe_get,
    select_best_links_per_pair,
)

logger = logging.getLogger(__name__)

RULE_IDS = ["XD_STATIC_ROUTE_ASYMMETRIC"]


def _get_link_ips(link: dict) -> tuple[set[str], set[str]]:
    """Extract IP addresses from link L3 metadata for both endpoints."""
    local_ips: set[str] = set()
    remote_ips: set[str] = set()

    l3 = link.get("l3") or {}
    local_l3 = l3.get("local") or {}
    remote_l3 = l3.get("remote") or {}

    if local_l3.get("ip"):
        local_ips.add(local_l3["ip"])
    if remote_l3.get("ip"):
        remote_ips.add(remote_l3["ip"])

    return local_ips, remote_ips


def _load_static_routes(facts: dict, hostname: str) -> list[dict]:
    """Load static routes from device facts, return flat list."""
    data = safe_get(facts, hostname, "genie_static_routing")
    if not data:
        return []

    routes = []
    for vrf_name, vrf in data.get("vrf", {}).items():
        if not isinstance(vrf, dict):
            continue
        for af_name, af in vrf.get("address_family", {}).items():
            if not isinstance(af, dict):
                continue
            for prefix, route in af.get("routes", {}).items():
                if not isinstance(route, dict):
                    continue
                nh = route.get("next_hop", {})
                # Collect all next-hop IPs
                nh_ips = []
                ads = []
                for _idx, entry in nh.get("next_hop_list", {}).items():
                    if isinstance(entry, dict) and entry.get("next_hop"):
                        nh_ips.append(entry["next_hop"])
                        ad = entry.get("preference") or route.get("route_preference")
                        ads.append(ad)
                routes.append({
                    "prefix": prefix,
                    "vrf": vrf_name,
                    "next_hop_ips": nh_ips,
                    "ads": ads,
                })
    return routes


def evaluate(
    links: list[dict],
    facts: dict[str, dict[str, Any]],
) -> list:
    """Evaluate static route asymmetry between link neighbors."""
    from netcopilot.rules.finding import Finding

    findings: list[Finding] = []
    filtered = select_best_links_per_pair(links)

    for link in filtered:
        dev_a = link.get("local_device_id", "")
        dev_b = link.get("remote_device_id", "")
        if not dev_a or not dev_b:
            continue

        routes_a = _load_static_routes(facts, dev_a)
        routes_b = _load_static_routes(facts, dev_b)
        if not routes_a or not routes_b:
            continue

        # Get link IPs to verify routes traverse this link
        local_ips, remote_ips = _get_link_ips(link)

        # Index routes by (vrf, prefix)
        idx_a: dict[tuple[str, str], dict] = {}
        for r in routes_a:
            # Check if any next-hop points to the remote device's IP
            for nh_ip in r["next_hop_ips"]:
                if nh_ip in remote_ips:
                    idx_a[(r["vrf"], r["prefix"])] = r
                    break

        idx_b: dict[tuple[str, str], dict] = {}
        for r in routes_b:
            for nh_ip in r["next_hop_ips"]:
                if nh_ip in local_ips:
                    idx_b[(r["vrf"], r["prefix"])] = r
                    break

        # Find matching prefixes with different ADs
        common = set(idx_a.keys()) & set(idx_b.keys())
        for key in common:
            r_a = idx_a[key]
            r_b = idx_b[key]
            vrf, prefix = key

            # Compare AD values
            ads_a = [a for a in r_a["ads"] if a is not None]
            ads_b = [a for a in r_b["ads"] if a is not None]
            if not ads_a or not ads_b:
                continue

            min_ad_a = min(ads_a)
            min_ad_b = min(ads_b)
            if min_ad_a != min_ad_b:
                pair = tuple(sorted([dev_a, dev_b]))
                findings.append(make_finding(
                    rule_id="XD_STATIC_ROUTE_ASYMMETRIC",
                    severity="low",
                    title="Asymmetric Static Route AD",
                    element_type="link",
                    element_id=f"{pair[0]}--{pair[1]}/static/{vrf}/{prefix}/asymmetric",
                    message=(
                        f"Static route {prefix} (VRF {vrf}) has different AD: "
                        f"{dev_a}={min_ad_a}, {dev_b}={min_ad_b}"
                    ),
                    key_facts={
                        "prefix": prefix, "vrf": vrf,
                        "device_a": dev_a, "ad_a": min_ad_a,
                        "device_b": dev_b, "ad_b": min_ad_b,
                    },
                    recommendation=(
                        "Verify asymmetric administrative distance is intentional — "
                        "mismatched AD can cause routing loops"
                    ),
                ))

    return findings
