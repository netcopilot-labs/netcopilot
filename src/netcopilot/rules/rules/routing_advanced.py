"""
Routing/VRF Advanced Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Examines Genie routing and VRF learn() output for route health,
    VRF configuration, and missing SVI anomalies.

Rule IDs: ROUTE_INACTIVE, ROUTE_BLACKHOLE_STATIC, ROUTE_DEFAULT_MISSING,
          VRF_EMPTY_NO_INTERFACES, VRF_NO_RD_CONFIGURED, VRF_MISSING_RT,
          VLAN_MISSING_SVI (disabled)
Severity: varies

Noise Reduction:
    Fix 5: VLAN_MISSING_SVI — disabled (L2-only VLANs are valid design)
    Fix 7: VRF rules — exclude system/default VRFs
"""

from typing import Any

import ipaddress
import re

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config

# System/default VRFs to exclude from VRF health checks.
# These are auto-created by IOS XE/XR and intentionally lack RD, RT, interfaces.
_SYSTEM_VRFS = {"default", "mgmt-intf", "mgmt-vrf", "management", "mgmt"}


def _mask_to_cidr(ip: str, mask: str) -> str:
    """Convert IOS XE ``network X mask Y`` to CIDR notation."""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net)
    except (ValueError, TypeError):
        return f"{ip}/{mask}"


def _extract_bgp_network_prefixes(run_path: str, hostname: str) -> set[str]:
    """Return set of CIDR prefixes from BGP ``network`` statements in running config."""
    config = load_running_config(run_path, hostname)
    if not config:
        return set()
    prefixes: set[str] = set()
    in_bgp = False
    for line in config.splitlines():
        stripped = line.strip()
        # Track whether we're inside a router bgp section
        if re.match(r"^router\s+bgp\s", stripped):
            in_bgp = True
            continue
        if in_bgp and stripped and not stripped.startswith("!") and not line[0].isspace():
            in_bgp = False
        if not in_bgp:
            continue
        # IOS XR: "network 203.0.113.0/24"
        m = re.match(r"network\s+(\d+\.\d+\.\d+\.\d+/\d+)", stripped)
        if m:
            prefixes.add(m.group(1))
            continue
        # IOS XE: "network 10.0.0.0 mask 255.255.255.0"
        m = re.match(r"network\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)", stripped)
        if m:
            prefixes.add(_mask_to_cidr(m.group(1), m.group(2)))
    return prefixes


# -------------------------------------------------------------------------
# ROUTE_INACTIVE — Non-static inactive route
# -------------------------------------------------------------------------

class RouteInactiveRule(BaseRule):
    """Flags routes present in RIB but marked inactive."""

    rule_id = "ROUTE_INACTIVE"
    severity = "low"
    title = "Route Inactive"
    description = "Route is present in the routing table but marked inactive"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_routing")
            if not data:
                continue

            for vrf_name, vrf in data.get("vrf", {}).items():
                if not isinstance(vrf, dict):
                    continue
                for af_name, af in vrf.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    for prefix, route in af.get("routes", {}).items():
                        if not isinstance(route, dict):
                            continue
                        active = route.get("active", True)
                        source = route.get("source_protocol", "")
                        # Skip static (handled by STATIC_ROUTE_INACTIVE)
                        if source == "static":
                            continue
                        if active is False:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="device",
                                element_id=f"{hostname}/route/{vrf_name}/{prefix}/inactive",
                                message=(
                                    f"Route {prefix} ({source}) inactive "
                                    f"in VRF {vrf_name}"
                                ),
                                key_facts={
                                    "prefix": prefix, "vrf": vrf_name,
                                    "source_protocol": source,
                                },
                                recommendation="Investigate why route is inactive — check next-hop and protocol state",
                            ))

        return findings


# -------------------------------------------------------------------------
# ROUTE_BLACKHOLE_STATIC — Static route with null next-hop
# -------------------------------------------------------------------------

class RouteBlackholeStaticRule(BaseRule):
    """Flags static routes pointing to Null0 (blackhole routes).

    audit fix: skip Null0 routes that match a BGP ``network``
    statement in the running config — these are intentional aggregate anchors.
    """

    rule_id = "ROUTE_BLACKHOLE_STATIC"
    severity = "info"
    title = "Blackhole Static Route"
    description = "Static route points to Null0 — verify blackhole is intentional"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_static_routing")
            if not data:
                continue

            # Load running config to find BGP network statements (aggregate anchors)
            bgp_prefixes = _extract_bgp_network_prefixes(run_path, hostname)

            for vrf_name, vrf in data.get("vrf", {}).items():
                if not isinstance(vrf, dict):
                    continue
                for af_name, af in vrf.get("address_family", {}).items():
                    if not isinstance(af, dict):
                        continue
                    for prefix, route in af.get("routes", {}).items():
                        if not isinstance(route, dict):
                            continue
                        # Skip if prefix matches a BGP network statement
                        if prefix in bgp_prefixes:
                            continue
                        for nh_key, nh_data in route.get("next_hop", {}).items():
                            if not isinstance(nh_data, dict):
                                continue
                            for idx_key, idx_val in nh_data.items():
                                if not isinstance(idx_val, dict):
                                    continue
                                outgoing = str(idx_val.get("outgoing_interface", "")).lower()
                                if "null" in outgoing:
                                    findings.append(Finding.create_from_rule(
                                        rule=self, element_type="device",
                                        element_id=f"{hostname}/route/{vrf_name}/{prefix}/blackhole",
                                        message=(
                                            f"Static route {prefix} points to "
                                            f"{outgoing} (blackhole)"
                                        ),
                                        key_facts={"prefix": prefix, "vrf": vrf_name, "next_hop": outgoing},
                                        recommendation="Verify blackhole route is intentional for traffic filtering",
                                    ))

        return findings


# -------------------------------------------------------------------------
# ROUTE_DEFAULT_MISSING — No default route
# -------------------------------------------------------------------------

class RouteDefaultMissingRule(BaseRule):
    """Flags VRFs without a default route (0.0.0.0/0)."""

    rule_id = "ROUTE_DEFAULT_MISSING"
    severity = "info"
    title = "Default Route Missing"
    description = "VRF has no default route — may prevent internet/upstream reachability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_routing")
            if not data:
                continue

            for vrf_name, vrf in data.get("vrf", {}).items():
                if not isinstance(vrf, dict):
                    continue
                # Only check default VRF
                if vrf_name != "default":
                    continue
                ipv4 = vrf.get("address_family", {}).get("ipv4", {})
                if not isinstance(ipv4, dict):
                    continue
                routes = ipv4.get("routes", {})
                has_default = "0.0.0.0/0" in routes
                if routes and not has_default:
                    # Also check genie_static_routing — devices like sw-a/sw-b
                    # carry their default route only in the static routing table,
                    # not reflected in the dynamic genie_routing table.
                    static_data = load_device_facts(
                        run_path, hostname, "genie_static_routing"
                    )
                    if static_data:
                        for s_vrf in static_data.get("vrf", {}).values():
                            if isinstance(s_vrf, dict):
                                s_routes = (
                                    s_vrf.get("address_family", {})
                                    .get("ipv4", {})
                                    .get("routes", {})
                                )
                                if "0.0.0.0/0" in s_routes:
                                    has_default = True
                                    break
                if routes and not has_default:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/route/default-missing",
                        message=f"No default route (0.0.0.0/0) in global table",
                        key_facts={"vrf": vrf_name, "route_count": len(routes)},
                        recommendation="Verify default route exists or is learned via IGP/BGP",
                    ))

        return findings


# -------------------------------------------------------------------------
# VRF_EMPTY_NO_INTERFACES — VRF with no interfaces
# -------------------------------------------------------------------------

class VrfEmptyNoInterfacesRule(BaseRule):
    """Flags VRFs with no interfaces assigned.

    audit fix: Genie ``show vrf detail`` often doesn't
    populate the ``interfaces`` field.  Fall back to scanning the running
    config for ``vrf forwarding <name>`` (IOS XE) / ``vrf <name>`` (IOS XR)
    under interface stanzas before concluding the VRF is empty.
    """

    rule_id = "VRF_EMPTY_NO_INTERFACES"
    severity = "info"
    title = "VRF Empty — No Interfaces"
    description = "VRF is defined but has no interfaces assigned"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_vrf")
            if not data:
                continue

            # Load running config for cross-reference
            config_text = load_running_config(run_path, hostname) or ""

            for vrf_name, vrf in data.get("vrfs", {}).items():
                if not isinstance(vrf, dict):
                    continue
                # exclude system/default VRFs
                if vrf_name.lower() in _SYSTEM_VRFS:
                    continue
                # First check Genie data
                interfaces = vrf.get("interfaces", [])
                if interfaces:
                    continue
                # Genie field empty — cross-reference running config
                if config_text:
                    pattern = rf"vrf\s+(?:forwarding\s+)?{re.escape(vrf_name)}\b"
                    if re.search(pattern, config_text):
                        continue  # VRF referenced in interface config
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/vrf/{vrf_name}/empty",
                    message=f"VRF '{vrf_name}' has no interfaces assigned",
                    key_facts={"vrf": vrf_name},
                    recommendation="Assign interfaces to this VRF or remove it if unused",
                ))

        return findings


# -------------------------------------------------------------------------
# L3VPN context detection (shared by the RD / RT rules)
# -------------------------------------------------------------------------

def _device_runs_l3vpn(run_path: str, hostname: str) -> bool:
    """True if the device runs BGP MPLS L3VPN (a BGP vpnv4/vpnv6 address-family).

    Route distinguishers and route-targets are MPLS L3VPN constructs. A device
    doing only VRF-lite (``vrf definition`` + per-VRF IGP, no BGP VPNv4) does
    not need them — a VRF-lite VRF without RD/RT is correct, not a finding. So
    VRF_NO_RD / VRF_MISSING_RT only apply to L3VPN PEs.
    """
    config = load_running_config(run_path, hostname)
    if not config:
        return False
    return bool(re.search(r"address-family\s+vpnv[46]", config, re.IGNORECASE))


# -------------------------------------------------------------------------
# VRF_NO_RD_CONFIGURED — VRF without route distinguisher
# -------------------------------------------------------------------------

class VrfNoRdConfiguredRule(BaseRule):
    """Flags VRFs without a route distinguisher configured."""

    rule_id = "VRF_NO_RD_CONFIGURED"
    severity = "low"
    title = "VRF No Route Distinguisher"
    description = "VRF has no route distinguisher — required for MPLS VPN"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_vrf")
            if not data:
                continue
            # RD is an MPLS L3VPN construct — VRF-lite devices don't need it.
            if not _device_runs_l3vpn(run_path, hostname):
                continue

            for vrf_name, vrf in data.get("vrfs", {}).items():
                if not isinstance(vrf, dict):
                    continue
                # exclude system/default VRFs
                if vrf_name.lower() in _SYSTEM_VRFS:
                    continue
                # Skip Cisco IOS XE internal platform VRFs (e.g. __Platform_iVRF:_ID00_)
                if vrf_name.startswith("__"):
                    continue
                rd = vrf.get("route_distinguisher")
                if not rd or rd == "<not set>":
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/vrf/{vrf_name}/no-rd",
                        message=f"VRF '{vrf_name}' has no route distinguisher",
                        key_facts={"vrf": vrf_name},
                        recommendation="Configure route distinguisher for VPN route distribution",
                    ))

        return findings


# -------------------------------------------------------------------------
# VRF_MISSING_RT — VRF without route targets
# -------------------------------------------------------------------------

class VrfMissingRtRule(BaseRule):
    """Flags VRFs without import/export route targets.

    audit fix: Genie ``show vrf detail`` stores route
    targets under ``route_targets`` (plural) as a dict keyed by RT value,
    each containing ``{"route_target": "X:Y", "rt_type": "import|export|both"}``.
    The previous code looked for ``route_target`` (singular) with
    ``import_rt_list``/``export_rt_list`` which never matched.
    """

    rule_id = "VRF_MISSING_RT"
    severity = "info"
    title = "VRF Missing Route Targets"
    description = "VRF has no import or export route targets configured"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_vrf")
            if not data:
                continue
            # Route-targets are an MPLS L3VPN construct — VRF-lite devices
            # don't need them.
            if not _device_runs_l3vpn(run_path, hostname):
                continue

            for vrf_name, vrf in data.get("vrfs", {}).items():
                if not isinstance(vrf, dict):
                    continue
                if vrf_name.lower() in _SYSTEM_VRFS:
                    continue
                # Skip Cisco IOS XE internal platform VRFs (e.g. __Platform_iVRF:_ID00_)
                if vrf_name.startswith("__"):
                    continue
                af = vrf.get("address_family", {})
                if not af:
                    continue
                for af_name, af_data in af.items():
                    if not isinstance(af_data, dict):
                        continue
                    route_targets = af_data.get("route_targets", {})
                    if not route_targets:
                        findings.append(Finding.create_from_rule(
                            rule=self, element_type="device",
                            element_id=f"{hostname}/vrf/{vrf_name}/{af_name}/no-rt",
                            message=(
                                f"VRF '{vrf_name}' ({af_name}) has no "
                                f"route targets configured"
                            ),
                            key_facts={"vrf": vrf_name, "address_family": af_name},
                            recommendation="Configure import/export route targets if VRF participates in L3VPN",
                        ))

        return findings


# -------------------------------------------------------------------------
# VLAN_MISSING_SVI — VLAN without SVI
# -------------------------------------------------------------------------

class VlanMissingSviRule(BaseRule):
    """Flags VLANs without a corresponding SVI (interface Vlan)."""

    rule_id = "VLAN_MISSING_SVI"
    severity = "info"
    title = "VLAN Missing SVI"
    description = "VLAN is configured but has no corresponding SVI for L3 routing"

    def is_enabled(self) -> bool:
        """Disabled in — L2-only VLANs are a valid design choice without NetBox intent."""
        return False

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            vlans = load_device_facts(run_path, hostname, "genie_vlan")
            intfs = load_device_facts(run_path, hostname, "genie_interface")
            if not vlans:
                continue

            # Collect SVI VLAN IDs from interfaces
            svi_vlans = set()
            if intfs:
                for intf_name in intfs:
                    lower = intf_name.lower()
                    if lower.startswith("vlan"):
                        try:
                            vlan_id = int(lower.replace("vlan", ""))
                            svi_vlans.add(str(vlan_id))
                        except ValueError:
                            pass

            # Check each VLAN
            for vlan_id, vlan_data in vlans.get("vlans", {}).items():
                if not isinstance(vlan_data, dict):
                    continue
                # Skip VLAN 1 (default) and VLANs > 1000 (internal)
                try:
                    vid = int(vlan_id)
                except ValueError:
                    continue
                if vid <= 1 or vid > 1000:
                    continue
                state = str(vlan_data.get("state", "active")).lower()
                if state != "active":
                    continue
                if vlan_id not in svi_vlans:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="device",
                        element_id=f"{hostname}/vlan/{vlan_id}/no-svi",
                        message=f"VLAN {vlan_id} has no SVI configured",
                        key_facts={"vlan_id": vlan_id, "vlan_name": vlan_data.get("name", "")},
                        recommendation="Create 'interface Vlan{id}' if L3 routing is needed for this VLAN",
                    ))

        return findings
