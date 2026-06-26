"""
Static Route Inactive — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: STATIC_ROUTE_INACTIVE
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class StaticRouteInactiveRule(BaseRule):
    """Detects static routes that are configured but not active in the routing table."""

    rule_id = "STATIC_ROUTE_INACTIVE"
    severity = "high"
    title = "Static Route Inactive"
    description = "Detects static routes that are configured but not active in the routing table"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_static_routing")
            if not data:
                continue
            # Structure: vrf.{name}.address_family.{af}.routes.{prefix}.next_hop.{nh}
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
                        if active is False:
                            findings.append(Finding.create_from_rule(
                                rule=self, element_type="device",
                                element_id=f"{hostname}/static/{vrf_name}/{prefix}",
                                message=f"Static route {prefix} is inactive",
                                key_facts={
                                    "prefix": prefix, "vrf": vrf_name,
                                    "address_family": af_name, "active": False,
                                },
                                recommendation="Verify next-hop reachability or remove stale static route",
                            ))

        return findings
