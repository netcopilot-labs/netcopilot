"""
BGP Neighbor Receiving Zero Prefixes — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: BGP_NEIGHBOR_ZERO_PREFIXES
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class BgpZeroPrefixesRule(BaseRule):
    """Detects BGP neighbors in Established state but receiving zero prefixes."""

    rule_id = "BGP_NEIGHBOR_ZERO_PREFIXES"
    severity = "high"
    title = "BGP Neighbor Receiving Zero Prefixes"
    description = "Detects BGP neighbors in Established state but receiving zero prefixes"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_bgp")
            if not data:
                continue
            # Navigate: instance.*.vrf.*.neighbor.*
            for inst_name, inst in data.get("instance", {}).items():
                if not isinstance(inst, dict):
                    continue
                for vrf_name, vrf in inst.get("vrf", {}).items():
                    if not isinstance(vrf, dict):
                        continue
                    for nbr_addr, nbr in vrf.get("neighbor", {}).items():
                        if not isinstance(nbr, dict):
                            continue
                        state = str(nbr.get("session_state", "")).lower()
                        if state != "established":
                            continue
                        # Check address families for zero prefixes
                        for af_name, af in nbr.get("address_family", {}).items():
                            if not isinstance(af, dict):
                                continue
                            prefixes = af.get("prefixes", {})
                            received = prefixes.get("received", prefixes.get("total_entries", -1))
                            if received == 0:
                                findings.append(Finding.create_from_rule(
                                    rule=self, element_type="device",
                                    element_id=f"{hostname}/bgp/{vrf_name}/{nbr_addr}",
                                    message=f"BGP neighbor {nbr_addr} receiving 0 prefixes in {af_name}",
                                    key_facts={
                                        "neighbor": nbr_addr, "vrf": vrf_name,
                                        "address_family": af_name, "prefixes_received": 0,
                                    },
                                    recommendation="Verify BGP peer configuration, route policies, and prefix advertisements",
                                ))

        return findings
