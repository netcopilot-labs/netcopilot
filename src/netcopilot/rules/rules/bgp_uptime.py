"""
BGP Neighbor Uptime Too Short — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: BGP_NEIGHBOR_UPTIME_TOO_SHORT
Severity: medium
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class BgpUptimeRule(BaseRule):
    """Detects BGP neighbors with very short uptime indicating session instability."""

    rule_id = "BGP_NEIGHBOR_UPTIME_TOO_SHORT"
    severity = "low"
    title = "BGP Neighbor Uptime Too Short"
    description = "Detects BGP neighbors with very short uptime indicating session instability"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_bgp")
            if not data:
                continue
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
                        # Parse up_time — format varies: "01:02:03" or "1w2d" etc.
                        up_time = str(nbr.get("up_time", ""))
                        if not up_time:
                            continue
                        # default; tune per deployment — flag sessions < 1 hour
                        # Simple heuristic: if "w" or "d" in uptime, it's stable
                        if "w" in up_time or "d" in up_time:
                            continue
                        # If format is HH:MM:SS, check hours
                        parts = up_time.split(":")
                        if len(parts) == 3:
                            try:
                                hours = int(parts[0])
                                if hours < 1:
                                    findings.append(Finding.create_from_rule(
                                        rule=self, element_type="device",
                                        element_id=f"{hostname}/bgp/{vrf_name}/{nbr_addr}",
                                        message=f"BGP neighbor {nbr_addr} uptime very short ({up_time})",
                                        key_facts={"neighbor": nbr_addr, "vrf": vrf_name, "up_time": up_time},
                                        recommendation="Investigate BGP session stability — check for flaps, authentication, or route policy issues",
                                    ))
                            except ValueError:
                                continue

        return findings
