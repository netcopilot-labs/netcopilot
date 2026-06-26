"""
Interface Error Rate High — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: INTF_ERROR_RATE_HIGH
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class IntfErrorRateRule(BaseRule):
    """Detects interfaces with elevated input/output error counters."""

    rule_id = "INTF_ERROR_RATE_HIGH"
    severity = "low"
    title = "Interface Error Rate High"
    description = "Detects interfaces with elevated input/output error counters"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        run_path = context.get("run_path", "")
        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            data = load_device_facts(run_path, hostname, "genie_interface")
            if not data:
                continue
            for intf_name in sorted(data.keys()):
                intf = data[intf_name]
                if not isinstance(intf, dict):
                    continue
                counters = intf.get("counters", {})
                if not counters:
                    continue
                in_errors = counters.get("in_errors", 0)
                out_errors = counters.get("out_errors", 0)
                last_clear = counters.get("last_clear", "unknown")
                # Cumulative counters (since last clear or reload) — not a
                # real-time rate.  Medium severity because we cannot tell if
                # errors are recent without a second collection point.
                threshold = 100
                if in_errors > threshold or out_errors > threshold:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}",
                        message=f"{intf_name}: error counters elevated (last_clear={last_clear})",
                        key_facts={
                            "interface": intf_name, "in_errors": in_errors,
                            "out_errors": out_errors, "threshold": threshold,
                            "last_clear": last_clear,
                        },
                        recommendation="Investigate interface errors — check cables, transceivers, speed/duplex. Counters are cumulative since last clear.",
                    ))

        return findings
