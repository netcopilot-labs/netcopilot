"""
Interface CRC Errors Detected — Deep Python rule for the hybrid rule engine.

Detection Logic:
    Iterates over model devices, loads facts/config, checks for violations.

Rule ID: INTF_CRC_ERROR_RATE_HIGH
Severity: high
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts, load_running_config


class IntfCrcErrorRule(BaseRule):
    """Detects interfaces with CRC errors indicating physical layer problems."""

    rule_id = "INTF_CRC_ERROR_RATE_HIGH"
    severity = "low"
    title = "Interface CRC Errors Detected"
    description = "Detects interfaces with CRC errors indicating physical layer problems"

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
                crc = counters.get("in_crc_errors", 0)
                # default; tune per deployment — threshold 10 CRC errors
                if crc and int(crc) > 10:
                    findings.append(Finding.create_from_rule(
                        rule=self, element_type="interface",
                        element_id=f"{hostname}/{intf_name}",
                        message=(
                            f"{intf_name}: CRC errors detected ({crc}) "
                            f"[cumulative — counters since last clear]"
                        ),
                        key_facts={"interface": intf_name, "crc_errors": crc},
                        recommendation=(
                            "Check physical cabling, transceivers, and speed/duplex settings. "
                            "Note: counters are cumulative since last 'clear counters' "
                            "— compare two collection runs to determine if errors are active."
                        ),
                    ))

        return findings
