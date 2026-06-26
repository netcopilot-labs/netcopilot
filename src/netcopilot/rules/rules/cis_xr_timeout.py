"""
CIS IOS XR Exec-Timeout Rule — Deep Python rule for the hybrid engine. Detects IOS XR devices with exec-timeout 0 0 (infinite)
on console or VTY lines.

Detection Logic:
    Loads running_config.txt, searches for 'exec-timeout 0 0' which means
    the session never times out. CIS recommends a timeout ≤ 10 minutes.

Rule ID: CIS_XR_1_2_EXEC_TIMEOUT
Severity: medium (overridden to cis by engine)
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


class CisXrExecTimeoutRule(BaseRule):
    """Flags IOS XR devices with exec-timeout 0 0 (no session timeout)."""

    rule_id = "CIS_XR_1_2_EXEC_TIMEOUT"
    severity = "low"
    title = "XR Exec-Timeout Disabled"
    description = "CIS: exec-timeout should not be 0 0 — sessions must time out"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            if device.get("os_family", "") != "iosxr":
                continue

            config = load_running_config(run_path, hostname)
            if config is None:
                continue

            # Find all lines with exec-timeout 0 0 and their context
            lines_with_zero = []
            for m in re.finditer(
                r"^(line\s+\S+.*?)$.*?exec-timeout\s+0\s+0",
                config, re.MULTILINE | re.DOTALL,
            ):
                lines_with_zero.append(m.group(1).strip())

            # Fallback: just check if exec-timeout 0 0 exists anywhere
            if not lines_with_zero and "exec-timeout 0 0" in config:
                lines_with_zero.append("(unidentified line context)")

            if lines_with_zero:
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/cis/xr/exec-timeout",
                    message=(
                        f"exec-timeout 0 0 (infinite) configured — "
                        f"idle sessions never expire"
                    ),
                    key_facts={
                        "lines_affected": ", ".join(lines_with_zero[:5]),
                        "exec_timeout": "0 0 (infinite)",
                    },
                    recommendation=(
                        "Set exec-timeout to ≤10 minutes: "
                        "'line console / exec-timeout 10 0' and "
                        "'line default / exec-timeout 10 0'"
                    ),
                ))

        return findings
