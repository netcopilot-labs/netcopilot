"""
STP Global Config Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Iterates all devices → loads genie_stp.json → checks global STP config flags.

Rule IDs:
    STP_BPDUGUARD_DISABLED_GLOBALLY  — info  (best practice for access ports)
    STP_BPDUFILTER_ENABLED_GLOBALLY  — low   (silently drops BPDUs — loop risk)
    STP_LOOPGUARD_DISABLED_GLOBALLY  — info  (protects unidirectional link failures)

Addendum: STP Rules.
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_device_facts


def _get_stp_global(run_path: str, hostname: str) -> dict | None:
    """Load genie_stp.json and return the global config dict, or None."""
    data = load_device_facts(run_path, hostname, "genie_stp")
    if not data or not isinstance(data, dict):
        return None
    return data.get("global") or {}


class StpBpduGuardDisabledGloballyRule(BaseRule):
    """Flags devices where BPDU Guard is not enabled globally.

    BPDU Guard globally enabled triggers err-disable on PortFast ports that
    receive BPDUs, protecting against accidental switch connections on
    access ports.
    """

    rule_id = "STP_BPDUGUARD_DISABLED_GLOBALLY"
    severity = "info"
    title = "STP BPDU Guard Disabled Globally"
    description = "Global BPDU Guard is not enabled — access ports lack automatic loop protection"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            if device.get("os_family") not in ("iosxe",):
                continue
            hostname = device.get("hostname", "")
            global_cfg = _get_stp_global(run_path, hostname)
            if global_cfg is None:
                continue
            if global_cfg.get("bpdu_guard") is False:
                findings.append(Finding.create_from_rule(
                    rule=self,
                    element_type="device",
                    element_id=f"{hostname}/stp/global/bpdu_guard",
                    message=f"{hostname}: global BPDU Guard is disabled",
                    key_facts={"bpdu_guard": False},
                    recommendation=(
                        "Enable with 'spanning-tree portfast bpduguard default'. "
                        "Ensure PortFast is configured on all access ports first."
                    ),
                ))

        return findings


class StpBpduFilterEnabledGloballyRule(BaseRule):
    """Flags devices where BPDU Filter is enabled globally.

    BPDU Filter enabled globally suppresses BPDU transmission on PortFast
    ports, effectively removing those ports from spanning tree. This can
    silently create loops if a switch is connected to an access port.
    """

    rule_id = "STP_BPDUFILTER_ENABLED_GLOBALLY"
    severity = "low"
    title = "STP BPDU Filter Enabled Globally"
    description = "Global BPDU Filter is enabled — BPDUs suppressed on PortFast ports, loop risk"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            if device.get("os_family") not in ("iosxe",):
                continue
            hostname = device.get("hostname", "")
            global_cfg = _get_stp_global(run_path, hostname)
            if global_cfg is None:
                continue
            # Inverse logic: True fires the finding (enabled is dangerous)
            if global_cfg.get("bpdu_filter") is True:
                findings.append(Finding.create_from_rule(
                    rule=self,
                    element_type="device",
                    element_id=f"{hostname}/stp/global/bpdu_filter",
                    message=f"{hostname}: global BPDU Filter is enabled — BPDUs suppressed on PortFast ports",
                    key_facts={"bpdu_filter": True},
                    recommendation=(
                        "Disable with 'no spanning-tree portfast bpdufilter default'. "
                        "BPDU Filter hides loops — prefer BPDU Guard which err-disables the port instead."
                    ),
                ))

        return findings


class StpLoopGuardDisabledGloballyRule(BaseRule):
    """Flags devices where Loop Guard is not enabled globally.

    Loop Guard prevents alternate or root ports from becoming designated
    ports due to loss of BPDUs on a unidirectional link, which would
    otherwise create a forwarding loop.
    """

    rule_id = "STP_LOOPGUARD_DISABLED_GLOBALLY"
    severity = "info"
    title = "STP Loop Guard Disabled Globally"
    description = "Global Loop Guard is not enabled — unidirectional link failures may cause loops"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            if device.get("os_family") not in ("iosxe",):
                continue
            hostname = device.get("hostname", "")
            global_cfg = _get_stp_global(run_path, hostname)
            if global_cfg is None:
                continue
            if global_cfg.get("loop_guard") is False:
                findings.append(Finding.create_from_rule(
                    rule=self,
                    element_type="device",
                    element_id=f"{hostname}/stp/global/loop_guard",
                    message=f"{hostname}: global Loop Guard is disabled",
                    key_facts={"loop_guard": False},
                    recommendation=(
                        "Enable with 'spanning-tree loopguard default'. "
                        "Protects against unidirectional fiber failures on uplink ports."
                    ),
                ))

        return findings
