"""
Collection Strategy Rule — Detect devices not collected via pyATS primary path.

As of pyATS/Unicon is the primary collection strategy for all
Cisco devices. This rule detects devices that fell back to a
secondary strategy and grades the finding severity by how far the device
diverged from the preferred path.

Detection Logic:
    For each device in manifest["devices"]:
        strategy == "pyats"              → no finding (primary, expected)
        strategy == "rest" + fortios     → no finding (REST is FortiGate primary)
        strategy in ("netconf",
                     "restconf",
                     "restconf_fallback") → low severity (structured data,
                                            but pyATS unavailable)
        strategy in ("ssh", "ssh_fallback",
                     "ssh_forced")       → medium severity (CLI text only,
                                            no Genie structured output)

Why This Matters:
    pyATS provides Genie-parsed structured output alongside raw CLI text.
    NETCONF/RESTCONF provides structured YANG data but no Genie ops models.
    SSH provides only raw CLI text — the least rich data source.
    Deeper protocol analysis depends on Genie ops models for deep protocol analysis.

Example Finding (NETCONF fallback):
    {
        "finding_id": "SSH_FALLBACK::core-sw-02",
        "rule_id": "SSH_FALLBACK",
        "severity": "info",
        "title": "NETCONF Collection (pyATS Unavailable)",
        "message": "Device 'core-sw-02' collected via NETCONF ...",
        "evidence": {
            "element_type": "device",
            "element_id": "core-sw-02",
            "key_facts": {
                "hostname": "core-sw-02",
                "collection_strategy": "netconf"
            }
        }
    }

Example Finding (SSH fallback):
    {
        "finding_id": "SSH_FALLBACK::core-rtr-01",
        "rule_id": "SSH_FALLBACK",
        "severity": "low",
        "title": "Legacy SSH Collection (pyATS and NETCONF Unavailable)",
        "message": "Device 'core-rtr-01' collected via SSH ...",
    }

Related ADRs:
    - SSH as Degraded Collection Mode
    - pyATS/Genie as Primary Cisco Collection Stack
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
from typing import Any

# -------------------------------------------------------------------------
# Local imports
# -------------------------------------------------------------------------
from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


# -------------------------------------------------------------------------
# Strategy classification
# -------------------------------------------------------------------------
# Strategies that require no finding — primary path for their device family.
_PRIMARY_STRATEGIES = {"pyats", "rest"}

# Strategies that represent structured fallback (YANG data, no Genie ops models).
_STRUCTURED_FALLBACK_STRATEGIES = {"netconf", "restconf", "restconf_fallback"}

# Strategies that represent legacy CLI-only collection (lowest data richness).
_LEGACY_FALLBACK_STRATEGIES = {"ssh", "ssh_fallback", "ssh_forced"}


class SSHFallbackRule(BaseRule):
    """
    Detect devices not collected via their primary strategy (pyATS for Cisco).

    Generates graded findings:
    - low: NETCONF/RESTCONF used (structured data, but no Genie ops models)
    - medium: SSH used (CLI text only — least rich data source)
    - no finding: pyATS (primary) or REST/FortiGate (primary for their OS)
    """

    # -------------------------------------------------------------------------
    # Required class attributes
    # -------------------------------------------------------------------------
    rule_id = "SSH_FALLBACK"
    severity = "info"   # default; actual severity set per finding in evaluate()
    title = "Collection Strategy Fallback"
    description = "Device not collected via primary pyATS strategy"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Check manifest for devices that did not use the primary collection strategy.

        Args:
            model: The network model (not used directly by this rule).
            context: Contains manifest with collection_strategy per device.

        Returns:
            List of findings for devices on non-primary strategies.
        """
        findings: list[Finding] = []

        manifest = context.get("manifest", {})
        manifest_devices = manifest.get("devices", [])

        for device in manifest_devices:
            strategy = device.get("collection_strategy", "")
            os_family = device.get("os", "")
            hostname = device.get("hostname", device.get("inventory_name", "unknown"))
            mgmt_ip = device.get("target", "unknown")

            # -----------------------------------------------------------------
            # Primary strategies: no finding
            # -----------------------------------------------------------------
            if strategy in _PRIMARY_STRATEGIES:
                continue

            # -----------------------------------------------------------------
            # Structured fallback: NETCONF or RESTCONF
            # Severity: low — YANG data collected, but Genie ops models missing
            # -----------------------------------------------------------------
            if strategy in _STRUCTURED_FALLBACK_STRATEGIES:
                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity="info",
                    title=f"{'RESTCONF' if 'restconf' in strategy else 'NETCONF'} Collection (pyATS Unavailable)",
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"Collected via {strategy.upper()} "
                        f"instead of the primary pyATS strategy ({mgmt_ip}). Structured YANG data was "
                        f"collected successfully, but Genie ops models are unavailable — "
                        f"+ deep protocol analysis will be limited for this device."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "management_ip": mgmt_ip,
                        "os": os_family,
                        "collection_strategy": strategy,
                        "impact": "no_genie_ops_models",
                    },
                    recommendation=(
                        "Verify pyATS can connect to this device via Unicon SSH. "
                        "Check for SSH key negotiation issues "
                        "(some C9KV devices need disabled_algorithms for rsa-sha2). "
                        "Review pyATS adapter logs for the specific connection error."
                    ),
                )
                findings.append(finding)

            # -----------------------------------------------------------------
            # Legacy SSH fallback: ssh, ssh_fallback, ssh_forced
            # Severity: medium — CLI text only, no structured data at all
            # -----------------------------------------------------------------
            elif strategy in _LEGACY_FALLBACK_STRATEGIES:
                forced_note = " (manually forced via --force-ssh)" if strategy == "ssh_forced" else ""
                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity="low",
                    title="Legacy SSH Collection (pyATS and NETCONF Unavailable)",
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"Collected via legacy SSH{forced_note} "
                        f"instead of pyATS ({mgmt_ip}). Only raw CLI text was collected — "
                        f"no Genie ops models, no structured YANG data. "
                        f"+ protocol analysis will not be possible for this device."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "management_ip": mgmt_ip,
                        "os": os_family,
                        "collection_strategy": strategy,
                        "impact": "cli_text_only",
                    },
                    recommendation=(
                        "Verify pyATS/Unicon can reach the device via SSH. "
                        "Check SSH credentials and key algorithms. "
                        "For IOS XR: ensure 'ssh server v2' is configured. "
                        "Review pyATS adapter logs to identify the root cause."
                    ),
                )
                findings.append(finding)

        return findings
