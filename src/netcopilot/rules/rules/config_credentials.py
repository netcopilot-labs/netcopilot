"""
Plaintext Credentials in Config — Deep Python rule for the hybrid engine. Detects embedded credentials in running config URLs
such as scp://user:password@host paths in archive config.

Detection Logic:
    Searches running_config.txt for URL patterns containing embedded
    credentials: (scp|ftp|tftp|http|https)://user:pass@host.
    Masks the password in evidence to avoid leaking it in findings.

Rule ID: CONFIG_PLAINTEXT_CREDENTIALS
Severity: medium
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


# Match URLs with embedded credentials: protocol://user:pass@host
_CRED_URL_RE = re.compile(
    r"((?:scp|ftp|tftp|https?)://)([^:]+):([^@]+)@(\S+)",
    re.IGNORECASE,
)


def _mask_url(match: re.Match) -> str:
    """Return URL with password masked."""
    return f"{match.group(1)}{match.group(2)}:****@{match.group(4)}"


class ConfigPlaintextCredentialsRule(BaseRule):
    """Flags running configs that contain embedded plaintext credentials in URLs."""

    rule_id = "CONFIG_PLAINTEXT_CREDENTIALS"
    severity = "low"
    title = "Plaintext Credentials in Config"
    description = "Running config contains URL with embedded username:password — credentials exposed"

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            config = load_running_config(run_path, hostname)
            if config is None:
                continue

            # Build masked evidence; skip SCEP/PKI URLs where the regex
            # captures a port number (pure integer) as the "password".
            # e.g. http://192.0.2.200:80/ejbca/... → group(3)="80" → skip.
            masked_urls = []
            for m in _CRED_URL_RE.finditer(config):
                if m.group(3).isdigit():
                    continue  # port number, not a real password
                masked_urls.append(_mask_url(m))

            if not masked_urls:
                continue

            findings.append(Finding.create_from_rule(
                rule=self, element_type="device",
                element_id=f"{hostname}/config/plaintext-credentials",
                message=(
                    f"{len(masked_urls)} URL(s) with embedded "
                    f"plaintext credentials found in running config"
                ),
                key_facts={
                    "credential_count": len(masked_urls),
                    "masked_urls": ", ".join(masked_urls[:5]),
                },
                recommendation=(
                    "Remove embedded credentials from config URLs. "
                    "Use key-based authentication or credential vaults instead."
                ),
            ))

        return findings
