"""
Config Password Hash Deep Rules — Deep Python rules for the hybrid rule engine.

Detection Logic:
    Scans running-config for weak password hash algorithms:
    - Type 0 (secret 0): plaintext password
    - Type 5 with $1$ prefix: MD5 hash (easily crackable)
    - Type 7 (password 7): reversible Vigenère encoding

Rule IDs: WEAK_PASSWORD_HASH
Severity: medium

audit: new rule to detect weak password hashes that
should be upgraded to type 8/9 (PBKDF2) or type 6 (AES).
"""

import re
from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding
from netcopilot.rules.generic_evaluator import load_running_config


class WeakPasswordHashRule(BaseRule):
    """Flags devices with weak password hashes in running config."""

    rule_id = "WEAK_PASSWORD_HASH"
    severity = "low"
    title = "Weak Password Hash"
    description = "Running config contains weak password hashes (MD5/type 7/plaintext)"

    # Patterns that indicate weak hashes
    _PATTERNS = [
        # Type 5 with MD5 ($1$) — weak
        (re.compile(r"secret\s+5\s+\$1\$"), "MD5 (type 5/$1$)"),
        # Type 7 — reversible encoding
        (re.compile(r"password\s+7\s+"), "type 7 (reversible)"),
        # Type 0 — plaintext
        (re.compile(r"secret\s+0\s+"), "plaintext (type 0)"),
    ]

    def evaluate(self, model: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        run_path = context.get("run_path", "")

        for device in model.get("devices", []):
            hostname = device.get("hostname", "")
            config = load_running_config(run_path, hostname)
            if not config:
                continue

            weak_types: dict[str, int] = {}
            for line in config.splitlines():
                stripped = line.strip()
                for pattern, desc in self._PATTERNS:
                    if pattern.search(stripped):
                        weak_types[desc] = weak_types.get(desc, 0) + 1

            if weak_types:
                total = sum(weak_types.values())
                details = ", ".join(f"{k}: {v}" for k, v in sorted(weak_types.items()))
                findings.append(Finding.create_from_rule(
                    rule=self, element_type="device",
                    element_id=f"{hostname}/config/weak-password-hash",
                    message=(
                        f"{total} weak password hash(es) found — {details}"
                    ),
                    key_facts={"weak_hash_types": weak_types, "total_count": total},
                    recommendation=(
                        "Upgrade to type 8/9 (PBKDF2-SHA256) hashes: "
                        "'username <user> secret 9 <password>'"
                    ),
                ))

        return findings
