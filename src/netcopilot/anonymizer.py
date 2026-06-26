"""SessionAnonymizer — scrubs network-identifying data before external-API calls.

Deterministic within a session with round-trip fidelity: the same identifier
always maps to the same label, and ``deanonymize`` restores the original text.
Use it to wrap any cloud LLM provider (e.g. Claude) so real device names, IPs,
sites, VRFs, AS numbers, ISP/platform names, and credentials never leave the
host. Local providers (Ollama) need no anonymization — data stays on-prem.

Scrubs: hostnames, ALL IPs, site names, VRF names, AS numbers, ISP names,
platform models, SNMP communities, credentials.
"""

from __future__ import annotations

import re


class SessionAnonymizer:
    """Replace network identifiers with generic labels before external API calls."""

    def __init__(self):
        self._device_map: dict[str, str] = {}
        self._device_reverse: dict[str, str] = {}
        self._ip_map: dict[str, str] = {}
        self._ip_reverse: dict[str, str] = {}
        self._site_map: dict[str, str] = {}
        self._site_reverse: dict[str, str] = {}
        self._vrf_map: dict[str, str] = {}
        self._vrf_reverse: dict[str, str] = {}
        self._asn_map: dict[str, str] = {}
        self._asn_reverse: dict[str, str] = {}
        self._platform_map: dict[str, str] = {}
        self._platform_reverse: dict[str, str] = {}
        self._isp_map: dict[str, str] = {}
        self._isp_reverse: dict[str, str] = {}
        self._device_n = 0
        self._ip_n = 0
        self._vrf_n = 0
        self._asn_n = 0
        self._platform_n = 0
        self._isp_n = 0

    def register_device(self, hostname: str) -> str:
        """Register a device hostname and return its anonymized label."""
        if hostname not in self._device_map:
            self._device_n += 1
            label = f"device-{self._device_n}"
            self._device_map[hostname] = label
            self._device_reverse[label] = hostname
        return self._device_map[hostname]

    def register_site(self, site: str) -> str:
        """Register a site name and return its anonymized label."""
        if site not in self._site_map:
            idx = len(self._site_map)
            label = f"site-{chr(65 + idx % 26)}"
            self._site_map[site] = label
            self._site_reverse[label] = site
        return self._site_map[site]

    def register_vrf(self, vrf: str) -> str:
        """Register a VRF name and return its anonymized label."""
        if vrf.lower() in ("default", "global", "root"):
            return vrf
        if vrf not in self._vrf_map:
            self._vrf_n += 1
            label = f"vrf-{self._vrf_n}"
            self._vrf_map[vrf] = label
            self._vrf_reverse[label] = vrf
        return self._vrf_map[vrf]

    def register_asn(self, asn: str) -> str:
        """Register an AS number and return its anonymized label.

        Accepts both "65010" and "AS65010" — normalizes to register both forms
        to avoid double-prefix ("ASAS64502") bugs.
        """
        # Normalize: strip leading "AS" for the raw number
        raw = asn.lstrip("AS") if asn.upper().startswith("AS") else asn
        prefixed = f"AS{raw}"  # "AS65010"

        if prefixed not in self._asn_map:
            self._asn_n += 1
            label = f"AS{64500 + self._asn_n}"
            self._asn_map[prefixed] = label      # AS65010 → AS64501
            self._asn_reverse[label] = prefixed
            # Also map raw number so bare "65010" in text gets caught
            self._asn_map[raw] = str(64500 + self._asn_n)  # 65010 → 64501
            self._asn_reverse[str(64500 + self._asn_n)] = raw
        return self._asn_map[prefixed]

    def register_platform(self, platform: str) -> str:
        """Register a platform/model and return its anonymized label."""
        if platform not in self._platform_map:
            self._platform_n += 1
            label = f"platform-{self._platform_n}"
            self._platform_map[platform] = label
            self._platform_reverse[label] = platform
        return self._platform_map[platform]

    def register_isp(self, isp: str) -> str:
        """Register an ISP/carrier name and return its anonymized label."""
        if isp not in self._isp_map:
            self._isp_n += 1
            label = f"isp-{self._isp_n}"
            self._isp_map[isp] = label
            self._isp_reverse[label] = isp
        return self._isp_map[isp]

    @staticmethod
    def _is_route_prefix(ip: str) -> bool:
        """Check if an IP is a route prefix (not a real host address)."""
        return ip in ("0.0.0.0", "255.255.255.255")

    def anonymize(self, text: str) -> str:
        """Replace all identifying network data with anonymous labels."""
        # 1. Replace ALL IPs (skip route prefixes)
        text = re.sub(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
            lambda m: m.group(0) if self._is_route_prefix(m.group(0)) else self._replace_ip(m.group(0)),
            text,
        )
        # 2. Replace hostnames (longest first to avoid partial matches)
        for hostname, label in sorted(self._device_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(hostname, label)
        # 3. Replace site names (longest first)
        for site, label in sorted(self._site_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(site, label)
        # 4. Replace VRF names (longest first)
        for vrf, label in sorted(self._vrf_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(vrf, label)
        # 5. Replace AS numbers (longest first — "AS65010" before "65010")
        for asn, label in sorted(self._asn_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(asn, label)
        # 6. Replace platform names (longest first)
        for platform, label in sorted(self._platform_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(platform, label)
        # 7. Replace ISP/carrier names (longest first)
        for isp, label in sorted(self._isp_map.items(), key=lambda x: -len(x[0])):
            text = text.replace(isp, label)
        # 8. Scrub credentials — redact common patterns
        text = self._scrub_credentials(text)
        return text

    def deanonymize(self, text: str) -> str:
        """Restore original data from anonymous labels."""
        # Reverse in order: ISPs, platforms, ASNs, VRFs, sites, IPs, devices.
        # Use longest label first to avoid partial replacement.
        for label, isp in sorted(self._isp_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, isp)
        for label, platform in sorted(self._platform_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, platform)
        for label, asn in sorted(self._asn_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, asn)
        for label, vrf in sorted(self._vrf_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, vrf)
        for label, site in sorted(self._site_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, site)
        # IPs: reverse longest labels first (10.0.0.19 before 10.0.0.1)
        for label, ip in sorted(self._ip_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, ip)
        # Devices: longest label first
        for label, hostname in sorted(self._device_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, hostname)
        # Restore scrubbed credentials
        text = self._unscrub_credentials(text)
        return text

    def get_summary(self) -> dict:
        """Return anonymization stats for display."""
        return {
            "devices_anonymized": len(self._device_map),
            "ips_anonymized": len(self._ip_map),
            "sites_anonymized": len(self._site_map),
            "vrfs_anonymized": len(self._vrf_map),
            "asns_anonymized": len(self._asn_map),
            "platforms_anonymized": len(self._platform_map),
            "isps_anonymized": len(self._isp_map),
            "sample_mappings": [
                f"{hostname} → {label}"
                for hostname, label in list(self._device_map.items())[:3]
            ],
        }

    def _replace_ip(self, ip: str) -> str:
        """Replace an IP with a deterministic anonymized IP."""
        if ip not in self._ip_map:
            self._ip_n += 1
            label = f"10.0.0.{self._ip_n}"
            self._ip_map[ip] = label
            self._ip_reverse[label] = ip
        return self._ip_map[ip]

    # ── Credential scrubbing ────────────────────────────────────────
    # These are NOT reversible in spirit — credentials should never reach the
    # LLM. De-anonymize restores them from a fixed placeholder for display.

    # Patterns that match credential-like values. Each pattern's full match
    # is replaced with "[CREDENTIAL-N]" and stored for round-trip restoration.
    _CREDENTIAL_REGEXES = [
        # "keyword: value" or "keyword = value"
        r'(?i)(?:password|secret|community|token|key)\s*[:=]\s*\S+',
        # "user / pass" format
        r'(?i)(?:admin|root|user)\s*/\s*\S+',
        # "SSH: user / pass"
        r'(?i)SSH\s*:\s*\S+\s*/\s*\S+',
        # SNMP community
        r'(?i)(?:snmp[_-]?community|community[_-]?string)\s*[:=]?\s*\S+',
        # Serial numbers
        r'(?i)\bSN:\s*\S+',
        r'(?i)(?:serial[_\s]?(?:number|no)?)\s*[:=]?\s*[A-Z]{2,3}\w{6,}',
    ]

    def _scrub_credentials(self, text: str) -> str:
        """Replace credential patterns with numbered placeholders."""
        if not hasattr(self, '_cred_map'):
            self._cred_map: dict[str, str] = {}
            self._cred_reverse: dict[str, str] = {}
            self._cred_n = 0

        for pattern in self._CREDENTIAL_REGEXES:
            for m in reversed(list(re.finditer(pattern, text))):
                original = m.group(0)
                if original not in self._cred_map:
                    self._cred_n += 1
                    label = f"[CREDENTIAL-{self._cred_n}]"
                    self._cred_map[original] = label
                    self._cred_reverse[label] = original
                text = text[:m.start()] + self._cred_map[original] + text[m.end():]
        return text

    def _unscrub_credentials(self, text: str) -> str:
        """Restore credentials from placeholders."""
        if not hasattr(self, '_cred_reverse'):
            return text
        for label, original in sorted(self._cred_reverse.items(), key=lambda x: -len(x[0])):
            text = text.replace(label, original)
        return text
