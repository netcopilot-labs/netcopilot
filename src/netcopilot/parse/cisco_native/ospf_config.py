"""Parse OSPF process configuration from IOS XE running config.

Extracts process-level config that Genie's ``learn('ospf')`` does not reliably
capture: area types (stub/NSSA/totally-*), passive-interface default with
exceptions, capability vrf-lite, and redistribute directives.

Used by the link builder for OSPF model enrichment.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Regex to match ``router ospf <pid>`` or ``router ospf <pid> vrf <vrf>``
_ROUTER_OSPF_RE = re.compile(
    r"^router\s+ospf\s+(\d+)(?:\s+vrf\s+(\S+))?$"
)

# ``area <id> stub [no-summary]`` or ``area <id> nssa [... no-summary ...]``
_AREA_TYPE_RE = re.compile(
    r"^\s*area\s+(\d+)\s+(stub|nssa)(.*)$"
)

_PASSIVE_DEFAULT_RE = re.compile(r"^\s*passive-interface\s+default\s*$")
_NO_PASSIVE_RE = re.compile(r"^\s*no\s+passive-interface\s+(\S+)")
_CAPABILITY_VRF_LITE_RE = re.compile(r"^\s*capability\s+vrf-lite\s*$")
_REDISTRIBUTE_RE = re.compile(r"^\s*redistribute\s+(\S+)")


def parse_ospf_process_configs(
    config_text: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Parse OSPF process blocks from an IOS XE running configuration.

    Args:
        config_text: Full running-config text (plain string).

    Returns:
        Dict keyed by ``(process_id_str, vrf_name)`` with values::

            {
                "area_types":        {2: "stub", 102: "totally-nssa", ...},
                "passive_default":   True | False,
                "active_interfaces": ["Vlan1200", ...],   # no passive-intf exceptions
                "capability_vrf_lite": True | False,
                "redistribute":      ["static", "connected", ...],
            }

        VRF defaults to ``"default"`` when the ``router ospf`` line has no
        ``vrf`` keyword.
    """
    results: dict[tuple[str, str], dict[str, Any]] = {}
    current_key: tuple[str, str] | None = None
    current_cfg: dict[str, Any] | None = None

    for line in config_text.splitlines():
        # Detect block start
        m = _ROUTER_OSPF_RE.match(line)
        if m:
            # Save previous block
            if current_key is not None and current_cfg is not None:
                results[current_key] = current_cfg
            pid = m.group(1)
            vrf = m.group(2) or "default"
            current_key = (pid, vrf)
            current_cfg = {
                "area_types": {},
                "passive_default": False,
                "active_interfaces": [],
                "capability_vrf_lite": False,
                "redistribute": [],
            }
            continue

        # Block terminator: a line starting at column 0 that isn't indented
        # (e.g. ``!`` or another ``router ...`` or ``interface ...``)
        if current_cfg is not None and line and not line[0].isspace():
            if not _ROUTER_OSPF_RE.match(line):
                results[current_key] = current_cfg  # type: ignore[index]
                current_key = None
                current_cfg = None
            continue

        if current_cfg is None:
            continue

        # --- Inside an OSPF process block ---

        # Area type
        am = _AREA_TYPE_RE.match(line)
        if am:
            area_int = int(am.group(1))
            base_type = am.group(2)  # "stub" or "nssa"
            rest = am.group(3)
            if "no-summary" in rest:
                area_type = f"totally-{base_type}"
            else:
                area_type = base_type
            current_cfg["area_types"][area_int] = area_type
            continue

        # Passive interface default
        if _PASSIVE_DEFAULT_RE.match(line):
            current_cfg["passive_default"] = True
            continue

        # No passive-interface exception
        npm = _NO_PASSIVE_RE.match(line)
        if npm:
            current_cfg["active_interfaces"].append(npm.group(1))
            continue

        # Capability VRF-Lite
        if _CAPABILITY_VRF_LITE_RE.match(line):
            current_cfg["capability_vrf_lite"] = True
            continue

        # Redistribute
        rm = _REDISTRIBUTE_RE.match(line)
        if rm:
            current_cfg["redistribute"].append(rm.group(1))
            continue

    # Save last block
    if current_key is not None and current_cfg is not None:
        results[current_key] = current_cfg

    return results
