"""Remediation loader — interpolates CLI templates from the rule catalog.

Loads the rule catalog once, caches it, and provides per-finding CLI remediation
by interpolating key_facts into OS-specific templates.

Usage:
    cli = get_remediation("OSPF_INTERFACE_NO_AUTHENTICATION", "ios_xe",
                          {"process_id": "100", "area_id": "0.0.0.10",
                           "interface": "Vlan100"})
"""

import logging
import os as _os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

_CATALOG_CACHE: dict[str, dict] | None = None


def _find_catalog_path() -> Path:
    """Locate the rule catalog. RULE_CATALOG_PATH overrides; default is the
    catalog shipped as package data alongside the rules engine."""
    env_path = _os.environ.get("RULE_CATALOG_PATH")
    if env_path:
        return Path(env_path)
    # netcopilot/analysis/remediation_loader.py -> netcopilot/rules/rule-catalog.yaml
    return Path(__file__).resolve().parent.parent / "rules" / "rule-catalog.yaml"


_CATALOG_PATH = _find_catalog_path()


def _load_catalog() -> dict[str, dict]:
    """Load and cache the rule catalog keyed by rule_id."""
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE

    try:
        with open(_CATALOG_PATH) as f:
            rules = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        log.error("Failed to load the rule catalog: %s", exc)
        _CATALOG_CACHE = {}
        return _CATALOG_CACHE

    _CATALOG_CACHE = {r["rule_id"]: r for r in rules if "rule_id" in r}
    log.info("Loaded %d rules from the rule catalog", len(_CATALOG_CACHE))
    return _CATALOG_CACHE


def _extract_ospf_params(key_facts: dict) -> dict:
    """Extract OSPF parameters from json_path-style key_facts.

    OSPF findings store parameters in json_path like:
      vrf.CUSTOMER-VRF.address_family.ipv4.instance.100.areas.0.0.0.10.interfaces.Vlan100...
    This function extracts process_id, area_id, interface, and vrf.
    """
    json_path = key_facts.get("json_path", "")
    extra: dict[str, str] = {}

    m = re.search(r"vrf\.([^.]+)\.address_family", json_path)
    if m:
        extra["vrf"] = m.group(1)

    m = re.search(r"instance\.(\d+)\.areas", json_path)
    if m:
        extra["process_id"] = m.group(1)

    m = re.search(r"areas\.(\d+\.\d+\.\d+\.\d+)\.", json_path)
    if m:
        extra["area_id"] = m.group(1)

    m = re.search(r"interfaces\.([^.]+)", json_path)
    if m:
        extra["interface"] = m.group(1)

    return extra


def enrich_key_facts(rule_id: str, key_facts: dict) -> dict:
    """Enrich key_facts with extracted parameters for rules that use json_path."""
    enriched = dict(key_facts)
    if rule_id.startswith("OSPF_") and "json_path" in key_facts:
        enriched.update(_extract_ospf_params(key_facts))
    return enriched


def get_remediation(
    rule_id: str,
    os_family: str,
    key_facts: dict[str, Any],
) -> str | None:
    """Return interpolated CLI remediation for a finding, or None if no template.

    Args:
        rule_id: The rule identifier (e.g., "OSPF_INTERFACE_NO_AUTHENTICATION").
        os_family: Target OS (e.g., "ios_xe", "iosxr", "fortios").
        key_facts: Finding evidence key_facts dict.
    """
    catalog = _load_catalog()
    rule = catalog.get(rule_id)
    if not rule or "remediation" not in rule:
        return None

    templates = rule["remediation"]
    template = templates.get(os_family) or templates.get("generic")
    if not template:
        return None

    enriched = enrich_key_facts(rule_id, key_facts)
    try:
        return template.format_map(defaultdict(lambda: "<VALUE>", enriched))
    except (KeyError, ValueError) as exc:
        log.warning("Template interpolation failed for %s/%s: %s", rule_id, os_family, exc)
        return template


def get_all_remediations() -> dict[str, dict]:
    """Return all rules that have remediation templates (rule_id -> templates)."""
    catalog = _load_catalog()
    return {
        rule_id: rule["remediation"]
        for rule_id, rule in catalog.items()
        if "remediation" in rule
    }
