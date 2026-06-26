"""
Cross-Device Evaluator — Orchestrator for Phase 3 rule evaluation.

Pre-loads all device facts, canonicalizes interface keys, builds
protocol membership indices, and dispatches to rule family modules.

Consumes the network model produced by `src/model/model_builder.py`.

Called by engine.py after Phase 1 + Phase 2.
Phase 3 failure is isolated — does not crash Phase 1+2 findings.
"""

import logging
from pathlib import Path
from typing import Any

from netcopilot.rules.cross_device.helpers import (
    build_bgp_peer_index,
    build_device_degree,
    build_domain_index,
    build_ospf_link_index,
    canonicalize_facts_keys,
    get_device_hostnames,
    load_all_device_facts,
)
from netcopilot.rules.finding import Finding

logger = logging.getLogger(__name__)


def run_cross_device_rules(
    topology_model: dict[str, Any],
    facts_dir: str | Path,
) -> tuple[list[Finding], list[str], list[dict[str, str]]]:
    """
    Main entry point for cross-device rule evaluation (Phase 3).

    Args:
        topology_model: Parsed network_model.json dict (the parameter
            name is historical from when the artefact was
            once called topology_model.json).
        facts_dir: Path to facts/ directory (e.g., "runs/run_id/facts").

    Returns:
        Tuple of (findings, executed_rule_ids, errors).
    """
    findings: list[Finding] = []
    executed: list[str] = []
    errors: list[dict[str, str]] = []

    # -----------------------------------------------------------------
    # 1. Pre-load all device facts into memory
    # -----------------------------------------------------------------
    device_hostnames = get_device_hostnames(topology_model)
    facts = load_all_device_facts(facts_dir, device_hostnames)

    logger.info(
        f"Phase 3: loaded facts for {len(facts)}/{len(device_hostnames)} devices"
    )

    if not facts:
        logger.warning("Phase 3: no device facts loaded, skipping")
        return findings, executed, errors

    # -----------------------------------------------------------------
    # 2. Canonicalize interface keys
    # -----------------------------------------------------------------
    canonicalize_facts_keys(facts)

    # -----------------------------------------------------------------
    # 3. Build protocol membership indices
    # -----------------------------------------------------------------
    links = topology_model.get("links", [])
    adjacencies = topology_model.get("adjacencies", [])
    shared_services = topology_model.get("shared_services", [])
    l2_domains = topology_model.get("l2_domains", [])

    ospf_links = build_ospf_link_index(links, facts)
    bgp_peers = build_bgp_peer_index(adjacencies, facts)
    ospf_domains = build_domain_index(shared_services, "ospf_area")
    bgp_domains = build_domain_index(shared_services, "bgp_asn")
    device_degree = build_device_degree(links)

    logger.info(
        f"Phase 3 indices: {len(ospf_links)} OSPF links, "
        f"{len(bgp_peers)} BGP peers, {len(ospf_domains)} OSPF domains, "
        f"{len(bgp_domains)} BGP domains"
    )

    # -----------------------------------------------------------------
    # 4. Dispatch rules by protocol family
    # -----------------------------------------------------------------
    # Each family module is imported lazily and called with try/except
    # so one family failure doesn't stop others.

    families = [
        ("ospf_rules", _run_ospf_rules, {
            "ospf_links": ospf_links,
            "ospf_domains": ospf_domains,
            "adjacencies": adjacencies,
            "facts": facts,
        }),
        ("bgp_rules", _run_bgp_rules, {
            "bgp_peers": bgp_peers,
            "bgp_domains": bgp_domains,
            "adjacencies": adjacencies,
            "links": links,
            "facts": facts,
        }),
        ("interface_rules", _run_interface_rules, {
            "links": links,
            "shared_services": shared_services,
            "l2_domains": l2_domains,
            "facts": facts,
        }),
        ("topology_rules", _run_topology_rules, {
            "facts": facts,
            "shared_services": shared_services,
            "device_degree": device_degree,
            "model": topology_model,
        }),
        ("static_route_rules", _run_static_route_rules, {
            "links": links,
            "facts": facts,
        }),
    ]

    for family_name, runner, kwargs in families:
        try:
            family_findings, family_executed = runner(**kwargs)
            findings.extend(family_findings)
            executed.extend(family_executed)
            logger.info(
                f"Phase 3 {family_name}: {len(family_findings)} findings, "
                f"{len(family_executed)} rules"
            )
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"Phase 3 {family_name} failed: {error_msg}")
            errors.append({
                "rule_id": f"PHASE3:{family_name}",
                "error": error_msg,
            })

    return findings, sorted(set(executed)), errors


# -------------------------------------------------------------------------
# Family dispatchers (lazy imports to avoid import-time errors)
# -------------------------------------------------------------------------

def _run_ospf_rules(**kwargs: Any) -> tuple[list[Finding], list[str]]:
    """Run all OSPF cross-device rules."""
    from netcopilot.rules.cross_device import ospf_rules
    findings: list[Finding] = []
    executed: list[str] = []

    bilateral = ospf_rules.evaluate_bilateral(
        kwargs["ospf_links"], kwargs["facts"],
    )
    findings.extend(bilateral)

    domain = ospf_rules.evaluate_domain(
        kwargs["ospf_domains"], kwargs["facts"], kwargs["adjacencies"],
    )
    findings.extend(domain)

    adjacency = ospf_rules.evaluate_adjacency(
        kwargs["adjacencies"], kwargs["facts"],
    )
    findings.extend(adjacency)

    executed.extend(ospf_rules.RULE_IDS)
    return findings, executed


def _run_bgp_rules(**kwargs: Any) -> tuple[list[Finding], list[str]]:
    """Run all BGP cross-device rules."""
    from netcopilot.rules.cross_device import bgp_rules
    findings: list[Finding] = []
    executed: list[str] = []

    bilateral = bgp_rules.evaluate_bilateral(
        kwargs["bgp_peers"], kwargs["links"], kwargs["facts"],
    )
    findings.extend(bilateral)

    domain = bgp_rules.evaluate_domain(
        kwargs["bgp_domains"], kwargs["facts"],
    )
    findings.extend(domain)

    adjacency = bgp_rules.evaluate_adjacency(
        kwargs["adjacencies"],
    )
    findings.extend(adjacency)

    executed.extend(bgp_rules.RULE_IDS)
    return findings, executed


def _run_interface_rules(**kwargs: Any) -> tuple[list[Finding], list[str]]:
    """Run all interface cross-device rules."""
    from netcopilot.rules.cross_device import interface_rules
    findings: list[Finding] = []
    executed: list[str] = []

    bilateral = interface_rules.evaluate_bilateral(
        kwargs["links"], kwargs["facts"],
    )
    findings.extend(bilateral)

    topology = interface_rules.evaluate_topology(
        kwargs["shared_services"], kwargs["links"], kwargs["facts"],
        kwargs.get("l2_domains"),
    )
    findings.extend(topology)

    executed.extend(interface_rules.RULE_IDS)
    return findings, executed


def _run_topology_rules(**kwargs: Any) -> tuple[list[Finding], list[str]]:
    """Run all topology cross-device rules."""
    from netcopilot.rules.cross_device import topology_rules
    findings: list[Finding] = []
    executed: list[str] = []

    result = topology_rules.evaluate(
        kwargs["facts"],
        kwargs["shared_services"],
        kwargs["device_degree"],
        kwargs["model"],
    )
    findings.extend(result)

    executed.extend(topology_rules.RULE_IDS)
    return findings, executed


def _run_static_route_rules(**kwargs: Any) -> tuple[list[Finding], list[str]]:
    """Run all static route cross-device rules."""
    from netcopilot.rules.cross_device import static_route_rules
    findings: list[Finding] = []
    executed: list[str] = []

    result = static_route_rules.evaluate(
        kwargs["links"], kwargs["facts"],
    )
    findings.extend(result)

    executed.extend(static_route_rules.RULE_IDS)
    return findings, executed
