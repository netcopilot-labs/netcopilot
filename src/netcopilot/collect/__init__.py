"""Collect layer — pull raw read-only evidence off devices.

Strategies (pyATS, NETCONF, RESTCONF, vendor REST, SSH) implement a common
contract and are tried in priority order via the strategy chain; the richest
Cisco transport, pyATS, is optional (the ``[pyats]`` extra) and leads when
installed. The collector orchestrates them over an inventory and writes a run
manifest.
"""
from netcopilot.collect.base import CollectionResult, CollectionStrategy
from netcopilot.collect.chain import applicable_strategies, default_chain
from netcopilot.collect.collector import (
    collect_device,
    get_env_credentials,
    resolve_credentials,
    run_collection,
)
from netcopilot.collect.netconf import NetconfAdapter
from netcopilot.collect.rest import RestAdapter
from netcopilot.collect.restconf import RestconfAdapter
from netcopilot.collect.ssh import SSHAdapter

__all__ = [
    "CollectionResult",
    "CollectionStrategy",
    "SSHAdapter",
    "NetconfAdapter",
    "RestconfAdapter",
    "RestAdapter",
    "default_chain",
    "applicable_strategies",
    "run_collection",
    "collect_device",
    "get_env_credentials",
    "resolve_credentials",
]
