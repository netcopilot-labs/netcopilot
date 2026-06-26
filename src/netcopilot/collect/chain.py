"""Strategy chain — ordered collection fallback.

The collector tries strategies in priority order and keeps the first that both
*supports* a device and *succeeds*. This replaces a hardcoded
NETCONF→RESTCONF→SSH ladder with a single ordered list: adding a transport means
inserting it at the right position, not editing the orchestrator.

Order is most-structured first (richer data) down to SSH (universal fallback).
Today SSH is the only registered strategy; the structured transports
(pyATS/NETCONF/RESTCONF, vendor REST) slot in ahead of it as they land.
"""
from __future__ import annotations

from netcopilot.collect.base import CollectionStrategy
from netcopilot.collect.netconf import NetconfAdapter
from netcopilot.collect.rest import RestAdapter
from netcopilot.collect.restconf import RestconfAdapter
from netcopilot.collect.ssh import SSHAdapter

# pyATS is an optional, heavy, Linux/macOS-only transport behind the [pyats]
# extra. Import it lazily here so a plain install (without the extra) still
# imports this module — the adapter is simply absent from the chain.
try:
    from netcopilot.collect.pyats import PyATSAdapter
    _PYATS_AVAILABLE = True
except ImportError:  # [pyats] extra not installed
    _PYATS_AVAILABLE = False


def default_chain() -> list[CollectionStrategy]:
    """Return the strategy chain in priority order (highest priority first).

    Structured transports first (richer data), SSH last (universal fallback).
    Cisco devices try pyATS→NETCONF→RESTCONF→SSH; FortiGate matches only the
    vendor REST adapter. pyATS is the richest Cisco strategy (Genie structured
    evidence) so it leads when the [pyats] extra is installed; without it the
    chain begins at NETCONF.
    """
    chain: list[CollectionStrategy] = []
    if _PYATS_AVAILABLE:
        chain.append(PyATSAdapter())
    chain += [NetconfAdapter(), RestconfAdapter(), RestAdapter(), SSHAdapter()]
    return chain


def applicable_strategies(
    device: dict,
    chain: list[CollectionStrategy] | None = None,
) -> list[CollectionStrategy]:
    """Return the chain strategies that support ``device``, in priority order."""
    chain = default_chain() if chain is None else chain
    return [s for s in chain if s.supports(device)]
