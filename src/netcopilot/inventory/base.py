"""Inventory source abstraction.

An *inventory source* answers one question: which devices should NetCopilot
collect from, and how does it reach each one? It is the entry point of the
pipeline (``inventory -> collect -> parse -> model -> load``).

The contract is deliberately small — two methods over plain ``dict`` devices —
so any backing store can implement it: a YAML file (:mod:`netcopilot.inventory.yaml_source`),
or, on the roadmap, a CMDB such as NetBox. Each device dict carries at least
``name``, ``mgmt_ip``, and ``os``; collection-time hints (``role``, ``site``,
``skip_families``, ``ssh_only``, per-device credentials) are optional and
passed through verbatim for the collect layer to interpret.
"""
from abc import ABC, abstractmethod


class InventorySource(ABC):
    """Adapter interface for a source of devices to collect from.

    Concrete implementations live alongside this module (YAML today; other
    sources may be added without changing callers, which depend only on these
    two methods).
    """

    @abstractmethod
    def get_devices(self) -> list[dict]:
        """Return every device known to this source, as plain dicts."""

    @abstractmethod
    def get_device(self, name: str) -> dict | None:
        """Return a single device by ``name``, or ``None`` if not found."""
