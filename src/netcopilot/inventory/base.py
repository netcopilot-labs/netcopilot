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

# Canonical OS families the collect layer understands, plus the spellings real
# inventories use. The original tooling writes joined ``iosxe``/``iosxr``; the
# collect layer's canonical form is hyphenated ``ios-xe``/``ios-xr``. Normalizing
# on load lets an inventory be copied verbatim regardless of spelling or case.
_OS_ALIASES = {
    "ios-xe": "ios-xe", "iosxe": "ios-xe",
    "ios-xr": "ios-xr", "iosxr": "ios-xr",
    "fortios": "fortios",
}


def normalize_os(value: object) -> str:
    """Map an inventory ``os`` value to its canonical family.

    Accepts the joined (``iosxe``) and hyphenated (``ios-xe``) spellings in any
    case and returns the canonical ``ios-xe`` / ``ios-xr`` / ``fortios``. An
    unrecognized value passes through lowercased so downstream validation rejects
    it with a clear message instead of this helper masking a typo.
    """
    key = str(value).strip().lower()
    return _OS_ALIASES.get(key, key)


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
