"""Abstract base for declared-state adapters (s11, ADR-0013).

Declared state answers "what *should* the network look like?" — layer L0 in
NetCopilot's model (L0 declared / L1 collected). All adapters expose the same
four-method contract so downstream consumers (bootstrap, staging, drift) are
source-agnostic:

``get_devices() -> list[dict]``
    Full device list known to the source. Each dict carries at minimum
    ``name`` (str) and ``mgmt_ip`` (str). Additional keys depend on the
    source — the YAML adapter mirrors the inventory file's keys (``os``,
    ``role``, ``site``, ``cluster``, …); the NetBox adapter mirrors
    ``dcim.devices`` fields (``platform``, ``site``, ``status``, …).

``get_device(hostname: str) -> dict | None``
    Single-device lookup by name. ``None`` if not found.

``get_sites() -> list[dict]``
    Site list; each dict has at least ``slug`` and ``name``.

``get_interfaces(device: str) -> list[dict]``
    Interfaces declared for one device; each dict has at least ``name``.
    Sources that do not declare interfaces (plain YAML inventory) return
    ``[]`` so callers can stay source-agnostic.
"""
from abc import ABC, abstractmethod


class DeclaredStateSource(ABC):
    """Adapter interface for a declared-state source.

    Concrete implementations live in ``yaml_adapter.py`` (YAML inventory) and
    ``netbox_adapter.py`` (NetBox); any future CMDB adapter implements the
    same four methods.
    """

    @abstractmethod
    def get_devices(self) -> list[dict]:
        """Return all devices declared by this source as plain dicts."""

    @abstractmethod
    def get_device(self, hostname: str) -> dict | None:
        """Return a single device by hostname, or ``None`` if not found."""

    @abstractmethod
    def get_sites(self) -> list[dict]:
        """Return all sites declared by this source."""

    @abstractmethod
    def get_interfaces(self, device: str) -> list[dict]:
        """Return interfaces declared on ``device``, or ``[]`` if none."""
