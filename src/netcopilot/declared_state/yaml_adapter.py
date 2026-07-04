"""YAML inventory adapter (s11, ADR-0013).

Reads declared state from a NetCopilot inventory YAML (the same ``lab.yaml``
shape the ``netcopilot run --inventory`` path consumes). Path-based only — the
caller resolves the inventory location; this adapter never guesses one.
"""
from pathlib import Path

import yaml

from netcopilot.declared_state.base import DeclaredStateSource


class YAMLInventoryAdapter(DeclaredStateSource):
    """Read declared state from an inventory YAML file.

    ``YAMLInventoryAdapter(inventory_path="/path/to/lab.yaml")`` — the path is
    required; a missing file raises ``ValueError`` immediately rather than
    deferring the failure to the first query.
    """

    def __init__(self, inventory_path: str | Path):
        self._inventory_path = Path(inventory_path)
        if not self._inventory_path.is_file():
            raise ValueError(f"Inventory file not found: {self._inventory_path}")
        self._data: dict = yaml.safe_load(self._inventory_path.read_text(encoding="utf-8")) or {}

    def get_devices(self) -> list[dict]:
        """Return the ``devices:`` list from the inventory YAML as-is."""
        devices = self._data.get("devices") or []
        return list(devices)

    def get_device(self, hostname: str) -> dict | None:
        for dev in self.get_devices():
            if dev.get("name") == hostname:
                return dev
        return None

    def get_sites(self) -> list[dict]:
        """Sites are not first-class in YAML inventory.

        Derive a unique site list from the ``site`` field on each device.
        Each entry has ``slug`` (the raw value) and ``name`` (same string).
        Devices with no ``site`` are skipped.
        """
        slugs: set[str] = set()
        for dev in self.get_devices():
            site = dev.get("site")
            if site:
                slugs.add(str(site))
        return [{"slug": s, "name": s} for s in sorted(slugs)]

    def get_interfaces(self, device: str) -> list[dict]:
        """YAML inventory does not declare interfaces.

        Interface state lives in collected facts and Neo4j ``:Interface``
        nodes, not in the declared YAML. Returns ``[]`` so callers can write
        source-agnostic logic.
        """
        return []
