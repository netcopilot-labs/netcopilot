"""YAML inventory source.

Reads a device inventory from a YAML file you point it at — the bring-your-own
network entry point. The file is a mapping with a ``devices:`` list; each device
is a free-form dict (see ``examples/inventory.yaml`` for the documented shape).
Unknown keys are preserved untouched so the collect layer can read per-device
hints (``skip_families``, ``ssh_only``, credential overrides) without this
adapter needing to know about them.
"""
from pathlib import Path

import yaml

from netcopilot.inventory.base import InventorySource


class YAMLInventory(InventorySource):
    """Read the device inventory from a YAML file.

        YAMLInventory("examples/inventory.yaml")

    The file is parsed once at construction. ``devices`` is read from the
    top-level ``devices:`` key; an absent or empty key yields an empty inventory.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        if not self._path.is_file():
            raise ValueError(f"Inventory file not found: {self._path}")

        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        self._devices: list[dict] = list(data.get("devices") or [])

    def get_devices(self) -> list[dict]:
        return list(self._devices)

    def get_device(self, name: str) -> dict | None:
        for device in self._devices:
            if device.get("name") == name:
                return device
        return None
