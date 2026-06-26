"""Inventory layer — which devices to collect from, and how to reach them."""
from netcopilot.inventory.base import InventorySource
from netcopilot.inventory.yaml_source import YAMLInventory

__all__ = ["InventorySource", "YAMLInventory"]
