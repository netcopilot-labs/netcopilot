"""Inventory layer — which devices to collect from, and how to reach them."""
from netcopilot.inventory.base import InventorySource
from netcopilot.inventory.netbox_source import NetBoxInventory, NetBoxInventoryError
from netcopilot.inventory.yaml_source import YAMLInventory

#: URI scheme selecting the NetBox-backed source: ``netbox://<site>``.
NETBOX_SCHEME = "netbox://"


def get_inventory_source(spec: str, *, site: str | None = None) -> InventorySource:
    """Resolve an ``--inventory`` spec to a concrete source.

    ``netbox://<site>`` → :class:`NetBoxInventory` (site from the URI; a
    ``site`` argument, when given, must agree — one site per run, stated once).
    Anything else is a YAML file path → :class:`YAMLInventory` (callers resolve
    tenant folders to their ``lab.yaml`` before calling; this factory does not
    touch the filesystem beyond the YAML parse).
    """
    if spec.startswith(NETBOX_SCHEME):
        uri_site = spec[len(NETBOX_SCHEME):].strip("/")
        target = uri_site or site
        if not target:
            raise ValueError(
                "netbox:// inventory needs a site slug: netbox://<site>"
            )
        if site and uri_site and site != uri_site:
            raise ValueError(
                f"--site {site!r} disagrees with the inventory URI {spec!r} — "
                "one site per run"
            )
        return NetBoxInventory(target)
    return YAMLInventory(spec)


__all__ = [
    "InventorySource",
    "NetBoxInventory",
    "NetBoxInventoryError",
    "NETBOX_SCHEME",
    "YAMLInventory",
    "get_inventory_source",
]
