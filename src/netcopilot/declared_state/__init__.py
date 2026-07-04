"""Declared-state source adapters (s11, ADR-0013).

A ``DeclaredStateSource`` abstracts the "what should the network look like?"
question (layer L0) behind a uniform interface. Consumers read declared state
without caring whether it came from a YAML inventory, a NetBox instance, or
any future CMDB.

Selection at runtime is via the ``DECLARED_STATE_SOURCE`` environment variable
(default ``"yaml"``). The factory :func:`get_source` returns the matching
adapter; callers depend only on the contract in
:mod:`netcopilot.declared_state.base`.

Adapters:
    * ``"yaml"``   → :class:`YAMLInventoryAdapter` (an inventory ``lab.yaml`` path).
    * ``"netbox"`` → :class:`NetBoxAdapter` (NetBox 4.6+ via ``pynetbox``,
      installed with the ``[netbox]`` extra; ``NETBOX_URL`` +
      ``NETBOX_API_TOKEN`` from the environment).

Writes (staging → human approve → audit) live in
:mod:`netcopilot.declared_state.staging` and are gated by
``NETBOX_WRITE_ENABLED`` (default off) per Constitution Art. I.
"""
from netcopilot.declared_state.base import DeclaredStateSource
from netcopilot.declared_state.gate import WritesDisabled, require_write_enabled, write_enabled
from netcopilot.declared_state.yaml_adapter import YAMLInventoryAdapter
from netcopilot.declared_state.netbox_adapter import ImproperlyConfigured, NetBoxAdapter

_REGISTRY = {
    "yaml": YAMLInventoryAdapter,
    "netbox": NetBoxAdapter,
}


def get_source(name: str, **kwargs) -> DeclaredStateSource:
    """Return a :class:`DeclaredStateSource` adapter by name.

    Args:
        name: ``"yaml"`` or ``"netbox"``. Anything else raises ``ValueError``
            with the valid choices listed.
        **kwargs: Passed to the adapter constructor. ``"yaml"`` requires
            ``inventory_path``; ``"netbox"`` takes no required kwargs
            (``NETBOX_URL`` / ``NETBOX_API_TOKEN`` from the environment).

    Raises:
        ValueError: If ``name`` is unknown.
    """
    if name not in _REGISTRY:
        raise ValueError(
            f"Unknown declared-state source: {name!r}. Valid choices: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name](**kwargs)


__all__ = [
    "DeclaredStateSource",
    "YAMLInventoryAdapter",
    "NetBoxAdapter",
    "ImproperlyConfigured",
    "WritesDisabled",
    "get_source",
    "write_enabled",
    "require_write_enabled",
]
