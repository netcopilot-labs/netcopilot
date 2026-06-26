"""Network model layer — turn per-device facts into a typed network model.

Interface-name foundations, shared by the link builder and model builder:

- ``normalize_interface_name`` / ``canonicalize`` — reconcile the many
  interface-name spellings (CDP abbreviations, Genie full forms, FortiGate
  names) into one comparable form.
- ``classify_interface`` — bucket an interface name into physical / logical /
  vlan / management / aggregated / unknown.
- ``is_virtual_interface`` / ``VIRTUAL_INTERFACE_PREFIXES`` — the shared
  definition of "virtual / L3-only interface".
- ``build_model`` — the orchestrator that turns a collection run's per-device
  facts into the unified ``network_model.json`` (devices, interfaces, links,
  routing adjacencies, shared services, topology warnings).
"""

from netcopilot.model.interface_classifier import InterfaceType, classify_interface
from netcopilot.model.interface_normalizer import canonicalize, normalize_interface_name
from netcopilot.model.interface_taxonomy import (
    VIRTUAL_INTERFACE_PREFIXES,
    is_virtual_interface,
)
from netcopilot.model.model_builder import build_model

__all__ = [
    "InterfaceType",
    "VIRTUAL_INTERFACE_PREFIXES",
    "build_model",
    "canonicalize",
    "classify_interface",
    "is_virtual_interface",
    "normalize_interface_name",
]
