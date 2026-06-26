"""Parse layer — raw collected evidence -> canonical per-device facts JSON.

Parsers are pure functions (``filepath -> dict | None``) with no device
dependencies; ``facts_builder`` routes each device's raw output to the right
parser by collection strategy + OS and assembles the canonical schema.
"""
from netcopilot.parse.facts_builder import build_device_facts, build_facts

__all__ = ["build_facts", "build_device_facts"]
