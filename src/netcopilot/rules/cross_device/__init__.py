"""
Cross-Device Rule Package — .

Phase 3 of the hybrid rule engine: cross-device rules that compare
protocol parameters between connected devices using network_model.json.

Exports:
    run_cross_device_rules: Main entry point called by engine.py Phase 3.
"""

from netcopilot.rules.cross_device.evaluator import run_cross_device_rules

__all__ = ["run_cross_device_rules"]
