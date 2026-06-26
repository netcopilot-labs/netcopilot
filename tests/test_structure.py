"""F1-1 smoke test: the package and its subpackages import cleanly."""

import importlib

import pytest

MODULES = [
    "netcopilot",
    "netcopilot.llm",
    "netcopilot.inventory",
    "netcopilot.collect",
    "netcopilot.parse",
    "netcopilot.parse.iosxe",
    "netcopilot.parse.iosxr",
    "netcopilot.parse.cisco_native",
    "netcopilot.parse.openconfig",
    "netcopilot.parse.restconf",
    "netcopilot.parse.fortigate",
    "netcopilot.model",
    "netcopilot.graph",
    "netcopilot.mcp",
    "netcopilot.mcp.tools",
    "netcopilot.orchestrator",
]


@pytest.mark.parametrize("module", MODULES)
def test_subpackage_imports(module: str) -> None:
    importlib.import_module(module)
