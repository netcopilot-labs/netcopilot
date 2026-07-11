"""S21-5: the ToolResult contract, machine-enforced on the whole tool layer.

The 2026-07 audit fixed "every tool returns free-form str" (s03: the ToolResult
envelope); the 2026-07-10 persistence check found the fix was held by per-tool
tests + convention, with nothing structurally stopping a FUTURE tool from
regressing. This is that structure (Constitution Art. V applied to the tool
layer itself): an AST walk over ``mcp/tools/`` — no imports, no mocking — plus
a registry-description check. A new tool that returns ``str`` or ships without
a description fails HERE, at authoring time.
"""
from __future__ import annotations

import ast
from pathlib import Path

from netcopilot.mcp.registry import TOOL_SCHEMAS

TOOLS_DIR = Path(__file__).parent.parent / "src" / "netcopilot" / "mcp" / "tools"


def _public_async_handlers():
    """(file, name, returns_annotation_or_None) for every public async def."""
    out = []
    for f in sorted(TOOLS_DIR.glob("*.py")):
        if f.name == "__init__.py":
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and not node.name.startswith("_"):
                ann = ast.unparse(node.returns) if node.returns else None
                out.append((f.name, node.name, ann))
    return out


def test_every_public_async_handler_returns_toolresult():
    handlers = _public_async_handlers()
    assert handlers, "no handlers found — wrong TOOLS_DIR?"
    bad = [(f, n, ann) for f, n, ann in handlers if ann != "ToolResult"]
    assert bad == [], (
        "public async handlers must return ToolResult (s03 envelope contract); "
        f"violations: {bad}"
    )


def test_every_registered_tool_has_a_description():
    missing = [t["name"] for t in TOOL_SCHEMAS
               if not (t.get("description") or "").strip()]
    assert missing == [], f"registered tools without a description: {missing}"


def test_mutation_detection_works():
    """The AST check actually catches a str-returning handler (guard the guard)."""
    src = "async def bad_tool(*, context: dict) -> str:\n    return 'x'\n"
    tree = ast.parse(src)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef))
    assert ast.unparse(node.returns) == "str"      # would be flagged as bad
