"""Agent prompts + static onboarding copy, shipped as package data.

The system prompt is the routing contract that tells the model which MCP tool
answers which kind of question. The about/dashboard-guide texts are verbatim
operator-facing copy returned by the onboarding tools. All are loaded once and
cached.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

__all__ = ["load_system_prompt", "load_about", "load_dashboard_guide"]


@lru_cache(maxsize=8)
def _load(name: str) -> str:
    return (Path(__file__).parent / name).read_text(encoding="utf-8").strip()


def load_system_prompt() -> str:
    """Return the agent system prompt (cached)."""
    return _load("agent_system.txt")


def load_about() -> str:
    """Return the verbatim NetCopilot product description (cached)."""
    return _load("about_netcopilot.txt")


def load_dashboard_guide() -> str:
    """Return the verbatim dashboard tour (cached)."""
    return _load("dashboard_guide.txt")
