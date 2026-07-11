"""Deterministic-first tool routing (s21, ADR-0024).

A versioned catalogue (``routing.yaml``, package data) maps question intents to
the tool set offered to the model on the first turn. The deterministic layer
decides WHICH capability; the model fills arguments and reasons over the
result. An unmatched question falls back to the full tool set — no match means
exactly the pre-s21 behavior.

Load-time validation fails LOUD (Constitution Art. V): a malformed entry, an
invalid regex, a duplicate rule_id, an unknown tool name, or a missing
``evidence`` field raises :class:`RoutingConfigError` — a broken routing table
must never degrade silently into "the model picks everything again".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

__all__ = ["RouteDecision", "RoutingConfigError", "load_routing", "route"]

_DEFAULT_PATH = Path(__file__).parent / "routing.yaml"

#: Every entry must carry all of these. ``evidence`` is deliberately mandatory:
#: a routing rule without a documented failure is speculation, and speculation
#: is rejected at load, not reviewed away.
_REQUIRED_FIELDS = ("rule_id", "description", "patterns", "tools", "evidence", "added")


class RoutingConfigError(ValueError):
    """routing.yaml violates its contract — fail loud, never route on a guess."""


@dataclass(frozen=True)
class RouteDecision:
    """One deterministic routing decision (also the audit-event payload).

    ``dispatch_tool``/``dispatch_args`` are set when the entry carries a
    ``dispatch`` block: the loop calls that tool itself (static arguments,
    no model involvement) and the model reasons over the result. Without it,
    routing narrows the first turn's offered tools — advisory on serving
    stacks that don't enforce schema membership (measured 2026-07-11).
    """

    rule_id: str
    tools: tuple[str, ...]
    pattern: str  # the regex that matched — auditability, not just the outcome
    dispatch_tool: str | None = None
    dispatch_args: dict | None = None


def _known_tool_names() -> set[str]:
    # Imported lazily: the registry imports every tool module; the router must
    # stay importable (and unit-testable) without that cost.
    from netcopilot.mcp.registry import TOOL_SCHEMAS

    return {t["name"] for t in TOOL_SCHEMAS}


def load_routing(
    path: str | Path | None = None,
    *,
    known_tools: set[str] | None = None,
) -> list[dict]:
    """Parse + validate the routing catalogue; return entries with compiled patterns.

    Each returned entry is the YAML dict plus ``_compiled`` (list of compiled
    regexes, same order as ``patterns``).

    Raises:
        RoutingConfigError: any contract violation (see module docstring).
    """
    src = Path(path) if path is not None else _DEFAULT_PATH
    try:
        raw = yaml.safe_load(src.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RoutingConfigError(f"routing catalogue not found: {src}")
    except yaml.YAMLError as exc:
        raise RoutingConfigError(f"routing catalogue is not valid YAML: {exc}") from exc

    if raw is None:
        return []  # an empty catalogue is legal (routing disabled, full fallback)
    if not isinstance(raw, list):
        raise RoutingConfigError("routing catalogue must be a YAML list of entries")

    if known_tools is None:
        known_tools = _known_tool_names()

    entries: list[dict] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(raw):
        where = f"entry #{i + 1}"
        if not isinstance(entry, dict):
            raise RoutingConfigError(f"{where}: must be a mapping")
        missing = [f for f in _REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            raise RoutingConfigError(f"{where}: missing required field(s): {', '.join(missing)}")

        rule_id = entry["rule_id"]
        where = f"entry {rule_id!r}"
        if rule_id in seen_ids:
            raise RoutingConfigError(f"{where}: duplicate rule_id")
        seen_ids.add(rule_id)

        patterns = entry["patterns"]
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            raise RoutingConfigError(f"{where}: patterns must be a list of regex strings")
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error as exc:
                raise RoutingConfigError(f"{where}: invalid regex {p!r}: {exc}") from exc

        tools = entry["tools"]
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise RoutingConfigError(f"{where}: tools must be a list of tool names")
        unknown = [t for t in tools if t not in known_tools]
        if unknown:
            raise RoutingConfigError(
                f"{where}: unknown tool(s) {unknown} — not in the registry"
            )

        dispatch = entry.get("dispatch")
        if dispatch is not None:
            if not isinstance(dispatch, dict) or not dispatch.get("tool"):
                raise RoutingConfigError(f"{where}: dispatch must be a mapping with a 'tool'")
            if dispatch["tool"] not in tools:
                raise RoutingConfigError(
                    f"{where}: dispatch.tool {dispatch['tool']!r} must be one of the "
                    f"entry's tools {tools}"
                )
            args = dispatch.get("arguments", {})
            if not isinstance(args, dict):
                raise RoutingConfigError(f"{where}: dispatch.arguments must be a mapping")

        entries.append({**entry, "_compiled": compiled})

    return entries


@lru_cache(maxsize=1)
def _default_entries() -> tuple:
    """The packaged catalogue, loaded + validated once."""
    return tuple(load_routing())


def route(question: str) -> RouteDecision | None:
    """Match ``question`` against the catalogue; first matching entry wins.

    Returns ``None`` for an unmatched question — the caller must then behave
    exactly as if the router did not exist.
    """
    if not question:
        return None
    for entry in _default_entries():
        for rx in entry["_compiled"]:
            if rx.search(question):
                dispatch = entry.get("dispatch") or {}
                return RouteDecision(
                    rule_id=entry["rule_id"],
                    tools=tuple(entry["tools"]),
                    pattern=rx.pattern,
                    dispatch_tool=dispatch.get("tool"),
                    dispatch_args=dict(dispatch.get("arguments", {})) if dispatch else None,
                )
    return None
