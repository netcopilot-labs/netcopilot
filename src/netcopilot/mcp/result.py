"""ToolResult — the typed tool-result envelope (the machine-readable tool contract).

Lives in its own module so tool handlers can import it without a circular
import (the registry imports every tool module). The registry re-exports it,
so consumers may import from either place.
"""

from __future__ import annotations

from dataclasses import dataclass

# Valid values for ToolResult.status. ``ok`` carries data; the rest are the
# named failure modes tools already expressed as prose — now machine-readable.
VALID_RESULT_STATUSES = {"ok", "no_data", "not_found", "ambiguous", "error"}


@dataclass(frozen=True)
class ToolResult:
    """Typed tool-result envelope.

    ``text`` is what the model sees, verbatim (byte-identical to the
    pre-envelope strings). ``status`` distinguishes data from failure without
    parsing prose. ``verdict``/``highlight``/``verbatim`` carry semantics tools
    already compute, previously flattened into text or smuggled through string
    conventions.
    """

    status: str  # one of VALID_RESULT_STATUSES
    text: str
    verdict: dict | None = None
    highlight: dict | None = None
    verbatim: bool = False
