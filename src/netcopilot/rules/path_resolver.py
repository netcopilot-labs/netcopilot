"""
Path Resolver — Traverse nested JSON dicts using dot-path expressions with wildcards.

Network device facts from Genie/pyATS are deeply nested JSON structures.
For example, OSPF neighbor data might live at:

    facts["vrf"]["default"]["neighbor"]["192.0.2.1"]["state"]

Instead of hand-coding nested loops for every rule, this module lets you
write a dot-path string like "vrf.*.neighbor.*" and iterate over all
matching values, with a context dict that tells you which wildcard keys
were matched.

Architecture:
    dot-path string ──► resolve() ──► _resolve_recursive() ──► yields (context, value)
           │                │                  │                        │
           ▼                ▼                  ▼                        ▼
    "vrf.*.neighbor.*"  pre-compute       walks dict tree         ({"vrf": "default",
                        wildcard names    depth-first              "neighbor": "192.0.2.1"},
                        from path         sorted keys for          {"state": "FULL", ...})
                                          determinism

Design Principles:
    - Graceful degradation: missing keys, None values, non-dict intermediates
      all yield nothing — never raise exceptions
    - Determinism: wildcard keys are always iterated in sorted order so that
      the same input always produces the same output sequence
    - Context capture: each wildcard `*` captures the matched key using the
      path segment immediately before the `*` as the context key name

Example Usage:
    >>> from netcopilot.rules.path_resolver import resolve
    >>> data = {"vrf": {"default": {"neighbor": {"192.0.2.1": {"state": "FULL"}}}}}
    >>> list(resolve("vrf.*.neighbor.*", data))
    [({'vrf': 'default', 'neighbor': '192.0.2.1'}, {'state': 'FULL'})]
    >>> list(resolve("nonexistent.path", data))
    []
"""

# -------------------------------------------------------------------------
# Standard library imports
# -------------------------------------------------------------------------
from typing import Any, Iterator

# -------------------------------------------------------------------------
# Type Aliases
# -------------------------------------------------------------------------
# Context captures which keys matched at each wildcard position.
# Example: {"vrf": "default", "neighbor": "192.0.2.1"}
Context = dict[str, str]

# Each result is a (context, value) pair where context holds wildcard
# matches and value is the object at the resolved path
ResolveResult = tuple[Context, Any]


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------


def resolve(path: str, data: Any) -> Iterator[ResolveResult]:
    """
    Traverse a nested dict using a dot-path with optional wildcard segments.

    A dot-path like "vrf.*.neighbor.*" walks into the dict at each segment.
    Literal segments (e.g., "vrf") descend into that exact key. Wildcard
    segments ("*") iterate over ALL keys at that level in sorted order,
    capturing each key into the context dict.

    The context key for a wildcard is the path segment immediately before
    the "*". For example, in "vrf.*", the wildcard captures into
    context["vrf"]. If "*" appears at the start of the path (no preceding
    segment), it uses "_key" as the context key.

    Args:
        path: Dot-separated path string. Use "*" for wildcard segments.
              Examples: "vrf.*.neighbor.*", "ssh.version", "*.state"
        data: The nested dict (typically loaded from a Genie JSON file)
              to traverse.

    Returns:
        Iterator of (context, value) tuples. Context is a dict mapping
        wildcard names to matched keys. Value is whatever lives at the
        resolved path in the data.

        Yields nothing (empty iterator) if:
        - path is empty
        - data is None or not a dict at a point where traversal needs one
        - any intermediate key is missing
        - any intermediate value is None

    Example:
        >>> data = {"vrf": {"default": {"state": "up"}}}
        >>> list(resolve("vrf.*.state", data))
        [({'vrf': 'default'}, 'up')]
        >>> list(resolve("missing.path", data))
        []
    """
    # -------------------------------------------------------------------------
    # Input validation
    # -------------------------------------------------------------------------
    # Empty path or None data means nothing to resolve
    if not path or data is None:
        return

    # Split dot-path into individual segments for recursive traversal
    segments = path.split(".")

    # -------------------------------------------------------------------------
    # Pre-compute wildcard context key names
    # -------------------------------------------------------------------------
    # We compute these upfront so the recursive function doesn't need to
    # look backward through the path. Each wildcard gets a name based on
    # the segment that precedes it in the path.
    wildcard_names = _compute_wildcard_names(segments)

    # Delegate to recursive implementation
    yield from _resolve_recursive(segments, data, {}, wildcard_names)


# -------------------------------------------------------------------------
# Private Implementation
# -------------------------------------------------------------------------


def _compute_wildcard_names(segments: list[str]) -> list[str | None]:
    """
    Pre-compute the context key name for each segment position.

    For wildcard segments ("*"), the name is the preceding literal segment.
    For literal segments, the name is None (not used). This list is parallel
    to the segments list — same length, same indices.

    Naming rules:
    - "*" preceded by a literal → use that literal (e.g., "vrf.*" → "vrf")
    - "*" at position 0 (no predecessor) → "_key"
    - "*" preceded by another "*" → "_key_N" with incrementing suffix
    - Duplicate names get a numeric suffix: "vrf", "vrf_2", "vrf_3"

    Args:
        segments: The full list of dot-path segments.

    Returns:
        A list of the same length as segments. Each entry is either None
        (for literal segments) or a string context key name (for wildcards).

    Example:
        >>> _compute_wildcard_names(["vrf", "*", "neighbor", "*"])
        [None, 'vrf', None, 'neighbor']
        >>> _compute_wildcard_names(["*", "state"])
        ['_key', None]
    """
    names: list[str | None] = []
    # Track used names so we can add suffixes for duplicates
    used_names: dict[str, int] = {}

    for i, segment in enumerate(segments):
        if segment != "*":
            # Literal segment — no context key needed
            names.append(None)
        else:
            # ---------------------------------------------------------------
            # Determine base name from the preceding segment
            # ---------------------------------------------------------------
            if i > 0 and segments[i - 1] != "*":
                # Normal case: use the literal segment before this wildcard
                base_name = segments[i - 1]
            else:
                # No predecessor or predecessor is also "*"
                base_name = "_key"

            # ---------------------------------------------------------------
            # Handle duplicate names with numeric suffixes
            # ---------------------------------------------------------------
            # If "vrf" is already used, the next one becomes "vrf_2"
            if base_name in used_names:
                used_names[base_name] += 1
                final_name = f"{base_name}_{used_names[base_name]}"
            else:
                used_names[base_name] = 1
                final_name = base_name

            names.append(final_name)

    return names


def _resolve_recursive(
    segments: list[str],
    current: Any,
    context: Context,
    wildcard_names: list[str | None],
) -> Iterator[ResolveResult]:
    """
    Recursively walk segments through nested dicts, yielding results.

    This is the core traversal engine. It processes one segment at a time:
    - Literal segment: descend into that exact key if it exists
    - Wildcard "*": iterate all keys at this level in sorted order

    The recursion terminates when segments are exhausted, yielding the
    current value paired with the accumulated context.

    Args:
        segments: Remaining path segments to process (shrinks each level).
        current: The current position in the nested dict tree.
        context: Accumulated wildcard matches so far (grows each wildcard).
        wildcard_names: Pre-computed context key names (shrinks in parallel
                        with segments to stay aligned).

    Returns:
        Iterator of (context, value) tuples for all matching paths.
    """
    # -------------------------------------------------------------------------
    # Base case: no more segments — yield what we have
    # -------------------------------------------------------------------------
    if not segments:
        yield (context, current)
        return

    # -------------------------------------------------------------------------
    # Guard: can only descend into dicts
    # -------------------------------------------------------------------------
    # If current is not a dict, we can't look up the next segment.
    # This handles None, strings, numbers, lists, etc. gracefully.
    if not isinstance(current, dict):
        return

    # If the dict is empty, there's nothing to traverse into
    if not current:
        return

    segment = segments[0]
    remaining = segments[1:]
    remaining_names = wildcard_names[1:]

    if segment == "*":
        # -----------------------------------------------------------------
        # Wildcard: iterate ALL keys at this level
        # -----------------------------------------------------------------
        context_key = wildcard_names[0]

        # sorted() ensures deterministic iteration order — critical for
        # reproducible rule evaluation results across runs.
        # key=str handles mixed-type keys (unlikely in Genie JSON, but safe).
        for key in sorted(current.keys(), key=str):
            child = current[key]

            # Skip None values — they represent absent data in Genie output
            if child is None:
                continue

            # Copy context so each branch gets its own dict.
            # Without copy, all branches would share and overwrite each
            # other's wildcard captures.
            branch_context = dict(context)
            branch_context[context_key] = str(key)

            yield from _resolve_recursive(
                remaining, child, branch_context, remaining_names
            )
    else:
        # -----------------------------------------------------------------
        # Literal segment: descend into exact key (with greedy matching)
        # -----------------------------------------------------------------
        # Try the exact segment first (fast path for most keys).
        # If it doesn't match, try combining with subsequent segments
        # using dots to form longer keys. This handles IP addresses
        # (e.g., "192.0.2.1") and other dotted keys that appear in Genie
        # JSON output — the dot in the IP conflicts with our path separator.
        #
        # Example: path "neighbor.192.0.2.1.state" splits into
        # ["neighbor", "192", "0", "2", "1", "state"]. When "192" doesn't
        # match any key but "192.0.2.1" does, we greedily consume 4
        # segments and continue with ["state"].
        child = current.get(segment)

        if child is not None:
            # Fast path: exact segment matches a key
            yield from _resolve_recursive(
                remaining, child, context, remaining_names
            )
        else:
            # Greedy path: try combining segments to form dotted keys
            yield from _try_greedy_key_match(
                segment, remaining, current, context, remaining_names
            )


def _try_greedy_key_match(
    first_segment: str,
    remaining: list[str],
    current: dict,
    context: Context,
    remaining_names: list[str | None],
) -> Iterator[ResolveResult]:
    """
    Try combining consecutive segments with dots to match a dotted dict key.

    Genie JSON uses IP addresses and other dotted strings as dict keys
    (e.g., {"192.0.2.1": {...}}). Since our path syntax also uses dots as
    separators, "192.0.2.1" gets split into ["192", "0", "2", "1"].
    This function tries progressively longer combinations:
    "192", "192.0", "192.0.2", "192.0.2.1" — and uses the first match.

    Args:
        first_segment: The initial segment that didn't match on its own.
        remaining: Segments after the first one.
        current: The current dict being searched.
        context: Accumulated wildcard context.
        remaining_names: Pre-computed wildcard names for remaining segments.

    Returns:
        Iterator of (context, value) tuples if a greedy match is found,
        empty otherwise.
    """
    # Build up a candidate key by adding one segment at a time
    candidate = first_segment

    for i, next_seg in enumerate(remaining):
        # Don't consume wildcard segments into a greedy key
        if next_seg == "*":
            break

        candidate = f"{candidate}.{next_seg}"
        child = current.get(candidate)

        if child is not None:
            # Found a match — continue with the segments after the
            # consumed ones. i is 0-based index into remaining, so
            # we consumed remaining[0..i] (i+1 segments from remaining).
            after_match = remaining[i + 1:]
            after_names = remaining_names[i + 1:]
            yield from _resolve_recursive(
                after_match, child, context, after_names
            )
            return
