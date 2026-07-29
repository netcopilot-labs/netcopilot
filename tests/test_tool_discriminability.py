"""Registry hygiene: a new tool must not read like an existing one.

Tool selection degrades when the model cannot separate tools from their text.
The count of tools is the usual scapegoat, but the driver is overlap: two tools
that read alike compete for the same question no matter how few there are.

This test puts a ceiling on that. Any pair of tools whose name+description
embed closer than THRESHOLD fails, unless the pair is in KNOWN_OVERLAPS, which
is the frozen set measured on 2026-07-27. The allowlist is documented debt, not
an exemption: shrinking it is work, growing it needs a reason in review.

Optional dependency. It needs the `rag` extra for sentence-transformers, so it
skips where that is absent (including CI, which installs only `.[dev]`).
Making it a true CI gate would mean putting torch in CI for a hygiene check,
which is not a trade worth making. Same shape as tests/test_pyats_adapter.py.

    pip install -e ".[rag]"
    PYTHONPATH=src python -m pytest tests/test_tool_discriminability.py -q

The exploratory companion is internal/validation/tool_similarity.py, which
prints the full matrix and the per-tool risk map.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("sentence_transformers")
np = pytest.importorskip("numpy")

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

from netcopilot.mcp.registry import TOOL_SCHEMAS  # noqa: E402

#: Cosine similarity above which two tools are considered confusable.
#: Chosen from the 2026-07-27 measurement: 528 pairs, mean 0.301, max 0.794 on
#: the name+description basis. Six pairs sat above 0.70, all of them long
#: standing; nothing new should join them without a conversation.
THRESHOLD = 0.70

#: Measured 2026-07-27; re-measured 2026-07-28 after the s23-1 rewrite. The
#: worst pair (get_firewall_policies / get_security_policies, 0.794) was FIXED
#: by the rename to get_cisco_policies + the definitions-vs-verdicts rewrite
#: (now 0.547) — the allowlist shrank instead of growing. Sorted tuples so
#: ordering cannot cause a false pass. Each entry is a real overlap someone
#: chose to live with, not a mistake.
KNOWN_OVERLAPS: set[tuple[str, str]] = {
    ("get_netbox_write_history", "list_netbox_pending_writes"),  # 0.788
    ("compare_declared_vs_actual", "run_drift_check"),           # 0.780
    ("get_device_detail", "query_topology"),                     # 0.714
    ("get_network_neighborhood", "query_topology"),              # 0.712
    ("get_netbox_device", "get_netbox_site"),                    # 0.708
}


def _pairwise_similarity() -> tuple[list[str], "np.ndarray"]:
    """Encode name+description per tool and return (names, cosine matrix)."""
    from sentence_transformers import SentenceTransformer

    names = [t["name"] for t in TOOL_SCHEMAS]
    texts = [f"{t['name']}: {t.get('description', '')}" for t in TOOL_SCHEMAS]

    emb = SentenceTransformer("all-MiniLM-L6-v2").encode(
        texts, normalize_embeddings=True, show_progress_bar=False
    )
    sim = emb @ emb.T
    np.fill_diagonal(sim, -1.0)  # a tool is not confusable with itself
    return names, sim


def test_no_new_confusable_tool_pairs() -> None:
    """No pair above THRESHOLD beyond the frozen, documented set."""
    names, sim = _pairwise_similarity()

    offenders = [
        (round(float(sim[i, j]), 3), *sorted((names[i], names[j])))
        for i in range(len(names))
        for j in range(i + 1, len(names))
        if sim[i, j] > THRESHOLD
    ]
    new = [o for o in offenders if (o[1], o[2]) not in KNOWN_OVERLAPS]

    assert not new, (
        "These tool pairs read too much alike (cosine > "
        f"{THRESHOLD} on name+description):\n"
        + "\n".join(f"  {s}  {a} <-> {b}" for s, a, b in sorted(new, reverse=True))
        + "\n\nA model choosing between them is guessing. Either sharpen the "
        "descriptions so they name what is DIFFERENT about each tool, rename "
        "one of them, merge them into a single tool with a parameter, or add "
        "the pair to KNOWN_OVERLAPS with a reason. Run "
        "internal/validation/tool_similarity.py for the full picture."
    )

    # Not an assertion: a stale entry means someone improved a description, and
    # the allowlist should shrink. Failing on it would make routine model
    # updates break the suite, so it reports instead.
    stale = KNOWN_OVERLAPS - {(a, b) for _, a, b in offenders}
    if stale:
        print(f"\nKNOWN_OVERLAPS entries now below {THRESHOLD}, safe to remove: {sorted(stale)}")


def test_every_tool_has_a_description() -> None:
    """An empty description makes a tool invisible to any selection mechanism."""
    blank = [t["name"] for t in TOOL_SCHEMAS if not t.get("description", "").strip()]
    assert not blank, f"tools with no description: {blank}"
