"""RAG MCP tools — vendor docs lookup + general networking knowledge.

 Two new tools that work in dual-mode (with or without network data):

    lookup_vendor_docs       — vendor-specific CLI/config questions
    lookup_network_knowledge — generic protocol / concept questions

Both are pure-RAG: they query the ChromaDB vendor_docs collection. They do
NOT touch Neo4j and have NO dependency on a pipeline run, which is why an
operator can ask "How do I configure VRRP on a C9300?" via Telegram or
Dashboard even before the first run.
"""

from __future__ import annotations

import logging

from netcopilot.rag import store

log = logging.getLogger(__name__)

# Cap on how much chunk text to show per result (chars)
_CHUNK_DISPLAY_CHARS = 1500
# Hard cap on the number of results returned (tool param can request fewer)
_MAX_RESULTS = 5
# Vector-similarity threshold below which we warn the LLM that the corpus
# does not have strong coverage. Calibrated empirically ():
#   strong queries (VRRP/BGP/FortiGate firewall) score >= 0.71
#   weak queries   (DMVPN/IPsec ISR/Juniper/Aruba)   score <= 0.58
# Threshold of 0.60 cleanly separates the two with comfortable headroom.
_LOW_COVERAGE_THRESHOLD = 0.60


def _format_results(query: str, results: list[dict]) -> str:
    """Render search results as plain text with source citations.

    Prepends a ⚠ LOW COVERAGE WARNING if the best vector-similarity score
    is below _LOW_COVERAGE_THRESHOLD, which signals the corpus does not
    contain strong matches for this query and the LLM should warn the
    operator instead of confidently citing.
    """
    if not results:
        return (
            f"No vendor documentation found for: {query}\n\n"
            "Possible reasons:\n"
            "- Vendor docs have not been ingested yet "
            "(run: python -m rag.ingest --docs-dir knowledge_base/vendor_docs/)\n"
            "- The query is too narrow — try simpler terms\n"
            "- The OS family filter excluded all matches"
        )

    # Low-coverage detection — use vector_score (cosine similarity) because
    # cross-encoder scores saturate near 1.0 even for tangential matches.
    top_vec = max(
        (r.get("vector_score", r.get("score", 0.0)) for r in results),
        default=0.0,
    )
    low_coverage = top_vec < _LOW_COVERAGE_THRESHOLD

    lines: list[str] = []
    if low_coverage:
        lines.extend(
            [
                "⚠ LOW COVERAGE HINT ⚠",
                f"The vendor corpus does not have strong matches for: {query!r}",
                f"(top vector similarity = {top_vec:.2f}, "
                f"threshold = {_LOW_COVERAGE_THRESHOLD:.2f}).",
                "",
                "The chunks below may be tangentially related. Briefly tell the "
                "operator the corpus is thin on this topic, then synthesize the "
                "best answer you can from these chunks AND your general networking "
                "knowledge — clearly labeling which parts come from general "
                "knowledge vs. the vendor docs. Do NOT refuse to answer; the "
                "operator still needs help. Avoid inventing fake .pdf filenames "
                "for the general-knowledge parts.",
                "",
            ]
        )

    lines.extend(["Vendor Documentation Results:", ""])
    sources_seen: list[tuple[str, int]] = []

    for i, r in enumerate(results, 1):
        section = r.get("toc_section", "(untitled section)")
        source = r.get("source_file", "?")
        page = r.get("page", 0)
        os_family = r.get("os_family", "?")
        score = r.get("score", 0.0)
        vec_score = r.get("vector_score", score)
        text = (r.get("text") or "").strip()
        if len(text) > _CHUNK_DISPLAY_CHARS:
            text = text[:_CHUNK_DISPLAY_CHARS] + " […truncated]"

        # Show both relevance scores: cross-encoder (re-ranked) and vector
        # (raw similarity). The vector score is what triggers low-coverage,
        # so it's diagnostic for the LLM.
        header = (
            f"{i}. {section} — {os_family.upper()}  "
            f"(rel {score:.2f} · sim {vec_score:.2f})"
        )
        cite = f"   Source: {source}, page {page}"
        lines.append(header)
        lines.append(cite)
        lines.append("")
        # Indent the chunk text for readability
        for line in text.splitlines():
            lines.append(f"   {line}")
        lines.append("")
        sources_seen.append((source, page))

    # De-duplicated sources footer
    uniq_sources = sorted({s for s, _ in sources_seen})
    pages_by_src: dict[str, list[int]] = {}
    for s, p in sources_seen:
        pages_by_src.setdefault(s, []).append(p)
    lines.append("---")
    src_list = ", ".join(
        f"{s} (pages {min(p)}-{max(p)})" if min(p) != max(p) else f"{s} (page {min(p)})"
        for s, p in ((src, pages_by_src[src]) for src in uniq_sources)
    )
    lines.append(f"Sources: {src_list}")
    return "\n".join(lines)


def _autodetect_os_family(context: dict, vendor: str | None) -> str | None:
    """Best-effort: pick os_family from context['device_os'] if set.

    Other tools (get_device_detail, query_topology) can populate
    context['device_os'] with the most-recently-discussed device's OS.
    Currently nothing does this, but the hook is in place for .
    """
    device_os = (context or {}).get("device_os")
    if not device_os:
        return None
    os_lower = str(device_os).lower()
    if "iosxe" in os_lower or "ios-xe" in os_lower:
        return "iosxe"
    if "iosxr" in os_lower or "ios-xr" in os_lower:
        return "iosxr"
    if "fortios" in os_lower or "fortigate" in os_lower:
        return "fortios"
    return None


async def lookup_vendor_docs(
    *,
    query: str,
    vendor: str | None = None,
    os_family: str | None = None,
    doc_type: str | None = None,
    n_results: int = 5,
    context: dict,
) -> str:
    """Look up vendor configuration / CLI documentation.

    Use for: "How do I configure X?", "What is the syntax for Y?",
    "Show me the Z command".
    """
    if not query or not query.strip():
        return "lookup_vendor_docs: empty query."

    # Auto-detect OS family from context if caller didn't specify
    if not os_family:
        os_family = _autodetect_os_family(context, vendor)

    n = max(1, min(int(n_results or 5), _MAX_RESULTS))

    try:
        results = store.search(
            query=query,
            vendor=vendor,
            os_family=os_family,
            doc_type=doc_type,
            n_results=n,
        )
    except Exception as exc:
        log.exception("lookup_vendor_docs failed: %s", exc)
        return f"lookup_vendor_docs failed: {exc}"

    return _format_results(query, results)


async def lookup_network_knowledge(
    *,
    query: str,
    n_results: int = 5,
    context: dict,
) -> str:
    """Look up general networking knowledge across all vendor docs.

    Use for conceptual questions ("explain VRRP vs HSRP", "what is DMVPN?",
    "differences between OSPF and EIGRP"). No vendor filter is applied,
    so the LLM gets a broader cross-vendor view.
    """
    if not query or not query.strip():
        return "lookup_network_knowledge: empty query."

    n = max(1, min(int(n_results or 5), _MAX_RESULTS))

    try:
        results = store.search(query=query, n_results=n)
    except Exception as exc:
        log.exception("lookup_network_knowledge failed: %s", exc)
        return f"lookup_network_knowledge failed: {exc}"

    return _format_results(query, results)
