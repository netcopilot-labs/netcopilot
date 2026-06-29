"""RAG ingestion pipeline — parse vendor PDFs and load into ChromaDB.

Usage:
    python -m rag.ingest --docs-dir knowledge_base/vendor_docs/
    python -m rag.ingest --docs-dir knowledge_base/vendor_docs/ --reset
    python -m rag.ingest --docs-dir knowledge_base/vendor_docs/ --only b_1712_sec*

Pipeline:
    1. Discover *.pdf files in --docs-dir
    2. For each PDF: classify, parse TOC, chunk via rag.chunker
    3. Embed chunks (acronym-expanded) and store in ChromaDB
    4. Print per-doc and total stats
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from fnmatch import fnmatch
from pathlib import Path

from netcopilot.rag import chunker, store

log = logging.getLogger("rag.ingest")


def discover_pdfs(docs_dir: Path, only: str | None = None) -> list[Path]:
    """Return sorted list of *.pdf files matching the optional glob."""
    if not docs_dir.exists():
        log.error("Docs dir not found: %s", docs_dir)
        return []
    pdfs = sorted(docs_dir.glob("*.pdf"))
    if only:
        pdfs = [p for p in pdfs if fnmatch(p.name, only)]
    return pdfs


def ingest_pdf(pdf_path: Path) -> tuple[int, int]:
    """Parse + embed + store one PDF. Returns (chunks_added, elapsed_ms).

    Re-ingesting a PDF replaces its prior chunks (delete-by-source, then add), so
    repeated runs stay idempotent — no duplicates, and an edited/shortened PDF
    drops its stale chunks instead of leaving orphans.
    """
    t0 = time.time()
    chunks = chunker.chunk_pdf(pdf_path)
    if not chunks:
        return 0, int((time.time() - t0) * 1000)
    store.delete_by_source(pdf_path.name)
    added = store.add_chunks(chunks)
    elapsed_ms = int((time.time() - t0) * 1000)
    return added, elapsed_ms


def main() -> int:
    parser = argparse.ArgumentParser(description="NetCopilot RAG ingestion")
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=Path("knowledge_base/vendor_docs"),
        help="Directory containing vendor PDFs",
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="Filename glob to limit ingestion (e.g. 'b_1712_sec*')",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset the collection before ingesting",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse + chunk but DO NOT embed/store (useful for chunk size tests)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    parser.add_argument(
        "--remove",
        metavar="FILE",
        default=None,
        help="Delete one document's chunks by filename (e.g. old-guide.pdf), then exit",
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Delete chunks for any PDF no longer present in --docs-dir, then exit",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Document lifecycle: remove one doc, or prune docs no longer in the folder.
    # Both touch only the store (no PDF parsing), then exit.
    if args.remove:
        n = store.delete_by_source(args.remove)
        print(f"Removed {n} chunk(s) for {args.remove!r}. Collection size: {store.collection_count()}")
        return 0

    if args.prune:
        in_folder = {p.name for p in discover_pdfs(args.docs_dir)}
        stale = sorted(store.list_sources() - in_folder)
        removed = sum(store.delete_by_source(s) for s in stale)
        print(f"Pruned {len(stale)} document(s), {removed} chunk(s). Collection size: {store.collection_count()}")
        for s in stale:
            print(f"  - {s}")
        return 0

    pdfs = discover_pdfs(args.docs_dir, args.only)
    if not pdfs:
        log.error("No PDFs found in %s", args.docs_dir)
        return 1

    log.info("Found %d PDFs in %s", len(pdfs), args.docs_dir)

    if args.reset and not args.dry_run:
        # Wipe BEFORE warming the client (the warm-up call will recreate it)
        import shutil

        if store.DEFAULT_CHROMA_DIR.exists():
            shutil.rmtree(store.DEFAULT_CHROMA_DIR)
            log.info("Wiped collection dir: %s", store.DEFAULT_CHROMA_DIR)
        store.reset()

    if not args.dry_run:
        # Warm-up: initialize ChromaDB client + embedding model BEFORE pymupdf
        # is touched. There appears to be a runtime conflict between pymupdf's
        # MuPDF initialization and ChromaDB's lazy init that causes a deadlock
        # if the order is reversed (observed: hangs in `_get_client` after the
        # first PDF is parsed).
        log.info("Warming RAG store…")
        store._get_collection()
        store._get_embed_model()
        log.info("RAG store ready (chunks already in store: %d)", store.collection_count())

    total_chunks = 0
    total_ms = 0
    failures: list[str] = []
    per_doc: list[tuple[str, int, int]] = []

    for pdf in pdfs:
        try:
            if args.dry_run:
                t0 = time.time()
                chunks = chunker.chunk_pdf(pdf)
                added = len(chunks)
                elapsed_ms = int((time.time() - t0) * 1000)
                # Print chunk size distribution for dry-run
                if chunks:
                    sizes = sorted(len(c.text) for c in chunks)
                    log.info(
                        "  size stats: min=%d p50=%d p95=%d max=%d",
                        sizes[0],
                        sizes[len(sizes) // 2],
                        sizes[int(len(sizes) * 0.95)],
                        sizes[-1],
                    )
            else:
                added, elapsed_ms = ingest_pdf(pdf)
        except Exception as exc:
            log.exception("Failed: %s", pdf.name)
            failures.append(pdf.name)
            continue
        total_chunks += added
        total_ms += elapsed_ms
        per_doc.append((pdf.name, added, elapsed_ms))
        log.info("✓ %-60s %5d chunks  %6d ms", pdf.name, added, elapsed_ms)

    print("\n" + "=" * 78)
    print(f"Total: {total_chunks} chunks across {len(per_doc)} docs in {total_ms / 1000:.1f}s")
    if not args.dry_run:
        print(f"Collection size: {store.collection_count()} chunks")
        print(f"Stored at: {store.DEFAULT_CHROMA_DIR}")
    if failures:
        print(f"Failures: {len(failures)}")
        for f in failures:
            print(f"  - {f}")
    print("=" * 78)
    return 0 if not failures else 2


if __name__ == "__main__":
    sys.exit(main())
