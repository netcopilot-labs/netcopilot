"""ChromaDB wrapper — vector store with metadata-filtered search.

ChromaDB runs embedded (no server) with file-based persistence. Embedding
model loads lazily on first use and is cached in the same data directory.

Design:
    - Single collection: "vendor_docs" (all PDFs share one namespace)
    - Distance: cosine (default)
    - Embeddings: sentence-transformers all-MiniLM-L6-v2 (384 dims, MIT)
    - Metadata filtering: vendor, os_family, doc_type via ChromaDB `where`
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from netcopilot.rag.acronyms import expand as expand_acronyms

log = logging.getLogger(__name__)

COLLECTION_NAME = "vendor_docs"
DEFAULT_EMBED_MODEL = "all-MiniLM-L6-v2"
DEFAULT_CROSS_ENCODER = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# How many candidates to fetch from the vector store before cross-encoder
# re-ranking. The cross-encoder is precise but expensive (~50ms for 20 pairs),
# so we limit the candidate pool. Final results returned = min(n_results, n_candidates).
DEFAULT_N_CANDIDATES = 20

# Default location of the persistent vector store. Override with
# RAG_CHROMA_DIR env var (e.g. in Docker, /app/data/chromadb).
DEFAULT_CHROMA_DIR = Path(
    os.environ.get("RAG_CHROMA_DIR")
    or Path(__file__).resolve().parents[1] / "data" / "chromadb"
)


# Reentrant: _get_collection acquires this lock and then calls _get_client,
# which also acquires it on the same thread.
_lock = threading.RLock()
_client = None
_collection = None
_embed_model = None
_cross_encoder = None


def _get_client():
    """Lazy-init ChromaDB persistent client. Singleton."""
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                # Disable anonymous telemetry — it can hang on networks
                # without outbound HTTPS to posthog.
                os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
                import chromadb  # type: ignore
                from chromadb.config import Settings  # type: ignore

                DEFAULT_CHROMA_DIR.mkdir(parents=True, exist_ok=True)
                _client = chromadb.PersistentClient(
                    path=str(DEFAULT_CHROMA_DIR),
                    settings=Settings(anonymized_telemetry=False),
                )
                log.info("ChromaDB client initialized at %s", DEFAULT_CHROMA_DIR)
    return _client


def _get_embed_model():
    """Lazy-load sentence-transformers model. Singleton.

    Model files are cached by HuggingFace transformers under
    ~/.cache/huggingface (or HF_HOME). In Docker we mount this as a volume.
    """
    global _embed_model
    if _embed_model is None:
        with _lock:
            if _embed_model is None:
                from sentence_transformers import SentenceTransformer  # type: ignore

                model_name = os.environ.get("RAG_EMBED_MODEL", DEFAULT_EMBED_MODEL)
                log.info("Loading embedding model: %s", model_name)
                _embed_model = SentenceTransformer(model_name)
    return _embed_model


def _get_cross_encoder():
    """Lazy-load cross-encoder for re-ranking. Singleton.

    Cross-encoders are MUCH more accurate than bi-encoders (sentence-transformers)
    because they process query+chunk together and produce a relevance score.
    They're too slow to use for the initial vector search (would require
    scoring all 28k chunks per query), but perfect for re-ranking ~20 candidates.

    Model: ms-marco-MiniLM-L-6-v2 (~80 MB, MIT, CPU-friendly).
    """
    global _cross_encoder
    if _cross_encoder is None:
        with _lock:
            if _cross_encoder is None:
                from sentence_transformers import CrossEncoder  # type: ignore

                model_name = os.environ.get("RAG_CROSS_ENCODER", DEFAULT_CROSS_ENCODER)
                log.info("Loading cross-encoder: %s", model_name)
                _cross_encoder = CrossEncoder(model_name)
    return _cross_encoder


def _get_collection():
    """Get or create the vendor_docs collection."""
    global _collection
    if _collection is None:
        with _lock:
            if _collection is None:
                client = _get_client()
                _collection = client.get_or_create_collection(
                    name=COLLECTION_NAME,
                    metadata={"hnsw:space": "cosine"},
                )
    return _collection


def reset() -> None:
    """Reset the cached client/collection (for tests)."""
    global _client, _collection, _embed_model, _cross_encoder
    with _lock:
        _client = None
        _collection = None
        _embed_model = None
        _cross_encoder = None


def collection_count() -> int:
    """Return the number of chunks currently in the store."""
    try:
        return _get_collection().count()
    except Exception as exc:
        log.warning("collection_count failed: %s", exc)
        return 0


def add_chunks(chunks: list[Any], batch_size: int = 128) -> int:
    """Embed and persist a list of Chunk objects. Returns number added.

    Each chunk's text gets acronym-expanded before embedding so that the
    embedding sees "OSPF (Open Shortest Path First routing protocol)".
    The original (unexpanded) text is stored as `documents` for display.
    """
    if not chunks:
        return 0
    collection = _get_collection()
    model = _get_embed_model()

    added = 0
    for batch_start in range(0, len(chunks), batch_size):
        batch = chunks[batch_start : batch_start + batch_size]
        ids = [
            f"{c.metadata.get('source_file', 'doc')}:p{c.metadata.get('page', 0)}:c{c.metadata.get('chunk_index', 0)}:{batch_start + i}"
            for i, c in enumerate(batch)
        ]
        documents = [c.text for c in batch]
        # Embed acronym-expanded text
        embed_inputs = [expand_acronyms(c.text) for c in batch]
        embeddings = model.encode(embed_inputs, show_progress_bar=False).tolist()

        # ChromaDB metadata must be primitives (str/int/float/bool)
        metadatas = []
        for c in batch:
            md = {}
            for k, v in c.metadata.items():
                if v is None:
                    continue
                if isinstance(v, (str, int, float, bool)):
                    md[k] = v
                else:
                    md[k] = str(v)
            metadatas.append(md)

        collection.add(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
        )
        added += len(batch)
    return added


def search(
    query: str,
    *,
    vendor: str | None = None,
    os_family: str | None = None,
    doc_type: str | None = None,
    n_results: int = 5,
    n_candidates: int = DEFAULT_N_CANDIDATES,
    rerank: bool = True,
) -> list[dict]:
    """Search vendor docs by semantic similarity with metadata filters.

    Two-stage retrieval (C7S3b):
        Stage 1: bi-encoder (sentence-transformers) fetches top n_candidates
                 from the vector store using cosine similarity. Fast but coarse.
        Stage 2: cross-encoder (ms-marco-MiniLM) re-scores each candidate by
                 processing query+chunk together. Precise but slow per pair.
        Final:   return top n_results sorted by cross-encoder score.

    Args:
        query:        operator question (acronyms auto-expanded for retrieval)
        vendor:       "cisco" or "fortinet" (optional)
        os_family:    "iosxe", "iosxr", "fortios" (optional)
        doc_type:     e.g. "security_config_guide", "cli_reference" (optional)
        n_results:    max chunks to return (default 5)
        n_candidates: candidates pulled from vector store before re-ranking.
                      Default 20. Trade-off: higher = better recall but slower.
        rerank:       if False, skip cross-encoder (vector-only). Used by tests
                      and for latency-critical batch operations.

    Returns a list of dicts:
        {text, score, vector_score, source_file, toc_section, page, vendor,
         os_family, doc_type, has_config}

    `score` is the cross-encoder score (sigmoid-normalized to [0,1]) when
    rerank=True, otherwise the vector cosine similarity. `vector_score` is
    always the original vector similarity for diagnostics.

    Empty list if collection is empty or no matches.
    """
    if not query or not query.strip():
        return []

    try:
        collection = _get_collection()
    except Exception as exc:
        log.warning("search: collection unavailable: %s", exc)
        return []

    if collection.count() == 0:
        return []

    model = _get_embed_model()

    # Acronym-expand query at search time as well (must mirror ingest)
    expanded_query = expand_acronyms(query)
    query_embedding = model.encode([expanded_query], show_progress_bar=False).tolist()

    where = _build_where(vendor=vendor, os_family=os_family, doc_type=doc_type)

    # Stage 1: bi-encoder vector search — pull more candidates than we'll return
    # so the cross-encoder has room to re-order. If rerank is off, just pull n_results.
    fetch_n = max(n_results, n_candidates) if rerank else n_results

    try:
        result = collection.query(
            query_embeddings=query_embedding,
            n_results=fetch_n,
            where=where,
        )
    except Exception as exc:
        log.warning("search query failed (where=%s): %s", where, exc)
        return []

    docs = (result.get("documents") or [[]])[0]
    metas = (result.get("metadatas") or [[]])[0]
    distances = (result.get("distances") or [[]])[0]

    candidates: list[dict] = []
    for text, md, dist in zip(docs, metas, distances):
        vec_score = max(0.0, min(1.0, 1.0 - float(dist)))
        candidates.append(
            {
                "text": text,
                "score": round(vec_score, 4),  # initial = vector score
                "vector_score": round(vec_score, 4),
                "source_file": md.get("source_file", ""),
                "toc_section": md.get("toc_section", ""),
                "page": md.get("page", 0),
                "vendor": md.get("vendor", ""),
                "os_family": md.get("os_family", ""),
                "doc_type": md.get("doc_type", ""),
                "has_config": md.get("has_config", False),
            }
        )

    if not candidates:
        return []

    # Stage 2: cross-encoder re-ranking via Reciprocal Rank Fusion (RRF)
    #
    # Pure cross-encoder reranking is too literal for operator paraphrase queries
    # — e.g., "real-time check packets crossing firewall" matches "ping" lexically
    # better than "debug flow" semantically. Pure vector ranking misses on
    # conceptual queries — e.g., "OSPF area 0 backbone" picks a thin command
    # reference over the routing guide.
    #
    # RRF combines both rankings by summing 1/(K + rank) for each method,
    # rewarding chunks that score well on EITHER signal. K=60 is the standard
    # value from the original RRF paper (Cormack et al., 2009).
    if rerank and len(candidates) > 1:
        try:
            ce = _get_cross_encoder()
            pairs = [(query, c["text"]) for c in candidates]
            ce_logits = ce.predict(pairs, show_progress_bar=False)
            import math

            # Annotate every candidate with its CE score
            for c, logit in zip(candidates, ce_logits):
                c["ce_logit"] = float(logit)
                c["ce_score"] = round(
                    1.0 / (1.0 + math.exp(-float(logit))), 4
                )

            # Vector ranking is the order we received from ChromaDB
            vec_ranked = list(candidates)
            # Cross-encoder ranking is descending CE logit
            ce_ranked = sorted(
                candidates, key=lambda c: c["ce_logit"], reverse=True
            )

            # Build rank lookups (1-indexed) keyed by Python id() since
            # the dicts are mutable and unhashable.
            K = 60
            vec_rank = {id(c): i + 1 for i, c in enumerate(vec_ranked)}
            ce_rank = {id(c): i + 1 for i, c in enumerate(ce_ranked)}

            for c in candidates:
                rrf = (
                    1.0 / (K + vec_rank[id(c)])
                    + 1.0 / (K + ce_rank[id(c)])
                )
                c["rrf_score"] = round(rrf, 6)
                # User-facing `score` is the CE-normalized score for display.
                # We sort by RRF below.
                c["score"] = c["ce_score"]

            # Final ordering: RRF descending
            candidates.sort(key=lambda c: c["rrf_score"], reverse=True)
        except Exception as exc:
            log.warning(
                "Cross-encoder rerank failed, falling back to vector ordering: %s",
                exc,
            )
            # Vector-based ordering already in place from ChromaDB

    return candidates[:n_results]


def _build_where(
    *, vendor: str | None, os_family: str | None, doc_type: str | None
) -> dict | None:
    """Build a ChromaDB `where` filter from optional metadata params.

    ChromaDB requires a single key for one filter, or `$and` for multiple.
    """
    clauses = []
    if vendor:
        clauses.append({"vendor": vendor})
    if os_family:
        clauses.append({"os_family": os_family})
    if doc_type:
        clauses.append({"doc_type": doc_type})

    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}


def stats() -> dict:
    """Return collection stats for diagnostics / health checks."""
    try:
        collection = _get_collection()
        count = collection.count()
        return {
            "available": True,
            "chunk_count": count,
            "collection": COLLECTION_NAME,
            "path": str(DEFAULT_CHROMA_DIR),
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}
