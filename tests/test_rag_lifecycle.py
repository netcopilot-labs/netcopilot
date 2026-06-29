"""RAG document lifecycle: idempotent re-ingest (delete-then-add), per-document
removal, and pruning docs no longer in the folder. Uses a fake collection so no
ChromaDB or embedding model is touched."""

import sys

from netcopilot.rag import ingest, store


class _FakeCollection:
    """Minimal stand-in for a ChromaDB collection."""

    def __init__(self, counts=(0, 0), metas=None):
        self._counts = list(counts)
        self._metas = metas or []
        self.deleted = []

    def count(self):
        return self._counts.pop(0) if self._counts else 0

    def delete(self, where=None):
        self.deleted.append(where)

    def get(self, include=None):
        return {"metadatas": self._metas}


# ── store.delete_by_source / list_sources ────────────────────────────────────
def test_delete_by_source_returns_removed_count(monkeypatch):
    coll = _FakeCollection(counts=(10, 7))           # before=10, after=7
    monkeypatch.setattr(store, "_get_collection", lambda: coll)
    assert store.delete_by_source("old.pdf") == 3
    assert coll.deleted == [{"source_file": "old.pdf"}]


def test_list_sources_dedupes_and_skips_blank(monkeypatch):
    coll = _FakeCollection(
        metas=[{"source_file": "a.pdf"}, {"source_file": "a.pdf"},
               {"source_file": "b.pdf"}, {}]
    )
    monkeypatch.setattr(store, "_get_collection", lambda: coll)
    assert store.list_sources() == {"a.pdf", "b.pdf"}


# ── ingest_pdf is idempotent (delete BEFORE add) ─────────────────────────────
def test_ingest_pdf_replaces_prior_chunks(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ingest.chunker, "chunk_pdf", lambda p: [object()])

    def fake_delete(name):
        calls.append(("delete", name)); return 0

    def fake_add(chunks):
        calls.append(("add", len(chunks))); return len(chunks)

    monkeypatch.setattr(ingest.store, "delete_by_source", fake_delete)
    monkeypatch.setattr(ingest.store, "add_chunks", fake_add)

    pdf = tmp_path / "guide.pdf"
    pdf.write_bytes(b"%PDF")
    added, _ = ingest.ingest_pdf(pdf)

    assert added == 1
    assert calls == [("delete", "guide.pdf"), ("add", 1)]   # delete first, then add


# ── main --remove / --prune flags ────────────────────────────────────────────
def test_main_remove_deletes_one_doc(monkeypatch, capsys):
    seen = {}

    def fake_delete(f):
        seen["file"] = f; return 5

    monkeypatch.setattr(ingest.store, "delete_by_source", fake_delete)
    monkeypatch.setattr(ingest.store, "collection_count", lambda: 12)
    monkeypatch.setattr(sys, "argv", ["ingest", "--remove", "old.pdf"])

    assert ingest.main() == 0
    assert seen["file"] == "old.pdf"
    assert "Removed 5 chunk(s)" in capsys.readouterr().out


def test_main_prune_removes_docs_not_in_folder(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(ingest, "discover_pdfs", lambda d, only=None: [tmp_path / "a.pdf"])
    monkeypatch.setattr(ingest.store, "list_sources", lambda: {"a.pdf", "stale.pdf"})
    deleted = []

    def fake_delete(f):
        deleted.append(f); return 4

    monkeypatch.setattr(ingest.store, "delete_by_source", fake_delete)
    monkeypatch.setattr(ingest.store, "collection_count", lambda: 8)
    monkeypatch.setattr(sys, "argv", ["ingest", "--prune", "--docs-dir", str(tmp_path)])

    assert ingest.main() == 0
    assert deleted == ["stale.pdf"]                          # only the one absent from the folder
    assert "Pruned 1 document(s)" in capsys.readouterr().out
