"""F4d: RAG chunker (pypdfium2 engine) + acronym expansion.

The pypdfium2 PDF swap is exercised end-to-end against the real vendor corpus in
development (chunk_pdf produced 1075 chunks from a Cisco config guide); the corpus
PDFs are not redistributable, so the committed test drives chunk_pdf through a
fake PDF document that mimics the adapter interface.
"""

from pathlib import Path

from netcopilot.rag import acronyms, chunker


# ── Acronym expansion ────────────────────────────────────────────────────────

def test_known_acronyms_nonempty():
    known = acronyms.known_acronyms()
    assert known and all(isinstance(a, str) for a in known)


def test_expand_is_string_and_preserves_text():
    out = acronyms.expand("configure OSPF on the interface")
    assert isinstance(out, str)
    assert "OSPF" in out  # original token preserved (expansion is additive)


# ── classify_doc (pure, filename-based) ──────────────────────────────────────

def test_classify_doc_returns_metadata():
    meta = chunker.classify_doc(Path("some-fortios-cli-reference.pdf"))
    assert set(meta) >= {"vendor", "os_family", "doc_type"}


# ── chunk_pdf via the pypdfium2 adapter interface (fake document) ────────────

class _FakePage:
    def get_text(self, _mode="text"):
        # > MIN_CHARS so the section yields a real chunk
        return ("configure terminal\n  interface GigabitEthernet0/1\n"
                "  description uplink to core\n  no shutdown\n") * 12


class _FakeDoc:
    """Mimics chunker._PdfDoc: page_count, doc[i], get_toc, close."""
    page_count = 4

    def __init__(self, _path):
        pass

    def __getitem__(self, _i):
        return _FakePage()

    def get_toc(self, simple=True):
        return [[1, "Overview", 1], [1, "Configuration", 2], [1, "Verification", 3]]

    def close(self):
        pass


def test_chunk_pdf_produces_chunks_with_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(chunker, "_PdfDoc", _FakeDoc)
    pdf = tmp_path / "vendor-guide.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")  # only needs to exist; _FakeDoc ignores content

    chunks = chunker.chunk_pdf(pdf)
    assert chunks, "expected at least one chunk from the TOC sections"
    c = chunks[0]
    assert c.text and isinstance(c.metadata, dict)
    assert "source_file" in c.metadata
