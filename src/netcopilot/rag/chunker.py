"""TOC-driven structure-aware chunker for vendor PDF documentation.

The audit of 48 vendor PDFs found that ALL of them ship with rich TOC
bookmarks (1259 entries in IOS-XE Security alone, 5760 in FortiOS CLI Ref).
Most networking RAG systems use naive 500-char splits and destroy this
structure. We respect it.

Per-vendor strategy (audit-derived):

| Vendor   | Doc type      | Primary boundary  | Atomic blocks                |
|----------|---------------|-------------------|------------------------------|
| Cisco    | IOS-XE C9300  | TOC L2/L3         | Step procedures, Device(cfg) |
| Cisco    | IOS-XR NCS5k  | TOC L3            | "router bgp ... !" stanzas   |
| Fortinet | Admin Guide   | TOC L3            | "config ... end" blocks      |
| Fortinet | CLI Reference | TOC L3 (1:1)      | (already 1 cmd per entry)    |

Algorithm:
    1. Parse TOC bookmarks via pypdfium2 (Apache-2.0 / BSD-3 PDFium engine)
    2. Extract text between consecutive TOC entries
    3. If section > MAX_CHARS: sub-split at vendor-specific block boundaries
    4. If section < MIN_CHARS: merge with neighbour
    5. NEVER split inside a config block

Each chunk carries metadata: {vendor, os_family, doc_type, toc_section,
toc_level, page, source_file, has_config}.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  PDF engine adapter — pypdfium2 (Apache-2.0 / BSD-3), exposing the small
#  interface the chunker needs (page_count, doc[i], page.get_text, get_toc,
#  close). Keeping the engine behind this adapter lets the TOC-driven chunker
#  stay engine-agnostic. (Replaces PyMuPDF/fitz, which is AGPL.)
# ─────────────────────────────────────────────────────────────────────────────

class _PdfPage:
    """Wraps a pypdfium2 page; .get_text(...) mirrors PyMuPDF's text extraction."""

    def __init__(self, page):
        self._page = page

    def get_text(self, _mode: str = "text") -> str:
        tp = self._page.get_textpage()
        try:
            return tp.get_text_range()
        finally:
            tp.close()


class _PdfDoc:
    """Wraps a pypdfium2 PdfDocument with a PyMuPDF-shaped interface."""

    def __init__(self, path: Path):
        try:
            import pypdfium2 as pdfium  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "pypdfium2 is required for RAG ingestion. Install with: pip install pypdfium2"
            ) from exc
        self._pdf = pdfium.PdfDocument(str(path))

    @property
    def page_count(self) -> int:
        return len(self._pdf)

    def __getitem__(self, index: int) -> _PdfPage:
        return _PdfPage(self._pdf[index])

    def get_toc(self, simple: bool = True) -> list[list]:
        """Return [[level, title, page_1indexed], ...] (PyMuPDF get_toc shape)."""
        toc: list[list] = []
        for bm in self._pdf.get_toc():
            dest = bm.get_dest()
            page = (dest.get_index() + 1) if dest is not None else -1
            toc.append([bm.level + 1, bm.get_title(), page])  # pypdfium2 level is 0-based
        return toc

    def close(self) -> None:
        self._pdf.close()


# Chunk size budget. The audit confirms most TOC L3 sections fit comfortably.
MIN_CHARS = 200
MAX_CHARS = 2000
HARD_MAX_CHARS = 4000  # if a single block-bounded section exceeds this, force-split

# Vendor / doc-type detection from filename
_IOSXE_PREFIXES = ("b_1712_",)             # Catalyst 9300/9500 config guides
_IOSXR_PREFIXES = ("b-",)                  # NCS-5500 / NCS-55k config guides
_FORTIOS_PREFIXES = ("FortiOS",)
_CISCO_TECH_RE = re.compile(r"^\d{6}-")     # 217419-…, 224891-…, 225617-…


@dataclass
class Chunk:
    """One ingestible piece of text + metadata."""
    text: str
    metadata: dict = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.text)


# ─────────────────────────────────────────────────────────────────────────────
#  Vendor / doc-type classification from filename
# ─────────────────────────────────────────────────────────────────────────────

def classify_doc(path: Path) -> dict:
    """Return {vendor, os_family, doc_type, product} for a vendor PDF.

    Pure-function classification based on filename — no PDF parsing required.
    Used by the chunker AND the ingestion CLI for stats.
    """
    name = path.name

    # FortiOS family
    if name.startswith(_FORTIOS_PREFIXES):
        meta = {"vendor": "fortinet", "os_family": "fortios", "product": "fortigate"}
        if "CLI_Reference" in name:
            meta["doc_type"] = "cli_reference"
        elif "Administration_Guide" in name:
            meta["doc_type"] = "admin_guide"
        elif "Best_Practices" in name:
            meta["doc_type"] = "best_practices"
        elif "New_Features" in name:
            meta["doc_type"] = "new_features"
        elif "Log_Reference" in name:
            meta["doc_type"] = "log_reference"
        elif "Ports" in name:
            meta["doc_type"] = "ports_reference"
        elif "Troubleshooting" in name:
            meta["doc_type"] = "troubleshooting"
        else:
            meta["doc_type"] = "other"
        # Extract version, e.g. FortiOS-7.4.11-…
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", name)
        if m:
            meta["version"] = m.group(1)
        return meta

    # Cisco IOS-XE Catalyst 9000 series
    if name.startswith(_IOSXE_PREFIXES):
        meta = {
            "vendor": "cisco",
            "os_family": "iosxe",
            "product": "catalyst9000",
            "version": "17.12",
        }
        # b_1712_sec_9300 → security; b_1712_ip_9300 → ip routing; etc.
        if "_sec_" in name:
            meta["doc_type"] = "security_config_guide"
        elif "_ip_mcast_rtng" in name:
            meta["doc_type"] = "multicast_config_guide"
        elif "_ip_" in name:
            meta["doc_type"] = "ip_routing_config_guide"
        elif "_qos_" in name:
            meta["doc_type"] = "qos_config_guide"
        elif "_vlan_" in name:
            meta["doc_type"] = "vlan_config_guide"
        elif "_int_and_hw_" in name:
            meta["doc_type"] = "interfaces_config_guide"
        elif "_nmgmt_" in name:
            meta["doc_type"] = "network_mgmt_config_guide"
        elif "_sys_mgmt_" in name:
            meta["doc_type"] = "system_mgmt_config_guide"
        elif "_stck_mgr_ha_" in name:
            meta["doc_type"] = "stacking_ha_config_guide"
        elif "_bgp_evpn_vxlan_" in name:
            meta["doc_type"] = "bgp_evpn_vxlan_guide"
        elif "_cts_" in name:
            meta["doc_type"] = "trustsec_config_guide"
        elif "_bonjour_" in name:
            meta["doc_type"] = "bonjour_config_guide"
        elif "_programmability_" in name:
            meta["doc_type"] = "programmability_guide"
        elif "_9500_cr" in name:
            meta["doc_type"] = "command_reference"
            meta["product"] = "catalyst9500"
        else:
            meta["doc_type"] = "other"
        # 9500 vs 9300
        if "9500" in name:
            meta["product"] = "catalyst9500"
        elif "9300" in name:
            meta["product"] = "catalyst9300"
        return meta

    # Cisco IOS-XR NCS-5500 / NCS-55k
    if name.startswith(_IOSXR_PREFIXES) and ("ncs5500" in name or "ncs55k" in name):
        meta = {
            "vendor": "cisco",
            "os_family": "iosxr",
            "product": "ncs5500",
            "version": "7.11",
        }
        if "bgp" in name:
            meta["doc_type"] = "bgp_config_guide"
        elif "segment-routing" in name:
            meta["doc_type"] = "segment_routing_config_guide"
        elif "routing" in name:
            meta["doc_type"] = "routing_config_guide"
        elif "interfaces-hardware" in name:
            meta["doc_type"] = "interfaces_config_guide"
        elif "ip-addresses" in name:
            meta["doc_type"] = "ip_addresses_config_guide"
        elif "l2vpn" in name:
            meta["doc_type"] = "l2vpn_config_guide"
        elif "l3vpn" in name:
            meta["doc_type"] = "l3vpn_config_guide"
        elif "mpls" in name:
            meta["doc_type"] = "mpls_config_guide"
        elif "multicast" in name:
            meta["doc_type"] = "multicast_config_guide"
        elif "netflow" in name:
            meta["doc_type"] = "netflow_config_guide"
        elif "programmability" in name:
            meta["doc_type"] = "programmability_guide"
        elif "qos" in name:
            meta["doc_type"] = "qos_config_guide"
        elif "system-management" in name:
            meta["doc_type"] = "system_mgmt_config_guide"
        elif "system-monitoring" in name:
            meta["doc_type"] = "system_monitoring_config_guide"
        elif "system-security" in name:
            meta["doc_type"] = "security_config_guide"
        elif "system-setup" in name:
            meta["doc_type"] = "system_setup_config_guide"
        elif "telemetry" in name:
            meta["doc_type"] = "telemetry_config_guide"
        else:
            meta["doc_type"] = "other"
        return meta

    # Cisco system message guide (cross-platform)
    if "system-message-guide" in name:
        return {
            "vendor": "cisco",
            "os_family": "iosxr",
            "product": "ncs5500",
            "doc_type": "system_message_guide",
            "version": "17.12",
        }

    # Cisco tech articles (217419-, 224891-, 225617-)
    if _CISCO_TECH_RE.match(name):
        meta = {
            "vendor": "cisco",
            "os_family": "iosxe",
            "product": "catalyst9000",
            "doc_type": "tech_article",
        }
        return meta

    # Unknown — best-effort default
    log.warning("Unknown document type for %s — defaulting to vendor=unknown", name)
    return {
        "vendor": "unknown",
        "os_family": "unknown",
        "product": "unknown",
        "doc_type": "other",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Sub-splitting helpers (vendor-specific atomic block detection)
# ─────────────────────────────────────────────────────────────────────────────

# IOS-XE: detect "Step N" boundaries inside procedures
_IOSXE_STEP_RE = re.compile(r"(?m)^\s*(?:Step\s+\d+|Example:)\s")
_IOSXE_CONFIG_PROMPT_RE = re.compile(r"(?m)^[A-Za-z0-9_-]+\(config[^)]*\)#")
_IOSXE_EXEC_PROMPT_RE = re.compile(r"(?m)^[A-Za-z0-9_-]+#\s")

# IOS-XR: ! stanza delimiters and RP/0/RP0/CPU0:router prompts
_IOSXR_STANZA_RE = re.compile(r"(?m)^!\s*$")
_IOSXR_PROMPT_RE = re.compile(r"(?m)^RP/\d+/[A-Z]+\d+/CPU\d+:[\w-]+(?:\(config[^)]*\))?[#]")

# FortiOS: config ... end blocks
_FORTIOS_CONFIG_START_RE = re.compile(r"(?m)^\s*config\s+\S")
_FORTIOS_CONFIG_END_RE = re.compile(r"(?m)^\s*end\s*$")


def has_config_block(text: str, os_family: str) -> bool:
    """Detect whether a text contains a vendor CLI configuration block."""
    if os_family == "iosxe":
        return bool(
            _IOSXE_CONFIG_PROMPT_RE.search(text)
            or _IOSXE_EXEC_PROMPT_RE.search(text)
        )
    if os_family == "iosxr":
        return bool(_IOSXR_PROMPT_RE.search(text))
    if os_family == "fortios":
        return bool(
            _FORTIOS_CONFIG_START_RE.search(text)
            and _FORTIOS_CONFIG_END_RE.search(text)
        )
    return False


def _split_at_boundaries(text: str, boundary_re: re.Pattern, max_chars: int) -> list[str]:
    """Split text at boundary positions while respecting max_chars budget.

    Walks through boundary positions and accumulates pieces until adding
    the next piece would exceed max_chars; then emits a chunk and starts
    a new accumulator. Boundaries that don't help (whole text < max_chars)
    return the original text untouched.
    """
    if len(text) <= max_chars:
        return [text]

    positions = [m.start() for m in boundary_re.finditer(text)]
    if not positions:
        # No boundaries — fall back to paragraph split
        return _split_paragraphs(text, max_chars)

    # Always start at 0 and end at len(text)
    positions = [0] + [p for p in positions if p > 0] + [len(text)]
    chunks: list[str] = []
    cur_start = 0
    cur_end = 0
    for next_pos in positions[1:]:
        candidate_size = next_pos - cur_start
        if candidate_size > max_chars and cur_end > cur_start:
            # Emit accumulated piece
            piece = text[cur_start:cur_end].strip()
            if piece:
                chunks.append(piece)
            cur_start = cur_end
        cur_end = next_pos
    # Final piece
    piece = text[cur_start:cur_end].strip()
    if piece:
        chunks.append(piece)
    return chunks


def _split_paragraphs(text: str, max_chars: int) -> list[str]:
    """Last-resort split: paragraphs (blank lines), then if still too big, hard cut."""
    paragraphs = re.split(r"\n\s*\n", text)
    chunks: list[str] = []
    cur = ""
    for p in paragraphs:
        if len(cur) + len(p) + 2 <= max_chars:
            cur = (cur + "\n\n" + p) if cur else p
        else:
            if cur:
                chunks.append(cur.strip())
            if len(p) > max_chars:
                # Hard cut at HARD_MAX_CHARS
                for i in range(0, len(p), max_chars):
                    chunks.append(p[i : i + max_chars].strip())
                cur = ""
            else:
                cur = p
    if cur:
        chunks.append(cur.strip())
    return [c for c in chunks if c]


def _sub_split(text: str, os_family: str) -> list[str]:
    """Sub-split a too-large section using vendor-specific boundaries."""
    if os_family == "iosxe":
        # Try Step boundaries first
        parts = _split_at_boundaries(text, _IOSXE_STEP_RE, MAX_CHARS)
        if len(parts) > 1:
            return parts
        # Fall back to exec/config prompts
        return _split_at_boundaries(text, _IOSXE_EXEC_PROMPT_RE, MAX_CHARS)
    if os_family == "iosxr":
        # Use ! stanza delimiters
        return _split_at_boundaries(text, _IOSXR_STANZA_RE, MAX_CHARS)
    if os_family == "fortios":
        # Split between config blocks (boundary = end of an `end` line)
        return _split_at_boundaries(text, _FORTIOS_CONFIG_END_RE, MAX_CHARS)
    return _split_paragraphs(text, MAX_CHARS)


# ─────────────────────────────────────────────────────────────────────────────
#  TOC-driven extraction
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _TocEntry:
    level: int
    title: str
    page: int  # 1-indexed


def _normalize_toc(raw_toc: list) -> list[_TocEntry]:
    """Convert PyMuPDF get_toc() output to _TocEntry list.

    PyMuPDF returns [[level, title, page], ...] with 1-indexed page numbers.
    We strip empty/junk titles and clamp negative levels.
    """
    out: list[_TocEntry] = []
    for entry in raw_toc:
        if not entry or len(entry) < 3:
            continue
        level, title, page = entry[0], entry[1], entry[2]
        if not isinstance(title, str):
            continue
        title = title.strip()
        if not title:
            continue
        if not isinstance(level, int) or level < 1:
            level = 1
        if not isinstance(page, int) or page < 1:
            page = 1
        out.append(_TocEntry(level=level, title=title, page=page))
    return out


def _toc_target_level(os_family: str, doc_type: str, toc: list[_TocEntry]) -> int:
    """Decide which TOC level to use as the primary chunk boundary.

    Per audit-derived rules:
        - IOS-XE     → L3 if available, else L2
        - IOS-XR     → L3
        - FortiOS Admin → L3
        - FortiOS CLI Reference → L3 (1:1 — one command per entry)
    """
    if not toc:
        return 0
    levels = {e.level for e in toc}
    if os_family == "iosxe":
        return 3 if 3 in levels else (2 if 2 in levels else 1)
    if os_family == "iosxr":
        return 3 if 3 in levels else (2 if 2 in levels else 1)
    if os_family == "fortios":
        if doc_type == "cli_reference":
            return 3 if 3 in levels else 2
        return 3 if 3 in levels else (2 if 2 in levels else 1)
    return 2 if 2 in levels else 1


def _build_section_ranges(
    toc: list[_TocEntry], target_level: int, total_pages: int
) -> list[tuple[_TocEntry, int]]:
    """For each TOC entry at target_level, compute (entry, end_page_exclusive).

    The end of a section is the page of the next TOC entry at the same OR
    shallower level (whichever comes first). Last section ends at total_pages.
    """
    # Filter to "anchor" entries: those at or below target level get their
    # own range; deeper-level entries are subsections rolled up into them.
    anchors = [e for e in toc if e.level <= target_level]
    ranges: list[tuple[_TocEntry, int]] = []
    for i, entry in enumerate(anchors):
        # Find next anchor (any level <= target_level) for end page
        if i + 1 < len(anchors):
            end_page = anchors[i + 1].page
        else:
            end_page = total_pages + 1
        ranges.append((entry, end_page))
    # Keep only entries AT target level (not shallower) — those are the chunks.
    # Shallower (e.g. chapter L1) anchors are "container" headings; we still
    # want to include their introductory text, so we keep them too unless they
    # already have target-level children that fully cover the same pages.
    return ranges


def _extract_pages_text(doc, start_page: int, end_page: int) -> tuple[str, int]:
    """Return concatenated text for pages [start_page, end_page) (1-indexed).

    Returns (text, first_page_with_text).
    """
    pieces = []
    first_page = start_page
    for p in range(start_page, end_page):
        if p < 1 or p > doc.page_count:
            continue
        try:
            page = doc[p - 1]  # 0-indexed in PyMuPDF
            text = page.get_text("text")
        except Exception as exc:
            log.warning("Failed to extract page %d: %s", p, exc)
            continue
        if text:
            pieces.append(text)
    return "\n".join(pieces), first_page


def _clean_section_text(text: str, title: str) -> str:
    """Strip page headers/footers and normalize whitespace.

    Vendor PDFs repeat the doc title and page numbers on every page. We
    don't try to detect them perfectly — we just collapse runs of whitespace
    and remove obvious page-number-only lines.
    """
    if not text:
        return ""
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        # Drop bare page numbers
        if re.fullmatch(r"\s*\d+\s*", line):
            continue
        # Drop "Cisco IOS XE …" / "FortiOS …" footers if they appear alone
        lines.append(line)
    cleaned = "\n".join(lines)
    # Collapse 3+ blank lines into 2
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


# ─────────────────────────────────────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def chunk_pdf(pdf_path: Path) -> list[Chunk]:
    """Parse a vendor PDF and yield TOC-driven chunks with metadata.

    This is the SINGLE entry point used by the ingestion pipeline. All
    per-vendor logic happens inside.

    Returns an empty list if the PDF can't be parsed (logged as warning).
    """
    if not pdf_path.exists():
        log.error("PDF not found: %s", pdf_path)
        return []

    doc_meta = classify_doc(pdf_path)

    try:
        doc = _PdfDoc(pdf_path)
    except ImportError:
        raise  # missing pypdfium2 is a hard dependency error, not a bad PDF
    except Exception as exc:
        log.error("Failed to open %s: %s", pdf_path, exc)
        return []

    try:
        total_pages = doc.page_count
        raw_toc = doc.get_toc(simple=True)
        toc = _normalize_toc(raw_toc)

        if not toc:
            log.warning("%s has no TOC — falling back to whole-doc paragraph split", pdf_path.name)
            chunks = _fallback_no_toc(doc, pdf_path, doc_meta, total_pages)
        else:
            target_level = _toc_target_level(doc_meta["os_family"], doc_meta["doc_type"], toc)
            ranges = _build_section_ranges(toc, target_level, total_pages)
            chunks = _chunks_from_ranges(doc, pdf_path, doc_meta, ranges, target_level)
    finally:
        doc.close()

    # Final pass: merge tiny adjacent chunks (same TOC parent)
    chunks = _merge_tiny(chunks)
    # Drop residual chunks that are still below MIN_CHARS — too small to be
    # useful retrieval targets (typically section headers with no body).
    chunks = [c for c in chunks if len(c.text) >= MIN_CHARS]
    log.info(
        "%s: %d chunks (vendor=%s os=%s doc_type=%s)",
        pdf_path.name,
        len(chunks),
        doc_meta["vendor"],
        doc_meta["os_family"],
        doc_meta.get("doc_type", "?"),
    )
    return chunks


def _chunks_from_ranges(
    doc,
    pdf_path: Path,
    doc_meta: dict,
    ranges: list[tuple[_TocEntry, int]],
    target_level: int,
) -> list[Chunk]:
    """Convert TOC ranges into Chunk objects, sub-splitting large sections."""
    out: list[Chunk] = []
    os_family = doc_meta["os_family"]
    for entry, end_page in ranges:
        section_text, first_page = _extract_pages_text(doc, entry.page, end_page)
        section_text = _clean_section_text(section_text, entry.title)
        if not section_text:
            continue

        # Try to scope text to "between this heading and the next" within the
        # first page — useful when multiple TOC entries share the same page.
        # We do a best-effort literal-title cut; if not found, keep full text.
        scoped = _scope_to_heading(section_text, entry.title)
        if scoped:
            section_text = scoped

        if len(section_text) < MIN_CHARS:
            # Will get merged with neighbours later
            pass

        if len(section_text) <= MAX_CHARS:
            pieces = [section_text]
        else:
            pieces = _sub_split(section_text, os_family)
            # Force-cap any remaining giants
            final_pieces = []
            for p in pieces:
                if len(p) > HARD_MAX_CHARS:
                    final_pieces.extend(_split_paragraphs(p, MAX_CHARS))
                else:
                    final_pieces.append(p)
            pieces = final_pieces

        for idx, piece in enumerate(pieces):
            if not piece.strip():
                continue
            md = {
                **doc_meta,
                "source_file": pdf_path.name,
                "toc_section": entry.title[:200],
                "toc_level": entry.level,
                "page": int(first_page),
                "has_config": has_config_block(piece, os_family),
                "chunk_index": idx,
            }
            out.append(Chunk(text=piece, metadata=md))
    return out


def _scope_to_heading(text: str, title: str) -> str | None:
    """If `title` appears as a line in `text`, return text starting at that line.

    Helps when extracted page text contains multiple sections — we want to
    start at our heading. Returns None if heading not found cleanly.
    """
    if len(title) < 4:
        return None
    # Try literal title match first (case-insensitive, line-anchored)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().lower() == title.lower():
            return "\n".join(lines[i:])
    return None


def _merge_tiny(chunks: list[Chunk]) -> list[Chunk]:
    """Merge consecutive tiny chunks (< MIN_CHARS) within the same source file."""
    if not chunks:
        return chunks
    out: list[Chunk] = []
    buf: Chunk | None = None
    for c in chunks:
        if buf is None:
            buf = c
            continue
        # Same source file AND combined size still under MAX_CHARS AND
        # at least one is tiny → merge.
        same_src = buf.metadata.get("source_file") == c.metadata.get("source_file")
        combined_size = len(buf.text) + len(c.text) + 2
        if same_src and combined_size <= MAX_CHARS and (
            len(buf.text) < MIN_CHARS or len(c.text) < MIN_CHARS
        ):
            buf = Chunk(
                text=buf.text + "\n\n" + c.text,
                metadata={
                    **buf.metadata,
                    "has_config": buf.metadata.get("has_config") or c.metadata.get("has_config"),
                    # Keep the earlier section title and page
                },
            )
        else:
            out.append(buf)
            buf = c
    if buf is not None:
        out.append(buf)
    return out


def _fallback_no_toc(doc, pdf_path: Path, doc_meta: dict, total_pages: int) -> list[Chunk]:
    """Whole-doc paragraph split for PDFs without a TOC.

    All audited PDFs DO have TOCs, so this is purely defensive.
    """
    out: list[Chunk] = []
    for page_num in range(1, total_pages + 1):
        try:
            page = doc[page_num - 1]
            text = _clean_section_text(page.get_text("text"), "")
        except Exception:
            continue
        if not text:
            continue
        for piece in _split_paragraphs(text, MAX_CHARS):
            if len(piece) < MIN_CHARS:
                continue
            out.append(
                Chunk(
                    text=piece,
                    metadata={
                        **doc_meta,
                        "source_file": pdf_path.name,
                        "toc_section": "(no TOC)",
                        "toc_level": 0,
                        "page": page_num,
                        "has_config": has_config_block(piece, doc_meta["os_family"]),
                        "chunk_index": 0,
                    },
                )
            )
    return out
