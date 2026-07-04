"""S07-1 — ISDB REST collection: reference extraction + paged range resolver.

Uses synthetic ids/IPs only (RFC 5737 / invented service ids). No live device;
the httpx client is a stub that replays the endpoint's measured schema shape.
"""

from __future__ import annotations

import httpx
import pytest

from netcopilot.collect import rest


# ── reference extraction ─────────────────────────────────────────────────────

_NAME_TABLE = {"results": [
    {"name": "SYNTH-Blocklist.Node", "internet-service-id": 990001},
    {"name": "SYNTH-Monitor.Svc", "internet-service-id": 990002},
    {"name": "SYNTH-Unused.Svc", "internet-service-id": 990003},
]}


def test_build_name_index():
    idx = rest._build_isdb_name_index(_NAME_TABLE)
    assert idx == {"SYNTH-Blocklist.Node": 990001, "SYNTH-Monitor.Svc": 990002,
                   "SYNTH-Unused.Svc": 990003}


def test_extract_referenced_by_name():
    idx = rest._build_isdb_name_index(_NAME_TABLE)
    policies = {"results": [
        {"policyid": 1, "internet-service-name": [{"name": "SYNTH-Blocklist.Node"}]},
        {"policyid": 2, "internet-service-src-name": [{"name": "SYNTH-Monitor.Svc"}]},
        {"policyid": 3, "dstaddr": [{"name": "some-host"}]},  # no ISDB ref
    ]}
    refs = rest._extract_referenced_isdb(policies, idx)
    assert refs == {990001: "SYNTH-Blocklist.Node", 990002: "SYNTH-Monitor.Svc"}
    assert 990003 not in refs  # unreferenced service is never resolved


def test_extract_referenced_by_id():
    idx = rest._build_isdb_name_index(_NAME_TABLE)
    policies = {"results": [
        {"policyid": 5, "internet-service-id": [{"id": 990001}]},
    ]}
    refs = rest._extract_referenced_isdb(policies, idx)
    assert refs == {990001: "SYNTH-Blocklist.Node"}


def test_extract_no_policies():
    assert rest._extract_referenced_isdb(None, {}) == {}
    assert rest._extract_referenced_isdb({"results": []}, {}) == {}


def test_malformed_results_shape_does_not_crash():
    # A non-list `results` (e.g. an unexpected endpoint reply) must degrade to
    # empty, not raise — Article III.
    assert rest._build_isdb_name_index({"results": {"hostname": "x"}}) == {}
    assert rest._extract_referenced_isdb({"results": {"hostname": "x"}}, {}) == {}


# ── paged range resolver ─────────────────────────────────────────────────────

class _StubResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=self)  # type: ignore[arg-type]

    def json(self):
        return self._payload


class _StubClient:
    """Replays the internet-service-details schema: summary then paged entries."""

    def __init__(self, total, entries, fail_status=None):
        self.total = total
        self.entries = entries
        self.fail_status = fail_status
        self.calls = []

    def get(self, url, params=None, **kw):
        self.calls.append(params)
        if self.fail_status:
            return _StubResponse({}, status=self.fail_status)
        if params.get("summary_only"):
            return _StubResponse({"results": {"id": params["id"], "total": self.total}})
        start = params.get("start", 0)
        count = params.get("count", 500)
        page = self.entries[start:start + count]
        return _StubResponse({"results": {"id": params["id"], "entry": page}})


def _entry(start_ip, end_ip=None, proto=6):
    return {"proto": proto, "ip_range": {"start_ip": start_ip, "end_ip": end_ip or start_ip}}


def test_fetch_ranges_single_page(monkeypatch):
    monkeypatch.setattr(rest, "_get_with_retry", lambda c, u, p: c.get(u, p))
    entries = [_entry("192.0.2.1"), _entry("192.0.2.2"), _entry("198.51.100.0", "198.51.100.255")]
    client = _StubClient(total=3, entries=entries)
    out = rest._fetch_isdb_ranges(client, "https://fw", 990001, "SYNTH-Blocklist.Node")
    assert out["name"] == "SYNTH-Blocklist.Node"
    assert out["total"] == 3
    assert out["truncated"] is False
    assert out["ranges"] == ["192.0.2.1", "192.0.2.2", "198.51.100.0-198.51.100.255"]


def test_fetch_ranges_dedups_proto_rows(monkeypatch):
    monkeypatch.setattr(rest, "_get_with_retry", lambda c, u, p: c.get(u, p))
    # Same range twice (TCP + UDP) collapses to one.
    entries = [_entry("192.0.2.9", proto=6), _entry("192.0.2.9", proto=17)]
    client = _StubClient(total=2, entries=entries)
    out = rest._fetch_isdb_ranges(client, "https://fw", 990001, "svc")
    assert out["ranges"] == ["192.0.2.9"]


def test_fetch_ranges_endpoint_unavailable_returns_none(monkeypatch):
    monkeypatch.setattr(rest, "_get_with_retry", lambda c, u, p: c.get(u, p))
    client = _StubClient(total=0, entries=[], fail_status=404)
    assert rest._fetch_isdb_ranges(client, "https://fw", 990001, "svc") is None


def test_fetch_ranges_full_at_cap_boundary_not_truncated(monkeypatch):
    # total covered in exactly MAX_PAGES pages, with proto-row dups shrinking
    # the deduped list below total — must NOT be flagged truncated.
    monkeypatch.setattr(rest, "_get_with_retry", lambda c, u, p: c.get(u, p))
    monkeypatch.setattr(rest, "_ISDB_PAGE_SIZE", 2)
    monkeypatch.setattr(rest, "_ISDB_MAX_PAGES", 2)
    entries = [_entry("192.0.2.1", proto=6), _entry("192.0.2.1", proto=17),
               _entry("192.0.2.2", proto=6), _entry("192.0.2.2", proto=17)]
    client = _StubClient(total=4, entries=entries)
    out = rest._fetch_isdb_ranges(client, "https://fw", 990001, "svc")
    assert out["truncated"] is False
    assert out["ranges"] == ["192.0.2.1", "192.0.2.2"]


def test_fetch_ranges_page_cap_truncates(monkeypatch):
    monkeypatch.setattr(rest, "_get_with_retry", lambda c, u, p: c.get(u, p))
    monkeypatch.setattr(rest, "_ISDB_PAGE_SIZE", 2)
    monkeypatch.setattr(rest, "_ISDB_MAX_PAGES", 1)
    # total says 4 but the cap allows only 1 page of 2 → truncated.
    entries = [_entry(f"192.0.2.{i}") for i in range(4)]
    client = _StubClient(total=4, entries=entries)
    out = rest._fetch_isdb_ranges(client, "https://fw", 990001, "svc")
    assert out["truncated"] is True
    assert len(out["ranges"]) == 2
