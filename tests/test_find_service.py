"""S16-4: find_service tool contract — found / ambiguous / not_found / no_data."""

import asyncio
from unittest.mock import patch

from netcopilot.mcp.tools import find_service as fs

CTX = {"run_id": "r1"}


def _run(coro):
    return asyncio.run(coro)


class _Single:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class FakeSession:
    def __init__(self, *, total, rows=(), known=()):
        self.total, self.rows, self.known = total, list(rows), list(known)

    def run(self, query, **params):
        q = " ".join(query.split())
        if "count(s)" in q:
            return _Single({"n": self.total})
        if "RETURN s.name AS n" in q:
            return [{"n": n} for n in self.known]
        return [{"s": r} for r in self.rows]


def _fake_driver(session):
    class D:
        def session(self):
            s = session

            class C:
                def __enter__(self):
                    return s

                def __exit__(self, *a):
                    return False
            return C()
    return D()


def _call(session, **kw):
    with patch.object(fs, "is_available", return_value=True), \
         patch.object(fs, "get_driver", return_value=_fake_driver(session)):
        return _run(fs.find_service(context=CTX, **kw))


SVC = {"name": "cam-lobby-01", "ip": "198.51.100.26", "address": "198.51.100.26/28",
       "dns_name": "cam-lobby-01.demo.example", "description": "Lobby camera",
       "located": True, "location_method": "arp+fdb", "device": "acc-sw-03",
       "interface": "Gi1/0/5", "mac": "12:34:56:78:9a:bc", "observer_count": 2,
       "joined_at": "2026-07-06T18:00:00+00:00"}


def test_needs_name_or_ip():
    out = _run(fs.find_service(context=CTX))
    assert out.status == "error"


def test_no_data_when_join_never_ran():
    out = _call(FakeSession(total=0), name="cam")
    assert out.status == "no_data"
    assert "netbox services" in out.text        # actionable: how to run the join


def test_found_by_ip_full_detail():
    out = _call(FakeSession(total=3, rows=[SVC]), ip="198.51.100.26/28")
    assert out.status == "ok"
    assert "acc-sw-03, port Gi1/0/5" in out.text
    assert "port-precise" in out.text
    assert out.verdict == {"service": "cam-lobby-01", "ip": "198.51.100.26",
                           "located": True, "location_method": "arp+fdb",
                           "device": "acc-sw-03", "interface": "Gi1/0/5"}
    assert out.highlight == {"device": "acc-sw-03"}


def test_unlocated_service_is_honest():
    svc = dict(SVC, located=False, location_method="none", device=None,
               interface=None, mac=None)
    out = _call(FakeSession(total=1, rows=[svc]), name="cam")
    assert out.status == "ok"
    assert "NEVER SEEN" in out.text
    assert out.verdict["located"] is False and out.highlight is None


def test_ambiguous_lists_matches():
    rows = [SVC, dict(SVC, name="cam-lobby-02", ip="198.51.100.27")]
    out = _call(FakeSession(total=5, rows=rows), name="cam")
    assert out.status == "ok"
    assert "2 services match" in out.text and "cam-lobby-02" in out.text
    assert out.verdict == {"matches": 2, "ambiguous": True}


def test_not_found_names_the_known_services():
    out = _call(FakeSession(total=2, rows=[], known=["printer-f2", "ghost-svc"]),
                name="nonexistent")
    assert out.status == "not_found"
    assert "printer-f2" in out.text
