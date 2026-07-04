"""S11-2: staging machinery + write path — validation, gate, failure taxonomy,
audit completeness, bulk ordering.

The Neo4j driver is mocked (MagicMock) so the contract is enforced without a
graph; the pynetbox surface is a stub endpoint that raises per-status
exceptions to drive the 5-class failure taxonomy. Synthetic names throughout.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from netcopilot.declared_state.gate import WritesDisabled
from netcopilot.declared_state import staging
from netcopilot.declared_state.staging import (
    AuthAbortError,
    VALID_OBJECT_TYPES,
    VALID_SOURCES,
    _write_to_netbox,
    approve,
    approve_bulk,
    priority_for_drift,
    reject,
    stage_candidate,
)


# ── priority + validation (pure) ─────────────────────────────────────────────

def test_priority_for_drift_severities():
    assert priority_for_drift("critical") == 80
    assert priority_for_drift("high") == 70
    assert priority_for_drift("Warning") == 60
    assert priority_for_drift("info") == 40
    assert priority_for_drift("nonsense") == 50
    assert priority_for_drift(None) == 50


def test_stage_candidate_rejects_invalid_enums():
    with pytest.raises(ValueError, match="Invalid source"):
        stage_candidate(source="bogus", object_type="device", payload={}, reason="r")
    with pytest.raises(ValueError, match="Invalid object_type"):
        stage_candidate(source="bootstrap", object_type="pizza", payload={}, reason="r")


def test_stage_candidate_priority_bounds():
    with patch.object(staging, "get_driver") as gd:
        gd.return_value.session.return_value.__enter__.return_value = MagicMock()
        with pytest.raises(ValueError, match="priority"):
            stage_candidate(source="manual", object_type="device", payload={},
                            reason="r", priority=0)


def test_stage_candidate_creates_node(monkeypatch):
    session = MagicMock()
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    monkeypatch.setattr(staging, "get_driver", lambda: driver)
    monkeypatch.setattr(staging, "_index_ensured", True)

    cid = stage_candidate(source="bootstrap", object_type="device",
                          payload={"name": "acc-sw-01"}, reason="test stage")
    assert cid  # uuid returned
    create_call = session.run.call_args_list[0]
    assert "CREATE (p:NetBoxPendingWrite" in create_call.args[0]
    assert create_call.kwargs["source"] == "bootstrap"
    assert json.loads(create_call.kwargs["payload_json"]) == {"name": "acc-sw-01"}


# ── the write gate (Constitution Art. I) ─────────────────────────────────────

def test_write_to_netbox_is_gated(monkeypatch):
    monkeypatch.delenv("NETBOX_WRITE_ENABLED", raising=False)
    adapter = MagicMock()
    with pytest.raises(WritesDisabled):
        _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})
    adapter._nb.assert_not_called()  # no API interaction of any kind


def test_reject_is_not_gated(monkeypatch):
    # Reject makes no NetBox call → allowed with writes disabled; still audited.
    monkeypatch.delenv("NETBOX_WRITE_ENABLED", raising=False)
    monkeypatch.setattr(staging, "_read_pending", lambda cid: {
        "id": cid, "source": "bootstrap", "netbox_object_type": "device",
        "payload_json": json.dumps({"name": "acc-sw-01"}), "reason": "r",
    })
    audits = []
    monkeypatch.setattr(staging, "_create_audit_row",
                        lambda pending, write_result, source_override=None:
                        audits.append((pending["id"], source_override)) or "audit-1")
    monkeypatch.setattr(staging, "_atomic_delete_pending", lambda cid: True)
    assert reject("cand-1") is True
    assert audits == [("cand-1", "manual_reject")]


# ── failure taxonomy (mocked pynetbox endpoint) ──────────────────────────────

class _StatusError(Exception):
    def __init__(self, status, body="boom"):
        self.status_code = status
        self.error = body
        super().__init__(body)


def _adapter_with_endpoint(create_side_effect=None, create_return=None):
    endpoint = MagicMock()
    if create_side_effect is not None:
        endpoint.create.side_effect = create_side_effect
    else:
        rec = MagicMock(id=42)
        rec.serialize.return_value = {"id": 42, "name": "acc-sw-01"}
        endpoint.create.return_value = create_return or rec
    adapter = MagicMock()
    adapter._nb.dcim.devices = endpoint
    return adapter, endpoint


@pytest.fixture()
def writes_on(monkeypatch):
    monkeypatch.setenv("NETBOX_WRITE_ENABLED", "true")


def test_write_success_201(writes_on):
    adapter, _ = _adapter_with_endpoint()
    r = _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})
    assert r["api_response_status"] == 201 and r["netbox_object_id"] == 42
    assert r["api_method"] == "POST"


def test_write_auth_aborts(writes_on):
    adapter, _ = _adapter_with_endpoint(create_side_effect=_StatusError(403))
    with pytest.raises(AuthAbortError):
        _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})


def test_write_4xx_no_retry(writes_on):
    adapter, endpoint = _adapter_with_endpoint(create_side_effect=_StatusError(422))
    r = _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})
    assert r["api_response_status"] == 422 and "client error" in r["reason_append"]
    assert endpoint.create.call_count == 1        # no retry on 4xx


def test_write_5xx_retries_once(writes_on, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    adapter, endpoint = _adapter_with_endpoint(create_side_effect=_StatusError(503))
    r = _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})
    assert endpoint.create.call_count == 2        # retried exactly once
    assert r["api_response_status"] == 503 and "retried once" in r["reason_append"]


def test_write_400_already_exists_auto_resolves(writes_on):
    adapter, endpoint = _adapter_with_endpoint(
        create_side_effect=_StatusError(400, "device with this name already exists"))
    existing = MagicMock(id=7)
    existing.serialize.return_value = {"id": 7, "name": "acc-sw-01"}
    endpoint.get.return_value = existing
    r = _write_to_netbox(adapter, "device", {"name": "acc-sw-01"})
    assert r["api_response_status"] == 200 and r["netbox_object_id"] == 7
    assert "auto-resolved" in r["reason_append"]


# ── approve: audit on every outcome + pending lifecycle ──────────────────────

def _pending(cid="cand-1", object_type="device", name="acc-sw-01"):
    return {
        "id": cid, "source": "bootstrap", "netbox_object_type": object_type,
        "payload_json": json.dumps({"name": name}), "reason": "r",
        "priority": 50, "created_at": "2026-01-01T00:00:00Z",
    }


def test_approve_success_audits_and_deletes(writes_on, monkeypatch):
    monkeypatch.setattr(staging, "_read_pending", lambda cid: _pending(cid))
    audits, deletes = [], []
    monkeypatch.setattr(staging, "_create_audit_row",
                        lambda p, wr, source_override=None: audits.append(wr) or "a1")
    monkeypatch.setattr(staging, "_atomic_delete_pending", lambda cid: deletes.append(cid) or True)
    adapter, _ = _adapter_with_endpoint()
    out = approve("cand-1", adapter=adapter)
    assert out["outcome"] == "success" and deletes == ["cand-1"]
    assert audits[0]["api_response_status"] == 201   # audit row on success


def test_approve_failure_audits_and_keeps_pending(writes_on, monkeypatch):
    monkeypatch.setattr(staging, "_read_pending", lambda cid: _pending(cid))
    audits, deletes = [], []
    monkeypatch.setattr(staging, "_create_audit_row",
                        lambda p, wr, source_override=None: audits.append(wr) or "a1")
    monkeypatch.setattr(staging, "_atomic_delete_pending", lambda cid: deletes.append(cid) or True)
    adapter, _ = _adapter_with_endpoint(create_side_effect=_StatusError(422))
    out = approve("cand-1", adapter=adapter)
    assert out["outcome"] == "failed"
    assert audits and audits[0]["api_response_status"] == 422  # failure audited
    assert deletes == []                                       # pending preserved


def test_approve_missing_candidate_returns_none(monkeypatch):
    monkeypatch.setattr(staging, "_read_pending", lambda cid: None)
    assert approve("ghost", adapter=MagicMock()) is None


# ── bulk: topological order + auth abort ────────────────────────────────────

def test_approve_bulk_topological_order_and_summary(writes_on, monkeypatch):
    # site must be written before device regardless of listing order.
    pendings = {
        "c-dev": _pending("c-dev", "device", "acc-sw-01"),
        "c-site": _pending("c-site", "site", "demo") | {
            "payload_json": json.dumps({"slug": "demo", "name": "demo"})},
    }
    monkeypatch.setattr(staging, "_read_pending", lambda cid: pendings.get(cid))
    order = []
    monkeypatch.setattr(staging, "approve",
                        lambda cid, adapter=None: order.append(cid) or
                        {"outcome": "success", "audit_id": "a", "api_response_status": 201,
                         "netbox_object_id": 1})
    out = approve_bulk(ids=["c-dev", "c-site"], adapter=MagicMock())
    assert order == ["c-site", "c-dev"]           # topological: site first
    assert out["written"] == 2 and out["aborted"] is False


def test_approve_bulk_auth_abort_stops(writes_on, monkeypatch):
    pendings = {f"c{i}": _pending(f"c{i}") for i in range(3)}
    monkeypatch.setattr(staging, "_read_pending", lambda cid: pendings.get(cid))
    calls = []
    def fake_approve(cid, adapter=None):
        calls.append(cid)
        raise AuthAbortError("HTTP 403")
    monkeypatch.setattr(staging, "approve", fake_approve)
    out = approve_bulk(ids=["c0", "c1", "c2"], adapter=MagicMock())
    assert len(calls) == 1                        # stopped at the first auth failure
    assert out["aborted"] is True and out["abort_reason"].startswith("auth")
