"""s03-3: envelope fields — verbatim / highlight / verdict on the tools that
already compute those semantics. Fake drivers + monkeypatched internals; no
Neo4j, no LLM, no ChromaDB.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types

from netcopilot.mcp.tools import (
    analysis,
    device as device_tool,
    onboarding,
    path_tracer,
    rag,
    redundancy,
    report as report_tool,
    run_diff,
)


# ── shared fake Neo4j driver (scripted responses, in call order) ─────────────

class _FakeResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def single(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, script):
        self._script = script

    def run(self, *a, **k):
        return _FakeResult(self._script.pop(0))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, script):
        self._script = script

    def session(self):
        return _FakeSession(self._script)


# ── verbatim (onboarding) ────────────────────────────────────────────────────

def test_onboarding_tools_are_verbatim():
    for handler in (onboarding.about_netcopilot, onboarding.dashboard_guide,
                    onboarding.list_capabilities):
        res = asyncio.run(handler(context={}))
        assert res.verbatim is True and res.status == "ok" and res.text


# ── verdict (RAG low-coverage) ───────────────────────────────────────────────

def _rag_result(vec):
    return {"toc_section": "s", "source_file": "f.pdf", "page": 1,
            "os_family": "iosxe", "score": 0.9, "vector_score": vec,
            "text": "chunk"}


def test_rag_verdict_flags_low_coverage(monkeypatch):
    monkeypatch.setattr(rag.store, "search", lambda **kw: [_rag_result(0.40)])
    res = asyncio.run(rag.lookup_vendor_docs(query="obscure thing", context={}))
    assert res.verdict == {"low_coverage": True, "top_similarity": 0.40}
    assert "LOW COVERAGE" in res.text


def test_rag_verdict_high_coverage(monkeypatch):
    monkeypatch.setattr(rag.store, "search", lambda **kw: [_rag_result(0.85)])
    res = asyncio.run(rag.lookup_network_knowledge(query="vrrp", context={}))
    assert res.verdict == {"low_coverage": False, "top_similarity": 0.85}
    assert "LOW COVERAGE" not in res.text


# ── verdict (diff_runs) ──────────────────────────────────────────────────────

def _write_run(runs_dir, run_id, *, devices=None):
    run_dir = runs_dir / run_id
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    devs = devices if devices is not None else [{"device_id": "core-sw-01", "site": "demo"}]
    model = {"devices": devs, "interfaces": [], "links": [], "adjacencies": [],
             "shared_services": [], "l2_domains": [], "ospf_lsdb": []}
    (run_dir / "model" / "network_model.json").write_text(json.dumps(model))
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": []}))


def test_diff_runs_verdict_counts(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    _write_run(tmp_path, "runB", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                          {"device_id": "acc-sw-09", "site": "demo"}])
    res = asyncio.run(run_diff.diff_runs(run_a="runA", run_b="runB",
                                         context={"run_id": "", "site": "demo"}))
    assert res.verdict["drift"] is True and res.verdict["added"] == 1
    assert "Drift runA → runB" in res.text


def test_diff_runs_verdict_no_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    _write_run(tmp_path, "runA")
    _write_run(tmp_path, "runB")
    res = asyncio.run(run_diff.diff_runs(run_a="runA", run_b="runB",
                                         context={"run_id": "", "site": "demo"}))
    assert res.verdict["drift"] is False
    assert "No drift" in res.text


# ── highlight (generate_report) ──────────────────────────────────────────────

def test_report_highlight_field_carries_report_ready(monkeypatch):
    fake_report = types.SimpleNamespace(to_dict=lambda: {
        "report_id": "rpt-1", "site": "demo", "generated_at": "now",
        "prose_summary": "all good", "health": {}, "delta": {},
        "top_criticals": [], "cross_device_count": 0,
    })
    fake_mod = types.SimpleNamespace(build_general_report=lambda run_id: fake_report)
    monkeypatch.setitem(sys.modules,
                        "netcopilot.dashboard.backend.reports.generator", fake_mod)
    res = asyncio.run(report_tool.generate_report(scope="general",
                                                  context={"run_id": "r1"}))
    assert res.highlight["type"] == "report_ready"
    assert res.highlight["report_id"] == "rpt-1"
    assert "General Report" in res.text


# ── verdict + highlight (blast_radius) ───────────────────────────────────────

def test_blast_radius_verdict_and_highlight(monkeypatch):
    monkeypatch.setattr(analysis, "is_available", lambda: True)
    monkeypatch.setattr(analysis, "get_driver", lambda: _FakeDriver([
        [{"name": "core-x"}],   # exact-name lookup
        [],                     # neighbor links
        [{"n": 0}],             # s16: Service row count (layer not joined)
        [],                     # s16: services on device + neighbours
        [],                     # s20: FHRP groups the device is a member of
    ]))
    monkeypatch.setattr(analysis, "_blast_radius", lambda run_id: [
        {"device": "core-x", "risk_score": 60, "finding_count": 2,
         "severity_breakdown": {}, "recommendation": ""},
    ])
    res = asyncio.run(analysis.blast_radius(device="core-x", member=1,
                                            context={"run_id": "r"}))
    # S08-2: verdict + highlight carry the affected-neighbour / internet
    # impact; s16 adds the service dimension (layer not joined here → honest
    # "unknown, not zero" note + joined=False); s20 adds FHRP gateway impact.
    assert res.verdict == {"risk_level": "HIGH", "score": 60,
                           "affected_neighbors": 0, "internet_impact": 0,
                           "services_lost": 0, "services_at_risk": 0,
                           "service_layer_joined": False,
                           "fhrp_gateways_protected": 0, "fhrp_gateways_lost": 0}
    assert res.highlight == {"device": "core-x", "affected": [], "failedMember": 1}
    assert "Blast radius — core-x" in res.text
    assert "unknown, not zero" in res.text        # absent layer ≠ no services


def test_blast_radius_discloses_scope_semantics(monkeypatch):
    # S08-2 → s16: interface= now scopes the SERVICE attribution (real), but
    # the link analysis still models a full device failure — both said aloud;
    # max_hops remains unmodelled and disclosed.
    monkeypatch.setattr(analysis, "is_available", lambda: True)
    monkeypatch.setattr(analysis, "get_driver", lambda: _FakeDriver([
        [{"name": "core-x"}], [], [{"n": 0}], [], []]))
    monkeypatch.setattr(analysis, "_blast_radius", lambda run_id: [])
    res = asyncio.run(analysis.blast_radius(device="core-x", interface="Gi0/1",
                                            max_hops=5, context={"run_id": "r"}))
    assert "interface=Gi0/1 scopes the service list only" in res.text
    assert "max_hops=5 not applied" in res.text


def test_blast_radius_enumerates_services(monkeypatch):
    # s16: services on the failed device are LOST; services on affected
    # neighbours are at risk; port-precise ones survive interface scoping.
    monkeypatch.setattr(analysis, "is_available", lambda: True)
    svc_rows = [
        {"name": "cam-lobby-01", "ip": "198.51.100.26", "method": "arp+fdb",
         "device": "core-x", "port": "Gi1/0/5"},
        {"name": "printer-f2", "ip": "198.51.100.60", "method": "subnet",
         "device": "acc-y", "port": None},
    ]
    monkeypatch.setattr(analysis, "get_driver", lambda: _FakeDriver([
        [{"name": "core-x"}],
        [{"neighbor": "acc-y", "role": "access_switch", "link_type": "PHYSICAL_CABLE",
          "bgp_type": None, "local_as": None, "remote_as": None}],
        [{"n": 3}],
        svc_rows,
        [],                     # s20: FHRP groups the device is a member of
    ]))
    monkeypatch.setattr(analysis, "_blast_radius", lambda run_id: [])
    res = asyncio.run(analysis.blast_radius(device="core-x", context={"run_id": "r"}))
    assert "LOST with core-x" in res.text and "cam-lobby-01" in res.text
    assert "At risk on affected neighbours" in res.text and "printer-f2" in res.text
    assert res.verdict["services_lost"] == 1
    assert res.verdict["services_at_risk"] == 1
    assert res.verdict["service_layer_joined"] is True


# ── highlight (get_device_detail canonical name) ─────────────────────────────

def test_device_detail_highlight_canonical_name(monkeypatch):
    record = {
        "name": "acc-sw-03", "role": "access", "platform": "C9300",
        "os_type": "iosxe", "os_version": "17.9", "site": "demo",
        "cluster_size": None, "cluster_declared": None, "cluster_members": None,
        "serial": None, "is_route_reflector": None, "rr_cluster_id": None,
        "collected": True,
    }
    monkeypatch.setattr(device_tool, "is_available", lambda: True)
    monkeypatch.setattr(device_tool, "get_driver", lambda: _FakeDriver([[record]]))
    monkeypatch.setattr(device_tool, "load_findings_enriched", lambda run_id: [])
    res = asyncio.run(device_tool.get_device_detail(
        device="acc-sw-03", sections=["findings"],
        context={"run_id": "r1", "data_dir": None}))
    assert res.highlight == {"device": "acc-sw-03"}
    assert "Device: acc-sw-03" in res.text


# ── highlight (trace_path hop devices) ───────────────────────────────────────

def test_trace_path_highlight_hop_devices(monkeypatch):
    monkeypatch.setattr(path_tracer, "_shared_resolve", lambda name, run_id: "core-x")
    monkeypatch.setattr(path_tracer, "_build_ip_to_device", lambda run_id: {})
    monkeypatch.setattr(path_tracer, "_get_bgp_exit", lambda device, run_id: None)
    monkeypatch.setattr(path_tracer, "get_device_role", lambda device, run_id: "core")
    monkeypatch.setattr(path_tracer, "is_security_device", lambda device, run_id: False)
    monkeypatch.setattr(path_tracer, "_load_routes", lambda device, data_dir: {
        "default": [{"prefix": "0.0.0.0/0", "vrf": "default", "protocol": "static",
                     "next_hop": "203.0.113.1", "interface": "", "ad": 1,
                     "metric": 0, "active": True, "source": "static", "note": ""}],
    })
    res = asyncio.run(path_tracer.trace_path(source_device="core-x",
                                             context={"run_id": "r", "data_dir": "d"}))
    assert res.highlight == {"devices": ["core-x"]}
    assert "Hop 1: core-x" in res.text


# ── verdict (redundancy assessment, network mode) ────────────────────────────

def test_redundancy_network_verdict(monkeypatch):
    devices = [
        {"name": "core-x", "role": "core_switch", "cluster_size": 2,
         "building": "HQ", "collected": True, "os_type": "iosxe"},
        {"name": "acc-1", "role": "access_switch", "cluster_size": 1,
         "building": "HQ", "collected": True, "os_type": "iosxe"},
    ]
    neighbors = [
        {"dev": "acc-1", "neighbor": "core-x", "cables": 1},
        {"dev": "core-x", "neighbor": "acc-1", "cables": 1},
    ]
    monkeypatch.setattr(redundancy, "is_available", lambda: True)
    # 4th script entry feeds the FHRP gateway-redundancy query (no FHRP groups here);
    # the first 3 feed the device/neighbor/HA-affinity queries.
    monkeypatch.setattr(redundancy, "get_driver",
                        lambda: _FakeDriver([devices, neighbors, [], []]))
    res = asyncio.run(redundancy.get_redundancy_assessment(context={"run_id": "r"}))
    assert res.verdict == {"devices": 2, "ha_protected": 1, "spof_no_ha": 0,
                           "single_uplink": 1, "unreachable": 0,
                           "fhrp_groups": 0, "fhrp_unprotected": 0}
    assert "Redundancy assessment — Network overview" in res.text
