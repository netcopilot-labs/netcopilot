"""F2-6-a: load_model() against a real Neo4j — the second test tier.

Gated by NETCOPILOT_LIVE_TESTS=1 (same as test_live_tools) so it never runs by
accident or touches a Neo4j you didn't dedicate to testing. CI sets the flag +
a Neo4j service; locally it skips unless you opt in. Verifies the real Cypher
executes: nodes are created, interfaces link to their devices, and reload is
idempotent.
"""

import json
import os
import time

import pytest

from netcopilot.graph import client, schema
from netcopilot.graph.loader import load_model

from test_graph_load_model import MODEL  # synthetic network model (RFC 5737 IPs)

SITE = "loadtest"
RUN_ID = "loadmodel-0001"


@pytest.fixture(scope="module", autouse=True)
def _neo4j():
    if os.environ.get("NETCOPILOT_LIVE_TESTS") != "1":
        pytest.skip("set NETCOPILOT_LIVE_TESTS=1 (+ NEO4J_* to a dedicated test instance)")
    for _ in range(60):
        client.reset()
        if client.is_available():
            break
        time.sleep(2)
    else:
        pytest.skip("Neo4j not reachable")
    schema.ensure_indexes(client.get_driver())
    yield
    # clean our test data, leave the instance otherwise untouched
    with client.get_driver().session() as s:
        s.run("MATCH (n {site: $site, run_id: $run_id}) DETACH DELETE n", site=SITE, run_id=RUN_ID)
    client.close()


def _load(tmp_path):
    md = tmp_path / "run" / "model"
    md.mkdir(parents=True, exist_ok=True)  # _load may be called twice (idempotent-reload test)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    return load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)


def _count(cypher: str) -> int:
    with client.get_driver().session() as s:
        return s.run(cypher, site=SITE, run_id=RUN_ID).single()[0]


def test_load_model_materialises_graph(tmp_path):
    counts = _load(tmp_path)
    assert counts["devices"] == 2 and counts["interfaces"] == 2

    assert _count("MATCH (d:Device {site:$site, run_id:$run_id}) RETURN count(d)") == 2
    assert _count("MATCH (i:Interface {site:$site, run_id:$run_id}) RETURN count(i)") == 2
    # interfaces link to their parent device (the device_id == hostname invariant)
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id})-[r:HAS_INTERFACE]->(:Interface) RETURN count(r)"
    ) == 2
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id})-[r:PHYSICAL_CABLE]->(:Device) RETURN count(r)"
    ) == 1
    assert _count(
        "MATCH (:Interface {site:$site, run_id:$run_id})-[r:CONNECTS_TO]->(:Interface) RETURN count(r)"
    ) == 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id})-[r:ROUTING_ADJACENCY]->(:Device) RETURN count(r)"
    ) == 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id})-[r:MEMBER_OF]->(:SharedService) RETURN count(r)"
    ) == 2


def test_load_model_reload_is_idempotent(tmp_path):
    _load(tmp_path)
    _load(tmp_path)  # second load deletes the first
    assert _count("MATCH (d:Device {site:$site, run_id:$run_id}) RETURN count(d)") == 2
    assert _count("MATCH (r:Run {site:$site, run_id:$run_id}) RETURN count(r)") == 1


def test_load_routes_creates_route_nodes(tmp_path):
    # model + a genie_routing.json facts file → Route nodes via HAS_ROUTE.
    # Also confirms _classify_bgp_sessions / _enrich_bgp_decision_attributes
    # execute against real Neo4j without error (no eBGP here → they no-op).
    md = tmp_path / "run" / "model"
    md.mkdir(parents=True, exist_ok=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    facts = tmp_path / "run" / "facts" / "core-rtr-01"
    facts.mkdir(parents=True, exist_ok=True)
    (facts / "genie_routing.json").write_text(json.dumps(
        {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
            "192.0.2.0/24": {"source_protocol": "ospf", "route_preference": 110,
                             "next_hop": {"next_hop_list": {"1": {"next_hop": "198.51.100.254"}}}}}}}}}}))

    from netcopilot.graph.loader import load_model
    counts = load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    assert counts["routes"] >= 1
    assert _count("MATCH (r:Route {site:$site, run_id:$run_id}) RETURN count(r)") >= 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id, name:'core-rtr-01'})-[h:HAS_ROUTE]->(:Route) RETURN count(h)"
    ) >= 1


def test_load_firewall_and_arp(tmp_path):
    md = tmp_path / "run" / "model"
    md.mkdir(parents=True, exist_ok=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    facts = tmp_path / "run" / "facts" / "core-rtr-01"
    facts.mkdir(parents=True, exist_ok=True)
    (facts / "genie_arp.json").write_text(json.dumps(
        {"interfaces": {"GigabitEthernet0/1": {"ipv4": {"neighbors": {
            "192.0.2.5": {"link_layer_address": "aabb.ccdd.eeff", "origin": "dynamic"}}}}}}))
    (facts / "genie_acl.json").write_text(json.dumps({"acls": {"BLOCK-IN": {
        "type": "ipv4-acl-type", "aces": {"10": {"actions": {"forwarding": "deny"},
            "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.0/24": {}}}}}}}}}}))

    from netcopilot.graph.loader import load_model
    counts = load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    assert counts["arp_entries"] >= 1 and counts["firewall_policies"] >= 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id, name:'core-rtr-01'})-[h:HAS_ARP]->(:ArpEntry) RETURN count(h)"
    ) >= 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id, name:'core-rtr-01'})-[h:HAS_POLICY]->(:FirewallPolicy) RETURN count(h)"
    ) >= 1


def test_full_pipeline_collected_run_to_neo4j(tmp_path):
    # the whole F2-7 chain over a synthetic collected run: parse → model → load.
    from test_pipeline import _build_collected_run
    from netcopilot.pipeline import process_run

    _build_collected_run(tmp_path, run_id=RUN_ID)
    result = process_run(RUN_ID, site=SITE, runs_dir=tmp_path, load=True, driver=client.get_driver())
    assert result["load"]["devices"] == 2
    assert _count("MATCH (d:Device {site:$site, run_id:$run_id}) RETURN count(d)") == 2
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id})-[r:PHYSICAL_CABLE]->(:Device) RETURN count(r)"
    ) == 1


def test_rules_findings_loaded_into_neo4j(tmp_path):
    # the full F3 -> F2-6 loop: model + facts -> run_rules -> findings.json ->
    # load_model -> Finding nodes linked to their Device via HAS_FINDING.
    from netcopilot.rules.engine import run_rules
    from netcopilot.rules.findings_writer import write_findings
    from netcopilot.graph.loader import load_model

    run = tmp_path / "run"
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps(MODEL))  # has core-rtr-01
    (run / "manifest.json").write_text(json.dumps({"run_id": "r1", "devices": []}))
    facts = run / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_ntp.json").write_text(json.dumps(            # NTP_OFFSET_EXCESSIVE fires (>500ms)
        {"clock_state": {"system_status": {"clock_offset": 750.0}}}))

    result = run_rules("run", runs_base=str(tmp_path))
    assert result["metadata"]["total_findings"] >= 1
    write_findings(result, "run", runs_base=str(tmp_path))

    load_model(client.get_driver(), run, site=SITE, run_id=RUN_ID)
    assert _count("MATCH (f:Finding {site:$site, run_id:$run_id}) RETURN count(f)") >= 1
    assert _count(
        "MATCH (:Device {site:$site, run_id:$run_id, name:'core-rtr-01'})-[h:HAS_FINDING]->(:Finding) RETURN count(h)"
    ) >= 1


def test_findings_and_analyze_endpoints_live(tmp_path, monkeypatch):
    # F4c: /api/findings/{run_id} + /api/analyze/{run_id}/{rule_id} on a real run.
    from fastapi.testclient import TestClient

    from netcopilot.dashboard.backend import data_loader
    from netcopilot.dashboard.backend.main import app
    from netcopilot.rules.engine import run_rules
    from netcopilot.rules.findings_writer import write_findings

    run = tmp_path / RUN_ID          # run dir named by run_id (data_loader contract)
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps(MODEL))
    (run / "manifest.json").write_text(json.dumps({"run_id": RUN_ID, "devices": []}))
    facts = run / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_ntp.json").write_text(json.dumps(
        {"clock_state": {"system_status": {"clock_offset": 750.0}}}))

    result = run_rules(RUN_ID, runs_base=str(tmp_path))
    write_findings(result, RUN_ID, runs_base=str(tmp_path))
    load_model(client.get_driver(), run, site=SITE, run_id=RUN_ID)
    monkeypatch.setattr(data_loader, "RUNS_DIR", tmp_path)  # run_exists() finds the run dir

    tc = TestClient(app)
    rid = result["findings"][0]["rule_id"]

    fr = tc.get(f"/api/findings/{RUN_ID}")
    assert fr.status_code == 200 and fr.json()["findings"]

    ar = tc.get(f"/api/analyze/{RUN_ID}/{rid}")
    assert ar.status_code == 200


def test_device_endpoint_live(tmp_path):
    # F4c: the dashboard /api/device/{hostname} route returns device detail.
    from fastapi.testclient import TestClient

    from netcopilot.dashboard.backend.main import app

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)

    r = TestClient(app).get(f"/api/device/core-rtr-01?run_id={RUN_ID}")
    assert r.status_code == 200
    assert "core-rtr-01" in str(r.json())


def test_generate_report_tool_live(tmp_path):
    # F4e: the generate_report MCP tool builds a general report from Neo4j.
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE, "data_dir": str(tmp_path / "run")}

    out = asyncio.run(registry.dispatch("generate_report", {"scope": "general"}, ctx))
    assert out and "report" in out.lower()


def test_topology_endpoint_live(tmp_path):
    # F4c: the dashboard /api/topology route returns a Cytoscape graph for the run.
    from fastapi.testclient import TestClient

    from netcopilot.dashboard.backend.main import app

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)

    r = TestClient(app).get(f"/api/topology?run_id={RUN_ID}&view=physical")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"]
    assert any("core-rtr-01" in str(n) for n in body["nodes"])


def test_mgmt_view_does_not_rescue_data_cables_live(tmp_path):
    # A network with no MGMT_LINK edges (MODEL has only a PHYSICAL_CABLE): the
    # mgmt view must NOT fall back to data cables via the anti-orphan rescue, so it
    # honestly shows the devices unconnected rather than a fabricated backbone.
    # The same model in the physical view DOES show the cable.
    from fastapi.testclient import TestClient

    from netcopilot.dashboard.backend.main import app

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)

    tc = TestClient(app)
    phys = tc.get(f"/api/topology?run_id={RUN_ID}&view=physical").json()
    mgmt = tc.get(f"/api/topology?run_id={RUN_ID}&view=mgmt").json()

    assert len(phys["edges"]) == 1          # physical cable IS shown
    assert len(mgmt["edges"]) == 0          # NOT rescued into the mgmt view
    # both devices still render as (unconnected) nodes in the mgmt view
    assert {n["data"]["id"] for n in mgmt["nodes"]} == {"core-rtr-01", "dist-sw-01"}


def test_runs_endpoint_live(tmp_path):
    # F4c-1: the dashboard /api/runs route returns the loaded Run node.
    from fastapi.testclient import TestClient

    from netcopilot.dashboard.backend.main import app

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)

    r = TestClient(app).get("/api/runs")
    assert r.status_code == 200
    assert RUN_ID in [x["run_id"] for x in r.json()["runs"]]


def test_explain_and_analyze_tools_live(tmp_path):
    # F4b: explain_finding / analyze_findings end-to-end — run_rules -> findings.json
    # -> load_model -> Neo4j Finding, then the rule tools read catalog + remediation.
    import asyncio

    from netcopilot.mcp import registry
    from netcopilot.rules.engine import run_rules
    from netcopilot.rules.findings_writer import write_findings

    run = tmp_path / "run"
    (run / "model").mkdir(parents=True)
    (run / "model" / "network_model.json").write_text(json.dumps(MODEL))  # has core-rtr-01
    (run / "manifest.json").write_text(json.dumps({"run_id": "r1", "devices": []}))
    facts = run / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_ntp.json").write_text(json.dumps(
        {"clock_state": {"system_status": {"clock_offset": 750.0}}}))  # NTP offset rule fires

    result = run_rules("run", runs_base=str(tmp_path))
    assert result["findings"], "expected at least one finding to fire"
    write_findings(result, "run", runs_base=str(tmp_path))
    load_model(client.get_driver(), run, site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE}

    rid = result["findings"][0]["rule_id"]
    explain = asyncio.run(registry.dispatch("explain_finding", {"rule_id": rid}, ctx))
    assert f"Rule: {rid}" in explain

    analyze = asyncio.run(registry.dispatch("analyze_findings", {"rule_id": rid}, ctx))
    assert "SUMMARY" in analyze and rid in analyze


def test_systemic_patterns_tool_live(tmp_path):
    # F4b: get_systemic_patterns — the correlation engine's 4 Cypher queries execute
    # against a real run (no findings in this minimal MODEL → no insights, but the
    # engine + queries must run without error).
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE}

    out = asyncio.run(registry.dispatch("get_systemic_patterns", {}, ctx))
    assert "correlation insights" in out.lower()


def test_redundancy_tool_live(tmp_path):
    # F4b: get_redundancy_assessment against a real loaded run.
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE}

    out = asyncio.run(registry.dispatch("get_redundancy_assessment", {}, ctx))
    assert "Redundancy assessment — Network overview" in out
    assert "Summary:" in out


def test_trace_path_tool_live(tmp_path):
    # F4b: trace_path. _load_routes derives run_id from Path(data_dir).name, so the
    # run dir is named by RUN_ID (the context contract the dashboard/CLI must honor).
    import asyncio

    from netcopilot.mcp import registry

    run = tmp_path / RUN_ID
    md = run / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    facts = run / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_routing.json").write_text(json.dumps(
        {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
            "0.0.0.0/0": {"source_protocol": "static", "route_preference": 1,
                          "next_hop": {"next_hop_list": {"1": {"next_hop": "198.51.100.254"}}}}}}}}}}))

    load_model(client.get_driver(), run, site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE, "data_dir": str(run)}

    trace = asyncio.run(registry.dispatch("trace_path", {"source_device": "core-rtr-01"}, ctx))
    assert "Path: core-rtr-01" in trace

    miss = asyncio.run(registry.dispatch("trace_path", {"source_device": "nope-99"}, ctx))
    assert "not found" in miss


def test_security_tools_live(tmp_path):
    # F4b: get_security_posture (SecurityConfig) / get_security_policies (ACL + prefix-set).
    import asyncio

    from netcopilot.mcp import registry

    run = tmp_path / "run"
    md = run / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    f = run / "facts" / "core-rtr-01"
    f.mkdir(parents=True)
    (f / "security_config.json").write_text(json.dumps(
        {"config_source": "cisco", "ssh": {"version": 2, "timeout": 60}}))
    (f / "genie_acl.json").write_text(json.dumps({"acls": {"BLOCK-IN": {
        "type": "ipv4-acl-type", "aces": {"10": {"actions": {"forwarding": "deny"},
            "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.0/24": {}}}}}}}}}}))
    (f / "parsed_prefix_list.json").write_text(json.dumps(
        {"LOCAL": {"entries": [{"seq": 10, "action": "permit", "prefix": "192.0.2.0/24"}]}}))

    load_model(client.get_driver(), run, site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE, "data_dir": str(run)}

    posture = asyncio.run(registry.dispatch("get_security_posture", {"device": "core-rtr-01"}, ctx))
    assert "Security posture — core-rtr-01" in posture

    policies = asyncio.run(registry.dispatch("get_security_policies", {"device": "core-rtr-01"}, ctx))
    assert "Security policies — core-rtr-01" in policies

    overview = asyncio.run(registry.dispatch("get_security_posture", {}, ctx))
    assert "Network overview" in overview


def test_firewall_and_qos_tools_live(tmp_path):
    # F4b: get_firewall_policies (real ACL) / get_traffic_shapers (graceful no-data).
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    facts = tmp_path / "run" / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_acl.json").write_text(json.dumps({"acls": {"BLOCK-IN": {
        "type": "ipv4-acl-type", "aces": {"10": {"actions": {"forwarding": "deny"},
            "matches": {"l3": {"ipv4": {"source_ipv4_network": {"192.0.2.0/24": {}}}}}}}}}}))

    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE}

    fw = asyncio.run(registry.dispatch("get_firewall_policies", {"device": "core-rtr-01"}, ctx))
    assert "Firewall policies on core-rtr-01" in fw

    # No QoS facts in this run → graceful no-data, but the Cypher must execute.
    qos = asyncio.run(registry.dispatch("get_traffic_shapers", {}, ctx))
    assert "No QoS policies" in qos


def test_neighborhood_and_site_summary_tools_live(tmp_path):
    # F4b: get_network_neighborhood / get_site_summary against a real loaded run.
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE}

    nbr = asyncio.run(registry.dispatch("get_network_neighborhood", {"device": "core-rtr-01"}, ctx))
    assert "Network neighborhood — core-rtr-01" in nbr and "Direct neighbors" in nbr

    summary = asyncio.run(registry.dispatch("get_site_summary", {}, ctx))
    assert "core-rtr-01" in summary

    miss = asyncio.run(registry.dispatch("get_network_neighborhood", {"device": "nope-99"}, ctx))
    assert "not found" in miss


def test_device_and_shared_services_tools_live(tmp_path):
    # F4b: get_device_detail / get_shared_services against a real loaded run.
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE, "data_dir": str(tmp_path / "run")}

    detail = asyncio.run(registry.dispatch("get_device_detail", {"device": "core-rtr-01"}, ctx))
    assert "Device: core-rtr-01" in detail and "Interfaces" in detail

    svc = asyncio.run(registry.dispatch("get_shared_services", {}, ctx))
    assert "Shared services overview" in svc

    miss = asyncio.run(registry.dispatch("get_device_detail", {"device": "nope-99"}, ctx))
    assert "not found" in miss


def test_routing_and_ospf_tools_live(tmp_path):
    # F4b: get_routing_table / get_ospf_detail against a real loaded run.
    import asyncio

    from netcopilot.mcp import registry

    md = tmp_path / "run" / "model"
    md.mkdir(parents=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    facts = tmp_path / "run" / "facts" / "core-rtr-01"
    facts.mkdir(parents=True)
    (facts / "genie_routing.json").write_text(json.dumps(
        {"vrf": {"default": {"address_family": {"ipv4 unicast": {"routes": {
            "192.0.2.0/24": {"source_protocol": "ospf", "route_preference": 110,
                             "next_hop": {"next_hop_list": {"1": {"next_hop": "198.51.100.254"}}}}}}}}}}))

    load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    ctx = {"run_id": RUN_ID, "site": SITE, "data_dir": str(tmp_path / "run")}

    routing = asyncio.run(registry.dispatch("get_routing_table", {"device": "core-rtr-01"}, ctx))
    assert "192.0.2.0/24" in routing and "core-rtr-01" in routing

    # OSPF overview: the Cypher executes against SharedService (no ospf_area in this
    # MODEL → graceful "No OSPF areas found", but the header always renders).
    ospf_out = asyncio.run(registry.dispatch("get_ospf_detail", {}, ctx))
    assert "OSPF Areas Overview" in ospf_out

    # Unknown device resolves to a clean message, not an error.
    miss = asyncio.run(registry.dispatch("get_routing_table", {"device": "nope-99"}, ctx))
    assert "not found" in miss


def test_load_route_policies_security_and_vrfs(tmp_path):
    md = tmp_path / "run" / "model"
    md.mkdir(parents=True, exist_ok=True)
    (md / "network_model.json").write_text(json.dumps(MODEL))
    f = tmp_path / "run" / "facts" / "core-rtr-01"
    f.mkdir(parents=True, exist_ok=True)
    (f / "parsed_route_policy.json").write_text(json.dumps(
        {"SET-LP": {"sequences": [{"seq": 10, "action": "permit", "match": [], "set": ["local-preference 150"]}]}}))
    (f / "parsed_prefix_list.json").write_text(json.dumps(
        {"LOCAL": {"entries": [{"seq": 10, "action": "permit", "prefix": "192.0.2.0/24"}]}}))
    (f / "security_config.json").write_text(json.dumps({"ssh": {"version": 2, "timeout": 60}}))
    (f / "genie_vrf.json").write_text(json.dumps({"vrfs": {"MGMT": {}}}))
    (f / "genie_routing.json").write_text(json.dumps({"vrf": {}}))  # → 'default' vrf

    from netcopilot.graph.loader import load_model
    counts = load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=RUN_ID)
    assert counts["route_policies"] >= 1 and counts["prefix_set_entries"] >= 1
    assert counts["security_configs"] >= 1 and counts["vrfs"] >= 2  # MGMT + default
    assert _count("MATCH (rp:RoutePolicy {site:$site, run_id:$run_id}) RETURN count(rp)") >= 1
    assert _count("MATCH (p:PrefixSetEntry {site:$site, run_id:$run_id}) RETURN count(p)") >= 1
    assert _count("MATCH (s:SecurityConfig {site:$site, run_id:$run_id}) RETURN count(s)") >= 1
    assert _count(
        "MATCH (sv:SharedService {site:$site, run_id:$run_id, service_type:'vrf'}) RETURN count(sv)"
    ) >= 2


def test_member_of_disambiguates_ospf_area_by_vrf(tmp_path):
    """R1 Phase 2: the same OSPF area number in two VRFs must NOT cross-link
    members. The MEMBER_OF MATCH disambiguates by (vrf, process_id); before the
    fix, area 0.0.0.0 in RED and BLUE shared an identifier so every member
    matched both area nodes (inflated, wrong membership)."""
    import copy

    model = copy.deepcopy(MODEL)
    # Two ospf_area nodes, same identifier, different VRF/process. dist-sw-01 is
    # only in RED, so it must never link to the BLUE node.
    model["shared_services"] = [
        {"service_type": "ospf_area", "identifier": "0.0.0.0", "vrf": "RED",
         "process_id": "10", "area_type": "normal",
         "members": ["core-rtr-01", "dist-sw-01"]},
        {"service_type": "ospf_area", "identifier": "0.0.0.0", "vrf": "BLUE",
         "process_id": "20", "area_type": "normal", "members": ["core-rtr-01"]},
    ]
    model["ospf_lsdb"] = []  # no LSAs against the synthetic areas

    run_id = "memberof-vrf-0001"
    md = tmp_path / "run" / "model"
    md.mkdir(parents=True, exist_ok=True)
    (md / "network_model.json").write_text(json.dumps(model))

    def c(cypher: str) -> int:
        with client.get_driver().session() as s:
            return s.run(cypher, site=SITE, run_id=run_id).single()[0]

    try:
        load_model(client.get_driver(), tmp_path / "run", site=SITE, run_id=run_id)
        # 3 total: (core-rtr-01→RED), (dist-sw-01→RED), (core-rtr-01→BLUE).
        # Pre-fix this was 6 (every member matched both same-identifier nodes).
        assert c(
            "MATCH (:Device {site:$site,run_id:$run_id})-[r:MEMBER_OF]->"
            "(:SharedService {service_type:'ospf_area'}) RETURN count(r)"
        ) == 3
        assert c(
            "MATCH (:Device {name:'core-rtr-01',site:$site,run_id:$run_id})-[:MEMBER_OF]->"
            "(s:SharedService {service_type:'ospf_area',vrf:'RED'}) RETURN count(s)"
        ) == 1
        assert c(
            "MATCH (:Device {name:'core-rtr-01',site:$site,run_id:$run_id})-[:MEMBER_OF]->"
            "(s:SharedService {service_type:'ospf_area',vrf:'BLUE'}) RETURN count(s)"
        ) == 1
        # dist-sw-01 is NOT in BLUE — the contamination case.
        assert c(
            "MATCH (:Device {name:'dist-sw-01',site:$site,run_id:$run_id})-[:MEMBER_OF]->"
            "(s:SharedService {service_type:'ospf_area',vrf:'BLUE'}) RETURN count(s)"
        ) == 0
    finally:
        with client.get_driver().session() as s:
            s.run("MATCH (n {site:$site, run_id:$run_id}) DETACH DELETE n",
                  site=SITE, run_id=run_id)
