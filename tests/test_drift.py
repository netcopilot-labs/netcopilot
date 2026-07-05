"""S13-1: drift core — declared (adapter) vs observed (inventory + run facts).

The adapter is a fake (in-memory DeclaredStateSource with ping()); the run is
synthetic (RFC 5737 IPs, invented serials, demo site). No Neo4j — the persist
path is tested with patched graph functions.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from netcopilot.declared_state import drift
from netcopilot.declared_state.base import DeclaredStateSource


INVENTORY = """\
devices:
  - name: acc-sw-01
    mgmt_ip: 192.0.2.11
    os: ios-xe
    role: access_switch
    site: demo
  - name: core-st-01
    mgmt_ip: 192.0.2.21
    os: ios-xe
    role: core_switch
    site: demo
    cluster: {name: CORE_STACK, size: 2}
"""


def _write_run(tmp_path, run_id="demo-run"):
    """Standalone switch + 2-member stack, one interface each on obvious targets."""
    run = tmp_path / run_id
    for dev, serial, members in (
        ("acc-sw-01", "SYNTHSA01", []),
        ("core-st-01", None, [
            {"member_id": 1, "role": "active", "serial_number": "SYNTH0001",
             "platform": "C9500-32C", "priority": 15},
            {"member_id": 2, "role": "standby", "serial_number": "SYNTH0002",
             "platform": "C9500-32C", "priority": 14},
        ]),
    ):
        d = run / "facts" / dev
        d.mkdir(parents=True)
        (d / "device_facts.json").write_text(json.dumps({
            "device_info": {"platform": "C9500-32C" if members else "C9300-24T",
                            "serial": serial},
            "cluster_members": members,
        }))
        (d / "genie_interface.json").write_text(json.dumps({
            "GigabitEthernet1/0/1": {
                "enabled": True, "description": "uplink",
                "mtu": 1500, "phys_address": "1234.5678.9abc",
            },
        }))
    return run


class FakeAdapter(DeclaredStateSource):
    """In-memory declared source with a controllable ping."""

    def __init__(self, devices=None, interfaces=None, reachable=True):
        self.devices = devices or []
        self.interfaces = interfaces or {}
        self.reachable = reachable

    def ping(self):
        if not self.reachable:
            raise ConnectionError("declared source down")

    def get_devices(self):
        return list(self.devices)

    def get_device(self, hostname):
        return next((d for d in self.devices if d["name"] == hostname), None)

    def get_sites(self):
        return [{"slug": "demo", "name": "demo"}]

    def get_interfaces(self, device):
        return list(self.interfaces.get(device, []))


def _decl_device(name, *, site="demo", platform="Cisco IOS-XE", serial=None):
    return {"name": name, "site": site, "platform": platform, "serial": serial,
            "role": None, "status": "Active", "mgmt_ip": None, "netbox_id": 1}


def _decl_iface(name, *, enabled=True, description="uplink", mtu=1500,
                mac="12:34:56:78:9A:BC"):
    return {"name": name, "enabled": enabled, "description": description,
            "mtu": mtu, "mac_address": mac, "type": "1000BASE-T (1GE)",
            "netbox_id": 1}


def _synced_adapter():
    """Declared state that exactly matches _write_run's observed state."""
    return FakeAdapter(
        devices=[
            _decl_device("acc-sw-01", serial="SYNTHSA01"),
            _decl_device("core-st-01-1", serial="SYNTH0001"),
            _decl_device("core-st-01-2", serial="SYNTH0002"),
        ],
        interfaces={
            # Stack: interface Gi1/0/1 attributes to member position 1
            "acc-sw-01": [_decl_iface("GigabitEthernet1/0/1")],
            "core-st-01-1": [_decl_iface("GigabitEthernet1/0/1")],
        },
    )


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNS_DIR", str(tmp_path))
    inv = tmp_path / "lab.yaml"
    inv.write_text(INVENTORY)
    _write_run(tmp_path)
    return tmp_path


def _check(env, adapter, **kw):
    return drift.run_drift_check(
        "demo-run", env / "lab.yaml", adapter=adapter, load=False, **kw
    )


# ── Quiet baseline ───────────────────────────────────────────────────────────


def test_quiet_when_declared_matches_observed(env):
    report = _check(env, _synced_adapter())
    assert report.quiet, f"expected no drift, got: {report.counts_by_rule}"
    assert report.devices_checked == 3
    assert "No drift" in report.format_summary()


def test_mac_format_difference_is_not_drift(env):
    # NetBox colon-uppercase vs genie dotted-lowercase must normalise equal —
    # covered by the quiet baseline, asserted explicitly here.
    adapter = _synced_adapter()
    assert adapter.interfaces["acc-sw-01"][0]["mac_address"] == "12:34:56:78:9A:BC"
    report = _check(env, adapter)
    assert "INTENT_INTERFACE_ATTR_DRIFT" not in report.counts_by_rule


# ── Device-level rules ───────────────────────────────────────────────────────


def test_device_unknown_in_netbox(env):
    adapter = _synced_adapter()
    adapter.devices = [d for d in adapter.devices if d["name"] != "acc-sw-01"]
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_DEVICE_UNKNOWN_IN_NETBOX") == 1
    f = next(f for f in report.findings if f.rule_id == "INTENT_DEVICE_UNKNOWN_IN_NETBOX")
    assert f.evidence["element_id"] == "acc-sw-01"
    assert f.severity == "low"


def test_device_missing_in_network(env):
    adapter = _synced_adapter()
    adapter.devices.append(_decl_device("retired-sw-99"))
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_DEVICE_MISSING_IN_NETWORK") == 1
    f = next(f for f in report.findings if f.rule_id == "INTENT_DEVICE_MISSING_IN_NETWORK")
    assert f.severity == "high"


def test_missing_in_network_scoped_to_inventory_sites(env):
    # A declared device at ANOTHER site must not flood this run's drift.
    adapter = _synced_adapter()
    adapter.devices.append(_decl_device("other-site-sw", site="branch-two"))
    report = _check(env, adapter)
    assert "INTENT_DEVICE_MISSING_IN_NETWORK" not in report.counts_by_rule


def test_serial_drift_fires_and_clears(env):
    adapter = _synced_adapter()
    adapter.devices[1]["serial"] = "STALE9999"  # core-st-01-1
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_SERIAL_DRIFT") == 1
    f = next(f for f in report.findings if f.rule_id == "INTENT_SERIAL_DRIFT")
    assert f.evidence["key_facts"]["declared"] == "STALE9999"
    assert f.evidence["key_facts"]["observed"] == "SYNTH0001"
    # revert → clears
    adapter.devices[1]["serial"] = "SYNTH0001"
    assert _check(env, adapter).quiet


def test_serial_not_compared_when_undeclared(env):
    adapter = _synced_adapter()
    adapter.devices[0]["serial"] = None  # NetBox has no serial for acc-sw-01
    report = _check(env, adapter)
    assert "INTENT_SERIAL_DRIFT" not in report.counts_by_rule


def test_platform_drift(env):
    adapter = _synced_adapter()
    adapter.devices[0]["platform"] = "Cisco IOS-XR"
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_PLATFORM_DRIFT") == 1


def test_site_drift(env):
    adapter = _synced_adapter()
    adapter.devices[0]["site"] = "Demo-Annex"
    report = _check(env, adapter)
    # Site-scoping keeps the device in scope only if some declared site matches;
    # the device exists on both sides, so the mismatch is reported.
    assert report.counts_by_rule.get("INTENT_SITE_DRIFT") == 1


# ── Interface-level rules (aggregated per device) ────────────────────────────


def test_interface_missing_in_network_aggregates(env):
    adapter = _synced_adapter()
    adapter.interfaces["acc-sw-01"].append(_decl_iface("GigabitEthernet1/0/2"))
    adapter.interfaces["acc-sw-01"].append(_decl_iface("GigabitEthernet1/0/3"))
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_INTERFACE_MISSING_IN_NETWORK") == 1  # one per device
    f = next(f for f in report.findings if f.rule_id == "INTENT_INTERFACE_MISSING_IN_NETWORK")
    assert json.loads(f.evidence["key_facts"]["interfaces"]) == [
        "GigabitEthernet1/0/2", "GigabitEthernet1/0/3"]


def test_interface_unknown_in_netbox(env):
    adapter = _synced_adapter()
    adapter.interfaces["acc-sw-01"] = []  # nothing declared on this device
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_INTERFACE_UNKNOWN_IN_NETBOX") == 1
    assert report.counts_by_rule.get("INTENT_INTERFACE_ATTR_DRIFT") is None


def test_interface_attr_drift(env):
    adapter = _synced_adapter()
    adapter.interfaces["acc-sw-01"][0]["enabled"] = False
    adapter.interfaces["acc-sw-01"][0]["description"] = "stale text"
    report = _check(env, adapter)
    assert report.counts_by_rule.get("INTENT_INTERFACE_ATTR_DRIFT") == 1
    f = next(f for f in report.findings if f.rule_id == "INTENT_INTERFACE_ATTR_DRIFT")
    drifted = json.loads(f.evidence["key_facts"]["drift"])
    assert set(drifted["GigabitEthernet1/0/1"]) == {"enabled", "description"}


def test_no_interface_findings_for_undeclared_device(env):
    # Device absent from NetBox entirely → device-level finding only,
    # never 71 lines of interface noise on top.
    adapter = _synced_adapter()
    adapter.devices = [d for d in adapter.devices if d["name"] != "acc-sw-01"]
    adapter.interfaces.pop("acc-sw-01")
    report = _check(env, adapter)
    per_iface = [f for f in report.findings
                 if f.rule_id.startswith("INTENT_INTERFACE_")
                 and f.evidence["element_id"] == "acc-sw-01"]
    assert per_iface == []


# ── Honesty + persistence ────────────────────────────────────────────────────


def test_unreachable_source_raises_never_zero_drift(env):
    with pytest.raises(drift.DriftSourceUnavailable):
        _check(env, FakeAdapter(reachable=False))


def test_artifact_written_and_neo4j_refresh_scoped_to_intent(env):
    adapter = _synced_adapter()
    adapter.devices[1]["serial"] = "STALE9999"

    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__ = lambda s: fake_session
    fake_driver.session.return_value.__exit__ = MagicMock(return_value=False)

    with patch("netcopilot.graph.client.is_available", return_value=True), \
         patch("netcopilot.graph.client.get_driver", return_value=fake_driver), \
         patch("netcopilot.graph.client.get_site_for_run", return_value="demo"), \
         patch("netcopilot.graph.loader.load_findings_list", return_value=1) as load_mock:
        report = drift.run_drift_check("demo-run", env / "lab.yaml",
                                       adapter=adapter, load=True)

    artifact = env / "demo-run" / "drift" / "drift_findings.json"
    assert artifact.is_file()
    payload = json.loads(artifact.read_text())
    assert payload["metadata"]["total_findings"] == len(report.findings) == 1
    assert payload["findings"][0]["rule_id"] == "INTENT_SERIAL_DRIFT"

    delete_cypher = fake_session.run.call_args_list[0].args[0]
    assert "STARTS WITH 'INTENT_'" in delete_cypher  # engine findings untouched
    assert load_mock.call_args.args[2] == "demo"     # site threaded through


def test_missing_in_network_loads_as_standalone_node(env):
    # The device has no :Device node in the run (that's the finding!) — the
    # shared loader's MATCH would drop it silently; it must load unattached.
    adapter = _synced_adapter()
    adapter.devices.append(_decl_device("retired-sw-99"))

    fake_session = MagicMock()
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__ = lambda s: fake_session
    fake_driver.session.return_value.__exit__ = MagicMock(return_value=False)

    with patch("netcopilot.graph.client.is_available", return_value=True), \
         patch("netcopilot.graph.client.get_driver", return_value=fake_driver), \
         patch("netcopilot.graph.client.get_site_for_run", return_value="demo"), \
         patch("netcopilot.graph.loader.load_findings_list", return_value=0) as load_mock:
        drift.run_drift_check("demo-run", env / "lab.yaml", adapter=adapter, load=True)

    # Attached batch excludes the MISSING_IN_NETWORK finding…
    attached_rule_ids = [f["rule_id"] for f in load_mock.call_args.args[1]]
    assert "INTENT_DEVICE_MISSING_IN_NETWORK" not in attached_rule_ids
    # …and a standalone CREATE carries it with the loader-compatible props.
    create_calls = [c for c in fake_session.run.call_args_list
                    if "CREATE (fin:Finding)" in c.args[0]]
    assert len(create_calls) == 1
    props = create_calls[0].kwargs["findings"][0]
    assert props["rule_id"] == "INTENT_DEVICE_MISSING_IN_NETWORK"
    assert props["device"] == "retired-sw-99"
    assert props["site"] == "demo" and props["run_id"] == "demo-run"
    assert props["category"] == "intent"


# ── stage_correction (S13-3) ─────────────────────────────────────────────────


def _finding_row(rule_id, device="acc-sw-01", **kf):
    row = {
        "finding_id": f"{rule_id}::{device}", "rule_id": rule_id,
        "device": device, "element_id": device, "site": "demo",
        "severity": "high", "run_id": "demo-run",
    }
    row.update({f"kf_{k}": v for k, v in kf.items()})
    return row


def _neo4j_returning(row):
    fake_session = MagicMock()
    fake_session.run.return_value.single.return_value = {"f": row} if row else None
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__ = lambda s: fake_session
    fake_driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return fake_driver


def test_stage_correction_serial_drift(env):
    row = _finding_row("INTENT_SERIAL_DRIFT", declared="STALE9999", observed="SYNTH0001")
    adapter = _synced_adapter()
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(row)), \
         patch("netcopilot.declared_state.staging.list_pending", return_value=[]), \
         patch("netcopilot.declared_state.staging.stage_candidate",
               return_value="cand-1") as sc:
        out = drift.stage_correction("INTENT_SERIAL_DRIFT::acc-sw-01", "demo-run",
                                     adapter=adapter)
    assert out == {"staged": 1, "skipped": 0, "candidate_ids": ["cand-1"]}
    kw = sc.call_args.kwargs
    assert kw["source"] == "drift"
    assert kw["object_type"] == "device"
    assert kw["payload"] == {"name": "acc-sw-01", "serial": "SYNTH0001"}
    assert kw["before"]["id"] == 1                       # live netbox_id threaded
    assert kw["from_finding_id"] == "INTENT_SERIAL_DRIFT::acc-sw-01"
    assert kw["drift_severity"] == "high"


def test_stage_correction_interface_attr_drift(env):
    drifted = {"GigabitEthernet1/0/1": {
        "enabled": {"declared": False, "observed": True},
        "description": {"declared": "stale", "observed": "uplink"},
    }}
    row = _finding_row("INTENT_INTERFACE_ATTR_DRIFT", drift=json.dumps(drifted))
    adapter = _synced_adapter()
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(row)), \
         patch("netcopilot.declared_state.staging.list_pending", return_value=[]), \
         patch("netcopilot.declared_state.staging.stage_candidate",
               return_value="cand-1") as sc:
        out = drift.stage_correction("INTENT_INTERFACE_ATTR_DRIFT::acc-sw-01",
                                     "demo-run", adapter=adapter)
    assert out["staged"] == 1
    kw = sc.call_args.kwargs
    assert kw["object_type"] == "interface"
    assert kw["payload"]["enabled"] is True
    assert kw["payload"]["description"] == "uplink"
    assert kw["payload"]["device"] == {"name": "acc-sw-01"}


def test_stage_correction_idempotent_skip(env):
    row = _finding_row("INTENT_SERIAL_DRIFT", declared="STALE9999", observed="SYNTH0001")
    adapter = _synced_adapter()
    pending = [{"netbox_object_type": "device", "payload": {"name": "acc-sw-01"}}]
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(row)), \
         patch("netcopilot.declared_state.staging.list_pending", return_value=pending), \
         patch("netcopilot.declared_state.staging.stage_candidate") as sc:
        out = drift.stage_correction("INTENT_SERIAL_DRIFT::acc-sw-01", "demo-run",
                                     adapter=adapter)
    assert out == {"staged": 0, "skipped": 1, "candidate_ids": []}
    sc.assert_not_called()


def test_stage_correction_not_correctable(env):
    row = _finding_row("INTENT_DEVICE_MISSING_IN_NETWORK", device="ghost-sw-99")
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(row)):
        with pytest.raises(drift.NotCorrectable):
            drift.stage_correction("INTENT_DEVICE_MISSING_IN_NETWORK::ghost-sw-99",
                                   "demo-run", adapter=_synced_adapter())


def test_stage_correction_finding_not_found(env):
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(None)):
        with pytest.raises(KeyError):
            drift.stage_correction("INTENT_SERIAL_DRIFT::nope", "demo-run",
                                   adapter=_synced_adapter())


def test_stage_correction_unreachable_netbox_raises(env):
    row = _finding_row("INTENT_SERIAL_DRIFT", observed="SYNTH0001")
    with patch("netcopilot.graph.client.get_driver", return_value=_neo4j_returning(row)):
        with pytest.raises(drift.DriftSourceUnavailable):
            drift.stage_correction("INTENT_SERIAL_DRIFT::acc-sw-01", "demo-run",
                                   adapter=FakeAdapter(reachable=False))


def test_persist_without_neo4j_warns_not_silent(env):
    adapter = _synced_adapter()
    adapter.devices[1]["serial"] = "STALE9999"
    with patch("netcopilot.graph.client.is_available", return_value=False):
        report = drift.run_drift_check("demo-run", env / "lab.yaml",
                                       adapter=adapter, load=True)
    assert any("Neo4j unavailable" in w for w in report.warnings)


def test_run_not_loaded_in_neo4j_warns(env):
    adapter = _synced_adapter()
    adapter.devices[1]["serial"] = "STALE9999"
    with patch("netcopilot.graph.client.is_available", return_value=True), \
         patch("netcopilot.graph.client.get_driver", return_value=MagicMock()), \
         patch("netcopilot.graph.client.get_site_for_run", return_value=None):
        report = drift.run_drift_check("demo-run", env / "lab.yaml",
                                       adapter=adapter, load=True)
    assert any("not loaded in Neo4j" in w for w in report.warnings)


def test_catalog_remediation_entries_are_template_dicts():
    """Caught live in s13: a flat-string remediation crashes get_remediation.

    The catalog contract is ``remediation: {os_family: template}`` — enforce
    it catalog-wide so authoring mistakes fail here, not in a chat tool.
    """
    import yaml
    from pathlib import Path
    catalog_path = Path("src/netcopilot/rules/rule-catalog.yaml")
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    bad = [r["rule_id"] for r in raw
           if "remediation" in r and not isinstance(r["remediation"], dict)]
    assert bad == [], f"flat-string remediation (must be os_family->template dict): {bad}"
