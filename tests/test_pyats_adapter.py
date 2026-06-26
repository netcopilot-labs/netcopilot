"""F2-5-final: pyATS adapter — collect() orchestration + BGP-OOM smart-skip.

Skipped unless the optional ``[pyats]`` extra is installed. The pure summary
helpers are tested directly; ``collect()`` is driven against a fake testbed
(monkeypatched ``generate_testbed``) with a scripted fake device, so no real
network or pyATS connection is needed — only the importable module.
"""

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("pyats")

from netcopilot.collect import pyats as pyats_mod  # noqa: E402
from netcopilot.collect.chain import applicable_strategies, default_chain  # noqa: E402
from netcopilot.collect.pyats import (  # noqa: E402
    PyATSAdapter,
    _capture_raw_cli,
    _count_bgp_prefixes,
    _count_route_summary,
    _extract_peer_prefix_counts,
    _parse_bgp_peer_routes_text,
    _sanitize_command_to_filename,
)


# --------------------------------------------------------------------------
# Chain wiring — pyATS leads for Cisco when the extra is installed
# --------------------------------------------------------------------------

def test_pyats_prepended_to_default_chain():
    names = [s.name for s in default_chain()]
    assert names == ["pyats", "netconf", "restconf", "rest", "ssh"]


def test_pyats_leads_applicable_strategies_for_cisco():
    assert [s.name for s in applicable_strategies({"os": "ios-xe"})][0] == "pyats"
    assert [s.name for s in applicable_strategies({"os": "ios-xr"})][0] == "pyats"
    # FortiGate is REST-only — pyATS must not match it
    assert [s.name for s in applicable_strategies({"os": "fortios"})] == ["rest"]

# --------------------------------------------------------------------------
# Pure helpers — the BGP/routing OOM-guard math
# --------------------------------------------------------------------------

BGP_SUMMARY = {
    "instance": {"default": {"vrf": {"default": {"neighbor": {
        "198.51.100.2": {"address_family": {"ipv4 unicast": {"state_pfxrcd": "100"}}},
        "198.51.100.3": {"address_family": {"ipv4 unicast": {"prefixes": {"total_entries": 50}}}},
    }}}}},
}


def test_count_bgp_prefixes_handles_both_xr_and_xe_shapes():
    # XR state_pfxrcd ("100") + XE prefixes.total_entries (50)
    assert _count_bgp_prefixes(BGP_SUMMARY) == 150


def test_extract_peer_prefix_counts():
    counts = _extract_peer_prefix_counts(BGP_SUMMARY)
    assert counts == {"198.51.100.2": 100, "198.51.100.3": 50}


def test_count_route_summary():
    summary = {"route_source": {
        "connected": {"routes": 5},
        "local": {"routes": 3},
        "bgp": {"65001": {"routes": 10}},  # nested sub-key
    }}
    assert _count_route_summary(summary) == 18


def test_parse_bgp_peer_routes_text():
    raw = "\n".join([
        "   Network            Next Hop          Metric LocPrf Weight Path",
        "*> 203.0.113.0/24     198.51.100.108         0    100      0 64512 i",
        "*>i0.0.0.0/0          198.51.100.2              100      0 i",
        "garbage line that should be skipped",
    ])
    routes = _parse_bgp_peer_routes_text(raw)
    assert len(routes) == 2
    assert routes[0]["prefix"] == "203.0.113.0/24"
    assert routes[0]["next_hop"] == "198.51.100.108"
    assert routes[1]["prefix"] == "0.0.0.0/0"


# --------------------------------------------------------------------------
# collect() — driven against a fake testbed / fake device
# --------------------------------------------------------------------------

RUNNING_CONFIG = "\n".join([
    "hostname core-sw-01",
    "router ospf 1",
    "router bgp 65001",
    "interface GigabitEthernet1/0/1",
    " channel-group 1 mode active",
    "ip ssh version 2",
])


class _FakeOps:
    def __init__(self, info):
        self.info = info


class _FakeDevice:
    """Scripted stand-in for a connected pyATS device."""

    def __init__(self, *, connect_raises=False, bgp_summary=None):
        self.hostname = "real-core-sw-01"
        self._connect_raises = connect_raises
        self._bgp_summary = bgp_summary
        self.disconnected = False

    def connect(self, **kwargs):
        if self._connect_raises:
            raise ConnectionError("auth failed")

    def execute(self, cmd):
        if "running-config" in cmd:
            return RUNNING_CONFIG
        return f"output of: {cmd}\n"

    def learn(self, family):
        return _FakeOps({family: {"learned": True}})

    def parse(self, cmd):
        if self._bgp_summary is not None and "bgp summary" in cmd:
            return self._bgp_summary
        return {}  # stack/svl/qos/policy-map → empty → skipped gracefully

    def disconnect(self):
        self.disconnected = True


def _patch_testbed(monkeypatch, device):
    def fake_generate_testbed(devices, credentials):
        return SimpleNamespace(devices={d["name"]: device for d in devices})
    monkeypatch.setattr(pyats_mod, "generate_testbed", fake_generate_testbed)


DEVICE = {"name": "core-sw-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}
CREDS = {"username": "admin", "password": "testpass"}
PROFILE = ["show version", "show ip interface brief"]


def test_collect_writes_raw_genie_and_config_files(tmp_path, monkeypatch):
    _patch_testbed(monkeypatch, _FakeDevice())
    raw_dir = tmp_path / "raw"
    result = PyATSAdapter().collect(DEVICE, PROFILE, str(raw_dir), CREDS)

    assert result.success is True
    assert result.strategy_name == "pyats"
    assert result.hostname == "real-core-sw-01"

    # Phase 1 — raw text under raw/<name>/
    assert (raw_dir / "core-sw-01" / "show_version.txt").is_file()
    assert (raw_dir / "core-sw-01" / "show_ip_interface_brief.txt").is_file()

    # Phase 2 — Genie evidence under facts/<name>/
    facts = tmp_path / "facts" / "core-sw-01"
    assert (facts / "running_config.txt").is_file()
    assert (facts / "genie_ospf.json").is_file()
    assert (facts / "genie_bgp.json").is_file()
    assert (facts / "genie_interface.json").is_file()
    assert (facts / "genie_lag.json").is_file()        # channel-group → lag learn
    assert (facts / "security_config.json").is_file()  # always written

    # genie file content is the learned .info dict
    assert json.loads((facts / "genie_ospf.json").read_text()) == {"ospf": {"learned": True}}

    # family metadata (dynamic attrs) populated for the manifest
    assert "ospf" in result.families_collected
    assert "bgp" in result.families_collected
    assert result.facts_dir.endswith("facts/core-sw-01")


def test_collect_connection_failure_is_captured_not_raised(tmp_path, monkeypatch):
    _patch_testbed(monkeypatch, _FakeDevice(connect_raises=True))
    result = PyATSAdapter().collect(DEVICE, PROFILE, str(tmp_path / "raw"), CREDS)
    assert result.success is False
    assert result.error is not None
    assert "auth failed" in result.error


def test_skip_families_promotes_small_bgp_to_full_learn(tmp_path, monkeypatch):
    # A peer with a small RIB (< 50k) — the OOM guard promotes bgp back to a
    # full learn() rather than leaving it summary-only.
    small_summary = {"instance": {"default": {"vrf": {"default": {"neighbor": {
        "198.51.100.2": {"address_family": {"ipv4 unicast": {"state_pfxrcd": "42"}}},
    }}}}}}
    _patch_testbed(monkeypatch, _FakeDevice(bgp_summary=small_summary))

    device = {**DEVICE, "skip_families": ["bgp"]}
    result = PyATSAdapter().collect(device, PROFILE, str(tmp_path / "raw"), CREDS)

    assert result.success is True
    # promoted → fully learned (not just summary-parsed)
    assert "bgp" in result.families_collected
    assert (tmp_path / "facts" / "core-sw-01" / "genie_bgp.json").is_file()


# --------------------------------------------------------------------------
# StackWise/SVL parse-failure → raw capture + de-silence
#
# A real C9500 SVL pair can collect via pyATS while `show stackwise-virtual
# link` parse throws and is swallowed at debug level, so genie_svl_link.json
# (→ device.stack_ports → SVL/STACK health rules) was never produced and the
# raw output was lost. These tests lock the no-silent-fallback behaviour: the
# raw CLI output is preserved for the next collection to diagnose against.
# --------------------------------------------------------------------------

class _SvlFailDevice(_FakeDevice):
    """A clustered device whose StackWise/SVL parses raise (Genie mismatch)."""

    def parse(self, cmd):
        if "stackwise" in cmd or "stack-ports" in cmd:
            raise Exception("SchemaEmptyParserError: could not parse output")
        return super().parse(cmd)


def test_capture_raw_cli_writes_output_on_parse_failure(tmp_path):
    # The helper executes the raw command and writes it under the host dir.
    path = _capture_raw_cli(_FakeDevice(), tmp_path, "show stackwise-virtual link")
    assert path is not None
    assert path.name == _sanitize_command_to_filename("show stackwise-virtual link")
    assert path.name == "show_stackwise-virtual_link.txt"
    assert "show stackwise-virtual link" in path.read_text()


def test_capture_raw_cli_returns_none_on_empty_or_failed_execute(tmp_path):
    class _Blank(_FakeDevice):
        def execute(self, cmd):
            return "   \n"   # whitespace only → nothing worth preserving

    class _Boom(_FakeDevice):
        def execute(self, cmd):
            raise Exception("command rejected")

    assert _capture_raw_cli(_Blank(), tmp_path, "show stackwise-virtual link") is None
    assert _capture_raw_cli(_Boom(), tmp_path, "show stackwise-virtual link") is None


class _StackTextDevice(_FakeDevice):
    """Clustered device: SVL + stack-ports Genie parses raise, but the raw
    stack-ports CLI returns a valid C9300 ring → text fallback recovers it."""

    _STACK_TABLE = (
        "Sw#/Port#  Port Status  Neighbor/Port  Cable Length   Link OK   Link Active   Sync OK   #Changes  In Loopback\n"
        "1/1        OK           2/2            50cm           Yes       Yes           Yes       1         No\n"
        "2/2        OK           1/1            50cm           Yes       Yes           Yes       1         No\n"
    )

    def parse(self, cmd):
        if "stackwise" in cmd or "stack-ports" in cmd:
            raise Exception("SchemaEmptyParserError: could not parse output")
        return super().parse(cmd)

    def execute(self, cmd):
        if "stack-ports" in cmd:
            return self._STACK_TABLE
        return super().execute(cmd)


def test_stack_ports_text_fallback_recovers_genie_json(tmp_path, monkeypatch, caplog):
    # Genie can't parse the C9300 stack-ports output, but the text fallback
    # produces genie_stack_ports.json so traditional-stack health is monitored.
    _patch_testbed(monkeypatch, _StackTextDevice())
    clustered = {**DEVICE, "cluster": {"name": "CLUSTER_B", "size": 3}}
    raw_dir = tmp_path / "raw"

    import logging
    with caplog.at_level(logging.WARNING, logger="netcopilot.collect.pyats"):
        result = PyATSAdapter().collect(clustered, PROFILE, str(raw_dir), CREDS)

    assert result.success is True
    # Recovered stack topology written in the Genie schema (drop-in for model).
    stack_json = tmp_path / "facts" / "core-sw-01" / "genie_stack_ports.json"
    assert stack_json.is_file()
    sp = json.loads(stack_json.read_text())["stackports"]
    assert set(sp) == {"1/1", "2/2"}
    assert sp["1/1"]["neighbor"] == "2/2"
    # Topology captured → NOT silently dark → no de-silence warning.
    assert not any("no StackWise/SVL topology" in r.message for r in caplog.records)


def test_svl_parse_failure_captures_raw_and_warns(tmp_path, monkeypatch, caplog):
    # Clustered IOS XE switch whose SVL parse fails: the raw output must be
    # preserved AND a warning emitted (not swallowed at debug).
    _patch_testbed(monkeypatch, _SvlFailDevice())
    clustered = {**DEVICE, "cluster": {"name": "CLUSTER_A", "size": 2}}
    raw_dir = tmp_path / "raw"

    import logging
    with caplog.at_level(logging.WARNING, logger="netcopilot.collect.pyats"):
        result = PyATSAdapter().collect(clustered, PROFILE, str(raw_dir), CREDS)

    assert result.success is True
    # Raw SVL output preserved for the next collection to diagnose against.
    raw_svl = raw_dir / "core-sw-01" / "show_stackwise-virtual_link.txt"
    assert raw_svl.is_file()
    assert "show stackwise-virtual link" in raw_svl.read_text()
    # Stack-ports fallback also failed -> its raw is preserved too (the C9300
    # traditional-stack case where Genie cannot parse the summary output).
    raw_stack = raw_dir / "core-sw-01" / "show_switch_stack-ports_summary.txt"
    assert raw_stack.is_file()
    # Parsed JSON was NOT produced (parse failed) — so the gap is now visible.
    assert not (tmp_path / "facts" / "core-sw-01" / "genie_svl_link.json").exists()
    assert not (tmp_path / "facts" / "core-sw-01" / "genie_stack_ports.json").exists()
    # De-silenced: a clustered switch with no stack/SVL topology warns.
    assert any(
        "no StackWise/SVL topology" in r.message for r in caplog.records
    )
