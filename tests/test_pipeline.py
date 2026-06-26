"""F2-7: pipeline orchestrator — collect → parse → model → load.

The collect stage needs live devices, so the fixture tests drive process_run
(parse → model → load) over a synthetic *already-collected* run directory: raw
IOS XE show-text + a manifest. Reuses the proven raw-text builders from the IOS
XE parser tests so the fixtures match real column layouts. RFC 5737 IPs.
"""

import json

import pytest

from netcopilot.pipeline import PipelineError, process_run, run_pipeline
from test_graph_load_model import FakeDriver
from test_parse_iosxe import _cdp_header, _cdp_single, _ipbrief

SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a

{host} uptime is 1 day

Model Number                       : C9500
System Serial Number               : SYN{n}
Base Ethernet MAC Address          : 00:11:22:33:44:0{n}
"""


def _build_collected_run(tmp_path, run_id="pipe-run"):
    """Write a synthetic 2-device collected run (raw + manifest), CDP-bilateral."""
    run = tmp_path / run_id
    pairs = [
        ("core-rtr-01", "1", "GigabitEthernet1/0/1", "dist-sw-01", "Gig 1/0/2"),
        ("dist-sw-01", "2", "GigabitEthernet1/0/2", "core-rtr-01", "Gig 1/0/1"),
    ]
    for host, n, local_full, peer, peer_port in pairs:
        raw = run / "raw" / host
        raw.mkdir(parents=True)
        (raw / "show_version.txt").write_text(SHOW_VERSION.format(host=host, n=n))
        (raw / "show_ip_interface_brief.txt").write_text(
            _ipbrief([(local_full, f"192.0.2.{n}", "YES", "NVRAM", "up", "up")]))
        local_short = "Gig " + local_full.replace("GigabitEthernet", "")
        (raw / "show_cdp_neighbors.txt").write_text(
            "\n".join([_cdp_header(),
                       _cdp_single(peer, local_short, "150", "R S", "C9500", peer_port)]) + "\n")
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "timestamp_utc": "2026-06-18T12:00:00Z",
        "devices": [
            {"inventory_name": h, "hostname": h, "os": "ios-xe", "target": f"198.51.100.{n}",
             "role": "core", "site": "dc", "collection_strategy": "ssh", "status": "success"}
            for h, n, *_ in pairs],
    }))
    return run


def test_process_run_parse_and_model_no_load(tmp_path):
    _build_collected_run(tmp_path)
    result = process_run("pipe-run", site="dc", runs_dir=tmp_path, load=False)

    assert result["run_id"] == "pipe-run"
    assert result["facts"]["success_count"] == 2
    assert result["model"]["devices"] == 2
    assert result["model"]["interfaces"] == 2
    assert result["model"]["links"] == 1          # CDP-bilateral physical link
    assert "load" not in result                    # load=False

    # the model file was actually written for the loader to consume
    model = json.loads((tmp_path / "pipe-run" / "model" / "network_model.json").read_text())
    assert {d["device_id"] for d in model["devices"]} == {"core-rtr-01", "dist-sw-01"}

    # rules stage ran: findings.json persisted (load_model reads it) + count surfaced
    assert "findings" in result and isinstance(result["findings"], int)
    findings_doc = json.loads(
        (tmp_path / "pipe-run" / "findings" / "findings.json").read_text())
    assert "findings" in findings_doc            # full findings document written


def test_process_run_emits_progress_per_stage(tmp_path):
    _build_collected_run(tmp_path)
    events = []
    process_run("pipe-run", site="dc", runs_dir=tmp_path, load=False,
                progress=lambda stage, msg: events.append((stage, msg)))
    stages = [s for s, _ in events]
    # parse/model/rules fire without load; load_complete only when load=True
    assert stages == ["parse_complete", "model_complete", "rules_complete"]
    assert all(isinstance(m, str) and m for _, m in events)


def test_process_run_with_load_invokes_loader(tmp_path):
    _build_collected_run(tmp_path)
    driver = FakeDriver()
    result = process_run("pipe-run", site="dc", runs_dir=tmp_path, load=True, driver=driver)
    assert result["load"]["devices"] == 2
    # the loader actually ran its Device-create against the driver
    assert any("CREATE (dev:Device)" in c for c, _ in driver.calls)


def test_process_run_zero_devices_aborts_and_cleans(tmp_path):
    # A collected run where no device produced facts (e.g. all unreachable after a
    # dropped tunnel): empty raw/ → build_facts yields 0 → pipeline must abort
    # cleanly and discard the run instead of crashing in build_model.
    run = tmp_path / "empty-run"
    (run / "raw").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": "empty-run", "timestamp_utc": "2026-06-21T00:00:00Z",
        "devices": [
            {"inventory_name": "core-rtr-01", "hostname": "core-rtr-01", "os": "ios-xe",
             "target": "198.51.100.1", "role": "core", "site": "dc",
             "status": "error", "error": "unreachable"},
        ],
    }))
    with pytest.raises(PipelineError):
        process_run("empty-run", site="dc", runs_dir=tmp_path, load=False)
    assert not run.exists()   # the empty run directory was discarded


def test_run_pipeline_dry_run_collects_nothing(tmp_path):
    # a dry run never collects; process_run is not reached, no run_id produced
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "devices:\n"
        "  - name: core-rtr-01\n"
        "    mgmt_ip: 192.0.2.1\n"
        "    os: ios-xe\n"
    )
    from netcopilot.inventory import YAMLInventory
    result = run_pipeline(YAMLInventory(inv), site="dc", runs_dir=tmp_path, dry_run=True)
    assert result == {"run_id": "", "dry_run": True}
