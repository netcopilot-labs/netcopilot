"""s05-3: ``netcopilot validate`` CLI — verdict printout + exit codes 0/1/2.

Same synthetic on-disk style as test_cli_diff; the exit code IS the contract
(pipeline gate), so every verdict level pins its code.
"""

from __future__ import annotations

import argparse
import json

import pytest

from netcopilot.cli import _cmd_validate


def _write_run(runs_dir, run_id, *, site="demo", devices=None, interfaces=None, findings=None):
    run_dir = runs_dir / run_id
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    model = {
        "devices": devices if devices is not None else [{"device_id": "core-sw-01", "site": site}],
        "interfaces": interfaces or [],
        "links": [], "adjacencies": [], "shared_services": [],
        "l2_domains": [], "ospf_lsdb": [],
    }
    (run_dir / "model" / "network_model.json").write_text(json.dumps(model))
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": findings or []})
    )


def _iface(device_id, name, **kw):
    return {"interface_id": f"{device_id}:{name}", "device_id": device_id,
            "name": name, "oper_status": "up", **kw}


def _ns(after, before=None, scope=None, runs_dir=None):
    return argparse.Namespace(after=after, before=before, scope=scope, runs_dir=str(runs_dir))


DEVS = [{"device_id": "core-sw-01", "site": "demo"}, {"device_id": "acc-sw-09", "site": "demo"}]


def _two_runs(tmp_path, after_ifaces):
    _write_run(tmp_path, "2026-06-23_08-00-00", devices=DEVS,
               interfaces=[_iface("core-sw-01", "Gi1"), _iface("acc-sw-09", "Gi1")])
    _write_run(tmp_path, "2026-06-23_09-00-00", devices=DEVS, interfaces=after_ifaces)


def test_pass_exits_0(tmp_path, capsys):
    _two_runs(tmp_path, [_iface("core-sw-01", "Gi1", oper_status="down"),
                         _iface("acc-sw-09", "Gi1")])
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("2026-06-23_09-00-00", scope="core-sw-01", runs_dir=tmp_path))
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "verdict: PASS" in out and "scope: core-sw-01" in out


def test_warn_exits_1_without_scope(tmp_path, capsys):
    _two_runs(tmp_path, [_iface("core-sw-01", "Gi1", oper_status="down"),
                         _iface("acc-sw-09", "Gi1")])
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("2026-06-23_09-00-00", runs_dir=tmp_path))
    assert exc.value.code == 1
    assert "verdict: WARN" in capsys.readouterr().out


def test_fail_exits_2_out_of_scope(tmp_path, capsys):
    _two_runs(tmp_path, [_iface("core-sw-01", "Gi1"),
                         _iface("acc-sw-09", "Gi1", oper_status="down")])
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("2026-06-23_09-00-00", scope="core-sw-01", runs_dir=tmp_path))
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert "verdict: FAIL" in out and "acc-sw-09" in out


def test_before_defaults_to_previous_run(tmp_path, capsys):
    _two_runs(tmp_path, [_iface("core-sw-01", "Gi1"), _iface("acc-sw-09", "Gi1")])
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("2026-06-23_09-00-00", scope="core-sw-01", runs_dir=tmp_path))
    assert exc.value.code == 0
    assert "2026-06-23_08-00-00 → 2026-06-23_09-00-00" in capsys.readouterr().out


def test_unknown_run_exits_2(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("does-not-exist", runs_dir=tmp_path))
    assert exc.value.code == 2
    assert "validate failed" in capsys.readouterr().err


def test_no_previous_run_exits_2(tmp_path, capsys):
    _write_run(tmp_path, "2026-06-23_08-00-00", devices=DEVS)
    with pytest.raises(SystemExit) as exc:
        _cmd_validate(_ns("2026-06-23_08-00-00", runs_dir=tmp_path))
    assert exc.value.code == 2
    assert "specify --before" in capsys.readouterr().err
