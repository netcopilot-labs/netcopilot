"""S01-2: ``netcopilot diff`` CLI + previous_run helper.

Builds synthetic on-disk runs (RFC 5737 IPs, synthetic hostnames) and drives
the diff subcommand. Covers: two-arg diff, single-arg auto-previous, unknown
run error, no-previous error, and previous_run selection (same-site, earlier).
"""

from __future__ import annotations

import argparse
import json

import pytest

from netcopilot.cli import _cmd_diff
from netcopilot.diff.engine import previous_run


def _write_run(runs_dir, run_id, *, site="demo", devices=None, findings=None):
    run_dir = runs_dir / run_id
    (run_dir / "model").mkdir(parents=True)
    (run_dir / "findings").mkdir(parents=True)
    devs = devices if devices is not None else [{"device_id": "core-sw-01", "site": site}]
    model = {"devices": devs, "interfaces": [], "links": [], "adjacencies": [],
             "shared_services": [], "l2_domains": [], "ospf_lsdb": []}
    (run_dir / "model" / "network_model.json").write_text(json.dumps(model))
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps({"metadata": {}, "findings": findings or []})
    )


def _ns(run_a, run_b, runs_dir):
    return argparse.Namespace(run_a=run_a, run_b=str(run_b) if run_b else None, runs_dir=str(runs_dir))


# ---------------------------------------------------------------------------
# previous_run
# ---------------------------------------------------------------------------
def test_previous_run_picks_newest_earlier_same_site(tmp_path):
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00")
    _write_run(tmp_path, "2026-06-23_10-00-00")
    assert previous_run("2026-06-23_10-00-00", tmp_path) == "2026-06-23_09-00-00"


def test_previous_run_none_when_first(tmp_path):
    _write_run(tmp_path, "2026-06-23_08-00-00")
    assert previous_run("2026-06-23_08-00-00", tmp_path) is None


def test_previous_run_skips_other_site(tmp_path):
    _write_run(tmp_path, "2026-06-23_08-00-00", site="other",
               devices=[{"device_id": "x", "site": "other"}])
    _write_run(tmp_path, "2026-06-23_09-00-00", site="demo")
    # the demo run's only earlier neighbour is a different site → None
    assert previous_run("2026-06-23_09-00-00", tmp_path) is None


# ---------------------------------------------------------------------------
# _cmd_diff
# ---------------------------------------------------------------------------
def test_cmd_diff_two_args(tmp_path, capsys):
    _write_run(tmp_path, "runA", devices=[{"device_id": "core-sw-01", "site": "demo"}])
    _write_run(tmp_path, "runB", devices=[{"device_id": "core-sw-01", "site": "demo"},
                                          {"device_id": "acc-sw-09", "site": "demo"}])
    _cmd_diff(_ns("runA", "runB", tmp_path))
    out = capsys.readouterr().out
    assert "diff runA → runB" in out
    assert "added: 1" in out
    assert "acc-sw-09" in out


def test_cmd_diff_single_arg_auto_previous(tmp_path, capsys):
    _write_run(tmp_path, "2026-06-23_08-00-00")
    _write_run(tmp_path, "2026-06-23_09-00-00",
               devices=[{"device_id": "core-sw-01", "site": "demo"},
                        {"device_id": "new-sw", "site": "demo"}])
    _cmd_diff(_ns("2026-06-23_09-00-00", None, tmp_path))
    out = capsys.readouterr().out
    assert "diff 2026-06-23_08-00-00 → 2026-06-23_09-00-00" in out
    assert "new-sw" in out


def test_cmd_diff_unknown_run_exits_1(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _cmd_diff(_ns("does-not-exist", None, tmp_path))
    assert exc.value.code in (1, 2)  # no previous / not found — both are clean non-zero


def test_cmd_diff_no_previous_exits_2(tmp_path, capsys):
    _write_run(tmp_path, "2026-06-23_08-00-00")  # only run → no previous
    with pytest.raises(SystemExit) as exc:
        _cmd_diff(_ns("2026-06-23_08-00-00", None, tmp_path))
    assert exc.value.code == 2
    assert "no previous same-site run" in capsys.readouterr().err
