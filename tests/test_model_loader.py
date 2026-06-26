"""F2-5z-a: model/loader.load_run_data — manifest + per-device facts reader."""

import json

import pytest

from netcopilot.model.loader import load_run_data


def _run(tmp_path, devices):
    """Build a minimal run dir: manifest.json + facts/<name>/device_facts.json."""
    run = tmp_path / "2026-01-30_00-00-00"
    facts = run / "facts"
    for name in devices:
        d = facts / name
        d.mkdir(parents=True)
        (d / "device_facts.json").write_text(json.dumps({"hostname": name, "os": "ios-xe"}))
    (run / "manifest.json").write_text(json.dumps({
        "run_id": "2026-01-30_00-00-00",
        "devices": [{"inventory_name": n, "hostname": n} for n in devices],
    }))
    return run


def test_load_run_data(tmp_path):
    run = _run(tmp_path, ["core-rtr-01", "dist-sw-01"])
    data = load_run_data(run)
    assert set(data["facts"]) == {"core-rtr-01", "dist-sw-01"}
    assert data["facts"]["core-rtr-01"]["os"] == "ios-xe"
    assert data["manifest"]["run_id"] == "2026-01-30_00-00-00"


def test_load_run_data_missing_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_run_data(tmp_path / "nope")


def test_load_run_data_missing_manifest(tmp_path):
    run = tmp_path / "r"
    (run / "facts" / "core-rtr-01").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        load_run_data(run)
