"""Run-trashcan deletion: the endpoint wipes the graph AND the on-disk run dir,
with a path-traversal guard so a crafted run_id can't remove anything outside
RUNS_DIR."""

import pytest

from netcopilot.dashboard.backend.routes import runs_trigger


@pytest.fixture
def fake_graph(monkeypatch):
    """Stub Neo4j so each test exercises only the disk-removal path."""
    monkeypatch.setattr("netcopilot.graph.client.get_driver", lambda: None, raising=False)
    monkeypatch.setattr(
        "netcopilot.graph.loader.delete_run",
        lambda driver, run_id, site=None: 0,
        raising=False,
    )


def test_delete_removes_on_disk_run_dir(tmp_path, monkeypatch, fake_graph):
    monkeypatch.setattr(runs_trigger, "RUNS_DIR", tmp_path)
    run_dir = tmp_path / "2026-06-28_07-30-00"
    (run_dir / "facts").mkdir(parents=True)
    (run_dir / "facts" / "x.json").write_text("{}")

    resp = runs_trigger.delete_run_endpoint(site="demo", run_id="2026-06-28_07-30-00")

    assert resp["dir_removed"] is True
    assert not run_dir.exists()


def test_delete_path_traversal_is_blocked(tmp_path, monkeypatch, fake_graph):
    monkeypatch.setattr(runs_trigger, "RUNS_DIR", tmp_path)
    victim = tmp_path.parent / "victim_dir"
    victim.mkdir()
    (victim / "keep.txt").write_text("important")

    resp = runs_trigger.delete_run_endpoint(site="demo", run_id="../victim_dir")

    assert resp["dir_removed"] is False
    assert victim.exists()
    assert (victim / "keep.txt").exists()


def test_delete_missing_dir_is_noop(tmp_path, monkeypatch, fake_graph):
    monkeypatch.setattr(runs_trigger, "RUNS_DIR", tmp_path)

    resp = runs_trigger.delete_run_endpoint(site="demo", run_id="never-collected")

    assert resp["dir_removed"] is False
