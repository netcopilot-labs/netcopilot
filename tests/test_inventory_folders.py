"""Folder-per-tenant inventories: a self-contained tenant is a directory under
``inventory/`` holding ``lab.yaml`` + its own ``credentials.env``. Flat
``<name>.yaml`` files keep working alongside (single-network quickstart)."""

import os

import pytest

from netcopilot.cli import _load_env_file, _resolve_inventory_path
from netcopilot.dashboard.backend.routes import runs_trigger


# ── CLI: credentials.env loading + inventory path resolution ─────────────────
def test_load_env_file_parses_and_strips(tmp_path, monkeypatch):
    monkeypatch.delenv("FOO_X", raising=False)
    monkeypatch.delenv("QUOTED", raising=False)
    f = tmp_path / "credentials.env"
    f.write_text('# a comment\nFOO_X=bar\nQUOTED="baz"\n\nNO_EQUALS_LINE\n')
    assert _load_env_file(f) == 2
    assert os.environ["FOO_X"] == "bar"
    assert os.environ["QUOTED"] == "baz"


def test_resolve_folder_loads_creds_and_returns_labyaml(tmp_path, monkeypatch):
    monkeypatch.delenv("T_USER", raising=False)
    d = tmp_path / "tenant-a"
    d.mkdir()
    (d / "lab.yaml").write_text("devices: []\n")
    (d / "credentials.env").write_text("T_USER=admin\n")
    lab = _resolve_inventory_path(str(d))
    assert lab == str(d / "lab.yaml")
    assert os.environ["T_USER"] == "admin"     # folder creds loaded into env


def test_resolve_flat_file_is_passthrough(tmp_path):
    f = tmp_path / "t.yaml"
    f.write_text("devices: []\n")
    assert _resolve_inventory_path(str(f)) == str(f)


def test_resolve_folder_without_labyaml_errors(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    with pytest.raises(SystemExit):
        _resolve_inventory_path(str(d))


# ── Picker: discovers both flat files and folder tenants ─────────────────────
def _isolate_inventory_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(runs_trigger, "_INVENTORY_DIR", tmp_path)
    monkeypatch.setattr(runs_trigger, "_DEMO_DIR", tmp_path / "no_demos")  # → no demos


def test_list_inventories_discovers_flat_and_folders(tmp_path, monkeypatch):
    _isolate_inventory_dir(tmp_path, monkeypatch)
    (tmp_path / "flat.yaml").write_text("devices: []\n")
    d = tmp_path / "tenant-b"
    d.mkdir()
    (d / "lab.yaml").write_text("devices: []\n")
    (tmp_path / "junk").mkdir()                 # no lab.yaml → ignored

    items = {i["id"]: i for i in runs_trigger._list_inventories()}
    assert items["flat"]["path"].endswith("flat.yaml")
    assert items["tenant-b"]["path"].endswith("tenant-b")     # path = the folder
    assert "junk" not in items


def test_delete_folder_inventory_removes_the_folder(tmp_path, monkeypatch):
    _isolate_inventory_dir(tmp_path, monkeypatch)
    d = tmp_path / "tenant-c"
    d.mkdir()
    (d / "lab.yaml").write_text("devices: []\n")
    (d / "credentials.env").write_text("X=1\n")

    resp = runs_trigger.delete_inventory("tenant-c")
    assert resp["deleted"] is True
    assert not d.exists()                        # whole folder gone, creds included
