"""NETCOPILOT_HIDE_DEMOS hides the bundled demo labs from the inventory picker
(production deployments) without deleting files or rebuilding the image."""

from netcopilot.dashboard.backend.routes import runs_trigger


def test_demos_visible_by_default(monkeypatch):
    monkeypatch.delenv("NETCOPILOT_HIDE_DEMOS", raising=False)
    assert runs_trigger._demos_hidden() is False


def test_hide_demos_toggle_on(monkeypatch):
    for val in ("1", "true", "YES", "on"):
        monkeypatch.setenv("NETCOPILOT_HIDE_DEMOS", val)
        assert runs_trigger._demos_hidden() is True
        assert runs_trigger._demo_inventories() == []


def test_hide_demos_off_values(monkeypatch):
    for val in ("", "0", "false", "no"):
        monkeypatch.setenv("NETCOPILOT_HIDE_DEMOS", val)
        assert runs_trigger._demos_hidden() is False
