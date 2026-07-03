"""s04-1: context.build_context — the single run-context resolver.

Every context carries data_dir (the file-reading tools silently degrade to
no_data without it — the failure class that motivated the fix). Pure tests,
Neo4j gated off via monkeypatch.
"""

from netcopilot import context


def test_build_context_with_run_id_carries_data_dir(monkeypatch):
    monkeypatch.setattr(context, "is_available", lambda: False)
    monkeypatch.setenv("RUNS_DIR", "/data/runs")
    ctx = context.build_context(run_id="hq_2026-01-15_10-00-00")
    assert ctx == {
        "run_id": "hq_2026-01-15_10-00-00",
        "site": "hq",
        "data_dir": "/data/runs/hq_2026-01-15_10-00-00",
    }


def test_build_context_runs_dir_defaults_to_runs(monkeypatch):
    monkeypatch.setattr(context, "is_available", lambda: False)
    monkeypatch.delenv("RUNS_DIR", raising=False)
    ctx = context.build_context(run_id="hq_2026-01-15_10-00-00")
    assert ctx["data_dir"] == "runs/hq_2026-01-15_10-00-00"


def test_build_context_no_resolvable_run_degrades_with_empty_data_dir(monkeypatch):
    monkeypatch.setattr(context, "is_available", lambda: False)
    ctx = context.build_context(site="hq")
    assert ctx == {"run_id": "", "site": "hq", "data_dir": ""}


def test_build_context_explicit_site_wins_over_prefix(monkeypatch):
    monkeypatch.setattr(context, "is_available", lambda: False)
    ctx = context.build_context(site="campus", run_id="hq_2026-01-15_10-00-00")
    assert ctx["site"] == "campus"
