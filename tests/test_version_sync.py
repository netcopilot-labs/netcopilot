"""Version-drift guard (s23-6).

``pyproject.toml`` has now lagged the published tag TWICE (stuck at 1.0.0
when v1.2.0 shipped; stuck at 2.0.0 when v2.1.0 shipped — fixed in PR #21).
This guard makes the third occurrence impossible to miss: the declared
version must be >= the newest ``v*`` tag reachable from HEAD.

Equal is fine (the tagged release commit); greater is fine (pre-release
work); LESS is the drift. Skips where git or tags are unavailable (CI does a
shallow, tagless checkout — this is a local/release gate, same doctrine as
the eval).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _semver(text: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", text.strip())
    if not m:
        raise ValueError(f"not a MAJOR.MINOR.PATCH version: {text!r}")
    return tuple(int(g) for g in m.groups())  # type: ignore[return-value]


def test_pyproject_version_not_behind_latest_tag():
    try:
        tag = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", "--match", "v*"],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git unavailable")
    if tag.returncode != 0:
        pytest.skip("no v* tag reachable (shallow/tagless checkout)")

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert m, "pyproject.toml has no version line"

    declared, tagged = _semver(m.group(1)), _semver(tag.stdout)
    assert declared >= tagged, (
        f"pyproject.toml declares {m.group(1)} but the newest reachable tag "
        f"is {tag.stdout.strip()} — bump pyproject (and the README badge) "
        "before or with the release. This drift has shipped twice already.")
