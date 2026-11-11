"""
Tests for the .gitignore Hardener.

These tests run without `git init`, so they exercise the built-in matcher.
The Git-backed path is used automatically in real Git projects.
"""

from pathlib import Path

from decaloguex import engine
from decaloguex.rules.gitignore import simple_is_ignored


def ids(findings):
    """The rule IDs of some findings, e.g. ["GIT-003"]."""
    return [f.rule_id for f in findings]


def test_missing_gitignore_is_created(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    findings = engine.scan(tmp_path).findings
    assert ids(findings) == ["GIT-003"]

    engine.apply_fixes(findings)
    content = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in content and "!.env.example" in content


def test_unprotected_env_file_gets_pattern_appended(tmp_path):
    (tmp_path / ".gitignore").write_text("node_modules/", encoding="utf-8")  # no newline at the end
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "server.key").write_text("...", encoding="utf-8")

    findings = engine.scan(tmp_path).findings
    assert ids(findings) == ["GIT-001"]

    engine.apply_fixes(findings)
    lines = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "node_modules/"  # the existing line was kept intact
    assert ".env" in lines and "*.key" in lines


def test_already_protected_project_is_clean(tmp_path):
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("A=\n", encoding="utf-8")  # templates are fine

    assert engine.scan(tmp_path).findings == []


def test_simple_matcher_rules():
    rules = [".env.*", "!.env.example", "secrets/", "/config/prod.pem"]
    assert simple_is_ignored(".env.local", rules)
    assert not simple_is_ignored(".env.example", rules)  # negation wins (it comes last)
    assert simple_is_ignored("secrets/a.txt", rules)     # a folder pattern
    assert simple_is_ignored("config/prod.pem", rules)   # an anchored pattern
    assert not simple_is_ignored("other/config/prod.pem", rules)


def test_git_backed_check_sees_ignored_env(tmp_path):
    """Regression test: on Windows, text-mode pipes turned ".env" into
    ".env\r" before Git saw it, so an ignored .env was reported as exposed."""
    import shutil
    import subprocess

    import pytest

    if shutil.which("git") is None:
        pytest.skip("git is not installed")  # marks the test "skipped", not failed
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(".env\n.env.*\n", encoding="utf-8")
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("B=2\n", encoding="utf-8")

    assert engine.scan(tmp_path).findings == []
