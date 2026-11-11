"""
Tests for Exposed Secret Scrubbing.

JAVA COMPARISON: pytest is Python's JUnit, but lighter:
  * any function named test_* is a test, with no @Test annotation needed;
  * plain `assert x == y` replaces assertEquals, and pytest prints both
    values when it fails;
  * `tmp_path` is a "fixture": pytest sees the parameter name and passes in
    a fresh, empty temporary folder for each test (like JUnit 5's @TempDir).

Run them with:  pytest      (or the Testing panel in VS Code)
"""

from pathlib import Path

from decaloguex import engine
from decaloguex.cli import run_scan
from decaloguex.rules.secrets import mask, to_env_name

# Fake keys are built by joining pieces, so this file never contains a
# complete key-shaped string. Otherwise GitHub's own secret scanning would
# block every push of this test file.
FAKE_STRIPE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
FAKE_OPENAI = "sk-" + "proj-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"


def write(folder: Path, name: str, text: str) -> Path:
    """Helper: write a file into the test folder and return its path."""
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def test_javascript_key_moves_to_env(tmp_path):
    app = write(tmp_path, "app.js", f'const stripeKey = "{FAKE_STRIPE}";\nconsole.log(stripeKey);\n')

    exit_code = run_scan(tmp_path, assume_yes=True, no_color=True)

    code = app.read_text(encoding="utf-8")
    assert "process.env.STRIPE_SECRET_KEY" in code
    assert FAKE_STRIPE not in code  # the secret is gone from the code...
    assert f"STRIPE_SECRET_KEY={FAKE_STRIPE}" in (tmp_path / ".env").read_text(encoding="utf-8")  # ...and in .env
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8")  # ...which is protected
    assert exit_code == 0


def test_python_password_gets_os_import_after_docstring(tmp_path):
    app = write(tmp_path, "db.py", '"""Database helpers."""\nimport sys\n\nDB_PASSWORD = "hunter2!xyz"\n')

    run_scan(tmp_path, assume_yes=True, no_color=True)

    code = app.read_text(encoding="utf-8")
    assert 'DB_PASSWORD = os.environ.get("DB_PASSWORD")' in code
    # `import os` must come AFTER the docstring, or it stops being a docstring.
    assert code.startswith('"""Database helpers."""\nimport os\nimport sys')
    # "!" isn't in the safe-unquoted character set, so the value is quoted.
    assert 'DB_PASSWORD="hunter2!xyz"' in (tmp_path / ".env").read_text(encoding="utf-8")


def test_dry_run_changes_nothing(tmp_path):
    original = f'const key = "{FAKE_OPENAI}";\n'
    app = write(tmp_path, "app.ts", original)

    exit_code = run_scan(tmp_path, dry_run=True, no_color=True)

    assert app.read_text(encoding="utf-8") == original
    assert not (tmp_path / ".env").exists()
    assert exit_code == 1  # problems remain


def test_answering_no_changes_nothing(tmp_path):
    original = f'const key = "{FAKE_OPENAI}";\n'
    app = write(tmp_path, "app.ts", original)

    # A fake `ask` function that always answers "n". This is the function-
    # as-dependency trick described in cli.run_scan.
    exit_code = run_scan(tmp_path, no_color=True, ask=lambda prompt: "n")

    assert app.read_text(encoding="utf-8") == original
    assert exit_code == 1


def test_placeholders_and_non_secrets_are_ignored(tmp_path):
    write(tmp_path, "config.py",
          'api_key = "your-api-key-here"\n'     # placeholder
          'TOKEN_URL = "https://example.com/t"\n'  # name ends in URL
          'password_field = "password123"\n'    # name ends in FIELD
          'secret_env = "STRIPE_SECRET_KEY"\n'  # an env-var name, not a value
          '# password = "hunter2!xyz"\n')       # inside a comment

    findings = engine.scan(tmp_path).findings

    assert [f for f in findings if f.rule_id.startswith("SEC")] == []


def test_jsx_attribute_gets_braces(tmp_path):
    app = write(tmp_path, "Map.jsx", f'export const M = () => <Widget apiKey="{FAKE_OPENAI}" />;\n')

    run_scan(tmp_path, assume_yes=True, no_color=True)

    assert 'apiKey={process.env.OPENAI_API_KEY}' in app.read_text(encoding="utf-8")


def test_same_key_in_two_files_is_written_once(tmp_path):
    write(tmp_path, "a.js", f'const k = "{FAKE_STRIPE}";\n')
    write(tmp_path, "b.js", f'const k = "{FAKE_STRIPE}";\n')

    run_scan(tmp_path, assume_yes=True, no_color=True)

    assert (tmp_path / ".env").read_text(encoding="utf-8").count("STRIPE_SECRET_KEY=") == 1


def test_key_inside_longer_string_is_reported_not_rewritten(tmp_path):
    original = f'const header = "Bearer {FAKE_OPENAI}";\n'
    app = write(tmp_path, "api.js", original)

    findings = engine.scan(tmp_path).findings
    sec = [f for f in findings if f.rule_id == "SEC-001"]

    assert len(sec) == 1 and sec[0].fix is None  # detected, but no automatic fix
    assert app.read_text(encoding="utf-8") == original


def test_mask_never_shows_the_whole_secret():
    shown = mask(FAKE_STRIPE, reveal=True)
    assert FAKE_STRIPE not in shown
    assert shown.endswith(FAKE_STRIPE[-4:])
    assert mask("hunter2!xyz", reveal=False) == "••••••••"


def test_env_names():
    assert to_env_name("stripeKey") == "STRIPE_KEY"
    assert to_env_name("db-password") == "DB_PASSWORD"
    assert to_env_name("apiKey2") == "API_KEY2"
