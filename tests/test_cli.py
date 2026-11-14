"""
Tests for the screen and the choices: fix all, one by one, or nothing.

The fake `ask` functions below stand in for a person typing. Each one
hands back the next answer from a list, like someone pressing keys.
"""

import re
from pathlib import Path

import json

from decaloguex.cli import run_scan
from decaloguex.explain import EXPLANATIONS

# Two separate problems in one file: two hard-coded passwords.
TWO_PROBLEMS = 'DB_PASSWORD = "hunter2!xyz"\nAPI_SECRET = "s3cr3t!value"\n'


def typing(*answers):
    """A fake keyboard: each call returns the next answer.

    iter() turns the list into an iterator, and next() takes one item at a
    time, like calling Iterator.next() in Java.
    """
    remaining = iter(answers)
    return lambda prompt: next(remaining)


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def test_fix_all(tmp_path):
    app = write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, ask=typing("a"))
    code = app.read_text(encoding="utf-8")
    assert "hunter2" not in code and "s3cr3t" not in code


def test_one_by_one_yes_then_no(tmp_path):
    app = write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, ask=typing("o", "y", "n", "n"))  # one by one: yes, no, then no to .gitignore
    code = app.read_text(encoding="utf-8")
    assert "hunter2" not in code    # the first was fixed...
    assert "s3cr3t!value" in code   # ...the second was skipped


def test_moving_a_secret_always_protects_env(tmp_path):
    # Fix the first password but say no to everything else, including the
    # .gitignore fix. The .gitignore fix must go in anyway, or the new .env
    # file holding the password could be uploaded.
    write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, ask=typing("o", "y", "n", "n"))
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_one_by_one_then_all_the_rest(tmp_path):
    app = write(tmp_path, "app.py", TWO_PROBLEMS)
    exit_code = run_scan(tmp_path, ask=typing("o", "a"))  # "a" fixes this one and everything after
    code = app.read_text(encoding="utf-8")
    assert "hunter2" not in code and "s3cr3t" not in code
    assert exit_code == 0


def test_one_by_one_then_skip_the_rest(tmp_path):
    original = TWO_PROBLEMS
    app = write(tmp_path, "app.py", original)
    exit_code = run_scan(tmp_path, ask=typing("o", "q"))  # "q" skips everything left
    assert app.read_text(encoding="utf-8") == original
    assert exit_code == 1


def test_just_pressing_enter_changes_nothing(tmp_path):
    app = write(tmp_path, "app.py", TWO_PROBLEMS)
    exit_code = run_scan(tmp_path, ask=typing(""))
    assert app.read_text(encoding="utf-8") == TWO_PROBLEMS
    assert exit_code == 1


def test_report_uses_plain_words(tmp_path, capsys):
    # capsys is a pytest fixture that captures everything printed.
    write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, dry_run=True)
    shown = capsys.readouterr().out
    assert "Password written in your code" in shown
    assert "hunter2" not in shown  # the secret itself is never printed


def test_every_rule_has_a_plain_explanation():
    # Find every rule ID the rules can produce, e.g. "SQL-001", in their source.
    rules_folder = Path(__file__).parent.parent / "decaloguex" / "rules"
    used = set()
    for rule_file in rules_folder.glob("*.py"):
        used |= set(re.findall(r'"((?:SEC|GIT|SQL|ERR|ASYNC|DEBUG|XSS|CORS|TLS|MASS)-\d{3})"',
                               rule_file.read_text(encoding="utf-8")))
    missing = used - EXPLANATIONS.keys()
    assert not missing, f"Add these to explain.py: {sorted(missing)}"


# --- The approval stamp -----------------------------------------------------------

def test_clean_code_gets_the_stamp(tmp_path, capsys):
    write(tmp_path, "app.py", "print('hello')\n")
    write(tmp_path, ".gitignore", ".env\n")
    run_scan(tmp_path)
    shown = capsys.readouterr().out
    assert "DECALOGUEX VERIFICATION COMPLETE" in shown and "A P P R O V E D" in shown


def test_fixing_everything_earns_the_stamp(tmp_path, capsys):
    write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, ask=typing("a"))
    assert "VERIFICATION COMPLETE" in capsys.readouterr().out


def test_no_stamp_while_problems_are_left(tmp_path, capsys):
    # Approving code that still has problems would be false advertising.
    write(tmp_path, "app.py", TWO_PROBLEMS)
    run_scan(tmp_path, ask=typing("o", "y", "n", "n"))  # fix one, skip the rest
    shown = capsys.readouterr().out
    assert "VERIFICATION COMPLETE" not in shown
    assert "Not approved yet" in shown


# --- Confidence levels: "sure" problems vs places "worth a look" --------------------------

def _maybe_project(tmp_path):
    (tmp_path / "page.js").write_text("el.innerHTML = userBio;\n", encoding="utf-8")       # worth a look
    (tmp_path / "app.py").write_text("DEBUG = True\n", encoding="utf-8")                    # sure


def test_worth_a_look_cards_are_hidden_by_default(tmp_path, capsys):
    _maybe_project(tmp_path)
    run_scan(tmp_path, dry_run=True, no_color=True, no_animation=True)
    shown = capsys.readouterr().out
    assert "Plus 1 place worth a look" in shown and "decaloguex scan --all" in shown
    assert "XSS-001" not in shown and "DEBUG-001" in shown


def test_all_shows_worth_a_look_cards(tmp_path, capsys):
    _maybe_project(tmp_path)
    run_scan(tmp_path, dry_run=True, no_color=True, no_animation=True, show_all=True)
    shown = capsys.readouterr().out
    assert "XSS-001" in shown and "worth a look" not in shown


def test_json_counts_worth_a_look_and_marks_confidence(tmp_path, capsys):
    from decaloguex.cli import run_json
    _maybe_project(tmp_path)
    run_json(tmp_path)
    report = json.loads(capsys.readouterr().out)
    rules = [f["rule"] for f in report["findings"]]
    assert report["worth_a_look"] == 1 and "DEBUG-001" in rules and "XSS-001" not in rules
    run_json(tmp_path, show_all=True)
    report = json.loads(capsys.readouterr().out)
    assert {f["confidence"] for f in report["findings"]} == {"sure", "worth_a_look"}
