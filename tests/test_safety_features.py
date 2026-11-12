"""
Tests for the safety features: settings files, blind spots, crash-proofing,
undo, the JSON report and telemetry.
"""

import json
from pathlib import Path

from decaloguex import cli, engine, telemetry
from decaloguex.rules import secrets

STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def typing(*answers):
    """A fake keyboard (see test_cli.py)."""
    remaining = iter(answers)
    return lambda prompt: next(remaining)


# --- Settings files -------------------------------------------------------------

def test_secrets_in_settings_files_are_reported(tmp_path):
    write(tmp_path, "config.yml", "database:\n  host: localhost\n  password: Sup3rS3cretPass!\n")
    write(tmp_path, "appsettings.json", f'{{ "Stripe": {{ "ApiKey": "{STRIPE}" }} }}\n')
    write(tmp_path, ".env", f"STRIPE={STRIPE}\n")  # .env is the RIGHT place: not reported
    findings = [f for f in engine.scan(tmp_path).findings if f.rule_id.startswith("SEC")]
    assert sorted((f.path.name, f.line) for f in findings) == [("appsettings.json", 1), ("config.yml", 3)]
    assert all(f.fix is None for f in findings)  # report-only, with instructions


# --- Blind spots and crash-proofing ------------------------------------------

def test_unsupported_languages_are_listed(tmp_path):
    write(tmp_path, "main.rs", "fn main() {}\n")
    write(tmp_path, "lib.rs", "pub fn f() {}\n")
    write(tmp_path, "app.dart", "void main() {}\n")
    spots = engine.scan(tmp_path).blind_spots
    assert dict(spots.unsupported) == {"Rust": 2, "Dart": 1}


def test_a_tripped_rule_does_not_stop_the_scan(tmp_path, monkeypatch):
    # Make the SQL rule crash on purpose. The scan must carry on and list it.
    def broken_rule(file, info):
        raise IndexError("boom")
    monkeypatch.setattr(engine.sql, "check", broken_rule)
    write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')

    result = engine.scan(tmp_path)
    assert [f.rule_id for f in result.findings if f.rule_id.startswith("SEC")] == ["SEC-002"]  # still found
    assert result.blind_spots.tripped == [{"path": "app.py", "rule": "sql", "error": "IndexError"}]


def test_blind_spots_report_is_saved_and_kept_out_of_git(tmp_path):
    write(tmp_path, "main.rs", "fn main() {}\n")
    cli.run_scan(tmp_path, no_color=True, no_animation=True, ask=typing("n"))
    report = json.loads((tmp_path / ".decaloguex" / "blind-spots.json").read_text(encoding="utf-8"))
    assert report["unsupported_languages"] == {"Rust": 1}
    assert (tmp_path / ".decaloguex" / ".gitignore").read_text(encoding="utf-8").strip().endswith("*")


# --- Undo -----------------------------------------------------------------------

def test_undo_puts_everything_back(tmp_path):
    original = 'DB_PASSWORD = "hunter2!xyz"\n'
    app = write(tmp_path, "app.py", original)
    cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    assert app.read_text(encoding="utf-8") != original
    assert (tmp_path / ".env").exists() and (tmp_path / ".gitignore").exists()

    assert cli.run_undo(tmp_path, no_color=True) == 0

    assert app.read_text(encoding="utf-8") == original      # the code is back...
    assert not (tmp_path / ".env").exists()                 # ...and files the fix created are gone
    assert not (tmp_path / ".gitignore").exists()
    assert cli.run_undo(tmp_path, no_color=True) == 1       # nothing left to undo


def test_undo_asks_before_throwing_away_later_edits(tmp_path):
    app = write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    app.write_text(app.read_text(encoding="utf-8") + "print('my new work')\n", encoding="utf-8")

    assert cli.run_undo(tmp_path, no_color=True, ask=typing("n")) == 1
    assert "my new work" in app.read_text(encoding="utf-8")  # kept, because they said no


def test_only_ten_backups_are_kept(tmp_path):
    for number in range(12):
        write(tmp_path, f"app{number}.py", 'DB_PASSWORD = "hunter2!xyz"\n')
        cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    backups = [p for p in (tmp_path / ".decaloguex" / "undo").iterdir() if p.is_dir()]
    assert len(backups) == 10


# --- JSON for AI tools ----------------------------------------------------------

def test_json_report(tmp_path, capsys):
    write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    exit_code = cli.main(["scan", str(tmp_path), "--json"])
    report = json.loads(capsys.readouterr().out)
    [finding] = [f for f in report["findings"] if f["rule"] == "SEC-002"]
    assert finding["file"] == "app.py" and finding["line"] == 1 and finding["status"] == "fixable"
    assert "hunter2" not in json.dumps(report)  # secrets never appear in the report
    assert exit_code == 1


def test_json_with_yes_fixes_and_says_so(tmp_path, capsys):
    write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    cli.main(["scan", str(tmp_path), "--json", "--yes"])
    report = json.loads(capsys.readouterr().out)
    assert report["fixes_applied"] >= 1 and report["undo"] == "decaloguex undo"
    assert {f["status"] for f in report["findings"]} == {"fixed"}


# --- Telemetry --------------------------------------------------------------------

def test_stats_never_contain_code_paths_or_secrets(tmp_path):
    secret_folder = tmp_path / "my-secret-project"
    write(secret_folder, "billing.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    result = engine.scan(secret_folder)
    stats = json.dumps(telemetry.scan_stats(result, "all", result.findings))
    for private in ("hunter2", "billing", "my-secret-project", str(tmp_path)):
        assert private not in stats
    assert '"SEC-002": 1' in stats  # only rule IDs and counts


def test_telemetry_switches(monkeypatch):
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    assert telemetry.is_enabled()
    telemetry.set_enabled(False)
    assert not telemetry.is_enabled()
    telemetry.set_enabled(True)
    monkeypatch.setenv("DO_NOT_TRACK", "1")  # the standard "don't track me" setting wins
    assert not telemetry.is_enabled()


def test_notice_is_shown_exactly_once(monkeypatch):
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    assert telemetry.take_notice() is not None
    assert telemetry.take_notice() is None
    assert telemetry.take_notice() is None


def test_nothing_is_sent_without_a_key(monkeypatch):
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    monkeypatch.setattr(telemetry, "POSTHOG_API_KEY", "")
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda payload: sent.append(payload))
    telemetry.send("scan_completed", {})
    telemetry.finish()
    assert sent == []


def test_stats_are_sent_with_a_key(monkeypatch):
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    monkeypatch.setenv("DECALOGUEX_POSTHOG_KEY", "phc_test")
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda payload: sent.append(payload))
    telemetry.take_notice()  # nothing is sent until the user has seen the notice
    telemetry.send("scan_completed", {"files_total": 3})
    telemetry.finish()
    [payload] = sent
    assert payload["event"] == "scan_completed" and payload["properties"]["files_total"] == 3
    assert payload["properties"]["$process_person_profile"] is False
    assert payload["distinct_id"] == telemetry.install_id()  # the same random ID each time
