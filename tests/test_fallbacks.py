"""
SEC-004: a backup secret anyone can guess.

    process.env.JWT_SECRET || 'superSecret'

If the real secret is missing, the app uses a word written in its code.
The fix removes the backup (so the app stops instead) and puts a fresh
secret in .env (so it still works on this computer).
"""

from pathlib import Path

from decaloguex import cli, engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def backups(folder: Path) -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id == "SEC-004"]


def fix(folder: Path) -> None:
    cli.run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


def env_of(folder: Path) -> str:
    return (folder / ".env").read_text(encoding="utf-8")


def test_javascript_backup_is_removed_and_a_random_secret_goes_in_env(tmp_path):
    # js-1-express-realworld: src/app/routes/auth/auth.ts
    app = write(tmp_path, "auth.js", "require('dotenv').config();\n"
                                     "const secret = process.env.JWT_SECRET || 'superSecret';\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "superSecret" not in code
    assert "process.env.JWT_SECRET || (() => { throw new Error(\"JWT_SECRET isn't set\"); })()" in code
    env = env_of(tmp_path)
    assert "JWT_SECRET=" in env and "superSecret" not in env  # a new random one, not the guessable word


def test_a_database_password_keeps_its_value(tmp_path):
    # A database password has to match the database, so a random one would lock you out.
    app = write(tmp_path, "settings.py", "import os\nfrom dotenv import load_dotenv\nload_dotenv()\n"
                                         "DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres123')\n")
    fix(tmp_path)
    assert 'DB_PASSWORD = os.environ["DB_PASSWORD"]' in app.read_text(encoding="utf-8")
    assert "DB_PASSWORD=postgres123" in env_of(tmp_path)


def test_ruby_csharp_and_kotlin(tmp_path):
    write(tmp_path, "config.rb", 'SECRET = ENV.fetch("SECRET_KEY_BASE", "abc123")\n')
    write(tmp_path, "Auth.cs", 'var key = Environment.GetEnvironmentVariable("JWT_KEY") ?? "devkey";\n')
    write(tmp_path, "Auth.kt", 'val key = System.getenv("JWT_SECRET") ?: "devkey"\n')
    found = {f.path.name: f for f in backups(tmp_path)}
    assert set(found) == {"config.rb", "Auth.cs", "Auth.kt"}


def test_already_in_env_is_not_added_again(tmp_path):
    write(tmp_path, ".env", "JWT_SECRET=already-set-here\n")
    write(tmp_path, "auth.js", "require('dotenv').config();\nconst s = process.env.JWT_SECRET || 'x1';\n")
    fix(tmp_path)
    assert env_of(tmp_path).count("JWT_SECRET") == 1


def test_not_a_secret_or_no_backup_word_is_left_alone(tmp_path):
    write(tmp_path, "app.js", "const port = process.env.PORT || 3000;\n"
                              "const secret = process.env.JWT_SECRET || '';\n"
                              "const expires = process.env.TOKEN_EXPIRES_IN || '7d';\n"
                              "const secretSoftware = 'superSecret';\n"
                              "// const s = process.env.JWT_SECRET || 'inAComment';\n")
    assert backups(tmp_path) == []


def test_php_and_spring_get_instructions(tmp_path):
    write(tmp_path, "config.php", "<?php\n$key = getenv('APP_SECRET') ?: 'devsecret';\n")
    write(tmp_path, "src/main/resources/application.yml", "jwt:\n  secret: ${JWT_SECRET:mySecretKey}\n")
    found = backups(tmp_path)
    assert len(found) == 2 and all(f.fix is None and f.note for f in found)


def test_app_that_does_not_load_env_gets_instructions(tmp_path, monkeypatch):
    monkeypatch.delenv("DECALOGUEX_ENV_LOADED")  # the tests normally pretend every app loads .env
    write(tmp_path, "auth.js", "const secret = process.env.JWT_SECRET || 'superSecret';\n")
    found = backups(tmp_path)
    assert len(found) == 1 and found[0].fix is None


def test_backup_that_looks_like_a_password_is_reported_once(tmp_path):
    write(tmp_path, "auth.js", "require('dotenv').config();\n"
                               "const secret = process.env.SESSION_SECRET || 'Hunter2!secret';\n")
    rules = [f.rule_id for f in engine.scan(tmp_path).findings if f.rule_id.startswith("SEC")]
    assert rules == ["SEC-004"]


def test_test_files_are_not_changed(tmp_path):
    write(tmp_path, "tests/auth.test.js", "const s = process.env.JWT_SECRET || 'superSecret';\n")
    assert backups(tmp_path) == []


def test_flask_secret_key_gets_a_random_value_whatever_the_setting_is_called(tmp_path):
    # python-1-flask-realworld: conduit/settings.py. CONDUIT_SECRET doesn't sound
    # app-made, but it's stored in SECRET_KEY, which signs every login.
    app = write(tmp_path, "settings.py", "import os\nfrom dotenv import load_dotenv\nload_dotenv()\n\n"
                                         "class Config(object):\n"
                                         "    SECRET_KEY = os.environ.get('CONDUIT_SECRET', 'secret-key')  # TODO: Change me\n")
    fix(tmp_path)
    assert "SECRET_KEY = os.environ[\"CONDUIT_SECRET\"]  # TODO: Change me" in app.read_text(encoding="utf-8")
    env = env_of(tmp_path)
    assert "CONDUIT_SECRET=" in env and "secret-key" not in env


def test_a_guessable_database_password_backup_is_not_reported(tmp_path):
    # php-2-koel-music-app: config/database.php, for a CI test database. A backup
    # database password only works against a database set up with it; it isn't
    # an open door the way a guessable login key is.
    write(tmp_path, "config/database.php", "<?php\nreturn ['password' => env('DB_PASSWORD', 'postgres')];\n")
    write(tmp_path, "settings.py", "import os\nDB_PASSWORD = os.getenv('DB_PASSWORD', 'mysql')\n")
    assert backups(tmp_path) == []


def test_a_third_party_key_backup_that_is_just_a_word_is_not_reported(tmp_path):
    # A made-up word can't work as a real Stripe or OpenAI key, so it opens nothing.
    write(tmp_path, "pay.js", "const key = process.env.STRIPE_API_KEY || 'devkey';\n")
    assert backups(tmp_path) == []
