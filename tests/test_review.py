"""
Tests added during the pre-launch code review.

Each test here proves one real problem that the review found. Every one of
them FAILED before its fix was written, and passes now. They stay in the
suite so the same mistakes can't creep back in.

They're grouped the way the review was prioritised:
  1. Wrong fixes        a "fix" that would break or change the program
  2. False alarms       ordinary code reported as a problem
  3. Safety features    undo, telemetry, crash-proofing
  4. Speed
"""

import json
from pathlib import Path

import pytest

from decaloguex import cli, engine, languages, telemetry, undo

# Built from pieces so this file never contains a full key (see test_secrets.py).
STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def fix(folder: Path) -> None:
    cli.run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


def found(folder: Path, prefix: str) -> list:
    """The findings whose rule ID starts with `prefix`, e.g. "SEC"."""
    return [f for f in engine.scan(folder).findings if f.rule_id.startswith(prefix)]


# ===========================================================================
# 1. WRONG FIXES: secrets
# ===========================================================================

def test_secret_is_not_moved_if_the_app_never_loads_env(tmp_path, monkeypatch):
    # Moving a key into .env only works if the app READS .env when it starts.
    # Plain Node and Python don't. Without that, the app would start with an
    # empty key and break, so the tool must explain instead of "fixing".
    monkeypatch.delenv("DECALOGUEX_ENV_LOADED")
    original = f'const stripe = new Stripe("{STRIPE}");\n'
    app = write(tmp_path, "server.js", original)

    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None and "dotenv" in finding.note
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original
    assert not (tmp_path / ".env").exists()


def test_secret_is_moved_once_the_app_loads_env(tmp_path, monkeypatch):
    monkeypatch.delenv("DECALOGUEX_ENV_LOADED")
    write(tmp_path, "index.js", 'require("dotenv").config();\nrequire("./server");\n')
    app = write(tmp_path, "server.js", f'const stripe = new Stripe("{STRIPE}");\n')
    fix(tmp_path)
    assert "process.env.STRIPE_SECRET_KEY" in app.read_text(encoding="utf-8")


@pytest.mark.parametrize("manifest, content, source, code, expected", [
    # Next.js loads .env by itself.
    ("package.json", '{"dependencies": {"next": "^15.0.0"}}', "lib.js", 'const k = "{KEY}";\n', "process.env."),
    ("requirements.txt", "flask\npython-dotenv\n", "app.py", 'API_KEY = "{KEY}"\n', "os.environ.get("),
    ("composer.json", '{"require": {"vlucas/phpdotenv": "^5.6"}}', "a.php", '<?php\n$apiKey = "{KEY}";\n', "getenv("),
    ("Gemfile", 'gem "dotenv"\n', "a.rb", 'api_key = "{KEY}"\n', "ENV["),
])
def test_env_loading_is_recognised_from_the_project_files(tmp_path, monkeypatch, manifest, content, source, code, expected):
    monkeypatch.delenv("DECALOGUEX_ENV_LOADED")
    write(tmp_path, manifest, content)
    app = write(tmp_path, source, code.replace("{KEY}", STRIPE))
    fix(tmp_path)
    assert expected in app.read_text(encoding="utf-8")


@pytest.mark.parametrize("source, code, hint", [
    ("app.py", 'API_KEY = "{KEY}"\n', "python-dotenv"),
    ("a.php", '<?php\n$apiKey = "{KEY}";\n', "phpdotenv"),
    ("A.java", 'class A {{ String apiKey = "{KEY}"; }}\n', "dotenv"),
    ("a.rb", 'api_key = "{KEY}"\n', "dotenv"),
])
def test_other_languages_also_need_env_loading(tmp_path, monkeypatch, source, code, hint):
    monkeypatch.delenv("DECALOGUEX_ENV_LOADED")
    original = code.replace("{KEY}", STRIPE).replace("{{", "{").replace("}}", "}")
    app = write(tmp_path, source, original)
    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None and hint in finding.note
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_browser_code_is_not_given_process_env(tmp_path):
    # In a Vite/React app, `process` doesn't exist in the browser, so
    # process.env.X crashes the page. And a key in browser code is public
    # anyway: the only real fix is moving that code to a server.
    write(tmp_path, "package.json", '{"dependencies": {"react": "^18.0.0", "vite": "^5.0.0"}}')
    original = f'import React from "react";\nconst ai = new OpenAI({{ apiKey: "{STRIPE}" }});\n'
    app = write(tmp_path, "App.jsx", original)
    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None and "browser" in finding.note
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_use_client_file_is_browser_code_even_in_nextjs(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "^15.0.0"}}')
    write(tmp_path, "Pay.tsx", f'"use client";\nconst key = "{STRIPE}";\n')
    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None and "browser" in finding.note


def test_typescript_gets_a_non_null_mark(tmp_path):
    # process.env.X has the type `string | undefined`. Under TypeScript's
    # strict mode, putting that where a `string` is expected stops the
    # build. The ! tells TypeScript "this will be set".
    app = write(tmp_path, "pay.ts", f'const key: string = "{STRIPE}";\n')
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == "const key: string = process.env.STRIPE_SECRET_KEY!;\n"


def test_php_values_that_must_be_constant_are_not_rewritten(tmp_path):
    # PHP only allows fixed values in these three places. Putting getenv()
    # there is a fatal error: the whole page stops loading.
    original = (
        "<?php\n"
        "class Config {\n"
        f'    private $apiKey = "{STRIPE}";\n'            # a property's starting value
        f'    public function pay($key = "{STRIPE}") {{\n'  # a parameter's default
        f'        static $cached = "{STRIPE}";\n'           # a static variable
        "    }\n}\n"
    )
    app = write(tmp_path, "Config.php", original)
    findings = found(tmp_path, "SEC")
    assert len(findings) == 3 and all(f.fix is None for f in findings)
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_csharp_default_parameter_is_not_rewritten(tmp_path):
    # C# default values must be known when the program is built.
    write(tmp_path, "Pay.cs", f'class Pay {{ void Charge(string key = "{STRIPE}") {{ }} }}\n')
    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None


# ===========================================================================
# 1. WRONG FIXES: error messages
# ===========================================================================

def test_shorthand_error_keeps_its_key_name(tmp_path):
    # { err } means { err: err }. The app reading the response expects the
    # key "err", so the fix must not rename it to "error".
    app = write(tmp_path, "a.js", "try { a(); } catch (err) {\n  res.status(500).json({ err });\n}\n")
    fix(tmp_path)
    assert 'res.status(500).json({ err: "Something went wrong. Please try again." });' in app.read_text(encoding="utf-8")


def test_status_chosen_at_run_time_is_left_to_a_human(tmp_path):
    # `err.status || 500` also sends deliberate messages like 404 "Not found".
    # Replacing the text would hide those from users, so only report it.
    original = "app.use((err, req, res, next) => {\n  res.status(err.status || 500).json({ message: err.message });\n});\n"
    app = write(tmp_path, "a.js", original)
    [finding] = found(tmp_path, "ERR")
    assert finding.fix is None
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_python_status_chosen_at_run_time_is_left_to_a_human(tmp_path):
    write(tmp_path, "a.py",
          "def view():\n    try:\n        work()\n    except Exception as e:\n"
          '        return jsonify({"error": str(e)}), e.code\n')
    [finding] = found(tmp_path, "ERR")
    assert finding.fix is None


def test_error_is_logged_when_existing_log_line_leaves_it_out(tmp_path):
    # console.log('save failed') doesn't record WHAT failed. If the error
    # also vanished from the response, nobody could ever find the cause.
    app = write(tmp_path, "a.js",
                "try { a(); } catch (err) {\n  console.log('save failed');\n  res.status(500).send(err.message);\n}\n")
    fix(tmp_path)
    assert "console.error(err);" in app.read_text(encoding="utf-8")


def test_python_error_is_logged_when_existing_print_leaves_it_out(tmp_path):
    app = write(tmp_path, "a.py",
                "def view():\n    try:\n        work()\n    except Exception as e:\n"
                '        print("save failed")\n'
                '        return jsonify({"error": str(e)}), 500\n')
    fix(tmp_path)
    assert 'logging.exception("Unhandled error")' in app.read_text(encoding="utf-8")


def test_go_response_call_is_kept(tmp_path):
    # The fix once replaced the WHOLE call with a bare string, deleting the
    # response. Only the error text inside it may change.
    app = write(tmp_path, "h.go",
                "package main\n\nfunc show(c *gin.Context) {\n\terr := load()\n\tif err != nil {\n"
                "\t\tc.String(500, err.Error())\n\t\treturn\n\t}\n}\n")
    fix(tmp_path)
    assert 'c.String(500, "Something went wrong. Please try again.")' in app.read_text(encoding="utf-8")


def test_go_code_outside_web_handlers_is_left_alone(tmp_path):
    # `if err != nil` is everywhere in Go, not just in web handlers. Writing
    # an error into a text buffer or a file isn't "showing it to visitors".
    original = ("package main\n\nfunc collect(buf *strings.Builder) {\n\terr := step()\n\tif err != nil {\n"
                "\t\tbuf.WriteString(err.Error())\n\t}\n}\n")
    app = write(tmp_path, "m.go", original)
    assert found(tmp_path, "ERR") == []
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


# ===========================================================================
# 1. WRONG FIXES: async
# ===========================================================================

def test_await_is_not_added_to_another_class_s_normal_method(tmp_path):
    # Class A has an async run(); class B has a normal run(). `await` on B's
    # normal method would crash with "object can't be used in 'await'".
    original = ("class A:\n    async def run(self):\n        ...\n\n"
                "class B:\n    def run(self):\n        ...\n    async def go(self):\n        self.run()\n")
    app = write(tmp_path, "a.py", original)
    assert found(tmp_path, "ASYNC") == []
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_async_generators_and_decorated_functions_are_not_awaited(tmp_path):
    # An `async def` with `yield` is a generator: `await` on it crashes.
    # A decorator can turn an async function into something else entirely.
    write(tmp_path, "a.py",
          "async def ticks():\n    yield 1\n\n"
          "@background\nasync def job():\n    ...\n\n"
          "async def main():\n    ticks()\n    job()\n")
    findings = found(tmp_path, "ASYNC")
    assert [f.line for f in findings] == [10]       # only job() is reported...
    assert findings[0].fix is None                   # ...and it isn't changed


def test_cypress_chains_do_not_get_catch(tmp_path):
    # Cypress commands have .then() but no .catch(): adding one crashes the test.
    write(tmp_path, "spec.js", "cy.get('#save').then((button) => check(button));\n")
    assert found(tmp_path, "ASYNC") == []


def test_route_that_already_uses_the_name_next_is_left_to_a_human(tmp_path):
    # Adding a `next` parameter next to `const next = ...` is a syntax error
    # ("already declared") that only shows up when the app starts.
    write(tmp_path, "s.js",
          'const express = require("express");\napp.get("/", async (req, res) => {\n'
          "  const next = await page(req);\n  res.json(next);\n});\n")
    [finding] = found(tmp_path, "ASYNC")
    assert finding.fix is None


def test_csharp_async_void_is_only_changed_when_nothing_else_depends_on_it(tmp_path):
    app = write(tmp_path, "Page.cs",
                "class Page : Base {\n"
                "    protected override async void OnAppearing() { await Load(); }\n"  # must match the base class
                "    async void Tick() { await Load(); }\n"                              # used as an event handler
                "    private async void Refresh() { await Load(); }\n"                   # only ever called: safe
                "    void Wire() { timer.Elapsed += Tick; Refresh(); }\n"
                "}\n")
    by_line = {f.line: f for f in found(tmp_path, "ASYNC")}
    assert by_line[2].fix is None and by_line[3].fix is None and by_line[4].fix is not None
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "override async void OnAppearing" in code and "async void Tick" in code
    assert "private async System.Threading.Tasks.Task Refresh()" in code


def test_java_handler_does_not_reuse_a_name_in_scope(tmp_path):
    # Java forbids a lambda parameter named like a nearby variable, and
    # `e` is what almost everyone calls the caught exception.
    app = write(tmp_path, "A.java",
                "class A { void f() {\n  try { x(); } catch (Exception e) {\n"
                "    CompletableFuture.runAsync(() -> retry());\n  }\n}}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert ".exceptionally(asyncError -> {" in code and "exceptionally(e ->" not in code


# ===========================================================================
# 1. WRONG FIXES: SQL
# ===========================================================================

def test_limit_is_left_to_a_human(tmp_path):
    # Values from a web form arrive as text. MySQL rejects LIMIT '10', so a
    # query that worked before would start failing.
    write(tmp_path, "a.js", 'const mysql = require("mysql2");\ndb.query(`SELECT * FROM posts LIMIT ${req.query.limit}`);\n')
    [finding] = found(tmp_path, "SQL")
    assert finding.fix is None and "whole number" in finding.note


def test_value_that_is_really_a_piece_of_sql_is_left_to_a_human(tmp_path):
    # This ${...} produces SQL text ('abc' with its quotes, or the word NULL),
    # not a plain value. As a placeholder it would compare against the
    # literal text "NULL" instead.
    write(tmp_path, "a.js",
          'const mysql = require("mysql2");\n'
          "db.query(`SELECT * FROM t WHERE owner = ${id ? `'${id}'` : \"NULL\"}`);\n")
    [finding] = found(tmp_path, "SQL")
    assert finding.fix is None


def test_percent_format_with_a_bundle_of_values_is_left_to_a_human(tmp_path):
    # `% params` hands over a ready-made tuple. Wrapping it again as
    # (params,) would pass the whole tuple as ONE value, which fails.
    write(tmp_path, "a.py", 'import sqlite3\ncur.execute("SELECT * FROM t WHERE a = %s" % params)\n')
    [finding] = found(tmp_path, "SQL")
    assert finding.fix is None


def test_php_curly_brace_values_are_fixed_properly(tmp_path):
    app = write(tmp_path, "a.php",
                "<?php\n$pdo = new PDO($dsn);\n"
                "$r = $pdo->query(\"SELECT * FROM t WHERE id = {$row['id']}\");\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "$r = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n$r->execute([$row['id']]);" in code


def test_php_file_using_mysqli_too_is_left_to_a_human(tmp_path):
    # mysqli's prepared statements work differently from PDO's, and the
    # tool can't tell which kind of connection $db is.
    write(tmp_path, "a.php",
          "<?php\n$pdo = new PDO($dsn);\n$db = new mysqli($host);\n"
          '$r = $db->query("SELECT * FROM t WHERE id = $id");\n')
    [finding] = found(tmp_path, "SQL")
    assert finding.fix is None


# ===========================================================================
# 2. FALSE ALARMS
# ===========================================================================

@pytest.mark.parametrize("name, code", [
    # Words shown on screen, not passwords.
    ("labels.js", 'const labels = { username: "Username", password: "Password", token: "Contraseña" };\n'),
    # The NAME of a storage slot, not the token itself.
    ("auth.js", 'const TOKEN_KEY = "auth_token";\nlocalStorage.getItem(TOKEN_KEY);\n'),
    # Laravel validation rules.
    ("c.php", "<?php\n$request->validate(['password' => 'required|min:8']);\n"),
    # Go struct tags describe JSON field names.
    ("m.go", 'package main\n\ntype User struct {\n\tPassword string `json:"password"`\n\tToken string `json:"auth_token"`\n}\n'),
    # A template placeholder.
    ("mail.py", 'reset = {"token": "{{reset_token_value}}"}\n'),
])
def test_names_and_labels_are_not_secrets(tmp_path, name, code):
    app = write(tmp_path, name, code)
    assert found(tmp_path, "SEC") == []
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == code


def test_ordinary_words_containing_sk_dash_are_not_openai_keys(tmp_path):
    write(tmp_path, "a.js", 'const cls = "task-management-dashboard";\nconst url = "/risk-assessment-questionnaire";\n')
    assert found(tmp_path, "SEC") == []


# ===========================================================================
# 3. SAFETY FEATURES
# ===========================================================================

def test_a_file_edited_after_the_scan_is_not_patched(tmp_path):
    # The tool waits for an answer after scanning. If the file changes in
    # that time (an editor's auto-save, say), the planned edit would land in
    # the wrong place and scramble the code.
    app = write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    result = engine.scan(tmp_path)
    changed = '# a new first line\nDB_PASSWORD = "hunter2!xyz"\n'
    app.write_text(changed, encoding="utf-8")

    outcome = engine.apply_fixes(result.findings, result.root, result.fingerprints)

    assert app.read_text(encoding="utf-8") == changed
    assert [f.rule_id for f in outcome.rejected] == ["SEC-002"]


def test_undo_still_works_if_fixing_was_interrupted(tmp_path, monkeypatch):
    # Ctrl+C (or a crash) halfway through used to leave changed files with
    # no way back, because the backup's index was only written at the end.
    original = 'DB_PASSWORD = "hunter2!xyz"\n'
    app = write(tmp_path, "app.py", original)
    result = engine.scan(tmp_path)

    def interrupted(append):
        raise KeyboardInterrupt
    monkeypatch.setattr(engine, "append_to_file", interrupted)
    with pytest.raises(KeyboardInterrupt):
        engine.apply_fixes(result.findings, result.root)
    assert app.read_text(encoding="utf-8") != original  # half-done

    assert cli.run_undo(tmp_path, assume_yes=True, no_color=True) == 0
    assert app.read_text(encoding="utf-8") == original


def test_a_file_that_cannot_be_written_is_skipped_not_fatal(tmp_path):
    app = write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    result = engine.scan(tmp_path)
    app.chmod(0o444)  # read-only
    try:
        outcome = engine.apply_fixes([f for f in result.findings if f.rule_id == "SEC-002"], result.root)
    finally:
        app.chmod(0o644)
    assert [f.rule_id for f in outcome.rejected] == ["SEC-002"]
    assert not (tmp_path / ".env").exists()  # and its secret was NOT moved


def test_a_file_that_cannot_be_read_does_not_stop_the_scan(tmp_path, monkeypatch):
    write(tmp_path, "locked.py", "x = 1\n")
    write(tmp_path, "app.py", 'DB_PASSWORD = "hunter2!xyz"\n')
    real_load = languages.load

    def load(path):
        if path.name == "locked.py":
            raise PermissionError("locked")
        return real_load(path)
    monkeypatch.setattr(languages, "load", load)

    result = engine.scan(tmp_path)
    assert [f.rule_id for f in result.findings if f.rule_id.startswith("SEC")] == ["SEC-002"]
    assert result.blind_spots.tripped == [{"path": "locked.py", "rule": "read", "error": "PermissionError"}]


def test_nothing_is_sent_before_the_notice_has_been_shown(monkeypatch):
    # People must be TOLD about usage stats before any are sent, so the
    # very first run only shows the notice.
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    monkeypatch.setenv("DECALOGUEX_POSTHOG_KEY", "phc_test")
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda payload: sent.append(payload))

    telemetry.send("scan_completed", {})      # first run: not told yet
    telemetry.finish()
    assert sent == []

    assert telemetry.take_notice() is not None  # now they've been told
    telemetry.send("scan_completed", {})
    telemetry.finish()
    assert len(sent) == 1
    assert sent[0]["properties"]["$geoip_disable"] is True  # and no location lookup


def test_a_first_time_user_is_told_first_and_still_counted(tmp_path, monkeypatch, capsys):
    # A beta tester ran DecalogueX once and never showed up in PostHog:
    # the notice came at the END, after the send had been skipped. Now it
    # comes at the start, so even a one-run user is told, then counted.
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    monkeypatch.setenv("DECALOGUEX_POSTHOG_KEY", "phc_test")
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda payload: sent.append(payload))
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    cli.run_scan(tmp_path, dry_run=True, no_color=True, no_animation=True)
    telemetry.finish()
    assert "anonymous usage stats" in capsys.readouterr().out
    assert len(sent) == 1

    cli.run_scan(tmp_path, dry_run=True, no_color=True, no_animation=True)  # second run: no notice again
    telemetry.finish()
    assert "anonymous usage stats" not in capsys.readouterr().out
    assert len(sent) == 2


def test_json_mode_first_run_is_told_then_counted(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DECALOGUEX_TELEMETRY")
    monkeypatch.setenv("DECALOGUEX_POSTHOG_KEY", "phc_test")
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda payload: sent.append(payload))
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    cli.run_json(tmp_path)
    telemetry.finish()
    output = capsys.readouterr()
    assert "anonymous usage stats" in output.err   # notice on stderr, JSON untouched
    json.loads(output.out)
    assert len(sent) == 1


# ===========================================================================
# 4. SPEED
# ===========================================================================

def test_a_long_string_in_many_pieces_does_not_stall_the_scan(tmp_path):
    # A string written as 3,000 short pieces (common in generated data
    # files) used to take about 50 SECONDS, because every piece made the
    # SQL rule re-read all 3,000. It should take a fraction of a second.
    import time
    pieces = "".join(f'    "line {n} of a very long piece of text "\n' for n in range(3000))
    write(tmp_path, "big.py", "TEXT = (\n" + pieces + ")\n")
    started = time.perf_counter()
    engine.scan(tmp_path)
    assert time.perf_counter() - started < 5  # generous, so slow computers still pass


def test_nodes_can_be_looked_up_by_type_in_file_order(tmp_path):
    # Rules used to walk the whole tree looking for a few node types. Now
    # the file hands each rule just the nodes it asked for.
    path = write(tmp_path, "a.py", 'a = "one"\nb = f(2)\nc = "three"\n')
    file = languages.load(path)
    assert [languages.text(n) for n in file.nodes_of("string")] == ['"one"', '"three"']
    mixed = [n.type for n in file.nodes_of("string", "call")]
    assert mixed == ["string", "call", "string"]  # still in the order they appear
