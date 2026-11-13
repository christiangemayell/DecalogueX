"""
Tests from testing DecalogueX on real open-source projects (round 1).

Each test here is a small copy of real code, from a real project, that
DecalogueX got wrong before it was fixed. The project each came from is
named in the test, so you can see the original.
"""

import json
import time
from pathlib import Path

from decaloguex import cli, engine
from decaloguex.rules import config_files

STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def found(folder: Path, prefix: str = "") -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id.startswith(prefix) and not f.rule_id.startswith("GIT")]


def fix(folder: Path) -> None:
    cli.run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


# --- 1. Test and example files ---------------------------------------------------

def test_test_files_are_never_changed(tmp_path):
    # koel: tests/Feature/ChangePasswordTest.php. A "change password" test needs
    # a password to type; rewriting it to getenv('NEW_PASSWORD') breaks the test.
    original = "<?php\n$this->putAs('api/me/password', ['new_password' => 'new-secret-1234'], $user);\n"
    test = write(tmp_path, "tests/Feature/ChangePasswordTest.php", original)
    write(tmp_path, "src/app.go", 'package main\n\nfunc login() { password := "Hunter2!secret" }\n')
    findings = found(tmp_path, "SEC")
    assert [f.path.name for f in findings] == ["app.go"]  # the test file isn't flagged...
    fix(tmp_path)
    assert test.read_text(encoding="utf-8") == original     # ...or changed


def test_a_real_key_in_a_test_is_still_reported_but_not_changed(tmp_path):
    original = f'const stripe = new Stripe("{STRIPE}");\n'
    test = write(tmp_path, "src/payments.test.js", original)
    [finding] = found(tmp_path, "SEC")
    assert finding.fix is None and "test" in finding.note
    fix(tmp_path)
    assert test.read_text(encoding="utf-8") == original


def test_seed_data_and_fixtures_count_as_tests(tmp_path):
    # monica: database/factories/UserFactory.php and app/Console/.../SetupDummyAccount.php
    write(tmp_path, "database/factories/UserFactory.php", "<?php\nreturn ['password' => 'admin123'];\n")
    write(tmp_path, "spec/fixtures/users.yml", "admin:\n  password: Sup3rS3cret!x\n")
    assert found(tmp_path, "SEC") == []
    assert engine.scan(tmp_path).blind_spots.test_files == 2


# --- 2. Only the name a value is STORED under counts -------------------------------

def test_go_import_lines_are_not_secrets(tmp_path):
    # gitea: cmd/admin_user_change_password.go
    write(tmp_path, "cmd/admin.go", 'package cmd\n\nimport (\n\t"gitea.dev/modules/auth/password"\n'
                                    '\t"gitea.dev/modules/optional2"\n)\n')
    assert found(tmp_path, "SEC") == []


def test_text_next_to_a_secret_name_is_not_a_secret(tmp_path):
    # koel: tests/.../PingTest.php (the same code outside a test folder)
    write(tmp_path, "src/Ping.php",
          "<?php\n$url = '/rest/ping.view?apiKey=' . $user->subsonic_api_key . '&f=jsonp&callback=x2';\n")
    assert found(tmp_path, "SEC") == []


def test_other_arguments_of_a_call_are_not_names(tmp_path):
    # gitea: models/migrations/v1_19/v239.go
    write(tmp_path, "m.go", 'package m\n\nfunc up() { x.Exec("UPDATE access_token SET scope = ?", "all,sudo2") }\n')
    assert found(tmp_path, "SEC") == []


def test_real_assignments_are_still_found(tmp_path):
    write(tmp_path, "a.php", "<?php\n$dbPassword = 'Hunter2!secret';\n$config = ['api_key' => 'abc123XYZ!def'];\n")
    write(tmp_path, "b.go", 'package b\n\nvar cfg = Config{Password: "Hunter2!secret"}\n')
    write(tmp_path, "c.kt", 'fun f() {\n    val apiSecret: String = "abc123XYZ!def"\n}\n')
    assert sorted(f.path.name for f in found(tmp_path, "SEC")) == ["a.php", "a.php", "b.go", "c.kt"]


# --- 3. Values that aren't secrets ---------------------------------------------------

def test_values_that_are_not_secrets(tmp_path):
    write(tmp_path, "scopes.go", 'package auth\n\nconst AccessTokenScopeReadUser = "read:user"\n')  # gitea
    write(tmp_path, "lang/ja/auth.php", "<?php\nreturn ['password' => 'パスワードが正しくありません。'];\n")  # monica
    write(tmp_path, "src/hash.php", "<?php\n$password = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';\n")
    write(tmp_path, "app.ini", "[db]\nSECRET_KEY   = $SECRET_KEY\nPASSWD  = ${DB_PASSWD}\n")  # gitea
    assert found(tmp_path, "SEC") == []


# --- 4. Settings files: only "name = value" at the start of a line --------------------

def test_library_names_in_build_files_are_not_secrets(tmp_path):
    # spring-realworld: build.gradle
    write(tmp_path, "build.gradle", "dependencies {\n    implementation 'io.jsonwebtoken:jjwt-api:0.11.2'\n}\n")
    assert found(tmp_path, "SEC") == []


def test_secrets_in_scripts_and_connection_strings_are_found(tmp_path):
    write(tmp_path, "deploy.sh", 'export STRIPE_SECRET="abc123XYZ!def"\n')
    write(tmp_path, "setup.ps1", '$env:API_KEY = "ghi456UVW!jkl"\n')  # a different value (the same one is grouped)
    # eShopOnWeb: appsettings.Docker.json
    write(tmp_path, "appsettings.json",
          '{ "Db": "Server=sql;User Id=sa;Password=@someThingComplicated1234" }\n')
    assert sorted(f.path.name for f in found(tmp_path, "SEC")) == ["appsettings.json", "deploy.sh", "setup.ps1"]


def test_very_long_lines_are_quick(tmp_path):
    # forem: spec/support/fixtures/vcr_cassettes/feeds_import.yml took 5 MINUTES,
    # because of one enormous line of recorded web page.
    long_line = "body: " + "token: abc_" * 80_000
    path = write(tmp_path, "data.yml", f"{long_line}\npassword: Hunter2!secret\n")
    started = time.perf_counter()
    findings = config_files.check(path)
    assert time.perf_counter() - started < 2
    assert [f.line for f in findings] == [2]  # the ordinary line is still checked


# --- 5. .then() only matters on servers ------------------------------------------------

def test_then_in_a_website_front_end_is_not_reported(tmp_path):
    # monica: 116 of these in resources/js (Vue pages that run in the browser)
    write(tmp_path, "resources/js/Pages/Contact.vue",
          '<script>\nimport axios from "axios";\naxios.post("/api").then((r) => show(r));\n</script>\n')
    write(tmp_path, "resources/js/app.js", 'import { createApp } from "vue";\nnavigator.serviceWorker.ready.then(go);\n')
    assert found(tmp_path, "ASYNC") == []


# --- 6. Go background tasks only matter in web handlers ---------------------------------

def test_go_goroutines_outside_web_handlers_are_left_alone(tmp_path):
    # gitea: over 100 of these, nearly all deliberate
    write(tmp_path, "worker.go", "package main\n\nfunc start() {\n\tgo func() {\n\t\tsync()\n\t}()\n\tgo serve()\n}\n")
    assert found(tmp_path, "ASYNC") == []


def test_go_goroutines_inside_web_handlers_are_still_fixed(tmp_path):
    write(tmp_path, "h.go", "package main\n\nfunc handle(w http.ResponseWriter, r *http.Request) {\n"
                            "\tgo func() {\n\t\tsendEmail()\n\t}()\n}\n")
    [finding] = found(tmp_path, "ASYNC")
    assert finding.rule_id == "ASYNC-006" and finding.fix is not None


# --- 7. Minified and generated files ------------------------------------------------

def test_minified_files_are_skipped_and_listed(tmp_path):
    # ktor-samples: chat/src/backendMain/resources/js/chat.js (one enormous line)
    write(tmp_path, "public/chat.js", 'const db = require("db");' + "a.then(b);" * 1_000 + "\n")
    write(tmp_path, "public/vendor.min.js", "x.then(y);\n")
    result = engine.scan(tmp_path)
    assert [f for f in result.findings if f.rule_id.startswith("ASYNC")] == []
    assert sorted(result.blind_spots.generated) == ["public/chat.js", "public/vendor.min.js"]


# --- 8. Smaller fixes --------------------------------------------------------------------

def test_env_template_spellings_are_not_secret_files(tmp_path):
    # laravel-realworld: .env.example.docker
    write(tmp_path, ".gitignore", "node_modules/\n")
    write(tmp_path, ".env.example.docker", "DB_PASSWORD=\n")
    assert [f for f in engine.scan(tmp_path).findings if f.rule_id.startswith("GIT")] == []


def test_go_client_error_status_names_are_left_alone(tmp_path):
    # gitea: modules/httplib/serve.go
    write(tmp_path, "serve.go", "package httplib\n\nfunc serve(w http.ResponseWriter, r *http.Request) {\n"
                                "\terr := check()\n\tif err != nil {\n"
                                "\t\thttp.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)\n\t}\n}\n")
    assert found(tmp_path, "ERR") == []


def test_kotlin_global_scope_with_arguments_is_reported_once(tmp_path):
    # ktor-samples: src/commonMain/kotlin/io/ktor/samples/mpp/client/Api.kt
    write(tmp_path, "Api.kt", "fun load() {\n    GlobalScope.launch(ApplicationDispatcher) {\n        fetch()\n    }\n}\n")
    assert len(found(tmp_path, "ASYNC")) == 1


def test_razor_and_erb_pages_are_checked(tmp_path):
    write(tmp_path, "Views/Pay.cshtml", f'@model PayModel\n<script>\nconst key = "{STRIPE}";\n</script>\n')
    write(tmp_path, "app/views/pay.html.erb", f'<%= form %>\n<script>\nconst key = "{STRIPE}";\n</script>\n')
    findings = found(tmp_path, "SEC")
    assert sorted(f.path.name for f in findings) == ["Pay.cshtml", "pay.html.erb"]
    assert all(f.line == 3 for f in findings)


def test_downloaded_libraries_are_skipped(tmp_path):
    write(tmp_path, "vendor/acme/lib/Client.php", "<?php\n$password = 'Hunter2!secret';\n")
    write(tmp_path, ".yarn/releases/yarn.cjs", "x.then(y);\n")
    assert engine.scan(tmp_path).files_checked == 0


def test_blind_spots_report_lists_tests_and_generated_files(tmp_path, capsys):
    write(tmp_path, "tests/test_app.py", "def test_a():\n    assert True\n")
    write(tmp_path, "static/app.min.js", "a();\n")
    cli.run_scan(tmp_path, no_color=True, no_animation=True, ask=lambda prompt: "n")
    shown = capsys.readouterr().out
    assert "1 test or example file" in shown and "1 minified or generated file" in shown
    report = json.loads((tmp_path / ".decaloguex" / "blind-spots.json").read_text(encoding="utf-8"))
    assert report["test_files_only_checked_for_real_keys"] == 1 and report["generated"] == ["static/app.min.js"]


def test_json_report_is_readable_when_saved_to_a_file(tmp_path):
    # Found while testing gitea, eShopOnWeb and chatwoot: on Windows, a --json
    # report saved to a file had "…" written in cp1252, not UTF-8, so other
    # programs couldn't read it. The report is now plain ASCII.
    import subprocess
    import sys
    write(tmp_path, "app.js", "app.get('/', async (req, res) => {\n"
                              "  try { await go() } catch (err) { res.status(500).send(err.message + 'some long text here') }\n});\n")
    out = subprocess.run([sys.executable, "-m", "decaloguex", "scan", str(tmp_path), "--json"],
                         capture_output=True)
    out.stdout.decode("ascii")  # fails if anything isn't plain ASCII
    assert json.loads(out.stdout)["findings"]
