"""
Tests for PHP, Java, C#, Go, Ruby, Kotlin, Swift and web pages (HTML, Vue, Svelte).

Each test writes one small file in the language, runs the scan with every
fix applied, and checks the result line by line.
"""

from pathlib import Path

from decaloguex import engine, languages
from decaloguex.cli import run_scan

# Built from pieces so this file never contains a full key (see test_secrets.py).
STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def fix(folder: Path) -> None:
    run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


def rule_ids(folder: Path) -> list[str]:
    return sorted(f.rule_id for f in engine.scan(folder).findings if not f.rule_id.startswith("GIT"))


def still_valid(path: Path) -> bool:
    """The fixed file must still be valid code."""
    return not languages.has_syntax_errors(languages.detect(path), path.read_bytes())


# --- PHP ----------------------------------------------------------------------

def test_php(tmp_path):
    app = write(tmp_path, "checkout.php",
                "<?php\n"
                f'$stripeKey = "{STRIPE}";\n'
                "$pdo = new PDO($dsn);\n"
                '$result = $pdo->query("SELECT * FROM orders WHERE id = $id");\n'
                "try {\n    charge();\n} catch (Exception $e) {\n"
                "    echo 'Payment failed: ' . $e->getMessage();\n}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "$stripeKey = getenv('STRIPE_SECRET_KEY');" in code
    assert "$result = $pdo->prepare('SELECT * FROM orders WHERE id = ?');\n$result->execute([$id]);" in code
    assert "    error_log((string) $e);\n    echo 'Something went wrong. Please try again.';" in code
    assert still_valid(app)


# --- Java ---------------------------------------------------------------------

def test_java(tmp_path):
    app = write(tmp_path, "Orders.java",
                "class Orders {\n"
                f'    String apiKey = "{STRIPE}";\n'
                "    void go() { CompletableFuture.runAsync(() -> sync()); }\n"
                "    Object get() {\n        try {\n            return load();\n"
                "        } catch (Exception e) {\n"
                "            return ResponseEntity.status(500).body(e.getMessage());\n        }\n    }\n}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'String apiKey = System.getenv("STRIPE_SECRET_KEY");' in code
    assert ".exceptionally(asyncError -> { asyncError.printStackTrace(); return null; })" in code
    assert 'e.printStackTrace();\n            return ResponseEntity.status(500).body("Something went wrong.' in code
    assert still_valid(app)


def test_java_sql_gets_instructions(tmp_path):
    write(tmp_path, "Repo.java",
          'class Repo { void f() { stmt.executeQuery("SELECT * FROM users WHERE id = " + id); } }\n')
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "SQL-001"]
    assert finding.fix is None and "PreparedStatement" in finding.note


# --- C# -----------------------------------------------------------------------

def test_csharp(tmp_path):
    app = write(tmp_path, "Orders.cs",
                "class Orders {\n"
                '    string password = "Hunter2!secretpw";\n'
                "    async void Refresh() { await Load(); }\n"
                "    void OnClick(object sender, EventArgs e) { }\n"
                "    IActionResult Get() {\n        try {\n            return Ok(Load());\n"
                "        } catch (Exception ex) {\n            return StatusCode(500, ex.Message);\n        }\n    }\n}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'System.Environment.GetEnvironmentVariable("PASSWORD")' in code
    assert "async System.Threading.Tasks.Task Refresh()" in code
    assert 'return StatusCode(500, "Something went wrong. Please try again.");' in code
    assert still_valid(app)


def test_csharp_bad_request_is_left_alone(tmp_path):
    write(tmp_path, "Api.cs",
          "class Api { IActionResult Post() { try { Save(); return Ok(); } "
          "catch (Exception ex) { return BadRequest(ex.Message); } } }\n")
    assert "ERR-001" not in rule_ids(tmp_path)


# --- Go -----------------------------------------------------------------------

GO_HANDLER = (
    "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\n"
    "func handler(w http.ResponseWriter, r *http.Request) {\n"
    f'\tapiKey := "{STRIPE}"\n'
    '\trows, err := db.Query("SELECT * FROM orders WHERE id = " + id)\n'
    "\tif err != nil {\n\t\thttp.Error(w, err.Error(), 500)\n\t\treturn\n\t}\n"
    "\tgo func() {\n\t\tsendEmail()\n\t}()\n"
    "\tfmt.Println(apiKey, rows, os.Args)\n}\n"
)


def test_go(tmp_path):
    write(tmp_path, "go.mod", "module shop\n\nrequire github.com/lib/pq v1.10.9\n")
    app = write(tmp_path, "main.go", GO_HANDLER)
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'apiKey := os.Getenv("STRIPE_SECRET_KEY")' in code
    assert 'db.Query("SELECT * FROM orders WHERE id = $1", id)' in code  # PostgreSQL: $1
    assert 'http.Error(w, "Something went wrong. Please try again.", 500)' in code
    assert "defer func() {" in code and "recover()" in code
    assert still_valid(app)


def test_go_mysql_uses_question_marks(tmp_path):
    write(tmp_path, "go.mod", "module shop\n\nrequire github.com/go-sql-driver/mysql v1.8.0\n")
    app = write(tmp_path, "main.go", GO_HANDLER)
    fix(tmp_path)
    assert 'db.Query("SELECT * FROM orders WHERE id = ?", id)' in app.read_text(encoding="utf-8")


def test_go_secret_without_os_import_gets_instructions(tmp_path):
    write(tmp_path, "main.go", f'package main\n\nfunc f() {{\n\tkey := "{STRIPE}"\n\t_ = key\n}}\n')
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "SEC-001"]
    assert finding.fix is None and 'import "os"' in finding.note


# --- Ruby ---------------------------------------------------------------------

def test_ruby(tmp_path):
    app = write(tmp_path, "orders_controller.rb",
                "class OrdersController\n"
                f'  STRIPE = "{STRIPE}"\n'
                "  def show\n"
                "    Order.where(\"customer = '#{params[:name]}'\")\n"
                "  rescue => e\n"
                "    render json: { error: e.message }, status: 500\n"
                "  end\nend\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'STRIPE = ENV["STRIPE_SECRET_KEY"]' in code
    assert "Order.where('customer = ?', params[:name])" in code
    assert "    warn e.full_message\n    render json: { error: \"Something went wrong." in code
    assert still_valid(app)


# --- Kotlin and Swift -----------------------------------------------------------

def test_kotlin(tmp_path):
    app = write(tmp_path, "Orders.kt",
                "fun load() {\n"
                f'    val apiKey = "{STRIPE}"\n'
                "    GlobalScope.launch { work() }\n"
                "    try {\n        x()\n    } catch (e: Exception) {\n"
                "        call.respond(HttpStatusCode.InternalServerError, e.message)\n    }\n}\n")
    ids = rule_ids(tmp_path)
    assert "ASYNC-008" in ids  # reported with instructions
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'val apiKey = System.getenv("STRIPE_SECRET_KEY")' in code
    assert "e.printStackTrace()\n        call.respond(HttpStatusCode.InternalServerError, \"Something" in code


def test_swift(tmp_path):
    app = write(tmp_path, "Keys.swift", f'import Foundation\nlet apiKey = "{STRIPE}"\nTask {{ try await work() }}\n')
    assert "ASYNC-009" in rule_ids(tmp_path)
    fix(tmp_path)
    assert 'let apiKey = (ProcessInfo.processInfo.environment["STRIPE_SECRET_KEY"] ?? "")' in \
        app.read_text(encoding="utf-8")


def test_constants_are_not_rewritten(tmp_path):
    # A constant is fixed when the program is built, so it can't read the
    # environment. Changing it would break the build: report instead.
    write(tmp_path, "Keys.cs", f'class Keys {{ const string Key = "{STRIPE}"; }}\n')
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "SEC-001"]
    assert finding.fix is None and "constant" in finding.note


# --- Web pages ------------------------------------------------------------------

def test_vue_script_is_checked(tmp_path):
    page = write(tmp_path, "App.vue",
                 "<template><div>{{ total }}</div></template>\n"
                 "<script setup>\n"
                 'fetch("/api").then((r) => r.json()).then(show)\n'
                 "</script>\n")
    fix(tmp_path)
    assert '.then(show).catch((err) => console.error(err))' in page.read_text(encoding="utf-8")


def test_key_in_browser_code_gets_honest_advice(tmp_path):
    # .env can't hide a key from the visitor's browser, so it's not "fixed".
    write(tmp_path, "index.html", f'<html><script>\nconst key = "{STRIPE}";\n</script></html>\n')
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "SEC-001"]
    assert finding.fix is None and "browser" in finding.note
    assert finding.line == 2  # the line in the real file, not just inside the script


def test_script_only_keeps_positions():
    page = b"<p>hi</p>\n<script>let a = 1;</script>\n<b>x</b>"
    masked = languages.script_only(page)
    assert len(masked) == len(page)                 # same length...
    assert masked.index(b"let a") == page.index(b"let a")  # ...same positions
    assert b"<p>" not in masked                      # markup blanked out
