"""
Build tests: do DecalogueX's fixes still COMPILE?

The other tests check what a fix looks like. These go one step further: they
take a small program full of mistakes in each language, let DecalogueX fix
everything, then build the result with that language's real tool. A fix
that reads well but doesn't compile would fail here.

Outside libraries (Spring, Entity Framework, kotlinx.coroutines...) are
replaced by small stand-ins ("stubs") with the same shape, so the programs
build without downloading anything.

Each test is skipped if its language's tool isn't installed on this computer.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from decaloguex.cli import run_scan

STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"


def needs(tool: str) -> str:
    """The tool's full path, or skip the test if it isn't installed."""
    path = shutil.which(tool)
    if path is None:
        pytest.skip(f"{tool} is not installed")
    return path


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def fix_everything(folder: Path) -> None:
    run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


def build(command: list[str], folder: Path, timeout: int = 300) -> None:
    """Run a build command and fail the test (showing its errors) if it fails."""
    result = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, f"build failed:\n{result.stdout}\n{result.stderr}"


def changed(path: Path, original: str) -> str:
    """The file's new text, after checking DecalogueX really changed it."""
    code = path.read_text(encoding="utf-8")
    assert code != original, "DecalogueX didn't fix anything, so the build proves nothing"
    return code


# --- Go -----------------------------------------------------------------------------

GO_APP = f"""package main

// database driver: github.com/lib/pq
import (
\t"database/sql"
\t"fmt"
\t"net/http"
\t"os"
)

var db *sql.DB

func sendEmail() {{}}

func handler(w http.ResponseWriter, r *http.Request) {{
\tid := r.URL.Query().Get("id")
\tapiKey := "{STRIPE}"
\trows, err := db.Query("SELECT * FROM orders WHERE id = " + id)
\tif err != nil {{
\t\thttp.Error(w, err.Error(), 500)
\t\treturn
\t}}
\tdefer rows.Close()
\tgo func() {{
\t\tsendEmail()
\t}}()
\tfmt.Fprintln(w, apiKey, len(os.Args))
}}

func main() {{ http.HandleFunc("/", handler) }}
"""


def test_go_fixes_build(tmp_path):
    go = needs("go")
    write(tmp_path, "go.mod", "module demo\n\ngo 1.21\n")
    app = write(tmp_path, "main.go", GO_APP)
    fix_everything(tmp_path)
    code = changed(app, GO_APP)
    assert "recover()" in code and "$1" in code and "os.Getenv" in code
    build([go, "build", "./..."], tmp_path)


# --- PHP ----------------------------------------------------------------------------

PHP_APP = f"""<?php
$stripeKey = "{STRIPE}";
$pdo = new PDO('sqlite::memory:');
$result = $pdo->query("SELECT * FROM orders WHERE id = $orderId");
echo $_GET['name'];
try {{
    charge($stripeKey);
}} catch (Exception $e) {{
    echo 'Payment failed: ' . $e->getMessage();
}}
"""


def test_php_fixes_build(tmp_path):
    php = needs("php")
    app = write(tmp_path, "checkout.php", PHP_APP)
    fix_everything(tmp_path)
    code = changed(app, PHP_APP)
    assert "prepare(" in code and "htmlspecialchars(" in code and "getenv(" in code
    build([php, "-l", str(app)], tmp_path)  # PHP has no compile step: -l is its syntax check


# --- Ruby ---------------------------------------------------------------------------

RUBY_APP = f"""class OrdersController
  STRIPE = "{STRIPE}"
  def show
    Order.where("customer = '#{{params[:name]}}'")
  rescue => e
    render json: {{ error: e.message }}, status: 500
  end
end
"""


def test_ruby_fixes_build(tmp_path):
    ruby = needs("ruby")
    app = write(tmp_path, "orders_controller.rb", RUBY_APP)
    fix_everything(tmp_path)
    code = changed(app, RUBY_APP)
    assert "where('customer = ?'" in code and 'ENV["STRIPE_SECRET_KEY"]' in code
    build([ruby, "-c", str(app)], tmp_path)  # -c checks the syntax without running it


# --- Java ---------------------------------------------------------------------------

JAVA_APP = f"""import java.util.List;
import java.util.concurrent.CompletableFuture;

interface RowMapper<T> {{ T map(Object row); }}

class JdbcTemplate {{
    <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {{ return null; }}
    int update(String sql, Object... args) {{ return 0; }}
}}

class ResponseEntity {{
    static Builder status(int code) {{ return new Builder(); }}
    static class Builder {{ Object body(Object value) {{ return value; }} }}
}}

public class Orders {{
    String apiKey = "{STRIPE}";
    JdbcTemplate jdbcTemplate = new JdbcTemplate();

    List<String> find(String id) {{
        return jdbcTemplate.query("SELECT name FROM orders WHERE id = " + id, row -> "x");
    }}

    Object get() {{
        try {{
            return load();
        }} catch (Exception e) {{
            CompletableFuture.runAsync(() -> sync());
            return ResponseEntity.status(500).body(e.getMessage());
        }}
    }}

    Object load() throws Exception {{ return null; }}
    void sync() {{}}
}}
"""


def test_java_fixes_build(tmp_path):
    javac = needs("javac")
    app = write(tmp_path, "Orders.java", JAVA_APP)
    fix_everything(tmp_path)
    code = changed(app, JAVA_APP)
    assert "WHERE id = ?\", row -> \"x\", id)" in code and "asyncError ->" in code
    build([javac, "-d", str(tmp_path / "out"), str(app)], tmp_path)


# --- C# -----------------------------------------------------------------------------

CSHARP_APP = f"""using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using Dapper;

namespace Dapper
{{
    public static class SqlMapper
    {{
        public static IEnumerable<T> Query<T>(this IDbConnection connection, string sql, object? param = null)
            => Enumerable.Empty<T>();
    }}
}}

public class DbSet<T> {{ }}

public static class EfStub
{{
    public static IQueryable<T> FromSqlRaw<T>(this DbSet<T> set, string sql, params object[] args)
        => Enumerable.Empty<T>().AsQueryable();
    public static IQueryable<T> FromSqlInterpolated<T>(this DbSet<T> set, FormattableString sql)
        => Enumerable.Empty<T>().AsQueryable();
}}

public class User {{ }}

public class Orders
{{
    string password = "Hunter2!secretpw";
    string jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "superSecret";
    DbSet<User> users = new DbSet<User>();
    IDbConnection connection = null!;

    object StatusCode(int code, object value) => value;
    object Ok(object value) => value;

    async void Refresh() {{ await System.Threading.Tasks.Task.Delay(1); }}

    public void Find(string id)
    {{
        var fromEf = users.FromSqlRaw($"SELECT * FROM users WHERE id = {{id}}").ToList();
        var fromDapper = connection.Query<User>($"SELECT * FROM users WHERE id = {{id}}");
        Refresh();
    }}

    public object Get()
    {{
        try
        {{
            return Ok(1);
        }}
        catch (Exception ex)
        {{
            return StatusCode(500, ex.Message);
        }}
    }}
}}

public static class Program {{ public static void Main() {{ }} }}
"""

CSHARP_PROJECT = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
  </PropertyGroup>
</Project>
"""


def test_csharp_fixes_build(tmp_path):
    dotnet = needs("dotnet")
    write(tmp_path, "Demo.csproj", CSHARP_PROJECT)
    app = write(tmp_path, "Orders.cs", CSHARP_APP)
    fix_everything(tmp_path)
    code = changed(app, CSHARP_APP)
    assert "FromSqlInterpolated(" in code and '"SELECT * FROM users WHERE id = @p0", new { p0 = id }' in code
    assert "async System.Threading.Tasks.Task Refresh()" in code or "async Task Refresh()" in code
    assert "?? throw new InvalidOperationException(" in code
    build([dotnet, "build", "-nologo", "-v", "q"], tmp_path)


# --- Kotlin -------------------------------------------------------------------------

KOTLIN_STUBS = """package kotlinx.coroutines

open class CoroutineContext {
    operator fun plus(other: CoroutineContext): CoroutineContext = this
}

fun CoroutineExceptionHandler(handler: (CoroutineContext, Throwable) -> Unit): CoroutineContext = CoroutineContext()

object Dispatchers { val IO: CoroutineContext = CoroutineContext() }

object GlobalScope {
    fun launch(context: CoroutineContext = CoroutineContext(), block: suspend () -> Unit) {}
}
"""

KOTLIN_APP = f"""import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Dispatchers

class JdbcTemplate {{
    fun <T> query(sql: String, mapper: (Any) -> T, vararg args: Any?): List<T> = emptyList()
}}

val jdbcTemplate = JdbcTemplate()
val jwtSecret = System.getenv("JWT_SECRET") ?: "superSecret"

fun x() {{}}
fun work() {{}}
fun respond(status: Int, message: String?) {{}}

fun load(id: String) {{
    val apiKey = "{STRIPE}"
    jdbcTemplate.query("SELECT name FROM orders WHERE id = $id", {{ row -> row }})
    GlobalScope.launch {{ work() }}
    GlobalScope.launch(Dispatchers.IO) {{ work() }}
    try {{
        x()
    }} catch (e: Exception) {{
        respond(500, e.message)
    }}
    println(apiKey)
}}

fun main() {{ load("1") }}
"""


def test_kotlin_fixes_build(tmp_path):
    kotlinc = needs("kotlinc")
    write(tmp_path, "stubs/Coroutines.kt", KOTLIN_STUBS)
    app = write(tmp_path, "Orders.kt", KOTLIN_APP)
    fix_everything(tmp_path)
    code = changed(app, KOTLIN_APP)
    assert "?: error(\"JWT_SECRET isn't set\")" in code
    assert "CoroutineExceptionHandler" in code and "WHERE id = ?\", { row -> row }, id)" in code
    build([kotlinc, str(app), str(tmp_path / "stubs" / "Coroutines.kt"), "-d", str(tmp_path / "out")],
          tmp_path, timeout=600)


# --- Swift --------------------------------------------------------------------------

SWIFT_APP = f"""import Foundation

func work() async throws {{}}

let apiKey = "{STRIPE}"
Task {{
    try await work()
}}
print(apiKey)
"""


def test_swift_fixes_build(tmp_path):
    swiftc = needs("swiftc")
    app = write(tmp_path, "main.swift", SWIFT_APP)
    fix_everything(tmp_path)
    code = changed(app, SWIFT_APP)
    assert "do {" in code and "catch {" in code and "ProcessInfo" in code

    # The full check (-typecheck) needs Swift's standard library, which on
    # Windows also needs Microsoft's C/C++ build tools (Visual Studio). If
    # those aren't installed, fall back to Swift's own syntax check (-parse):
    # weaker than a full build, but stricter than DecalogueX's built-in check.
    full = subprocess.run([swiftc, "-typecheck", str(app)], cwd=tmp_path, capture_output=True, text=True, timeout=300)
    setup_missing = "setjmp.h" in full.stderr or "unable to load standard library" in full.stderr
    if setup_missing:
        build([swiftc, "-parse", str(app)], tmp_path)
    else:
        assert full.returncode == 0, f"build failed:\n{full.stdout}\n{full.stderr}"
