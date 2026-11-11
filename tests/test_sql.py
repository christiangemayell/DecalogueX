"""
Tests for SQL Query Parameterization (SQL-001, SQL-002).

Each test writes a tiny file into pytest's temporary folder (tmp_path),
scans it, and checks what DecalogueX found or rewrote.
"""

from pathlib import Path

from decaloguex import engine
from decaloguex.cli import run_scan


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def sql_findings(folder: Path):
    """Only the SQL findings (the .gitignore rule also reports things)."""
    return [f for f in engine.scan(folder).findings if f.rule_id.startswith("SQL")]


def fix(folder: Path) -> None:
    run_scan(folder, assume_yes=True, no_color=True)


# --- JavaScript ---------------------------------------------------------------

def test_mysql_template_string_gets_question_marks(tmp_path):
    app = write(tmp_path, "app.js",
                'const mysql = require("mysql2");\n'
                "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n")
    fix(tmp_path)
    assert 'db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);' in app.read_text(encoding="utf-8")


def test_postgres_gets_numbered_placeholders_and_quotes_are_removed(tmp_path):
    app = write(tmp_path, "app.js",
                'import pg from "pg";\n'
                "await client.query(`SELECT * FROM users WHERE email = '${email}' AND age > ${age}`);\n")
    fix(tmp_path)
    # The quotes around '${email}' go: the database quotes placeholder values itself.
    assert 'client.query("SELECT * FROM users WHERE email = $1 AND age > $2", [email, age]);' in app.read_text(encoding="utf-8")


def test_callback_stays_last(tmp_path):
    app = write(tmp_path, "app.js",
                'const mysql = require("mysql");\n'
                'db.query("SELECT * FROM t WHERE id = " + id, (err, rows) => {});\n')
    fix(tmp_path)
    assert 'db.query("SELECT * FROM t WHERE id = ?", [id], (err, rows) => {});' in app.read_text(encoding="utf-8")


def test_driver_found_in_package_json(tmp_path):
    # The routes file imports ./db, not the driver. package.json says it's pg.
    write(tmp_path, "package.json", '{"dependencies": {"pg": "^8.11.0"}}')
    app = write(tmp_path, "routes.js",
                'const db = require("./db");\n'
                "db.query(`DELETE FROM posts WHERE id = ${id}`);\n")
    fix(tmp_path)
    assert 'db.query("DELETE FROM posts WHERE id = $1", [id]);' in app.read_text(encoding="utf-8")


def test_better_sqlite3_values_go_to_get(tmp_path):
    app = write(tmp_path, "app.js",
                'const Database = require("better-sqlite3");\n'
                "const row = db.prepare(`SELECT * FROM t WHERE id = ${id}`).get();\n")
    fix(tmp_path)
    assert 'db.prepare("SELECT * FROM t WHERE id = ?").get(id);' in app.read_text(encoding="utf-8")


def test_prisma_unsafe_values_are_spread(tmp_path):
    app = write(tmp_path, "app.ts",
                "await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`);\n")
    fix(tmp_path)
    assert 'prisma.$queryRawUnsafe("SELECT * FROM t WHERE id = $1", id);' in app.read_text(encoding="utf-8")


def test_query_in_a_variable_is_fixed_where_it_is_used(tmp_path):
    app = write(tmp_path, "app.js",
                'const mysql = require("mysql2");\n'
                "async function find(name) {\n"
                "  const sql = `SELECT * FROM users WHERE name = '${name}'`;\n"
                "  return db.query(sql);\n"
                "}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'const sql = "SELECT * FROM users WHERE name = ?";' in code
    assert "return db.query(sql, [name]);" in code


def test_query_variable_used_twice_is_reported_only(tmp_path):
    original = (
        'const mysql = require("mysql2");\n'
        "const sql = `SELECT * FROM users WHERE id = ${id}`;\n"
        "console.log(sql);\n"
        "db.query(sql);\n"
    )
    app = write(tmp_path, "app.js", original)
    [finding] = sql_findings(tmp_path)  # unpacking: fails if there isn't exactly one
    assert finding.rule_id == "SQL-002" and finding.fix is None
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original


def test_column_name_from_a_variable_is_reported_not_rewritten(tmp_path):
    write(tmp_path, "app.js",
          'const mysql = require("mysql2");\n'
          "db.query(`SELECT * FROM users ORDER BY ${req.query.sort}`);\n")
    [finding] = sql_findings(tmp_path)
    assert finding.fix is None and "allowed names" in finding.note


def test_value_inside_a_like_pattern_is_reported_not_rewritten(tmp_path):
    write(tmp_path, "app.js",
          'const mysql = require("mysql2");\n'
          "db.query(`SELECT * FROM posts WHERE title LIKE '%${q}%'`);\n")
    [finding] = sql_findings(tmp_path)
    assert finding.fix is None and "quoted" in finding.note


def test_unknown_database_library_is_reported_not_rewritten(tmp_path):
    write(tmp_path, "app.js", "db.query(`SELECT * FROM t WHERE id = ${id}`);\n")
    [finding] = sql_findings(tmp_path)
    assert finding.fix is None and "database library" in finding.note


def test_safe_queries_are_not_flagged(tmp_path):
    write(tmp_path, "app.js",
          'const mysql = require("mysql2");\n'
          'db.query("SELECT * FROM t WHERE id = ?", [id]);\n'      # already parameterized
          "sql`SELECT * FROM t WHERE id = ${id}`;\n"               # tagged template: safe
          "const msg = `Select ${count} items from the list`;\n"  # English, not SQL
          "db.query(`SELECT * FROM t`);\n")                        # no variables at all
    assert sql_findings(tmp_path) == []


# --- Python -------------------------------------------------------------------

def test_python_sqlite_f_string(tmp_path):
    app = write(tmp_path, "app.py",
                "import sqlite3\n"
                "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n")
    fix(tmp_path)
    assert 'cur.execute("SELECT * FROM users WHERE name = ?", (name,))' in app.read_text(encoding="utf-8")


def test_python_psycopg2_percent_format_and_literal_percent(tmp_path):
    app = write(tmp_path, "app.py",
                "import psycopg2\n"
                "cur.execute(\"SELECT * FROM t WHERE a = %s AND b LIKE 'x%%'\" % (a,))\n")
    fix(tmp_path)
    # With %s placeholders a real % must be written %% (psycopg2's rule).
    assert "cur.execute(\"SELECT * FROM t WHERE a = %s AND b LIKE 'x%%'\", (a,))" in app.read_text(encoding="utf-8")


def test_python_format_and_concatenation(tmp_path):
    app = write(tmp_path, "app.py",
                "import pymysql\n"
                'cur.execute("DELETE FROM t WHERE id = {}".format(item_id))\n'
                'cur.execute("UPDATE t SET name = \'" + name + "\' WHERE id = " + str(i))\n')
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'cur.execute("DELETE FROM t WHERE id = %s", (item_id,))' in code
    assert 'cur.execute("UPDATE t SET name = %s WHERE id = %s", (name, str(i)))' in code


def test_python_asyncpg_spread_values(tmp_path):
    app = write(tmp_path, "app.py",
                "import asyncpg\n"
                'row = await conn.fetchrow(f"SELECT * FROM t WHERE id = {uid}")\n')
    fix(tmp_path)
    assert 'await conn.fetchrow("SELECT * FROM t WHERE id = $1", uid)' in app.read_text(encoding="utf-8")


def test_python_query_variable(tmp_path):
    app = write(tmp_path, "app.py",
                "import sqlite3\n"
                "def find(uid):\n"
                '    query = f"SELECT * FROM users WHERE id = {uid}"\n'
                "    cur.execute(query)\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'query = "SELECT * FROM users WHERE id = ?"' in code
    assert "cur.execute(query, (uid,))" in code


def test_python_sqlalchemy_text_is_reported(tmp_path):
    # SQLAlchemy uses :name placeholders and a dict, so this is a manual step.
    write(tmp_path, "app.py",
          "from sqlalchemy import text\n"
          'session.execute(text(f"SELECT * FROM t WHERE id = {uid}"))\n')
    [finding] = sql_findings(tmp_path)
    assert finding.fix is None
