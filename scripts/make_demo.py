"""
make_demo.py: builds a small "vibe-coded" app full of mistakes, to try
DecalogueX on.

    python scripts/make_demo.py
    decaloguex scan demo

It writes into demo/, which .gitignore excludes. The fake keys are assembled
at runtime so this file can be pushed to GitHub without tripping its secret
scanner.

Run it again any time to reset the demo after DecalogueX has fixed it.
"""

import shutil
import subprocess
from pathlib import Path

# __file__ is this script's own path. .parent twice goes up from scripts/ to
# the project folder.
DEMO = Path(__file__).resolve().parent.parent / "demo"

STRIPE = "sk_" + "live_" + "51HxDemoOnlyNotARealKey00"
OPENAI = "sk-" + "proj-" + "DemoOnlyNotARealKey1234"

# Each file contains several typical AI-coding mistakes. The comments in the
# generated files say which rule should catch each one.
# (In these f-strings, {{ and }} produce a literal { and } in the output.)
FILES = {
    "package.json": """\
{
  "name": "demo-shop",
  "dependencies": {
    "dotenv": "^16.4.5",
    "express": "^4.18.2",
    "mysql2": "^3.9.0",
    "stripe": "^14.0.0"
  }
}
""",
    "server.js": f"""\
require("dotenv").config();  // reads the .env file, so process.env has the secrets in it
const express = require("express");
const mysql = require("mysql2/promise");
const Stripe = require("stripe");

const stripe = new Stripe("{STRIPE}");  // SEC-001: a live key in the code
const db = mysql.createPool({{ host: "localhost", user: "shop" }});
const app = express();
app.use(express.json());

// ASYNC-001: async route with no try/catch. If the database is down,
// this crashes the whole server.
// SQL-001: the id from the URL is glued into the SQL.
app.get("/products/:id", async (req, res) => {{
  const [rows] = await db.query(`SELECT * FROM products WHERE id = ${{req.params.id}}`);
  res.json(rows[0]);
}});

app.post("/checkout", async (req, res) => {{
  try {{
    // SQL-002: the query is built in a variable first.
    const sql = "SELECT price FROM products WHERE id = '" + req.body.productId + "'";
    const [rows] = await db.query(sql);
    const session = await stripe.checkout.sessions.create({{ mode: "payment", amount: rows[0].price }});
    res.json({{ url: session.url }});
  }} catch (err) {{
    // ERR-001: the raw error goes to the visitor.
    res.status(500).json({{ error: err.message }});
  }}
}});

// ASYNC-002: a promise chain with no .catch().
fetch("https://api.example.com/rates").then((r) => r.json()).then(console.log);

app.listen(3000);
""",
    "ai_helper.py": f'''\
"""Calls the OpenAI API to write product descriptions."""
import asyncio
import sqlite3

from dotenv import load_dotenv
from flask import Flask, jsonify
from openai import OpenAI

load_dotenv()  # reads the .env file, so os.environ has the secrets in it
app = Flask(__name__)
client = OpenAI(api_key="{OPENAI}")  # SEC-001
DB_PASSWORD = "Summer2024!db"  # SEC-002


def describe(product: str) -> str:
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{{"role": "user", "content": f"Describe {{product}}"}}],
    )
    return reply.choices[0].message.content


@app.route("/search")
def search(name):
    try:
        cur = sqlite3.connect("shop.db").cursor()
        # SQL-001: an f-string query.
        cur.execute(f"SELECT * FROM products WHERE name = '{{name}}'")
        return jsonify(cur.fetchall())
    except Exception as e:
        # ERR-001: the error text (maybe with SQL in it) goes to the visitor.
        return jsonify({{"error": str(e)}}), 500


async def send_receipt(email: str) -> None:
    await asyncio.sleep(1)  # pretend to send an email


async def finish_order(email: str) -> None:
    send_receipt(email)  # ASYNC-003: missing await, so the email never sends
    asyncio.create_task(send_receipt("admin@example.com"))  # ASYNC-004
''',
    # --- The same kinds of mistakes in other languages ---
    "checkout.php": f"""\
<?php
$stripeKey = "{STRIPE}";  // SEC-001
$pdo = new PDO($dsn);

// SQL-001: the order number from the web address goes straight into the SQL.
$result = $pdo->query("SELECT * FROM orders WHERE id = $orderId");

try {{
    chargeCard($stripeKey);
}} catch (Exception $e) {{
    echo 'Payment failed: ' . $e->getMessage();  // ERR-001
}}
""",
    # Tells DecalogueX that the PHP code loads .env too (through phpdotenv).
    "composer.json": '{"require": {"vlucas/phpdotenv": "^5.6"}}\n',
    "go.mod": "module demo-shop\n\nrequire github.com/lib/pq v1.10.9\n",
    "worker.go": """\
package main

import (
\t"fmt"
\t"net/http"
)

func orderHandler(w http.ResponseWriter, r *http.Request) {
\tid := r.URL.Query().Get("id")
\t// SQL-001: glued-together SQL.
\trows, err := db.Query("SELECT * FROM orders WHERE id = " + id)
\tif err != nil {
\t\thttp.Error(w, err.Error(), 500) // ERR-001
\t\treturn
\t}
\t// ASYNC-006: if this background job crashes, the whole server goes down.
\tgo func() {
\t\tsendReceipt(id)
\t}()
\tfmt.Fprintln(w, rows)
}
""",
    # A settings file with a password in it (reported with instructions).
    "config.yml": "database:\n  host: localhost\n  password: Sup3rS3cretPass!\n",
    # A language DecalogueX can't read yet: it shows up under BLIND SPOTS.
    "legacy.rs": "fn main() {\n    println!(\"old billing code\");\n}\n",
    # A local .env-style file that is NOT protected by any .gitignore yet.
    ".env.local": "SESSION_SECRET=local-dev-secret-123\n",
}


def main() -> None:
    if DEMO.exists():
        shutil.rmtree(DEMO)  # delete the old demo folder (like rm -rf)
    DEMO.mkdir()
    for name, content in FILES.items():
        (DEMO / name).write_text(content, encoding="utf-8")

    # Make the demo its own Git repo. DecalogueX treats the nearest folder with
    # .git as the project root. Without this, it would walk up to the
    # DecalogueX repo and put the demo's .env file there.
    if shutil.which("git"):
        subprocess.run(["git", "init", "--quiet"], cwd=DEMO, check=False)

    print(f"Demo app created in {DEMO}")
    print("Now run:  decaloguex scan demo")


# This block runs only when the file is executed directly, not when it's
# imported. It's Python's equivalent of `public static void main`.
if __name__ == "__main__":
    main()
