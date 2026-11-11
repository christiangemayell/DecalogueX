# DecalogueX: Crash Doctor

**DecalogueX finds and fixes the mistakes AI coding tools often make.**

You point it at a project. It reads the code, lists the problems, and asks
whether you want them fixed. Say yes, and it fixes them for you.

It works on **JavaScript**, **TypeScript** and **Python** code.

---

## Try it in 3 steps

Open the terminal in VS Code (menu: **Terminal → New Terminal**). Then type
these one at a time, pressing Enter after each:

**1. Build a practice app full of mistakes**
```
python scripts/make_demo.py
```

**2. Scan it**
```
decaloguex scan demo
```
It explains every problem it found in plain words, then asks what you want to do:

- **A**: fix everything
- **O**: go through them one by one, answering yes or no for each
- **N**: change nothing

Type `A` and press Enter.

**3. Scan it again**
```
decaloguex scan demo
```
This time it should say **No crash hazards found**. Everything got fixed.

Run step 1 again any time to get a fresh broken app to practise on.

---

## What it fixes

| Problem | Why it's bad | What DecalogueX does |
|---|---|---|
| **Passwords and API keys written in the code** | Anyone who sees the code can steal them. Bots search GitHub for them all day. | Moves them into a private `.env` file |
| **Secret files not hidden from Git** | `.env` can get uploaded to GitHub by accident | Adds them to `.gitignore` |
| **SQL injection** (user input glued into database queries) | A hacker can type database commands into a form and read or delete your data | Rewrites the query the safe way |
| **Error details shown to visitors** | Error messages can reveal file paths, database details and personal information | Shows visitors a friendly message and keeps the real error private |
| **Async code with no error handling** | One failed database call can crash the whole server, or a function silently never runs | Adds the missing error handling or `await` |

**It never guesses.** If it can't be sure a fix is safe, it changes nothing
and tells you what to do yourself. You'll see this as a **"Manual step"** in
the report.

---

## Useful commands

| Command | What it does |
|---|---|
| `decaloguex scan demo` | Scan the practice app and offer to fix it |
| `decaloguex scan .` | Scan the folder you're in |
| `decaloguex scan demo --dry-run` | Only show problems, never change anything |
| `decaloguex scan demo --yes` | Fix everything without asking |
| `decaloguex scan demo --no-animation` | Same screen, without the moving bars and spinners |
| `pytest` | Run the tests, to check the program still works |

You can also press **F5** in VS Code to run a scan step by step in the debugger.

---

## What's in this folder

| Item | What it is |
|---|---|
| `decaloguex/` | **The program itself.** This is the code that matters. |
| `tests/` | Checks that the program works. Run them with `pytest`. |
| `scripts/` | A helper that builds the practice app. |
| `demo/` | The practice app. It's rebuilt from scratch each time, so don't edit it. |
| `README.md` | This file. |
| `pyproject.toml` | The project's ID card: its name and what it needs to run. |
| `.gitignore` | The list of files Git should never save, like secrets and junk. |
| `.venv/` | Python and its add-ons, installed just for this project. Never touch it. |
| `.vscode/` | VS Code's settings for this project. |

---

## Reading the code

Every file starts with a plain-English explanation of what it does, and the
code is full of comments. Many of them compare Python to Java.

**Start with the tests.** Each test is a tiny "before → after" example, so
it's the easiest way to see what a rule does. Then read the rule itself.

Every rule file has the same layout:
1. **At the top:** what the problem is and how it's fixed
2. **Next:** `check()`, the main function, which shows the big picture
3. **Below that:** the small helper steps

A good order to read the program in:

| # | File | What it does |
|---|---|---|
| 1 | `decaloguex/models.py` | The basic building blocks: a *Finding* (a problem) and a *Fix* |
| 2 | `decaloguex/languages.py` | Turns code into a tree the rules can search |
| 3 | `decaloguex/rules/secrets.py` | Finds passwords and API keys |
| 4 | `decaloguex/rules/gitignore.py` | Checks the `.gitignore` file |
| 5 | `decaloguex/rules/errors.py` | Hides error details from visitors |
| 6 | `decaloguex/rules/async_.py` | Adds missing error handling to async code |
| 7 | `decaloguex/rules/sql.py` | Fixes SQL injection (the longest, because every database works a bit differently) |
| 8 | `decaloguex/engine.py` | Runs all the rules and saves the fixes safely |
| 9 | `decaloguex/cli.py` | The `decaloguex` command you type, step by step |
| 10 | `decaloguex/ui.py` | Everything on screen: the animations, problem cards and questions |
| 11 | `decaloguex/explain.py` | The plain-English explanation of every problem. Edit this to change what users read. |
| 12 | `decaloguex/scenes.py` | The fantasy animations (shield, dragon, wizard) shown while your code is fixed |

Smaller helper files: `project.py` (finds the project's files) and
`rules/common.py` (small jobs the rules share).

---

## How it keeps your code safe

- **It reads code properly.** It understands code as a tree, not as plain
  text, so comments or similar-looking words don't fool it.
- **It checks every fix.** After changing a file, it re-reads it. If the
  change would break the code, the file isn't saved.
- **It asks first.** Nothing changes unless you say yes, or use `--yes`.

---

<details>
<summary><b>Python for Java developers</b> (click to open)</summary>

| Java | Python |
|---|---|
| `record Point(int x, int y)` | `@dataclass class Point: x: int; y: int` |
| `HashMap`, `HashSet`, `ArrayList` | `dict`, `set`, `list` (`{k: v}`, `{a, b}`, `[a, b]`) |
| `null` | `None` |
| `this` | `self` (written out as the first method parameter) |
| `private` | a leading underscore by convention: `_helper()` |
| `for (Item i : items)` | `for i in items:` |
| `x -> x * 2` | `lambda x: x * 2` |
| `stream().filter().collect()` | `[x for x in items if test(x)]` |
| `String.format("%s!", s)` | `f"{s}!"` |
| `cond ? a : b` | `a if cond else b` |
| Curly braces for blocks | Indentation (4 spaces) is the block |
| JUnit `@Test`, `assertEquals` | pytest `def test_...():`, `assert a == b` |
| Maven `pom.xml` | `pyproject.toml` |
| Local Maven repo | `.venv/` |

</details>

<details>
<summary><b>The rule IDs</b> (click to open)</summary>

Each problem in the report has an ID, so you can look it up here.

| ID | The problem |
|---|---|
| SEC-001 | An API key in a known format (Stripe, OpenAI, AWS...) |
| SEC-002 | A password or secret stored in a variable with a secret-sounding name |
| SEC-003 | A private key (reported only) |
| GIT-001 | Secret files that `.gitignore` doesn't hide |
| GIT-002 | A secret file already saved in Git (reported only) |
| GIT-003 | No `.gitignore` file at all |
| SQL-001 | User input glued into a database query |
| SQL-002 | The same, but the query is stored in a variable first |
| ERR-001 | Error details sent to visitors |
| ASYNC-001 | An Express route with no error handling (can crash the server) |
| ASYNC-002 | A `.then()` chain with no `.catch()` |
| ASYNC-003 | A Python `async` function called without `await` (it never runs) |
| ASYNC-004 | A Python background task that can vanish before it finishes |

</details>

<details>
<summary><b>Setting up on a new computer</b> (click to open)</summary>

```
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

</details>
