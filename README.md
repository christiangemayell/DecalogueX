<p align="center">
  <img src="assets/logo.jpg" alt="DecalogueX logo: an ice-blue ten-point star" width="180">
</p>

# DecalogueX: Crash Doctor

**DecalogueX finds and fixes the mistakes AI coding tools often make.**

You point it at a project. It reads the code, explains every problem in
plain words, and asks whether you want them fixed. Say yes, and it fixes
them for you. Change your mind, and `decaloguex undo` puts everything back.

It checks **JavaScript, TypeScript, Python, PHP, Java, C#, Go, Ruby, Kotlin,
Swift, HTML, Vue and Svelte**, plus settings files like `.yml` and `.json`.

It's open source (MIT licence), and this is a **free early-access version**:
a full version is coming soon.

---

## Install (2 minutes)

**1. Get Python** (skip this if you already have it)

Download it from [python.org/downloads](https://www.python.org/downloads/)
and run the installer. **On Windows, tick "Add python.exe to PATH"** on the
first screen. That one tick saves most install problems.

**2. Install DecalogueX**

Open a terminal (on Windows: press the Start key, type **Terminal**, press
Enter) and type:

```
pip install decaloguex
```

That's it. Check it worked:

```
decaloguex --version
```

> **"decaloguex is not recognized"?** Use `python -m decaloguex` instead of
> `decaloguex` in every command below. It does exactly the same thing.
>
> **Trying an early version before it's released?** Install it from GitHub instead:
> `pip install git+https://github.com/christiangemayell/decaloguex`

---

## Check your project (3 steps)

**1. Open a terminal in your project's folder.** In VS Code or Cursor: menu
**Terminal → New Terminal**. It opens in your project's folder.

**2. Scan it:**
```
decaloguex scan .
```
(The `.` means "this folder".)

**3. Choose what to do.** DecalogueX explains every problem in plain words,
then asks:

- **A**: fix everything
- **O**: go through them one by one, answering yes or no for each
- **N**: change nothing

Changed your mind? `decaloguex undo` puts everything back.

When nothing is left to fix, you get the **DecalogueX approval stamp**.

---

### Use it inside your AI coding tool

DecalogueX comes as an **Agent Skill**, so your AI assistant can run it
after it writes code.

- **Claude Code:** run these in your terminal
  ```
  claude plugin marketplace add christiangemayell/decaloguex
  claude plugin install decaloguex@decaloguex
  ```
- **Cursor, Codex and other tools that support Agent Skills:** copy the
  `skills/decaloguex` folder into your project's `.agents/skills/` folder
  (or `.cursor/skills/` or `.claude/skills/`).
- **Any other AI tool:** add this line to your project's `AGENTS.md` file:
  ```
  After changing code, run `decaloguex scan . --json` and fix what it reports.
  ```

> **Use Node.js?** `npx decaloguex scan .` also works, but it still needs
> Python installed (step 1 above), because DecalogueX is written in Python.

---

## Try it on a practice app

Want to see it in action first? Download this project, open a terminal in
its folder, and run:

```
python scripts/make_demo.py
decaloguex scan demo
```

`make_demo.py` builds a small app full of mistakes. Type `A` to fix them all,
then run `decaloguex scan demo` again to see the approval stamp. Run
`make_demo.py` again any time for a fresh broken app. Add `--manual` to also
see a problem only a person can fix (a **"What to do"** card).

---

## What it fixes

| Problem | Why it's bad | What DecalogueX does |
|---|---|---|
| **Passwords and API keys written in the code** | Anyone who sees the code can steal them. Bots search GitHub for them all day. | Moves them into a private `.env` file |
| **Secret files not hidden from Git** | `.env` can get uploaded to GitHub by accident | Adds them to `.gitignore` |
| **SQL injection** (user input glued into database queries) | A hacker can type database commands into a form and read or delete your data | Rewrites the query the safe way |
| **Error details shown to visitors** | Error messages can reveal file paths, database details and personal information | Shows visitors a friendly message and keeps the real error private |
| **Async code with no safety net** | One failed database call can crash the whole server, or a job silently never runs | Adds the missing error handling |
| **Debug mode left on** | Debug pages show hackers your code, settings and sometimes a live console | Turns it off for the public, keeps it on for you (Django, Flask) |
| **Raw HTML put into a page** (XSS) | A hacker's text can run as code in your visitors' browsers and steal their logins | Escapes it (PHP `echo`), or tells you how |
| **Any website allowed to call your server** (CORS `*`) | Other websites can use your visitors' logins against your server | Tells you how to allow only your own site |
| **Security certificate check switched off** | Anyone on the same Wi-Fi can read and change the data you send | Tells you how to turn it back on |
| **Whole form saved without picking fields** | A visitor can add `"isAdmin": true` to a form and make themselves admin | Tells you how to save only the fields you expect |

**It never guesses.** If it can't be sure a fix is safe, it changes nothing
and tells you exactly what to do yourself, in a **"What to do"** card.

**It's honest about what it can't check.** Files in languages it can't read
yet are listed under **BLIND SPOTS** at the end of every scan, and saved in
`.decaloguex/blind-spots.json`.

### What it fixes in each language

| | Secrets | SQL injection | Error leaks | Crash risks |
|---|---|---|---|---|
| JavaScript / TypeScript | ✔ fixed | ✔ fixed | ✔ fixed | ✔ fixed |
| Python | ✔ fixed | ✔ fixed | ✔ fixed | ✔ fixed |
| PHP | ✔ fixed | ✔ fixed (PDO) | ✔ fixed | not needed |
| Go | ✔ fixed | ✔ fixed | ✔ fixed | ✔ fixed |
| Ruby | ✔ fixed | ✔ fixed (ActiveRecord) | ✔ fixed | not needed |
| C# | ✔ fixed | ✔ fixed (EF Core, Dapper) | ✔ fixed | ✔ fixed |
| Java | ✔ fixed | ✔ fixed (JdbcTemplate) | ✔ fixed | ✔ fixed |
| Kotlin | ✔ fixed | ✔ fixed (JdbcTemplate) | ✔ fixed | ✔ fixed |
| Swift | ✔ fixed | instructions | ✔ fixed | ✔ fixed |
| HTML / Vue / Svelte | instructions* | ✔ fixed | n/a | ✔ fixed |
| Settings files (.yml, .json...) and scripts (.sh, .ps1...) | instructions | n/a | n/a | n/a |

Razor (`.cshtml`, `.razor`) and ERB (`.erb`) pages are checked like HTML.
Test, example and fixture files are only checked for real-looking keys, and
never changed. Generated and minified files are skipped. Both are listed
under BLIND SPOTS.

**Every fix is build-tested.** `tests/test_builds.py` lets DecalogueX fix a
broken program in each language, then builds it with the real Go, PHP,
Ruby, Java, C#, Kotlin and Swift tools. If a language's tool isn't installed,
that test is skipped.

\* A key in a web page runs in the visitor's browser, so `.env` can't hide it.
DecalogueX explains how to move it to your server instead. The same goes for
browser-only React, Vue and Svelte apps.

### Secrets are only moved if your app loads `.env`

A `.env` file does nothing by itself. Your app has to **read** it when it
starts, usually with a small library called dotenv, or a framework that does
it for you, like Next.js. If nothing reads `.env`, a moved secret would come
back empty and your app would break.

So before moving a secret, DecalogueX looks for proof that `.env` gets
loaded: dotenv in your project's files, or a framework that loads it. If it
can't find any, it leaves the secret where it is and tells you the two-line
setup to do first. Then scan again, and it moves the secret for you.

If your app gets its settings another way (from Docker or your hosting
dashboard, say), set `DECALOGUEX_ENV_LOADED=1` and DecalogueX will take your
word for it.

---

## Useful commands

| Command | What it does |
|---|---|
| `decaloguex scan .` | Scan the folder you're in, explain the problems, and ask what to fix |
| `decaloguex scan . --dry-run` | Only show problems, never change anything |
| `decaloguex scan . --yes` | Fix everything without asking |
| `decaloguex scan . --all` | Also show places that are only *worth a look* (by default only sure problems are shown, with one line counting the rest) |
| `decaloguex undo` | Put back everything the last fix changed |
| `decaloguex scan . --json` | A report for AI tools (add `--yes` to also fix) |
| `decaloguex scan . --no-animation` | Same screen, without the moving bars and scenes |
| `decaloguex telemetry off` | Switch off the anonymous usage stats |
| `pytest` | Run the tests, to check the program still works |

You can also press **F5** in VS Code to run a scan step by step in the debugger.

---

### Silence a finding you've checked

If DecalogueX flags a line and you've looked at it and you're sure it's fine,
add a comment with `decaloguex-ignore` on that line or the line above:

```js
// decaloguex-ignore
el.innerHTML = bundledIcon;
```

DecalogueX also respects the markers other tools use, like `nosemgrep`,
`NOSONAR`, `# nosec` and `rubocop:disable Rails/OutputSafety`.

## Privacy

DecalogueX sends **anonymous usage stats** so it can be improved: things like
how many files of each language were checked, which rules found problems, and
which languages it couldn't read yet. A short notice tells you this the first
time you run it, and nothing at all is sent on that first run.

- **Never sent:** your code, file or folder names, project names, secrets,
  error messages, or anything that identifies you.
- **See exactly what was sent:** everything is also written to a log on your
  own computer, at `~/.decaloguex/telemetry.log`. `decaloguex telemetry`
  shows where it is.
- **Projects are counted, not identified:** each project gets a random code,
  kept in its `.decaloguex` folder, so DecalogueX can count how many
  projects use it each week. The code says nothing about the project.
- **Switch it off any time:** `decaloguex telemetry off`
- It's also off automatically if you've set `DO_NOT_TRACK=1`, and on
  automated test servers (CI).

### Tell us when it's wrong

When you go through fixes one by one (**O**), press **w** on any finding
that looks wrong: a false alarm, or a fix that doesn't look right. Nothing
gets changed, the finding is noted in `.decaloguex/blind-spots.json`, and
an anonymous count (the rule and the reason, never your code) helps make
DecalogueX more accurate.

The full list of what's sent is at the top of `decaloguex/telemetry.py`.

---

## What's in this folder

| Item | What it is |
|---|---|
| `decaloguex/` | **The program itself.** This is the code that matters. |
| `tests/` | Checks that the program works. Run them with `pytest`. |
| `scripts/` | A helper that builds the practice app. |
| `assets/` | The logo and other images for the README. |
| `demo/` | The practice app. It's rebuilt from scratch each time, so don't edit it. |
| `skills/` | The Agent Skill that teaches AI tools to use DecalogueX |
| `.claude-plugin/` | The files that let Claude Code install the skill |
| `npm/` | The small launcher behind `npx decaloguex` |
| `README.md` | This file. |
| `LICENSE` | The MIT licence: anyone may use this, with your name kept on it |
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
| 7 | `decaloguex/rules/sql.py` | Fixes SQL injection (long, because every database works a bit differently) |
| 8 | `decaloguex/rules/other_languages.py` | The same rules for PHP, Java, C#, Go, Ruby, Kotlin and Swift, using one "profile" per language |
| 9 | `decaloguex/rules/config_files.py` | Secrets in settings files |
| 9b | `decaloguex/rules/web.py` | Website mistakes: debug mode, XSS, CORS, certificates, mass assignment |
| 10 | `decaloguex/engine.py` | Runs all the rules and saves the fixes safely |
| 11 | `decaloguex/cli.py` | The `decaloguex` command you type, step by step |
| 12 | `decaloguex/ui.py` | Everything on screen: the animations, problem cards and questions |
| 13 | `decaloguex/explain.py` | The plain-English explanation of every problem. Edit this to change what users read. |
| 14 | `decaloguex/scenes.py` | The fantasy animations (shield, dragon, wizard) shown while your code is fixed |
| 15 | `decaloguex/undo.py` | The undo button |
| 16 | `decaloguex/blindspots.py` | The honest list of what couldn't be checked |
| 17 | `decaloguex/telemetry.py` | The anonymous usage stats |

Smaller helper files: `project.py` (finds the project's files and libraries)
and `rules/common.py` (small jobs the rules share).

---

## How it keeps your code safe

- **It reads code properly.** It understands code as a tree, not as plain
  text, so comments or similar-looking words don't fool it.
- **It checks every fix.** After changing a file, it re-reads it. If the
  change would break the code, the file isn't saved.
- **It only moves a secret if your app will find it again.** See "Secrets
  are only moved if your app loads `.env`" above.
- **It won't patch a file that changed after the scan.** If you edit a file
  while it's waiting for your answer, that file is skipped.
- **It asks first.** Nothing changes unless you say yes, or use `--yes`.
- **It can undo.** Every fix is backed up first; `decaloguex undo` restores it.
- **It doesn't crash on strange code.** If a rule gets confused by a file,
  it skips that file, keeps going, and lists it as a blind spot.

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
| SEC-002 | A password or secret stored under a secret-sounding name |
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
| ASYNC-005 | A C# `async void` method (an error crashes the whole app) |
| ASYNC-006 | A Go goroutine with no `recover()` (a panic crashes the whole program) |
| ASYNC-007 | A Java `CompletableFuture` whose errors are silently lost |
| ASYNC-008 | A Kotlin `GlobalScope.launch` with no error handler |
| ASYNC-009 | A Swift `Task` whose errors are silently lost |
| DEBUG-001 | Debug mode left on (fixed for Django and Flask) |
| XSS-001 | Raw HTML put into a web page (fixed for PHP `echo`) |
| CORS-001 | Any website allowed to call your server (reported only) |
| TLS-001 | Security certificate check switched off (reported only) |
| MASS-001 | A whole form saved without picking fields (reported only) |
| SEC-004 | A backup secret anyone can guess, like `process.env.JWT_SECRET \|\| 'superSecret'` |
| AUTH-001 | An owner check that lets logged-out visitors through (reported only) |
| AUTH-002 | Anyone logged in can change or delete anyone's data (reported only) |
| CMD-001 | Visitor text put into a computer command (reported only) |
| EVAL-001 | Visitor text run as code (reported only) |
| PATH-001 | Visitor picks which file is read (reported only) |
| DESER-001 | Data loaded in a way that can run hidden code (fixed for Python's yaml.load) |
| NOSQL-001 | MongoDB search built from visitor input (reported only) |
| REDIRECT-001 | Visitor picks where the site sends people (reported only) |
| SSRF-001 | Server fetches a web address the visitor chose (reported only) |
| XXE-001 | XML reader can be tricked into reading your files (reported only) |
| HASH-001 | Passwords scrambled with MD5 or SHA-1 (reported only) |
| CSRF-001 | Protection against fake form submissions switched off (reported only) |
| SEC-005 | A secret with a public name (`NEXT_PUBLIC_`, `VITE_`...), so it's built into the page (reported only) |
| JWT-001 | Login tokens accepted without checking their signature (reported only) |
| UPLOAD-001 | Uploaded files saved without checking them (reported only, worth a look) |
| RAND-001 | Guessable random numbers used for codes or tokens (reported only) |
| AI-001 | An AI service's key exposed in the browser (reported only) |
| AI-002 | What the AI wrote put into a page, a query or eval() (reported only) |
| AI-003 | AI features with no rate limit anywhere in the project (reported only, worth a look) |
| RLS-001 | A Supabase table with no access rules, or a rule letting anyone change rows (reported only) |

</details>

<details>
<summary><b>Setting up on a new computer</b> (click to open)</summary>

```
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

</details>
