---
name: decaloguex
description: Scan and fix security and crash bugs that AI coding tools commonly leave behind - leaked API keys and passwords, SQL injection, error messages that leak private details, and async code that can crash a server. Use after writing or changing code, before committing, or when the user asks to check code for security problems. Works on JavaScript, TypeScript, Python, PHP, Java, C#, Go, Ruby, Kotlin, Swift, HTML, Vue and Svelte.
license: MIT
compatibility: Needs Python 3.10+ (pip install decaloguex) or Node.js (npx decaloguex).
---

# DecalogueX: Crash Doctor

DecalogueX checks a project for the mistakes AI-written code often contains,
and fixes the ones it can fix safely. Run it after you write or change code.

## 1. Scan (changes nothing)

```
npx decaloguex scan . --json
```

If `decaloguex` is installed with pip, `decaloguex scan . --json` works too.

The JSON report lists every finding with:

- `rule`: e.g. `SEC-001` (secret), `SQL-001` (SQL injection), `ERR-001` (error leak), `ASYNC-001` (crash risk)
- `file` and `line`: where it is
- `explanation`: what's wrong, in plain words
- `status`:
  - `fixable`: DecalogueX can fix it automatically
  - `manual`: it can't be fixed safely by a tool; `manual_step` says what to do
- `blind_spots`: files it could not check (unsupported languages, very large files)

Exit code 0 means nothing was found. Exit code 1 means there are findings.

## 2. Fix

Tell the user what was found, then apply the automatic fixes:

```
npx decaloguex scan . --json --yes
```

Each fixed finding now has `"status": "fixed"`. Secrets are moved into
`.env`, and `.env` is added to `.gitignore`.

A secret is only moved if the app loads `.env` when it starts (for example
with the dotenv package, or a framework such as Next.js). If it doesn't, the
finding is `manual` and its `manual_step` gives the setup. Do that setup,
then scan again and the secret will be moved.

Then handle every `manual` finding yourself, following its `manual_step`.
For example: check a table or column name against a fixed list of allowed
names, or move a key out of browser code and onto the server.

## 3. Check and, if needed, undo

Run the project's tests after fixing. If something broke:

```
npx decaloguex undo --yes
```

This puts every file back exactly as it was before the last fix.

## Rules of thumb

- Never print or repeat secret values. The report already hides them.
- If secrets were found, tell the user to cancel those keys with the provider
  and make new ones, especially if the code was ever pushed online.
- Don't commit `.env` or the `.decaloguex/` folder. Both are ignored automatically.
