"""
supabase.py: RLS-001, Supabase database tables anyone can read or change.

THE PROBLEM
    Apps built with Lovable, Bolt and similar tools talk to their Supabase
    database straight from the visitor's browser, using a PUBLIC key. That's
    safe ONLY because of "Row Level Security" (RLS): rules in the database
    that say who may read or change each row. A table without RLS, or with a
    rule that lets everyone change everything, is open to anyone who opens
    the browser's developer tools.

WHAT COUNTS (in SQL files inside a supabase/ folder)
    1. A table is created, but RLS is never switched on for it anywhere:
           create table public.messages (...);
           -- missing:  alter table public.messages enable row level security;
    2. A rule (policy) that lets ANYONE change rows:
           create policy "..." on messages for update using (true);
       (Rules meant only for the server, "to service_role", are fine.)

A "What to do" card: the right rule depends on who should see what.
"""

from __future__ import annotations

import re
from pathlib import Path

from decaloguex.models import Finding, Severity

TABLE = r'(?:"?(?P<schema>\w+)"?\.)?"?(?P<name>\w+)"?'
CREATE_TABLE = re.compile(r"(?im)^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?" + TABLE)
ENABLE_RLS = re.compile(r"(?is)alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?" + TABLE + r"\s+enable\s+row\s+level\s+security")
OPEN_POLICY = re.compile(r"(?is)create\s+policy\b[^;]*?\bfor\s+(?:update|delete|insert|all)\b[^;]*?"
                         r"(?:using|with\s+check)\s*\(\s*true\s*\)[^;]*;")

NO_RLS_NOTE = ("Switch on Row Level Security for this table, then add rules for who may read and change rows:\n"
               "  alter table public.{name} enable row level security;\n"
               "  create policy \"Owners only\" on public.{name} for all using (auth.uid() = user_id);\n"
               "Without it, anyone with your app's public key (which is in the page) can read and change "
               "every row.")
OPEN_INSERT_NOTE = ("This rule lets anyone add rows. That's fine for something like a public form, but a "
                    "check such as  with check (auth.uid() = user_id)  stops people adding rows in someone "
                    "else's name.")
OPEN_NOTE = ("This rule lets ANYONE, even visitors who aren't logged in, change these rows. Replace `true` with a "
             "check such as  auth.uid() = user_id , so people can only change their own rows.")


def sql_files_to_check(paths: list[Path]) -> list[Path]:
    return [p for p in paths if p.suffix.lower() == ".sql" and "supabase" in (part.lower() for part in p.parts)]


def check(paths: list[Path]) -> list[Finding]:
    """Check a project's Supabase SQL files together (RLS is often switched on in a later file)."""
    texts = {}
    for path in sql_files_to_check(paths):
        try:
            texts[path] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    everything = "\n".join(texts.values())
    protected = {m.group("name").lower() for m in ENABLE_RLS.finditer(everything)}
    findings = []
    reported = set()
    for path, text in texts.items():
        for match in CREATE_TABLE.finditer(text):
            schema = (match.group("schema") or "public").lower()
            if schema != "public":
                continue  # a table in another schema (auth, storage, private...): not reachable with the public key
            name = match.group("name")
            if name.lower() in protected or name.lower() in reported:
                continue
            reported.add(name.lower())
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding("RLS-001", f"Database table '{name}' has no access rules", path, line,
                                    "Visitors can only read and change the rows they're allowed to.",
                                    Severity.CRITICAL, note=NO_RLS_NOTE.format(name=name)))
        for match in OPEN_POLICY.finditer(text):
            if re.search(r"(?i)\bto\s+service_role\b", match.group(0)):
                continue  # a rule for the server only
            line = text.count("\n", 0, match.start()) + 1
            if re.search(r"(?i)\bfor\s+insert\b", match.group(0)):
                # Adding rows: sometimes meant (a public question form), so "worth a look".
                findings.append(Finding("RLS-001", "Database rule lets anyone add rows", path, line,
                                        "Visitors can't add rows pretending to be someone else.",
                                        Severity.WARNING, note=OPEN_INSERT_NOTE))
            else:
                findings.append(Finding("RLS-001", "Database rule lets anyone change rows", path, line,
                                        "Visitors can only change their own rows.", Severity.CRITICAL, note=OPEN_NOTE))
    return findings
