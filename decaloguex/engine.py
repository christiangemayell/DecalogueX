"""
engine.py: runs the rules, and applies the fixes the user accepts.

There are two jobs, and only the second one ever writes to disk:

    scan(target)                -> ScanResult    look for problems
    apply_fixes(found, root)    -> ApplyResult   fix them, with safety checks

There's no printing and no questions in here, so the command line, the
tests and the AI-agent JSON mode can all use the same engine.

SAFETY NETS
    * If a rule trips over code it doesn't understand (or a file can't be
      read), that file is skipped, the scan carries on, and the trip is
      listed as a blind spot.
    * A secret is only moved to .env if the app is seen to load .env.
    * A file that changed between the scan and the fix is left alone.
    * Every fix is re-checked; a file is only saved if its code still parses.
    * Before anything is written, the originals are backed up for
      `decaloguex undo`.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from decaloguex import languages, project
from decaloguex.blindspots import MAX_FILE_SIZE, BlindSpots, unsupported_language
from decaloguex.models import AppendEdit, Finding, TextEdit
from decaloguex.rules import async_, config_files, errors, gitignore, other_languages, secrets, sql
from decaloguex.undo import Backup, fingerprint


@dataclass
class ScanResult:
    root: Path                  # the project folder
    files_checked: int
    seconds: float
    findings: list[Finding]
    languages: Counter = field(default_factory=Counter)        # "PHP" -> number of files checked
    blind_spots: BlindSpots = field(default_factory=BlindSpots)
    # What each file with a fix looked like when it was scanned, as a
    # fingerprint (see undo.fingerprint). apply_fixes uses it to make sure
    # the file hasn't changed since.
    fingerprints: dict[Path, str] = field(default_factory=dict)


@dataclass
class ApplyResult:
    applied: list[Finding] = field(default_factory=list)
    # Fixes that were NOT saved: they would have broken the file's syntax,
    # or they overlapped another fix in the same run.
    rejected: list[Finding] = field(default_factory=list)


# ===========================================================================
# SCANNING
# ===========================================================================

def scan(target: Path, on_progress: Callable[[int, int, Path], None] | None = None) -> ScanResult:
    """Run every rule and return what was found. Writes nothing.

    on_progress, if given, is called after each file as
    on_progress(files_done, files_total, path). The screen uses it to move
    the progress bar; the engine itself never prints anything.
    """
    started = time.perf_counter()  # a precise timer, like System.nanoTime()
    target = target.resolve()      # make the path absolute
    root = project.find_root(target)

    # Things shared by every file, set up once:
    planner = secrets.EnvPlanner(root / ".env")   # what goes into .env
    info = project.read_project_info(root)        # package.json, requirements.txt, go.mod

    result = ScanResult(root, 0, 0.0, [])
    code_files, settings_files = sort_files(target, root, result.blind_spots)

    total = len(code_files) + len(settings_files)
    for number, path in enumerate(code_files, start=1):
        check_code_file(result, root, path, planner, info)
        if on_progress is not None:
            on_progress(number, total, path)
    for number, path in enumerate(settings_files, start=len(code_files) + 1):
        result.findings += safely(result, root, path, "config", lambda: config_files.check(path))
        if on_progress is not None:
            on_progress(number, total, path)

    # Now that every file has been seen, we know whether the app loads .env.
    # Where it doesn't, moving a secret there would break the app, so those
    # fixes become "What to do" cards instead.
    result.findings = secrets.without_fixes_the_app_cannot_load(result.findings, info.env_loaders)

    # The .gitignore rule looks at the whole project. It's told about files
    # the fixes above would CREATE (the .env), so they get protected too.
    planned = {append.path for f in result.findings if f.fix for append in f.fix.appends}
    result.findings += safely(result, root, root / ".gitignore", "gitignore", lambda: gitignore.check(root, planned))

    result.files_checked = total
    result.blind_spots.manual = Counter(f.rule_id for f in result.findings if not f.fix)
    result.seconds = time.perf_counter() - started
    return result


def check_code_file(result: ScanResult, root: Path, path: Path, planner, info) -> None:
    """Read and parse one code file ONCE, then hand it to every rule that applies."""
    try:
        file = languages.load(path)
    except OSError as error:
        # The file is locked, or vanished mid-scan. Note it and move on.
        result.blind_spots.tripped.append(
            {"path": relative(root, path), "rule": "read", "error": type(error).__name__})
        return
    result.languages[file.lang.label] += 1
    if not file.lang.embedded and project.source_loads_env(file.lang.family, file.source):
        info.env_loaders.add(file.lang.family)  # this file loads .env (see project.py)

    if file.lang.family in ("js", "python"):
        # JavaScript/TypeScript and Python have detailed rules of their own.
        rules = {
            "secrets": lambda: secrets.check(file, planner, info),
            "sql": lambda: sql.check(file, info),
            "errors": lambda: errors.check(file),
            "async": lambda: async_.check(file, info),
        }
    else:
        # The other languages share one set of rules (see rules/other_languages.py).
        rules = {"other-languages": lambda: other_languages.check(file, planner, info)}

    found = []
    for rule_name, run_rule in rules.items():
        found += safely(result, root, path, rule_name, run_rule)
    if any(finding.fix for finding in found):
        result.fingerprints[path] = fingerprint(file.source)
    result.findings += found


def safely(result: ScanResult, root: Path, path: Path, rule_name: str, run_rule) -> list[Finding]:
    """Run one rule on one file. If it trips, note it as a blind spot and carry on.

    `except Exception` catches any error, like `catch (Exception e)` in Java.
    Without this, one strange file could stop the whole scan.
    """
    try:
        return run_rule()
    except Exception as error:
        result.blind_spots.tripped.append({
            "path": relative(root, path),
            "rule": rule_name,
            "error": type(error).__name__,  # the KIND of error only, e.g. "IndexError"
        })
        return []


def sort_files(target: Path, root: Path, spots: BlindSpots) -> tuple[list[Path], list[Path]]:
    """Split the files to scan into (code files, settings files).

    Anything DecalogueX can't check is noted as a blind spot on the way.
    """
    if target.is_file():
        paths = [target]
    else:
        paths = sorted(project.iter_files(target))

    code, settings = [], []
    for path in paths:
        if languages.detect(path):
            bucket = code
        elif config_files.is_config_file(path):
            bucket = settings
        else:
            language = unsupported_language(path)
            if language:
                spots.unsupported[language] += 1  # code we can't read yet
            continue
        try:
            too_big = path.stat().st_size > MAX_FILE_SIZE
        except OSError:
            continue  # the file vanished or can't be read
        if too_big:
            spots.too_big.append(relative(root, path))
        else:
            bucket.append(path)
    return code, settings


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


# ===========================================================================
# FIXING
# ===========================================================================

def apply_fixes(findings: list[Finding], root: Path | None = None,
                fingerprints: dict[Path, str] | None = None) -> ApplyResult:
    """Write every fix to disk, skipping any that clash or would break a file.

    The originals are backed up first, so `decaloguex undo` can put them back.

    `fingerprints` is ScanResult.fingerprints: what each file looked like
    when it was scanned. A file that has changed since then is skipped,
    because its planned edits would now land in the wrong places.
    """
    fixable = [f for f in findings if f.fix]
    if root is None and fixable:
        first = (fixable[0].fix.edits or fixable[0].fix.appends)[0].path
        root = project.find_root(first.parent)

    # Step 1: drop fixes that would edit the same code as an earlier fix.
    accepted, clashing = remove_clashes(fixable)

    # Step 2: back up, then patch each file (only saving it if it still parses).
    backup = Backup.start(root) if root is not None else None
    broken_files = patch_files(accepted, backup, fingerprints or {})

    # Step 3: sort out what worked, and do the appends (.env, .gitignore)
    # only for fixes that were really applied.
    result = ApplyResult()
    appends: list[AppendEdit] = []
    for finding in fixable:
        broke_a_file = any(edit.path in broken_files for edit in finding.fix.edits)
        if finding in clashing or broke_a_file:
            result.rejected.append(finding)
        else:
            result.applied.append(finding)
            appends += finding.fix.appends

    # dict.fromkeys(list) drops duplicates but keeps the order (a set would
    # scramble it), like Java's LinkedHashSet.
    for append in dict.fromkeys(appends):
        if backup is not None:
            backup.remember(append.path)
        append_to_file(append)

    if backup is not None:
        backup.finish()
    return result


def remove_clashes(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (accepted, clashing).

    Two rules can occasionally want to change the same code. Applying both
    would scramble it, so the first one wins and the later one is skipped.
    """
    accepted, clashing = [], []
    taken: dict[Path, list[TextEdit]] = defaultdict(list)  # edits already accepted, per file
    for finding in findings:
        if any(overlaps(edit, other) for edit in finding.fix.edits for other in taken[edit.path]):
            clashing.append(finding)
            continue
        accepted.append(finding)
        for edit in finding.fix.edits:
            taken[edit.path].append(edit)
    return accepted, clashing


def overlaps(a: TextEdit, b: TextEdit) -> bool:
    """True if two DIFFERENT edits touch the same bytes.

    Identical edits are fine (they're merged into one), and so are two
    inserts at the same spot.
    """
    if a == b:
        return False
    return a.start < b.end and b.start < a.end


def patch_files(findings: list[Finding], backup: Backup | None, fingerprints: dict[Path, str]) -> set[Path]:
    """Apply the text edits, file by file. Returns the files that were NOT saved."""
    # Group the edits by file. A set also merges identical edits, like the
    # same `import os` from three different secret fixes.
    edits_by_file: dict[Path, set[TextEdit]] = defaultdict(set)
    for finding in findings:
        for edit in finding.fix.edits:
            edits_by_file[edit.path].add(edit)

    broken = set()
    for path, edits in edits_by_file.items():  # .items() gives (key, value) pairs
        try:
            original = path.read_bytes()
        except OSError:
            broken.add(path)  # deleted or locked since the scan
            continue

        # THE FRESHNESS CHECK: every edit says "replace bytes 120 to 150".
        # If the file changed after it was scanned (an editor's auto-save,
        # say), those positions now point at different code.
        expected = fingerprints.get(path)
        if expected is not None and fingerprint(original) != expected:
            broken.add(path)
            continue
        updated = apply_text_edits(original, edits)

        # THE SAFETY CHECK: if the file parsed cleanly before but not after,
        # our patch broke it, so it isn't saved. (If it was already broken
        # before, the patch isn't to blame, so it's allowed.)
        lang = languages.detect(path)
        if lang and not languages.has_syntax_errors(lang, original) and languages.has_syntax_errors(lang, updated):
            broken.add(path)
            continue
        if backup is not None:
            backup.remember(path)  # copy the original BEFORE overwriting it
        try:
            path.write_bytes(updated)
        except OSError:
            # Read-only, or open in another program. Nothing was written, so
            # there's nothing to undo: skip the file rather than crash.
            if backup is not None:
                backup.forget(path)
            broken.add(path)
    return broken


def apply_text_edits(source: bytes, edits: set[TextEdit]) -> bytes:
    """Apply edits from the END of the file backwards.

    Going backwards matters: replacing a 30-byte string with a 25-byte one
    shifts everything after it. Working from the end, the edits still to do
    sit earlier in the file and haven't moved.
    """
    # The replacement text is a tie-breaker: when two edits insert at the same
    # spot (`import os` and `import logging`), the order is the same every run.
    # `lambda e: (...)` is an inline function, like Java's  e -> ...
    for edit in sorted(edits, key=lambda e: (e.start, e.end, e.replacement), reverse=True):
        source = source[: edit.start] + edit.replacement + source[edit.end :]
    return source


def append_to_file(append: AppendEdit) -> None:
    new_text = append.text.encode("utf-8")
    if not append.path.exists():
        header = append.header.encode("utf-8") if append.header else b""
        append.path.write_bytes(header + new_text)
        return
    existing = append.path.read_bytes()
    # Start on a fresh line if the file doesn't end with a newline.
    separator = b"\n" if existing and not existing.endswith(b"\n") else b""
    append.path.write_bytes(existing + separator + new_text)
