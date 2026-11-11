"""
engine.py: runs the rules, and applies the fixes the user accepts.

There are two jobs, and only the second one ever writes to disk:

    scan(target)        -> ScanResult    look for problems
    apply_fixes(found)  -> ApplyResult   fix them, with safety checks

There's no printing and no questions in here, so the command line and the
tests (and maybe one day a VS Code button) can all use the same engine.
"""

from __future__ import annotations

import time
from collections import defaultdict  # a dict that creates missing values for you
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from decaloguex import languages, project
from decaloguex.models import AppendEdit, Finding, TextEdit
from decaloguex.rules import async_, errors, gitignore, secrets, sql


@dataclass
class ScanResult:
    root: Path               # the project folder
    files_checked: int
    seconds: float
    findings: list[Finding]


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
    (Callable[[int, int, Path], None] means "a function taking an int, an
    int and a Path, returning nothing", like Java's functional interfaces.)
    """
    started = time.perf_counter()  # a precise timer, like System.nanoTime()
    target = target.resolve()      # make the path absolute
    root = project.find_root(target)

    # Things shared by every file, set up once:
    planner = secrets.EnvPlanner(root / ".env")   # what goes into .env
    info = project.read_project_info(root)        # package.json, requirements.txt

    findings = []
    paths = source_files(target)
    for number, path in enumerate(paths, start=1):
        # Each file is read and parsed ONCE, and every rule looks at the same tree.
        file = languages.load(path)
        findings += secrets.check(file, planner)
        findings += sql.check(file, info)
        findings += errors.check(file)
        findings += async_.check(file, info)
        if on_progress is not None:
            on_progress(number, len(paths), path)

    # The .gitignore rule looks at the whole project. It's told about files
    # the fixes above would CREATE (the .env), so they get protected too.
    planned = {append.path for f in findings if f.fix for append in f.fix.appends}
    findings += gitignore.check(root, planned)

    return ScanResult(root, len(paths), time.perf_counter() - started, findings)


def source_files(target: Path) -> list[Path]:
    """The files to scan: one file, or every supported file in a folder."""
    if target.is_file():
        return [target] if languages.detect(target) else []
    # A "comprehension": builds a list in one expression, like Java's
    # stream().filter(...).collect(toList()).
    return sorted(path for path in project.iter_files(target) if languages.detect(path))


# ===========================================================================
# FIXING
# ===========================================================================

def apply_fixes(findings: list[Finding]) -> ApplyResult:
    """Write every fix to disk, skipping any that clash or would break a file."""
    fixable = [f for f in findings if f.fix]

    # Step 1: drop fixes that would edit the same code as an earlier fix.
    accepted, clashing = remove_clashes(fixable)

    # Step 2: patch each file, but only save it if it still parses.
    broken_files = patch_files(accepted)

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
        append_to_file(append)
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


def patch_files(findings: list[Finding]) -> set[Path]:
    """Apply the text edits, file by file. Returns the files that were NOT saved."""
    # Group the edits by file. defaultdict(set) means edits_by_file[path]
    # starts as an empty set the first time it's used (Java: computeIfAbsent).
    # A set also merges identical edits, like the same `import os` from
    # three different secret fixes.
    edits_by_file: dict[Path, set[TextEdit]] = defaultdict(set)
    for finding in findings:
        for edit in finding.fix.edits:
            edits_by_file[edit.path].add(edit)

    broken = set()
    for path, edits in edits_by_file.items():  # .items() gives (key, value) pairs
        original = path.read_bytes()
        updated = apply_text_edits(original, edits)

        # THE SAFETY CHECK: if the file parsed cleanly before but not after,
        # our patch broke it, so it isn't saved. (If it was already broken
        # before, the patch isn't to blame, so it's allowed.)
        lang = languages.detect(path)
        if lang and not languages.has_syntax_errors(lang, original) and languages.has_syntax_errors(lang, updated):
            broken.add(path)
            continue
        path.write_bytes(updated)
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
