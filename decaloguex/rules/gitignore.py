"""
gitignore.py: the .gitignore Hardener (rules GIT-001, GIT-002, GIT-003).

THE PROBLEM
    Someone runs `git add .` and their .env file, full of passwords, goes to
    GitHub along with everything else.

THE RULES
    Unlike the other rules, this one looks at the whole PROJECT, not one file.

    GIT-001  Secret files exist (or are about to be created by the secret
             scrubber) that .gitignore doesn't cover.
             Fix: add the right lines, creating .gitignore if needed.
    GIT-002  A secret file is ALREADY saved in Git. Ignoring it now won't
             remove it from history, so this one is reported with
             instructions, not fixed.
    GIT-003  The project has no .gitignore at all.
             Fix: create one with safe defaults.

HOW IT CHECKS
    In a Git project, Git itself is asked which files are ignored
    (`git check-ignore`), which is exact. Without Git, a simpler built-in
    matcher is used instead.
"""

from __future__ import annotations

import shutil      # shutil.which("git") finds a program on the PATH
import subprocess  # runs other programs, like Java's ProcessBuilder
from fnmatch import fnmatchcase  # shell-style wildcards: *.pem, .env.*
from pathlib import Path

from decaloguex import project
from decaloguex.models import AppendEdit, Finding, Fix, Severity

# (wildcard matched against the FILE NAME, line to add to .gitignore)
SENSITIVE_FILES = [
    (".env", ".env"),
    (".env.*", ".env.*"),             # .env.local, .env.production, ...
    ("*.pem", "*.pem"),               # certificates and private keys
    ("*.key", "*.key"),
    ("*.p12", "*.p12"),
    ("*.pfx", "*.pfx"),
    ("id_rsa*", "id_rsa*"),           # SSH private keys
    ("id_ed25519*", "id_ed25519*"),
]

# Template files are MEANT to be saved: they list the variables, not the values.
TEMPLATE_FILES = {".env.example", ".env.sample", ".env.template", ".env.dist"}

# What a brand-new .gitignore contains.
# (The \ right after the opening """ stops the text starting with a blank line.)
BASELINE = """\
# Secrets: never upload these (added by DecalogueX)
.env
.env.*
!.env.example
*.pem
*.key

# Dependencies and caches
node_modules/
.venv/
__pycache__/
"""


# ===========================================================================
# THE RULE
# ===========================================================================

def check(root: Path, planned_files: set[Path]) -> list[Finding]:
    """Check the project's .gitignore.

    planned_files are files that this scan's fixes WILL create (the .env the
    secret scrubber writes). They need protecting too, even though they
    don't exist yet.
    """
    gitignore = root / ".gitignore"
    sensitive = find_sensitive_files(root, planned_files)

    if not gitignore.exists():
        return [missing_gitignore_finding(gitignore, sensitive)]

    findings = []
    use_git = git_available(root)

    # GIT-002: already saved in Git. Ignoring won't help; it has to be untracked.
    if use_git:
        for rel in sorted(tracked_by_git(root, sensitive)):
            findings.append(Finding(
                "GIT-002", f"Secret file already uploaded to Git: {rel}", root / rel, 0,
                impact="Ignoring it now won't remove it from GitHub's history. Revoke any keys inside it.",
                note=f"Run: git rm --cached {rel}",
            ))

    # GIT-001: exists (or will) but isn't covered by .gitignore.
    if use_git:
        ignored = ignored_by_git(root, sensitive)
    else:
        ignored = ignored_by_rules(root, sensitive)
    # Set difference: like Java's removeAll(), but it returns a new set.
    unprotected = sorted(set(sensitive) - ignored)

    if unprotected:
        patterns = patterns_for(unprotected)
        new_text = "\n# Added by DecalogueX: keep secret files off GitHub\n" + "".join(p + "\n" for p in patterns)
        findings.append(Finding(
            "GIT-001", "Secret files not protected by .gitignore: " + ", ".join(unprotected), gitignore, 0,
            impact="`git add .` can no longer upload these files to GitHub.",
            severity=Severity.CRITICAL,
            fix=Fix(appends=[AppendEdit(gitignore, new_text)],
                    preview_before=".gitignore",
                    preview_after=".gitignore + " + ", ".join(patterns)),
        ))
    return findings


def missing_gitignore_finding(gitignore: Path, sensitive: list[str]) -> Finding:
    """GIT-001 or GIT-003, for a project with no .gitignore at all."""
    if sensitive:
        rule_id, severity = "GIT-001", Severity.CRITICAL
        title = "No .gitignore, and secret files are exposed: " + ", ".join(sensitive)
    else:
        rule_id, severity = "GIT-003", Severity.WARNING
        title = "No .gitignore file"

    # The baseline covers the common cases. Add lines for anything unusual
    # it doesn't cover (an id_rsa key, say).
    extra = [p for p in patterns_for(sensitive) if p not in BASELINE.splitlines()]
    new_text = BASELINE + "".join(p + "\n" for p in extra)
    return Finding(
        rule_id, title, gitignore, 0,
        impact="Secret files like .env will never be uploaded by `git add .`.",
        severity=severity,
        fix=Fix(appends=[AppendEdit(gitignore, new_text)], preview_before="(missing)", preview_after="new .gitignore"),
    )


# ===========================================================================
# FINDING SECRET FILES
# ===========================================================================

def is_sensitive(name: str) -> bool:
    if name in TEMPLATE_FILES:
        return False
    return any(fnmatchcase(name, wildcard) for wildcard, _ in SENSITIVE_FILES)


def find_sensitive_files(root: Path, planned_files: set[Path]) -> list[str]:
    """Paths (relative to root, with / separators) of secret-looking files."""
    found = set()
    # `|` joins two sets (a union), so the soon-to-exist .env is checked too.
    for path in set(project.iter_files(root)) | set(planned_files):
        if not is_sensitive(path.name):
            continue
        try:
            found.add(path.relative_to(root).as_posix())  # as_posix() uses / even on Windows
        except ValueError:
            pass  # outside the project root; not our concern
    return sorted(found)


def patterns_for(rel_paths: list[str]) -> list[str]:
    """Which .gitignore lines cover these files, in a stable order."""
    names = [Path(rel).name for rel in rel_paths]
    patterns = []
    for wildcard, line in SENSITIVE_FILES:
        if any(fnmatchcase(name, wildcard) for name in names):
            patterns.append(line)
    if ".env.*" in patterns:
        # The ! line must come AFTER .env.* so the template can still be saved.
        patterns.append("!.env.example")
    return patterns


# ===========================================================================
# ASKING GIT
# ===========================================================================

def git_available(root: Path) -> bool:
    return shutil.which("git") is not None and (root / ".git").exists()


def run_git(root: Path, args: list[str], stdin: str = "") -> tuple[int, str] | None:
    """Run a git command. Returns (exit code, output text), or None if it failed.

    The input is sent as raw BYTES on purpose. In text mode, Python on
    Windows quietly turns every "\\n" into "\\r\\n", so Git would be asked
    about a file named ".env\\r" (which isn't ignored) instead of ".env".
    """
    try:
        result = subprocess.run(["git", *args], cwd=root, input=stdin.encode("utf-8"),
                                capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):  # catching two exception types at once
        return None
    return result.returncode, result.stdout.decode("utf-8", errors="replace")


def output_lines(output: str) -> set[str]:
    return {line.strip() for line in output.splitlines() if line.strip()}


def ignored_by_git(root: Path, rel_paths: list[str]) -> set[str]:
    # --no-index: also answer for files Git already tracks.
    # --stdin: read the paths from the input, one per line.
    result = run_git(root, ["check-ignore", "--no-index", "--stdin"], "\n".join(rel_paths))
    # Exit code 0 = some ignored, 1 = none ignored, anything else = an error.
    if result is None or result[0] not in (0, 1):
        return ignored_by_rules(root, rel_paths)
    return output_lines(result[1])


def tracked_by_git(root: Path, rel_paths: list[str]) -> set[str]:
    if not rel_paths:
        return set()
    result = run_git(root, ["ls-files", "--", *rel_paths])
    if result is None or result[0] != 0:
        return set()
    return output_lines(result[1])


# ===========================================================================
# THE BUILT-IN MATCHER (when Git isn't available)
# ===========================================================================

def ignored_by_rules(root: Path, rel_paths: list[str]) -> set[str]:
    rules = (root / ".gitignore").read_text(encoding="utf-8", errors="replace").splitlines()
    return {rel for rel in rel_paths if simple_is_ignored(rel, rules)}


def simple_is_ignored(rel_path: str, rules: list[str]) -> bool:
    """A simplified version of Git's ignore rules.

    It covers what real projects use: wildcards, folder/ patterns, /anchored
    patterns and !negation. Like Git, the LAST matching rule wins.
    """
    parts = rel_path.split("/")
    ignored = False
    for raw in rules:
        rule = raw.strip()
        if not rule or rule.startswith("#"):
            continue
        negate = rule.startswith("!")
        if negate:
            rule = rule[1:]                 # [1:] drops the first character
        folder_only = rule.endswith("/")
        rule = rule.rstrip("/")
        anchored = "/" in rule              # a / pins the rule to one location
        rule = rule.lstrip("/")

        if folder_only:
            matched = any(fnmatchcase(part, rule) for part in parts[:-1])  # parent folders only
        elif anchored:
            matched = fnmatchcase(rel_path, rule)
        else:
            matched = any(fnmatchcase(part, rule) for part in parts)       # the file or any folder

        if matched:
            ignored = not negate
    return ignored
