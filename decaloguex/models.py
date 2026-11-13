"""
models.py: the shared data types every part of DecalogueX passes around.

A rule (like the secret scanner) produces Findings. Each Finding may carry a
Fix, and a Fix is a list of edits. The CLI shows the findings, asks y/n, then
applies the edits. Keeping these types in one file means a rule never touches
the disk itself: it only describes what it *would* change.

JAVA COMPARISON: these are like Java records (record Finding(...) {}).
Python's @dataclass decorator generates the constructor, equals() and
toString() for you (Python names them __init__, __eq__ and __repr__).
"""

# Lets a type hint mention a class that's defined further down the file.
# (Java doesn't need this because it compiles the whole file first.)
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path  # Path is like java.nio.file.Path


class Severity(Enum):
    """How bad a finding is. Works like a Java enum."""

    CRITICAL = "critical"  # will crash the app or leak data
    WARNING = "warning"    # risky, but nothing is broken yet


# frozen=True makes instances immutable, like a Java record. It also makes
# them hashable, so identical edits can go into a set and duplicates vanish.
# (Python's set is Java's HashSet.)
@dataclass(frozen=True)
class TextEdit:
    """Replace the bytes from `start` up to (not including) `end` in `path`.

    When start == end nothing is removed: it is a pure insert.

    Positions are BYTE offsets, not character offsets, because that is what
    Tree-sitter reports. Every file is read and written as raw bytes so the
    offsets always line up.
    """

    path: Path
    start: int
    end: int
    replacement: bytes  # `bytes` is like Java's byte[]


@dataclass(frozen=True)
class AppendEdit:
    """Add `text` to the end of a file, creating the file if it doesn't exist.

    Used for writing to .env and .gitignore.
    """

    path: Path
    text: str
    # Written at the top only when the file is brand new. `str | None` means
    # "a String or null". In Python, null is called None.
    header: str | None = None


@dataclass
class Fix:
    """Everything needed to repair one finding."""

    # `list[TextEdit]` is like List<TextEdit>. default_factory=list gives every
    # Fix its OWN empty list. Writing `= []` would make them all share one
    # list object, a classic Python bug.
    edits: list[TextEdit] = field(default_factory=list)
    appends: list[AppendEdit] = field(default_factory=list)
    # Short before/after text for the terminal's "patch" line.
    preview_before: str = ""
    preview_after: str = ""


@dataclass
class Finding:
    """One problem the scanner found.

    The terminal shows each finding as three lines:
      1. title      what's wrong, and where
      2. the patch  preview_before -> preview_after (or `note` if no fix)
      3. impact     the plain-English benefit of fixing it
    """

    rule_id: str      # stable ID such as "SEC-001"; telemetry will report this later
    title: str
    path: Path
    line: int         # 1-based line number; 0 means "the whole project"
    impact: str
    severity: Severity = Severity.CRITICAL
    fix: Fix | None = None  # None = we can detect it but can't fix it safely
    note: str = ""          # advice shown when there is no automatic fix
    # For secrets only: a scrambled fingerprint of the secret, so the SAME
    # secret found in several files becomes one card. It can't be turned back
    # into the secret, and it's never shown, saved or sent anywhere.
    same_as: str = field(default="", repr=False, compare=False)
