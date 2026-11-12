"""
blindspots.py: an honest list of what DecalogueX could NOT check.

A security tool that quietly skips things gives people false confidence.
So every scan keeps track of its blind spots and shows them openly:

  unsupported   code files in languages DecalogueX can't read yet
                ("10 Rust files"). These tell you which language to add next.
  tripped       files where a rule hit something it didn't expect and had to
                stop. The rest of the scan carries on; these show where a
                rule needs improving.
  too_big       files too large to check quickly (usually generated code).
  manual        problems DecalogueX found but can't fix safely, by rule
                ("SQL-001: 3"). These show where an automatic fix is worth adding.

The report is saved in the project as .decaloguex/blind-spots.json so you
can look back at it, and (as anonymous counts only) it's part of the usage
stats, so you can see the most common blind spots across all users.
"""

from __future__ import annotations

import json
from collections import Counter  # a dict that counts things, like a HashMap<String, Integer>
from dataclasses import dataclass, field
from pathlib import Path

# Code file types DecalogueX recognises but can't check yet.
# Extension -> the language's name.
UNSUPPORTED_CODE = {
    ".rs": "Rust", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".dart": "Dart", ".scala": "Scala", ".lua": "Lua", ".pl": "Perl", ".r": "R",
    ".m": "Objective-C", ".mm": "Objective-C", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hs": "Haskell", ".clj": "Clojure", ".groovy": "Groovy",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".astro": "Astro",
    ".fs": "F#", ".vb": "Visual Basic", ".jl": "Julia", ".zig": "Zig", ".sol": "Solidity",
    ".cshtml": "Razor", ".erb": "Ruby templates", ".blade.php": "Blade templates",
}

MAX_FILE_SIZE = 2_000_000  # bytes. Bigger files are skipped (and listed as a blind spot).


@dataclass
class BlindSpots:
    """Everything a scan couldn't check, and why."""

    unsupported: Counter = field(default_factory=Counter)     # language -> number of files
    tripped: list[dict] = field(default_factory=list)          # {"path", "rule", "error"} per problem
    too_big: list[str] = field(default_factory=list)           # relative paths
    manual: Counter = field(default_factory=Counter)           # rule ID -> number of findings

    def is_empty(self) -> bool:
        return not (self.unsupported or self.tripped or self.too_big or self.manual)

    def files_not_checked(self) -> int:
        tripped_files = {t["path"] for t in self.tripped}
        return sum(self.unsupported.values()) + len(self.too_big) + len(tripped_files)

    def to_dict(self) -> dict:
        return {
            "unsupported_languages": dict(self.unsupported.most_common()),
            "tripped": self.tripped,
            "too_big": self.too_big,
            "manual_steps_by_rule": dict(sorted(self.manual.items())),
        }


def unsupported_language(path: Path) -> str | None:
    """The language name if this is a code file DecalogueX can't check yet."""
    name = path.name.lower()
    for extension, language in UNSUPPORTED_CODE.items():
        if name.endswith(extension):
            return language
    return None


def save(root: Path, spots: BlindSpots) -> Path | None:
    """Write the report to <project>/.decaloguex/blind-spots.json."""
    folder = private_folder(root)
    if folder is None:
        return None
    target = folder / "blind-spots.json"
    try:
        target.write_text(json.dumps(spots.to_dict(), indent=2), encoding="utf-8")
    except OSError:
        return None  # a read-only folder, say. Never worth crashing over.
    return target


def private_folder(root: Path) -> Path | None:
    """DecalogueX's own folder inside the project: .decaloguex/

    It holds the blind spots report and the undo backups. A .gitignore
    INSIDE it ("*", meaning everything) keeps the whole folder out of Git,
    without touching the project's own .gitignore. That matters because the
    backups can contain the secrets that were just moved out of the code.
    """
    folder = root / ".decaloguex"
    try:
        folder.mkdir(exist_ok=True)
        ignore = folder / ".gitignore"
        if not ignore.exists():
            ignore.write_text("# DecalogueX's private files. Never upload these.\n*\n", encoding="utf-8")
    except OSError:
        return None
    return folder
