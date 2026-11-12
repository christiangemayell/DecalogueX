"""
undo.py: the undo button.

Before DecalogueX changes anything, it copies every file it's about to
touch into a backup. `decaloguex undo` puts them all back exactly as they
were, and deletes any files the fixes created (like a new .env).

WHERE BACKUPS LIVE
    <project>/.decaloguex/undo/<date-and-time>/
        manifest.json   which files were changed, and how to put them back
        files/0.bak     the original contents of the first file
        files/1.bak     ...and so on

    The .decaloguex folder is kept out of Git automatically, because the
    backups can contain the secrets the fixes just moved out of the code.
    Only the last 10 backups are kept.

SAFETY
    The manifest remembers what each file looked like right AFTER the fix
    (as a "fingerprint", see fingerprint()). If you edit a file after
    fixing it, undo notices and asks before throwing your edits away.

    The manifest is saved again every time a file is backed up, not just
    at the end. So if fixing is interrupted halfway (Ctrl+C, a crash, a
    power cut), undo can still put back the files that had been changed.
"""

from __future__ import annotations

import hashlib  # makes "fingerprints" of file contents
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from decaloguex.blindspots import private_folder

KEEP_BACKUPS = 10


def fingerprint(data: bytes | None) -> str | None:
    """A short code that changes if even one letter of the file changes.

    SHA-256 turns any amount of data into 64 characters. Two different
    files practically never share one, so comparing fingerprints is a quick
    way to ask "is this file still exactly the same?".
    """
    return hashlib.sha256(data).hexdigest() if data is not None else None


# ===========================================================================
# MAKING A BACKUP (called by the engine, just before it writes)
# ===========================================================================

class Backup:
    """One backup, made just before a round of fixes is written.

    Usage (in engine.apply_fixes):
        backup = Backup.start(root)
        backup.remember(path)       # for every file about to change
        ...write the fixes...
        backup.finish()             # records how the files look now
    """

    def __init__(self, root: Path, folder: Path):
        self.root = root
        self.folder = folder
        self.entries: list[dict] = []

    @classmethod  # like a static factory method in Java: Backup.start(root)
    def start(cls, root: Path) -> Backup | None:
        private = private_folder(root)
        if private is None:
            return None
        # The date and time, down to the microsecond, so names never clash and sort in order.
        name = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        folder = private / "undo" / name
        try:
            (folder / "files").mkdir(parents=True)
        except OSError:
            return None
        return cls(root, folder)

    def remember(self, path: Path) -> None:
        """Copy a file's current contents into the backup (once per file)."""
        if any(entry["absolute"] == str(path) for entry in self.entries):
            return
        existed = path.exists()
        backup_name = None
        if existed:
            backup_name = f"files/{len(self.entries)}.bak"
            shutil.copyfile(path, self.folder / backup_name)
        self.entries.append({
            "absolute": str(path),
            "path": self.relative(path),
            "existed": existed,
            "backup": backup_name,
        })
        self.save()  # straight away, in case the fix is interrupted

    def forget(self, path: Path) -> None:
        """Drop a file from the backup: it turned out not to be changed after all."""
        self.entries = [entry for entry in self.entries if entry["absolute"] != str(path)]
        self.save()

    def save(self) -> None:
        manifest = {"created": datetime.now().isoformat(timespec="seconds"), "files": self.entries}
        (self.folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def finish(self) -> None:
        """Record each file's fingerprint after the fix, and save the manifest."""
        if not self.entries:
            shutil.rmtree(self.folder, ignore_errors=True)  # nothing changed: no backup needed
            return
        for entry in self.entries:
            path = Path(entry["absolute"])
            entry["after"] = fingerprint(path.read_bytes()) if path.exists() else None
        self.save()
        prune(self.folder.parent)

    def relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return str(path)


def prune(undo_folder: Path) -> None:
    """Keep only the newest KEEP_BACKUPS backups."""
    backups = sorted(p for p in undo_folder.iterdir() if p.is_dir())
    for old in backups[:-KEEP_BACKUPS]:  # [:-10] means "all but the last 10"
        shutil.rmtree(old, ignore_errors=True)


# ===========================================================================
# UNDOING (the `decaloguex undo` command)
# ===========================================================================

@dataclass
class UndoPlan:
    """What undo is about to do, so the user can be told (and asked) first."""

    folder: Path
    created: str
    files: list[dict]
    edited_since: list[str] = field(default_factory=list)  # files changed after the fix


def latest(root: Path) -> UndoPlan | None:
    """The most recent backup in this project, or None if there isn't one."""
    undo_folder = root / ".decaloguex" / "undo"
    if not undo_folder.is_dir():
        return None
    for folder in sorted((p for p in undo_folder.iterdir() if p.is_dir()), reverse=True):
        manifest_path = folder / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not manifest["files"]:
            continue  # an empty backup: nothing was changed that time
        plan = UndoPlan(folder, manifest["created"], manifest["files"])
        for entry in plan.files:
            if "after" not in entry:
                continue  # the fix was interrupted before this could be recorded
            path = Path(entry["absolute"])
            now = fingerprint(path.read_bytes()) if path.exists() else None
            if now != entry["after"]:
                plan.edited_since.append(entry["path"])
        return plan
    return None


def restore(plan: UndoPlan) -> list[str]:
    """Put every file back as it was. Returns the relative paths restored."""
    restored = []
    for entry in plan.files:
        path = Path(entry["absolute"])
        if entry["existed"]:
            shutil.copyfile(plan.folder / entry["backup"], path)
        elif path.exists():
            path.unlink()  # the fix created this file, so undo removes it
        restored.append(entry["path"])
    shutil.rmtree(plan.folder, ignore_errors=True)  # this backup has been used up
    return restored
