"""
project.py: finding the project root, listing the files to scan, and
reading which libraries the project depends on.
"""

from __future__ import annotations

import json  # reads package.json (Java: Jackson or Gson)
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Folders that are never worth scanning: other people's code (node_modules),
# generated output (dist, build), caches, and Git's own data.
# A Python set literal {...} is like a Java HashSet; `in` checks are fast.
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".decaloguex",
}


def find_root(target: Path) -> Path:
    """Find the project folder that holds .env and .gitignore.

    Walks up from the target until it finds a folder containing .git. If
    there is none (the project isn't a Git repo yet), the folder being
    scanned is treated as the root.
    """
    start = target if target.is_dir() else target.parent
    # [start, *start.parents] builds a list: start, then each parent folder up
    # to the drive root. The * "unpacks" one sequence into another, like
    # Java's Stream.concat(Stream.of(start), parents.stream()).
    for folder in [start, *start.parents]:
        if (folder / ".git").exists():  # the / operator joins paths: folder/".git"
            return folder
    return start


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every file under root, skipping the SKIP_DIRS folders."""
    # os.walk visits each folder and gives back (folder, subfolders, files).
    # It's like Files.walk() in Java, but one folder at a time.
    for folder, subfolders, files in os.walk(root):
        # Changing `subfolders` IN PLACE tells os.walk which folders to enter.
        # The [:] means "replace the list's contents" rather than pointing the
        # variable at a new list, which os.walk would never see.
        subfolders[:] = [name for name in subfolders if name not in SKIP_DIRS]
        for name in files:
            yield Path(folder) / name


# ---------------------------------------------------------------------------
# Which libraries does the project use?
# ---------------------------------------------------------------------------

@dataclass
class ProjectInfo:
    """Facts about the whole project that some rules need.

    The SQL rule needs to know the database library, because each one
    writes placeholders differently (? or $1 or %s). The async rule needs
    the Express version, because Express 5 already catches errors in async
    routes and Express 4 doesn't.

    A routes file often doesn't import the database library itself (it
    imports your own ./db.js instead), so the rules look at the project's
    dependency list as well as the file's imports.
    """

    # package.json: package name -> version range, e.g. {"express": "^4.18.2"}
    js_dependencies: dict[str, str] = field(default_factory=dict)
    # requirements.txt / pyproject.toml: normalized names, e.g. {"psycopg2-binary"}
    py_dependencies: set[str] = field(default_factory=set)


def normalize_py_name(name: str) -> str:
    """Python package names ignore case, and treat _ and . like - (PEP 503).

    So "PyMySQL", "pymysql" and "Py_MySQL" are all the same package.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def read_project_info(root: Path) -> ProjectInfo:
    """Read package.json, requirements*.txt and pyproject.toml if they exist.

    Every read is wrapped in try/except: a broken or half-written file must
    never stop the scan. The worst case is just "no dependencies known".
    """
    info = ProjectInfo()

    # --- JavaScript: package.json --------------------------------------------
    try:
        data = json.loads((root / "package.json").read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies"):
            # .get(key, {}) returns {} if the section is missing.
            for name, version in data.get(section, {}).items():
                info.js_dependencies[name] = str(version)
    except (OSError, ValueError, AttributeError):
        pass  # no package.json, or it isn't valid JSON

    # --- Python: requirements*.txt -------------------------------------------
    # .glob is like a shell wildcard: requirements.txt, requirements-dev.txt...
    for req_file in root.glob("requirements*.txt"):
        try:
            for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                # "Django>=4.2  # web framework" -> "Django"
                match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", line)
                if match and not line.lstrip().startswith(("#", "-")):
                    info.py_dependencies.add(normalize_py_name(match.group(1)))
        except OSError:
            pass

    # --- Python: pyproject.toml ----------------------------------------------
    try:
        import tomllib  # built into Python 3.11+; on 3.10 we simply skip this file

        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        for requirement in data.get("project", {}).get("dependencies", []):
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", requirement)
            if match:
                info.py_dependencies.add(normalize_py_name(match.group(1)))
    except (ImportError, OSError, ValueError, AttributeError):
        pass

    return info
