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
    # go.mod: module paths, e.g. {"github.com/lib/pq"}
    go_modules: set[str] = field(default_factory=set)
    # package.json: the text of the "scripts" section, e.g. 'node --env-file=.env server.js'
    js_scripts: str = ""
    # The language families whose apps load a .env file when they start.
    # See "Does the app load its .env file?" at the bottom of this file.
    env_loaders: set[str] = field(default_factory=set)


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
        info.js_scripts = " ".join(str(command) for command in data.get("scripts", {}).values())
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

    # --- Go: go.mod -----------------------------------------------------------
    try:
        go_mod = (root / "go.mod").read_text(encoding="utf-8", errors="replace")
        # Lines like  "github.com/lib/pq v1.10.9"  inside require ( ... ).
        info.go_modules = set(re.findall(r"^\s*(?:require\s+)?([\w.\-]+\.[\w]+/[\w.\-/]+)\s+v", go_mod, re.MULTILINE))
    except OSError:
        pass

    info.env_loaders = env_loaders_from_project_files(root, info)
    return info


# ---------------------------------------------------------------------------
# Does the app load its .env file?
# ---------------------------------------------------------------------------
#
# The secret rules move passwords and keys out of the code and into a file
# called .env. But a .env file does nothing by itself: the app has to READ
# it when it starts. Plain Node.js, Python, PHP, Java and the rest don't.
# They need a small library (usually called "dotenv"), or a framework that
# does it for them, like Next.js.
#
# If nothing loads .env, the moved secret comes back EMPTY and the app
# breaks (payments fail, logins fail). So before any secret is moved,
# DecalogueX looks for proof that .env is loaded. No proof, no move: it
# explains how to set up loading instead (ENV_LOADING_HELP below).

_WHY = "This app doesn't load its .env file yet, so the value would come back empty and break things. "
_THEN = " Then scan again and I'll move it for you."

# Family -> what to tell the user when the app doesn't load .env.
ENV_LOADING_HELP = {
    "js": _WHY + 'Run `npm install dotenv` and add `require("dotenv").config();` as the first line '
                 "of your main file." + _THEN,
    "python": _WHY + "Run `pip install python-dotenv` and add `from dotenv import load_dotenv` and "
                     "`load_dotenv()` at the top of your main file." + _THEN,
    "php": _WHY + "Run `composer require vlucas/phpdotenv` and load it when the app starts with "
                  "`Dotenv\\Dotenv::createUnsafeImmutable(__DIR__)->load();`." + _THEN,
    "java": _WHY + "Add a .env loader such as dotenv-java, or set the value as a real environment "
                   "variable where the app runs." + _THEN,
    "kotlin": _WHY + "Add a .env loader such as dotenv-kotlin, or set the value as a real environment "
                     "variable where the app runs." + _THEN,
    "csharp": _WHY + "Add the DotNetEnv package and call `DotNetEnv.Env.Load();` when the app starts." + _THEN,
    "go": _WHY + "Run `go get github.com/joho/godotenv` and call `godotenv.Load()` at the start of main()." + _THEN,
    "ruby": _WHY + 'Add `gem "dotenv"` to your Gemfile and `require "dotenv/load"` when the app starts.' + _THEN,
    "swift": _WHY + "Load .env when the app starts (Vapor does this for you; otherwise use a package "
                    "such as SwiftDotenv)." + _THEN,
}

# Family -> a pattern that, found in a source file, proves .env gets loaded.
_ENV_LOADING_CODE = {
    "js": re.compile(rb"""require\(\s*['"]dotenv|from\s+['"]dotenv|import\s+['"]dotenv/config|process\.loadEnvFile"""),
    "python": re.compile(rb"load_dotenv|dotenv_values|\.read_env\("),
    "php": re.compile(rb"Dotenv::create|Dotenv\\Dotenv"),
    "java": re.compile(rb"Dotenv\.(?:load|configure)"),
    "kotlin": re.compile(rb"Dotenv\.(?:load|configure)|dotenv\s*\{|dotenv\(\)"),
    "csharp": re.compile(rb"DotNetEnv|Env\.Load\("),
    "go": re.compile(rb"godotenv\."),
    "ruby": re.compile(rb"dotenv/load|Dotenv\.load"),
    "swift": re.compile(rb"(?i)dotenv"),
}

# package.json scripts that load .env: Node's --env-file option, the dotenv
# and env-cmd command-line tools, and Bun (which always loads .env).
SCRIPT_LOADS_ENV = re.compile(r"--env-file|\bdotenv\b|\benv-cmd\b|\bbun\b")


def source_loads_env(family: str, source: bytes) -> bool:
    """Does this source file contain code that loads .env?"""
    pattern = _ENV_LOADING_CODE.get(family)
    return bool(pattern and pattern.search(source))


def env_loaders_from_project_files(root: Path, info: ProjectInfo) -> set[str]:
    """Which language families load .env, judging by the project's own files.

    This looks at dependency lists (package.json, requirements.txt, ...).
    The engine adds to it while scanning, when it sees loading code in a
    source file (see source_loads_env above).

    If your app gets its settings some other way (from Docker or your
    hosting dashboard, say), set DECALOGUEX_ENV_LOADED=1 to tell
    DecalogueX "trust me, the values will be there".
    """
    if os.environ.get("DECALOGUEX_ENV_LOADED", "").lower() in ("1", "true", "yes"):
        return set(ENV_LOADING_HELP)  # every family

    def mentions(file_names: list[str], pattern: str) -> bool:
        """True if any of these files (in the project folder) contains the pattern."""
        for name in file_names:
            for path in root.glob(name):
                try:
                    if re.search(pattern, path.read_text(encoding="utf-8", errors="replace")):
                        return True
                except OSError:
                    pass
        return False

    loaders = set()

    # JavaScript: the dotenv package, a framework that loads .env by itself,
    # Node's own --env-file option, or Bun (which always loads .env).
    js_packages = ("dotenv", "next", "nuxt", "@nestjs/config")
    uses_package = any(name in info.js_dependencies for name in js_packages)
    uses_script = re.search(SCRIPT_LOADS_ENV, info.js_scripts)
    uses_bun = (root / "bun.lockb").exists() or (root / "bun.lock").exists()
    if uses_package or uses_script or uses_bun:
        loaders.add("js")

    # Python: a dotenv library, or Pipenv (which loads .env when it runs your app).
    if info.py_dependencies & {"python-dotenv", "django-environ", "environs"} or (root / "Pipfile").exists():
        loaders.add("python")

    if mentions(["composer.json"], r"vlucas/phpdotenv|symfony/dotenv|laravel/framework"):
        loaders.add("php")
    if mentions(["pom.xml", "build.gradle", "build.gradle.kts"], r"(?i)dotenv"):
        loaders.update({"java", "kotlin"})
    if mentions(["*.csproj", "*/*.csproj"], r"DotNetEnv"):
        loaders.add("csharp")
    if any("godotenv" in module for module in info.go_modules):
        loaders.add("go")
    if mentions(["Gemfile"], r"dotenv"):
        loaders.add("ruby")
    if mentions(["Package.swift"], r"(?i)vapor|dotenv"):
        loaders.add("swift")
    return loaders
