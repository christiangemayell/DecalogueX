"""
config_files.py: secrets hidden in settings files (rules SEC-001, SEC-002).

THE PROBLEM
    Keys and passwords don't only end up in code. They're often pasted into
    settings files that get uploaded with everything else:

        config.yml          password: hunter2
        appsettings.json    "ApiKey": "sk_live_..."
        docker-compose.yml  - STRIPE_KEY=sk_live_...

WHY THIS IS REPORT-ONLY
    Settings files are read by many different tools, and each one has its
    own way (or no way) of reading environment variables. Changing the file
    could quietly break the app, so DecalogueX explains what to do instead.

HOW IT WORKS
    Settings files aren't code, so there's no syntax tree. Each line is
    checked with the same patterns the code rules use:
      * a known key format anywhere on the line          -> SEC-001
      * a secret-sounding name set to a secret-looking value -> SEC-002
"""

from __future__ import annotations

import re
from pathlib import Path

from decaloguex.models import Finding, Severity
from decaloguex.rules import secrets

# Settings file types that are worth checking.
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
                     ".xml", ".tf", ".tfvars", ".plist", ".gradle",
                     # Scripts: setup and deployment scripts often set keys,
                     # like  export STRIPE_KEY=sk_live_...
                     ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
CONFIG_NAMES = {"dockerfile", ".npmrc", ".pypirc", ".envrc", "settings.py.example"}

# Files that are full of random-looking text but never hold secrets.
SKIP_NAMES = {"package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml", "tsconfig.json",
              "jsconfig.json", "package.json"}

MAX_SIZE = 1_000_000  # bigger files are almost always generated data, not settings
# Lines longer than this are data (recorded web pages, encoded images), not
# settings. Checking them was very slow: one test recording took 5 minutes.
MAX_LINE = 4_000

# A setting at the START of a line:  name = value,  name: value,  "name": "value".
# Starting at the line's beginning matters: a looser version, searching the
# whole line, flagged build-file lines like  implementation 'io.jsonwebtoken:jjwt'
# (it saw "jsonwebtoken" as a token name), and was very slow on long lines.
# The optional words in front cover scripts and Dockerfiles:
#   export API_KEY=...   set API_KEY=...   $env:API_KEY = "..."   ENV API_KEY=...   - API_KEY=...
SETTING = re.compile(
    r"""^\s*(?:export\s+|set\s+|setx\s+|\$env:|\$|ENV\s+|ARG\s+|-\s+)?"""
    r"""["']?(?P<name>[A-Za-z_][\w.\-]*)["']?\s*[:=]\s*["']?(?P<value>[^\s"'#,;]+)"""
)
# In JSON files several settings can share one line: {"user": "x", "password": "y"}.
# Both sides are in quotes there, so matching anywhere on the line is safe.
JSON_PAIR = re.compile(r""""(?P<name>[A-Za-z_][\w.\-]*)"\s*:\s*"(?P<value>[^"\\]*)\"""")
# Database "connection strings" hide a password in the middle of a long value:
#   "Server=db;User Id=sa;Password=@someThingComplicated1234"
CONNECTION_PASSWORD = re.compile(r"(?i)\b(?P<name>password|pwd)=(?P<value>[^;\"'\s]+)")

NOTE = ("Settings files and scripts get uploaded with your code. Put the value in an environment "
        "variable (or your host's secret settings) and have this file refer to it instead.")


def is_config_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SKIP_NAMES or name.startswith(".env"):
        return False  # .env files are the RIGHT place for secrets (the .gitignore rule protects them)
    return path.suffix.lower() in CONFIG_EXTENSIONS or name in CONFIG_NAMES


def check(path: Path) -> list[Finding]:
    """Check one settings file for secrets. Returns findings; writes nothing."""
    try:
        if path.stat().st_size > MAX_SIZE:
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    findings = []
    is_json = path.suffix.lower() == ".json"
    is_yaml = path.suffix.lower() in (".yml", ".yaml")
    section = ""  # the YAML section we're in, e.g. "development"
    for number, line in enumerate(lines, start=1):  # line numbers start at 1
        if len(line) > MAX_LINE:
            continue  # data, not a setting (see MAX_LINE)
        if is_yaml:
            top = YAML_SECTION.match(line)
            if top:
                section = top.group(1).lower()
        if not MIGHT_BE_SECRET.search(line):
            continue  # the quick pre-check (see MIGHT_BE_SECRET)
        finding = check_line(path, number, line, is_json)
        if finding is None:
            continue
        if section in LOCAL_SECTIONS and finding.rule_id != "SEC-001":
            continue  # Rails-style "development:" / "test:" settings: made-up values, kept on purpose
        findings.append(finding)
    return findings


# A top-level YAML heading with nothing after it:  "development:"
YAML_SECTION = re.compile(r"^([A-Za-z_][\w-]*)\s*:\s*(?:#.*)?$")
# Sections that only ever run on the developer's computer or in tests.
LOCAL_SECTIONS = {"development", "dev", "test", "testing", "local"}


# A quick pre-check, run on every line before the full checks: does the line
# mention anything secret-related at all? Most lines don't, and this one
# search is much quicker than the ten or so full checks. It matters for big
# files: one test project had 665,000 lines of translations, and checking
# them fully took minutes. (Every key format and secret word the full checks
# look for is included here, so the pre-check never hides a real finding.)
MIGHT_BE_SECRET = re.compile(
    r"sk_|rk_|AKIA|ASIA|gh[pousr]_|github_pat_|sk-|AIza|xox|-----BEGIN"
    r"|(?i:passw|pwd|secret|api[_-]?key|access[_-]?key|token|private)"
)


def check_line(path: Path, number: int, line: str, is_json: bool | None = None) -> Finding | None:
    if line.lstrip().startswith(("#", "//", ";", "<!--", "REM ", "rem ", "::")):
        return None  # a comment

    # SEC-001: a known key format anywhere on the line.
    for pattern in secrets.KNOWN_PATTERNS:
        match = pattern.find(line)
        if match:
            rule_id = "SEC-001" if pattern.fixable else "SEC-003"
            return Finding(rule_id, f"Exposed {pattern.label} in a settings file", path, number,
                           secrets.IMPACT, Severity.CRITICAL, note=NOTE,
                           same_as=secrets.fingerprint_of(match.group(0)))

    # SEC-002: a secret-sounding name with a secret-looking value.
    candidates = list(SETTING.finditer(line)) + list(CONNECTION_PASSWORD.finditer(line))
    if is_json is None:
        is_json = path.suffix.lower() == ".json"
    if is_json:
        candidates += list(JSON_PAIR.finditer(line))
    for match in candidates:
        name, value = match.group("name"), match.group("value")
        start, end = match.start("value"), match.end("value")
        quoted = start > 0 and line[start - 1] in "\"'"
        if quoted and end < len(line) and line[end] not in "\"'":
            continue  # the quoted text carries on past a space: a sentence, not a secret
        if not secrets.SECRET_NAME.search(name):
            continue
        if secrets.to_env_name(name).split("_")[-1].lower() in secrets.NOT_SECRET_LAST_WORDS:
            continue
        if secrets.looks_like_secret(value) and not secrets.is_password_hash(name, value):
            kind = "password" if re.search(r"passw|pwd", name, re.IGNORECASE) else "secret"
            return Finding("SEC-002", f"Hard-coded {kind} '{name}' in a settings file", path, number,
                           secrets.IMPACT, Severity.CRITICAL, note=NOTE, same_as=secrets.fingerprint_of(value))
    return None
