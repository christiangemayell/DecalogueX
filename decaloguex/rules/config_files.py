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
                     ".xml", ".tf", ".tfvars", ".plist", ".gradle"}
CONFIG_NAMES = {"dockerfile", ".npmrc", ".pypirc", "settings.py.example"}

# Files that are full of random-looking text but never hold secrets.
SKIP_NAMES = {"package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml", "tsconfig.json",
              "jsconfig.json", "package.json"}

MAX_SIZE = 1_000_000  # bigger files are almost always generated data, not settings

# name = value, name: value, "name": "value"  (and the quoted forms).
SETTING = re.compile(r"""["']?(?P<name>[A-Za-z_][\w.\-]*)["']?\s*[:=]\s*["']?(?P<value>[^\s"'#,;]+)""")

NOTE = ("Settings files get uploaded with your code. Put the value in an environment variable "
        "(or your host's secret settings) and have this file refer to it instead.")


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
    for number, line in enumerate(lines, start=1):  # line numbers start at 1
        finding = check_line(path, number, line)
        if finding is not None:
            findings.append(finding)
    return findings


def check_line(path: Path, number: int, line: str) -> Finding | None:
    if line.lstrip().startswith(("#", "//", ";", "<!--")):
        return None  # a comment

    # SEC-001: a known key format anywhere on the line.
    for pattern in secrets.KNOWN_PATTERNS:
        if pattern.regex.search(line):
            rule_id = "SEC-001" if pattern.fixable else "SEC-003"
            return Finding(rule_id, f"Exposed {pattern.label} in a settings file", path, number,
                           secrets.IMPACT, Severity.CRITICAL, note=NOTE)

    # SEC-002: a secret-sounding name with a secret-looking value.
    for match in SETTING.finditer(line):
        name, value = match.group("name"), match.group("value")
        if not secrets.SECRET_NAME.search(name):
            continue
        if secrets.to_env_name(name).split("_")[-1].lower() in secrets.NOT_SECRET_LAST_WORDS:
            continue
        if secrets.looks_like_secret(value):
            kind = "password" if re.search(r"passw|pwd", name, re.IGNORECASE) else "secret"
            return Finding("SEC-002", f"Hard-coded {kind} '{name}' in a settings file", path, number,
                           secrets.IMPACT, Severity.CRITICAL, note=NOTE)
    return None
