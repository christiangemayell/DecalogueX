"""
fallbacks.py: SEC-004, a backup secret anyone can guess.

THE PROBLEM
    process.env.JWT_SECRET || 'superSecret'

    reads as: "use the secret from the settings; if it isn't set, use the
    word superSecret". If someone puts the app online and forgets to set
    JWT_SECRET, the app quietly uses a secret that anyone who has read the
    code (on GitHub, say) knows. For a login secret, that means anyone can
    make themselves a login pass for ANY user, admins included.

    It's like a lock that opens with the owner's key, or, if they forgot to
    set one, with a word printed in the public instructions.

WHAT COUNTS
    All three must be true:
      1. the app reads a setting:   process.env.X, os.getenv("X"), ENV["X"]...
      2. with a backup written in the code:   || 'superSecret'
      3. and the setting's NAME sounds like a secret:   JWT_SECRET, API_KEY...
    So process.env.PORT || 3000 is fine (a port isn't a secret), and an
    empty backup (|| '') is fine (there's no word to guess).

THE FIX: a locked door
    The backup is removed. If the secret isn't set, the app stops with a
    clear message ("JWT_SECRET isn't set") instead of running unlocked.
    So that the app keeps working on YOUR computer, the secret goes in .env:
      * a secret the app makes up itself (a login or session secret) gets a
        brand-new RANDOM value, so it can't be guessed;
      * any other secret (a database password, an API key) keeps the value
        it had: that's the password your own database actually uses, and a
        random one would lock you out of it.

    JavaScript   process.env.X || 'abc'        ->  process.env.X || (() => { throw new Error("X isn't set") })()
    Python       os.getenv("X", "abc")         ->  os.environ["X"]           (stops with KeyError: 'X')
    Ruby         ENV.fetch("X", "abc")         ->  ENV.fetch("X")            (stops with KeyError)
    C#           GetEnvironmentVariable("X") ?? "abc"  ->  ... ?? throw new InvalidOperationException("X isn't set")
    Kotlin       System.getenv("X") ?: "abc"   ->  System.getenv("X") ?: error("X isn't set")
    PHP, Java and Spring settings get a "What to do" card.

    Like every secret fix, this only happens if the app loads .env (see
    project.py). Otherwise it's a card too.
"""

from __future__ import annotations

import re
import secrets as random_maker  # Python's own module for random secrets (not our rules/secrets.py)
from dataclasses import dataclass
from pathlib import Path

from decaloguex.languages import SourceFile
from decaloguex.models import AppendEdit, Finding, Fix, Severity, TextEdit
from decaloguex.rules import secrets
from decaloguex.rules.common import short

TITLE = "Backup secret anyone can guess"
IMPACT = "If the real secret is ever missing online, the app stops instead of using one everyone knows."

# A plain string with nothing inserted into it. ($, { and # would mean the
# text is built while the app runs, so it's not a fixed word.)
LITERAL = rb"""(?P<lit>'[^'\\\n${#]*'|"[^"\\\n${#]*"|`[^`\\\n${#]*`)"""


@dataclass(frozen=True)
class Shape:
    """One way of writing "this setting, or else this word"."""
    family: str             # which language (or "settings")
    regex: re.Pattern
    fixable: bool = True


def shape(family: str, regex: bytes, fixable: bool = True) -> Shape:
    return Shape(family, re.compile(regex), fixable)


SHAPES = [
    # JavaScript / TypeScript:  process.env.X || 'abc'   process.env['X'] ?? 'abc'
    shape("js", rb"(?P<lookup>process\.env(?:\.(?P<name>[A-Za-z_]\w*)|\[\s*['\"](?P<name2>\w+)['\"]\s*\]))"
                rb"\s*(?:\|\||\?\?)\s*" + LITERAL),
    # Python:  os.getenv("X", "abc")   os.environ.get("X", "abc")
    shape("python", rb"os\.(?:getenv|environ\.get)\(\s*['\"](?P<name>\w+)['\"]\s*,\s*" + LITERAL + rb"\s*\)"),
    # Python:  os.getenv("X") or "abc"
    shape("python", rb"os\.(?:getenv|environ\.get)\(\s*['\"](?P<name>\w+)['\"]\s*\)\s+or\s+" + LITERAL),
    # Ruby:  ENV.fetch("X", "abc")   ENV["X"] || "abc"
    shape("ruby", rb"ENV\.fetch\(\s*['\"](?P<name>\w+)['\"]\s*,\s*" + LITERAL + rb"\s*\)"),
    shape("ruby", rb"ENV\[\s*['\"](?P<name>\w+)['\"]\s*\]\s*\|\|\s*" + LITERAL),
    # C#:  Environment.GetEnvironmentVariable("X") ?? "abc"
    shape("csharp", rb"(?P<lookup>Environment\.GetEnvironmentVariable\(\s*\"(?P<name>\w+)\"\s*\))\s*\?\?\s*" + LITERAL),
    # Kotlin:  System.getenv("X") ?: "abc"
    shape("kotlin", rb"(?P<lookup>System\.getenv\(\s*\"(?P<name>\w+)\"\s*\))\s*\?:\s*" + LITERAL),
    # PHP (card):  getenv('X') ?: 'abc'   env('X', 'abc')   $_ENV['X'] ?? 'abc'
    shape("php", rb"getenv\(\s*['\"](?P<name>\w+)['\"]\s*\)\s*\?:\s*" + LITERAL, fixable=False),
    shape("php", rb"(?<![\w>$])env\(\s*['\"](?P<name>\w+)['\"]\s*,\s*" + LITERAL + rb"\s*\)", fixable=False),
    shape("php", rb"\$_ENV\[\s*['\"](?P<name>\w+)['\"]\s*\]\s*\?\?\s*" + LITERAL, fixable=False),
    # Java (card):  System.getenv().getOrDefault("X", "abc")   @Value("${jwt.secret:abc}")
    shape("java", rb"System\.getenv\(\)\.getOrDefault\(\s*\"(?P<name>\w+)\"\s*,\s*" + LITERAL + rb"\s*\)", fixable=False),
    shape("java", rb"@Value\(\s*\"\$\{(?P<name>[\w.-]+):(?P<lit>[^}\"\s]+)\}\"", fixable=False),
    shape("kotlin", rb"@Value\(\s*\"\\?\$\{(?P<name>[\w.-]+):(?P<lit>[^}\"\s]+)\}\"", fixable=False),
    # Spring settings (card):  secret: ${JWT_SECRET:mysecret}
    # (Only a single colon: docker-compose's ${X:-default} is a different thing.)
    shape("settings", rb"\$\{(?P<name>[A-Za-z_][\w.-]*):(?P<lit>[^-}\s'\"][^}\s'\"]*)\}", fixable=False),
    # Ktor settings (card):  secret: "$ADMIN_SECRET:test"
    shape("settings", rb"[\"']\$(?P<name>[A-Za-z_]\w*):(?P<lit>[^\s'\"]+)[\"']", fixable=False),
]

# Names that contain "token" or "secret" but hold something else: how long a
# login lasts (TOKEN_EXPIRES), which algorithm it uses, and so on.
NOT_SECRET_WORDS = {
    "expires", "expiry", "expiresin", "expiration", "exp", "ttl", "lifetime", "duration", "age", "maxage",
    "timeout", "algorithm", "alg", "issuer", "iss", "audience", "aud", "prefix", "length", "size",
}
# A duration or number, like "7d" or "3600": not a secret, whatever the name says.
NOT_SECRET_VALUE = re.compile(r"\d+\s*[smhdwy]?|\d+\s*(?:sec|min|hour|day|week)s?|true|false|none|null")

# Secrets the app makes up for itself: nothing outside the app has to know
# them, so a fresh random one works. (A database password or an API key
# has to MATCH something else, so those keep their value.)
APP_MADE = re.compile(r"(?i)jwt|session|cookie|signing|secret_?key|app_?key|app_?secret|admin|encrypt|hmac|csrf|salt|^secret$")

NOTE_PHP = ("Remove the backup value, so the app stops if the secret is missing: "
            "getenv('{name}') ?: throw new RuntimeException('{name} isn\\'t set'), "
            "and put {name} in your .env file.")
NOTE_OTHER = ("Remove the backup value ({value}), so the app stops if {name} is missing instead of using a "
              "value everyone can read, and set {name} in your settings or .env file.")


# Key names the secret rules don't count, but that are secrets here: JWT_KEY, APP_KEY...
SIGNING_KEY = re.compile(r"(?i)(?:jwt|signing|encryption|hmac|app|secret)[_.-]?key")


def is_secret_name(name: str) -> bool:
    """JWT_SECRET, apiKey, db.password, JWT_KEY: yes. PORT, TOKEN_EXPIRES: no."""
    if not (secrets.SECRET_NAME.search(name) or SIGNING_KEY.search(name)):
        return False
    last = re.split(r"[._\-]", name)[-1]
    # Also split camelCase: tokenExpiresIn -> ["token", "Expires", "In"] -> check every word.
    words = {w.lower() for w in re.findall(r"[A-Za-z][a-z]*|[A-Z]+(?![a-z])", name)} | {last.lower()}
    return not (words & NOT_SECRET_WORDS or last.lower() in secrets.NOT_SECRET_LAST_WORDS)


def check(file: SourceFile, planner: secrets.EnvPlanner, comments: list[tuple[int, int]]) -> list[Finding]:
    """Check one code file. Returns findings; writes nothing."""
    return search(file.path, file.source, file.lang.family, comments, planner)


def check_text_file(path: Path) -> list[Finding]:
    """Check a settings file (application.yml, application.properties...)."""
    try:
        source = path.read_bytes()
    except OSError:
        return []
    return search(path, source, "settings", [], None)


def search(path: Path, source: bytes, family: str, comments: list[tuple[int, int]],
           planner: secrets.EnvPlanner | None) -> list[Finding]:
    findings = []
    seen = set()
    for item in SHAPES:
        if item.family != family:
            continue
        for match in item.regex.finditer(source):
            if any(s <= match.start() < e for s, e in comments):
                continue  # in a comment
            name = (match.group("name") or match.groupdict().get("name2") or b"").decode()
            value = match.group("lit").decode("utf-8", "replace").strip("'\"`")
            if not value or not is_secret_name(name) or NOT_SECRET_VALUE.fullmatch(value.lower()):
                continue
            if not app_makes_it(source, match, name) and not secrets.looks_like_secret(value):
                # A backup database password like 'mysql' or 'postgres': it has
                # to match a real database to do anything, so it isn't the
                # open door a guessable login key is.
                continue
            line = source.count(b"\n", 0, match.start()) + 1
            if line in seen:
                continue
            seen.add(line)
            fix = make_fix(path, source, family, match, name, value, planner) if item.fixable else None
            if fix is not None:
                findings.append(Finding("SEC-004", TITLE, path, line, IMPACT, Severity.CRITICAL, fix=fix))
            else:
                note = NOTE_PHP if family == "php" else NOTE_OTHER
                findings.append(Finding("SEC-004", TITLE, path, line, IMPACT, Severity.CRITICAL,
                                        note=note.format(name=name, value=short(value, 30))))
    return findings


def app_makes_it(source: bytes, match: re.Match, name: str) -> bool:
    """Is this a secret the app makes up itself, like a login-signing key?

    Looks at the setting's name AND what it's stored in:
        SECRET_KEY = os.environ.get('CONDUIT_SECRET', 'secret-key')
    is Flask's login-signing key, whatever the setting is called.
    """
    line_start = source.rfind(b"\n", 0, match.start()) + 1
    stored_in = source[line_start:match.start()].decode("utf-8", "replace")
    return bool(APP_MADE.search(name) or APP_MADE.search(stored_in))


def make_fix(path: Path, source: bytes, family: str, match: re.Match, name: str, value: str,
             planner: secrets.EnvPlanner | None) -> Fix | None:
    if planner is None or not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    missing = f"{name} isn't set"
    if family == "js":
        new = f'{match.group("lookup").decode()} || (() => {{ throw new Error("{missing}"); }})()'
    elif family == "python":
        new = f'os.environ["{name}"]'
    elif family == "ruby":
        new = f'ENV.fetch("{name}")'
    elif family == "csharp":
        new = f'{match.group("lookup").decode()} ?? throw new InvalidOperationException("{missing}")'
    elif family == "kotlin":
        new = f'{match.group("lookup").decode()} ?: error("{missing}")'
    else:
        return None

    # What goes in .env, so the app keeps working on this computer.
    env_value = random_maker.token_urlsafe(32) if app_makes_it(source, match, name) else value
    already = planner.existing.get(name) or planner.planned.get(name)
    appends = []
    if already is None:
        planner.planned[name] = env_value
        appends = [AppendEdit(planner.env_path, secrets.env_line(name, env_value), header=secrets.ENV_HEADER)]

    old = match.group(0).decode("utf-8", "replace")
    edit = TextEdit(path, match.start(), match.end(), new.encode())
    return Fix(edits=[edit], appends=appends, preview_before=short(old, 50), preview_after=short(new, 60))
