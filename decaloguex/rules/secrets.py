"""
secrets.py: Exposed Secret Scrubbing (rules SEC-001, SEC-002, SEC-003).

THE PROBLEM
    AI tools often paste API keys straight into code:

        const stripe = new Stripe("sk_live_51H...");

    Once that file reaches GitHub, bots find the key within minutes.

THE FIX
    1. Move the value into the project's .env file, which stays on the
       user's computer (the .gitignore rule makes sure of that).
    2. Replace the string in the code with a lookup:
           JavaScript/TypeScript:  process.env.STRIPE_SECRET_KEY
           Python:                 os.environ.get("STRIPE_SECRET_KEY")
       For Python, `import os` is added if the file doesn't have it.

WHEN IT REPORTS INSTEAD OF FIXING
    * The app doesn't load its .env file (no dotenv, no framework that
      does it). The moved secret would come back empty and break the app,
      so the card explains the setup to do first. See project.py.
    * The code runs in the visitor's browser (a React/Vue page, a
      "use client" file, a <script> tag). .env can't hide anything there.

THE RULES
    SEC-001  The string matches a known key format (Stripe, AWS, GitHub,
             OpenAI, Anthropic, Google, Slack).
    SEC-002  Not a known format, but it's stored in a variable named like a
             secret (password, api_key, token, ...) and isn't a placeholder.
    SEC-003  A private key block (-----BEGIN ... PRIVATE KEY-----).
             Reported only: multi-line keys need care in .env files.

Only string literals are checked, so comments and code that merely mentions
the word "password" never cause false alarms.
"""

from __future__ import annotations

import re  # regular expressions, like java.util.regex
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node

from decaloguex import languages
from decaloguex.languages import SourceFile, field, line_of, text
from decaloguex.models import AppendEdit, Finding, Fix, Severity, TextEdit
from decaloguex.project import ENV_LOADING_HELP, ProjectInfo
from decaloguex.rules.common import js_imported_modules, python_import_edit

IMPACT = "Bots that scan GitHub can't steal it now. The value moved to .env, which stays on your computer."


# ===========================================================================
# THE RULE
# ===========================================================================

def check(file: SourceFile, planner: EnvPlanner, info: ProjectInfo | None = None) -> list[Finding]:
    """Scan one file for hard-coded secrets. Returns findings; writes nothing."""
    findings = []
    in_browser = runs_in_browser(file, info or ProjectInfo())
    for node in file.nodes_of(*STRING_TYPES):
        literal = read_literal(node, file)
        if literal is None:
            continue  # not a string
        # `a or b` gives a if it isn't None, otherwise b.
        finding = known_key_finding(file, literal, planner, in_browser) \
            or secret_name_finding(file, literal, planner, in_browser)
        if finding is not None:
            findings.append(finding)
    return findings


# The node types that are string literals (in JavaScript/TypeScript and Python).
STRING_TYPES = ("string", "template_string")


def known_key_finding(file: SourceFile, literal: Literal, planner: EnvPlanner, in_browser: bool) -> Finding | None:
    """SEC-001 / SEC-003: the string matches a known key format."""
    for pattern in KNOWN_PATTERNS:
        match = pattern.find(literal.value)
        if match is None:
            continue
        title = f"Exposed {pattern.label}"
        line = line_of(literal.node)

        if not pattern.fixable:  # a private key block
            return Finding("SEC-003", title, file.path, line,
                           impact="Anyone who sees this file can impersonate your server.",
                           note="Move it into a file outside your project and load it at startup.")

        is_whole_string = match.group(0) == literal.value.strip()
        if not is_whole_string or not literal.rewritable:
            return Finding("SEC-001", title, file.path, line,
                           impact="Bots that scan GitHub can steal this key and run up charges on your account.",
                           note="The key sits inside a longer string. Move it to .env by hand.")

        return fixable_finding(file, literal, planner, in_browser, "SEC-001", title,
                               env_name=pattern.env_name, shown=mask(literal.value, reveal=True))
    return None


def secret_name_finding(file: SourceFile, literal: Literal, planner: EnvPlanner, in_browser: bool) -> Finding | None:
    """SEC-002: the string is stored in a variable named like a secret."""
    name = variable_name(literal.node)
    if name is None or not SECRET_NAME.search(name):
        return None
    last_word = to_env_name(name).split("_")[-1].lower()  # [-1] is the last item of a list
    if last_word in NOT_SECRET_LAST_WORDS:
        return None  # e.g. TOKEN_URL holds a URL, not a token
    if not (looks_like_secret(literal.value) or guessable_secret(name, literal.value)) or not literal.rewritable:
        return None
    if is_password_hash(name, literal.value):
        return None
    if public_by_design(file, literal.node):
        return None

    kind = "password" if re.search(r"passw|pwd", name, re.IGNORECASE) else "secret"
    return fixable_finding(file, literal, planner, in_browser, "SEC-002", f"Hard-coded {kind} in '{name}'",
                           env_name=to_env_name(name), shown=mask(literal.value, reveal=False))


# Services whose "API keys" are MEANT to be public: they go in the web page
# and only allow safe things (searching, or connecting to your own app).
#   Algolia search keys, Firebase web config, PostHog/Mapbox public tokens...
PUBLIC_KEY_SERVICES = re.compile(
    rb"(?i)algolia|docsearch|firebase|authDomain|messagingSenderId|posthog|mapbox|publishable|recaptcha|sitekey")


def public_by_design(file: SourceFile, node: Node) -> bool:
    """Is this key in the settings of a service whose keys are public?

    Looks at the few lines around it, e.g. koel's docs:
        search: { provider: 'algolia', options: { appId: '...', apiKey: '...' } }
    """
    source = file.source
    start = node.start_byte
    for _ in range(4):  # back up four lines
        start = source.rfind(b"\n", 0, max(start - 1, 0)) + 1
    end = node.end_byte
    for _ in range(4):  # and forward four
        found = source.find(b"\n", end + 1)
        end = len(source) if found == -1 else found
    return PUBLIC_KEY_SERVICES.search(source[start:end]) is not None


def fixable_finding(file: SourceFile, literal: Literal, planner: EnvPlanner, in_browser: bool,
                    rule_id: str, title: str, env_name: str, shown: str) -> Finding:
    """Build the finding and its fix: swap the string for an env lookup."""
    if in_browser:
        # Code in a web page runs in the visitor's BROWSER. Anything it can
        # read, the visitor can read too, so .env can't hide it there. (In
        # many setups `process.env` doesn't even exist in the browser, so
        # the "fix" would crash the page.)
        return Finding(rule_id, title, file.path, line_of(literal.node), IMPACT, Severity.CRITICAL,
                       note="This code runs in the visitor's browser, so anyone can read the key. "
                            "Move the code that uses it to your server, and keep the key there in .env.")
    env_name, needs_append = planner.reserve(env_name, literal.value)
    replacement = env_lookup_code(file, env_name, literal.node)

    edits = [TextEdit(file.path, literal.node.start_byte, literal.node.end_byte, replacement.encode())]
    if file.is_python:
        import_edit = python_import_edit(file, "os")
        if import_edit is not None:
            # With 3 secrets in a file, all 3 fixes carry this same edit.
            # TextEdit is frozen (hashable), so the engine merges them into one.
            edits.append(import_edit)

    appends = []
    if needs_append:
        appends.append(AppendEdit(planner.env_path, env_line(env_name, literal.value), header=ENV_HEADER))

    fix = Fix(edits=edits, appends=appends, preview_before=f'"{shown}"', preview_after=replacement)
    return Finding(rule_id, title, file.path, line_of(literal.node), IMPACT, Severity.CRITICAL, fix=fix)


def env_lookup_code(file: SourceFile, env_name: str, node: Node) -> str:
    """The code that replaces the string literal."""
    if file.is_python:
        return f'os.environ.get("{env_name}")'
    code = f"process.env.{env_name}"
    if file.is_typescript:
        # To TypeScript, process.env.X might be undefined, and its strict mode
        # refuses to put that where a string is expected: the build fails.
        # The ! says "trust me, it's set". It changes nothing when the app runs.
        code += "!"
    # Inside a React tag (<Map apiKey="...">) code must be wrapped in { }.
    if node.parent is not None and node.parent.type == "jsx_attribute":
        return "{" + code + "}"
    return code


# ---------------------------------------------------------------------------
# Two checks that stop a "fix" from breaking the app
# ---------------------------------------------------------------------------

# Libraries that draw pages in the browser...
UI_LIBRARIES = {"react", "react-dom", "react-dom/client", "vue", "svelte", "preact", "solid-js", "@angular/core"}
# ...and frameworks that ALSO run that same code on a server.
SERVER_RENDERERS = ("next", "nuxt", "@remix-run/node", "@remix-run/react", "gatsby", "astro", "@sveltejs/kit")
# Things only a browser has.
BROWSER_ONLY = re.compile(rb"\bimport\.meta\.env\b|\bwindow\.|\bdocument\.|\blocalStorage\b")
USE_CLIENT = re.compile(rb"""^\s*["']use client["']""", re.MULTILINE)


def runs_in_browser(file: SourceFile, info: ProjectInfo) -> bool:
    """Is this JavaScript sent to the visitor's browser?

    If so, a secret in it is already public, and .env can't help.
    """
    if file.is_python:
        return False
    if file.lang.embedded:
        return True  # a <script> tag inside a web page
    if USE_CLIENT.search(file.source) or BROWSER_ONLY.search(file.source):
        return True  # Next.js's "use client" marker, or code that touches the page
    is_ui_code = file.path.suffix.lower() in (".jsx", ".tsx") or bool(js_imported_modules(file) & UI_LIBRARIES)
    renders_on_server = any(name in info.js_dependencies for name in SERVER_RENDERERS)
    return is_ui_code and not renders_on_server


def without_fixes_the_app_cannot_load(findings: list[Finding], env_loaders: set[str]) -> list[Finding]:
    """Turn secret fixes into "What to do" cards when the app doesn't load .env.

    Moving a secret into .env only works if the app READS .env when it
    starts (see project.py). Where it doesn't, the fix would leave the app
    with an empty key, so the finding keeps its warning but loses its fix,
    and explains how to set up .env loading first.
    """
    result = []
    for finding in findings:
        language = languages.detect(finding.path)
        # Any fix that relies on .env: moved secrets, and debug mode read from .env.
        uses_env = finding.fix is not None and (
            any(a.path.name == ".env" for a in finding.fix.appends)
            # A removed backup secret relies on the real one being set, from .env or elsewhere.
            or finding.rule_id == "SEC-004")
        if uses_env and language is not None and language.family not in env_loaders:
            finding = Finding(finding.rule_id, finding.title, finding.path, finding.line, finding.impact,
                              finding.severity, note=ENV_LOADING_HELP[language.family])
        result.append(finding)
    return result


# ===========================================================================
# WHAT COUNTS AS A SECRET
# ===========================================================================

@dataclass(frozen=True)
class SecretPattern:
    label: str          # shown to the user, e.g. "Stripe secret key"
    env_name: str       # the environment variable it's moved to
    regex: re.Pattern   # a compiled regex, like Pattern.compile() in Java
    fixable: bool = True
    # An extra test the match must pass (for formats a regex alone can't tell apart).
    check: object = None

    def find(self, text: str):
        """The match, or None. Made-up keys and failed extra tests don't count."""
        match = self.regex.search(text)
        if match is None or obviously_fake(match.group(0)):
            return None
        if self.check is not None and not self.check(match.group(0)):
            return None
        return match


# r"..." is a RAW string: backslashes are kept as-is, so you write \d rather
# than Java's "\\d". Always use raw strings for regexes in Python.
#
# (?<![0-9A-Za-z]) at the start means "not right after a letter or digit".
# Without it, ordinary words would match: "task-management-dashboard"
# contains "sk-management-dashboard", which looks like an OpenAI key.
# Made-up keys used in documentation and tests: Amazon's own example key
# AKIAIOSFODNN7EXAMPLE, or ghp_abcdefghijklmnopqrstuvwxyz1234567890.
FAKE_KEY = re.compile(r"EXAMPLE|abcdefghij|ABCDEFGHIJ|1234567890|0123456789|(.)\1{9}|x{6}|X{6}")


def obviously_fake(key: str) -> bool:
    return FAKE_KEY.search(key) is not None


def is_service_role_jwt(token: str) -> bool:
    """Is this a Supabase SERVICE-ROLE key? (A token whose middle part says role: service_role.)

    Supabase's public "anon" key looks the same but says role: anon, and is
    meant to be public. The service-role key skips ALL the database's rules.
    """
    import base64
    import json
    try:
        middle = token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(middle + "=" * (-len(middle) % 4)))
    except (IndexError, ValueError):
        return False
    return isinstance(data, dict) and data.get("role") == "service_role"


KNOWN_PATTERNS = [
    SecretPattern("Supabase secret key", "SUPABASE_SECRET_KEY",
                  re.compile(r"(?<![0-9A-Za-z])sb_secret_[0-9A-Za-z_-]{20,}")),
    SecretPattern("Supabase service-role key", "SUPABASE_SERVICE_ROLE_KEY",
                  re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
                  check=is_service_role_jwt),
    SecretPattern("Stripe secret key", "STRIPE_SECRET_KEY",
                  re.compile(r"(?<![0-9A-Za-z])(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    SecretPattern("AWS access key", "AWS_ACCESS_KEY_ID",
                  re.compile(r"(?<![0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])")),
    SecretPattern("GitHub token", "GITHUB_TOKEN",
                  re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}")),
    # Anthropic MUST come before OpenAI: "sk-ant-..." would also match the
    # looser OpenAI pattern, and the first match wins.
    SecretPattern("Anthropic API key", "ANTHROPIC_API_KEY",
                  re.compile(r"(?<![0-9A-Za-z])sk-ant-[0-9A-Za-z_\-]{20,}")),
    # (?=...[0-9]) means "with a digit somewhere in it": real keys are random
    # letters AND digits, while "sk-spinner-container-wrapper" is just words.
    SecretPattern("OpenAI API key", "OPENAI_API_KEY",
                  re.compile(r"(?<![0-9A-Za-z])sk-(?:proj-|svcacct-)?(?=[0-9A-Za-z_\-]*[0-9])[0-9A-Za-z_\-]{20,}")),
    SecretPattern("Google API key", "GOOGLE_API_KEY",
                  re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    SecretPattern("Slack token", "SLACK_TOKEN",
                  re.compile(r"xox[abposr]-[0-9A-Za-z\-]{10,}")),
    SecretPattern("private key", "PRIVATE_KEY",
                  # The header PLUS a long block of random characters: a header
                  # followed by "..." or "invalid" is a placeholder or a test.
                  re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\s|\\n|\\r)*[A-Za-z0-9+/=]{40,}"),
                  fixable=False),
]

# A variable whose name contains one of these probably holds a secret.
# re.IGNORECASE matches API_KEY, apiKey and api-key alike.
SECRET_NAME = re.compile(
    r"passw(?:or)?d|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|private[_-]?key",
    re.IGNORECASE,
)

# ...unless its LAST word says it holds something else: TOKEN_URL, passwordField.
NOT_SECRET_LAST_WORDS = {
    "url", "uri", "endpoint", "name", "type", "header", "field", "label",
    "placeholder", "length", "count", "limit", "id", "path", "file", "env", "var",
}

# Values that are obviously placeholders, not real secrets.
PLACEHOLDER = re.compile(
    r"your|xxx|example|changeme|placeholder|dummy|<|>|\$\{|\{\{|process\.env|os\.environ|\*\*\*",
    re.IGNORECASE,
)


HEX_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$")


# Names that ALWAYS hold a real secret (a key that signs logins or encrypts data).
STRONG_SECRET_NAME = re.compile(
    r"(?i)jwt[_-]?(?:secret|key)|secret[_-]?key|session[_-]?secret|signing[_-]?key|app[_-]?secret|"
    r"encryption[_-]?key|cookie[_-]?secret|auth[_-]?secret|token[_-]?secret|^secret$")


def guessable_secret(name: str, value: str) -> bool:
    """A word-only value under a name that must hold a real secret.

    The usual check skips word-only values (they're often labels, like
    password: "Password"). But under a name like JWT_SECRET, a value such as
    'zero-health-super-secret-key' isn't a label: it's a secret anyone can guess.
    """
    return bool(STRONG_SECRET_NAME.search(name)) and len(value) >= 8 and not re.search(r"\s", value) \
        and not re.fullmatch(r"[A-Z0-9_]+", value) and not REFERENCE.match(value) and not PLACEHOLDER.search(value)


def is_password_hash(name: str, value: str) -> bool:
    """"password": "0b14d501a594..." (64 hex characters) is a stored hash, not a password."""
    return bool(re.search(r"(?i)passw|pwd", name)) and HEX_HASH.match(value) is not None


def fingerprint_of(value: str) -> str:
    """A one-way scramble of a secret, used only to spot the same secret twice."""
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def looks_like_secret(value: str) -> bool:
    """Filter out values that are clearly NOT secrets."""
    if len(value) < 8:
        return False                          # too short
    if re.search(r"\s", value):
        return False                          # secrets don't contain spaces
    if re.search(r"://|^/", value):
        return False                          # a URL or file path
    if re.fullmatch(r"[A-Z0-9_]+", value):
        return False                          # an env-var NAME like "STRIPE_KEY"
    if PLACEHOLDER.search(value):
        return False                          # "your-key-here"
    if not value.isascii():
        return False                          # text in another language, like "パスワード"
    if all(letter.isalpha() or letter in "_-.:/," for letter in value):
        # Only letters and separators: a WORD or a NAME, not a secret.
        #   labels          { password: "Password" }
        #   storage names   TOKEN_KEY = "auth_token"
        #   permissions     AccessTokenScopeReadUser = "read:user"
        # Real secrets are random, so they nearly always contain a digit or
        # a symbol. (This lets a weak all-letters password through, but
        # "moving" a label to .env would break the page it's shown on.)
        return False
    if VALIDATION_RULE.search(value):
        return False                          # Laravel: 'password' => 'required|min:8'
    if REFERENCE.match(value):
        return False                          # points to a secret stored elsewhere: $DB_PASSWORD
    if PASSWORD_HASH.match(value):
        return False                          # a scrambled password ("hash"), not the password itself
    if REGEX_LIKE.search(value):
        return False                          # a text-matching pattern: yearToken = `\b\d{4}\b`
    if VERSION_LIKE.search(value):
        return False                          # a library and its version: io.jsonwebtoken:jjwt-api:0.11.2
    if CONTROLLER_ACTION.match(value):
        return False                          # a Rails route target: "password_resets#forgot_password"
    if CSS_CLASS.match(value):
        return False                          # a Tailwind CSS class: 'Rare Secret': 'text-orange-400'
    return len(set(value)) > 2                # "xxxxxxxx", "00000000"


# Words that form-validation rules are made of.
VALIDATION_RULE = re.compile(r"\b(?:required|nullable|sometimes|confirmed)\b")

# A REFERENCE to a secret stored somewhere else, which is exactly right:
#   $DB_PASSWORD   ${SECRET}   %API_KEY%   {{ secrets.TOKEN }}
REFERENCE = re.compile(r"^(?:\$\{?[A-Za-z_]\w*\}?(?::\S*)?|%[A-Za-z_]\w*%|\{\{.*\}\}|env\([A-Za-z_]\w*\))$")

# A Tailwind CSS class name:  text-orange-400   bg-slate-900/50
CSS_CLASS = re.compile(r"^(?:text|bg|border|ring|from|to|via|fill|stroke|shadow|outline|decoration|divide|"
                       r"placeholder|accent|caret)-[a-z]+(?:-\d{2,3})?(?:/\d+)?$")

# A web route's target, controller#action (Rails):  "password_resets#forgot_password"
CONTROLLER_ACTION = re.compile(r"^[a-z_/]+#[a-z_]+[!?]?$")

# Ends in a version number, like a library name:  jjwt-jackson:0.11.2   lodash@4.17.21
VERSION_LIKE = re.compile(r"[:@/v-]\d+\.\d+\.\d+(?:[-.][\w.]+)?['\",]*$")

# Text-matching patterns (regular expressions) use these; passwords don't.
REGEX_LIKE = re.compile(r"\\[bdswBDSW]|\(\?[:=!<]|\[\^|\{\d+(?:,\d*)?\}|\.\*|\.\+")

# Password hashes: one-way scrambles that can't be turned back into the
# password. Apps store THESE in databases on purpose (bcrypt, argon2...).
PASSWORD_HASH = re.compile(r"^\$(?:2[abxy]|argon2(?:id|i|d)|pbkdf2[\w-]*|scrypt)\$")


def to_env_name(name: str) -> str:
    """Turn a variable name into an environment-variable name.

    stripeKey -> STRIPE_KEY,  db-password -> DB_PASSWORD
    """
    # Put _ between a lowercase letter/digit and an uppercase letter (camelCase).
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    # Anything that isn't a letter or digit becomes _.
    snake = re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").upper()
    if not snake or snake[0].isdigit():
        snake = "SECRET_" + snake
    return snake


def mask(value: str, reveal: bool) -> str:
    """Hide a secret before printing it.

    Terminal output gets screenshotted and shared, so the full value is
    never printed. For known key formats we show the start (which tells you
    the key type) and the last 4 characters. Passwords are fully hidden.
    """
    if reveal and len(value) > 12:
        return value[: min(8, len(value) // 3)] + "••••" + value[-4:]
    return "••••••••"


# ===========================================================================
# READING STRINGS OUT OF THE TREE
# ===========================================================================

@dataclass
class Literal:
    """A string literal found in the code."""

    node: Node
    value: str        # the text between the quotes
    rewritable: bool  # is it safe to replace the whole literal?


def read_literal(node: Node, file: SourceFile) -> Literal | None:
    """If `node` is a string literal, return its contents. Otherwise None."""
    parent = node.parent
    # Never rewrite an object/dict KEY, e.g. {"sk_live_...": 1}. Only values.
    is_key = parent is not None and parent.type == "pair" and field(parent, "key") == node

    if file.is_python:
        return _read_python_literal(node, file, is_key)
    if node.type not in ("string", "template_string"):
        return None

    # Slice off the opening and closing quote, like Arrays.copyOfRange().
    inner = file.source[node.start_byte + 1 : node.end_byte - 1]
    # A template string with ${...} inside is built at runtime, so it isn't
    # one fixed value that could move to .env.
    has_substitution = any(child.type == "template_substitution" for child in node.children)
    rewritable = not has_substitution and b"\\" not in inner and not is_key
    return Literal(node, inner.decode("utf-8", errors="replace"), rewritable)


def _read_python_literal(node: Node, file: SourceFile, is_key: bool) -> Literal | None:
    # Python strings parse into: string_start, string_content..., string_end.
    # string_start holds the prefix letters and the quote, e.g.  f"   rb'
    if node.type != "string" or node.child_count < 2:
        return None
    start, end = node.children[0], node.children[-1]
    if start.type != "string_start" or end.type != "string_end":
        return None

    inner = file.source[start.end_byte : end.start_byte]
    prefix = text(start).lower().rstrip("'\"")  # "f", "rb", "" ...
    is_split = node.parent is not None and node.parent.type == "concatenated_string"
    has_interpolation = any(child.type == "interpolation" for child in node.children)
    rewritable = (
        "b" not in prefix                       # b"..." is bytes; os.environ gives str
        and not has_interpolation               # f"...{x}..." is built at runtime
        and b"\\" not in inner                  # escape sequences: leave to a human
        and not is_key
        # "abc" "def" is ONE string written in two halves. Swapping one half
        # for os.environ.get(...) would be a syntax error.
        and not is_split
    )
    return Literal(node, inner.decode("utf-8", errors="replace"), rewritable)


# Parent node type -> (field holding the NAME, field holding the VALUE).
_NAME_FIELDS = {
    "variable_declarator": ("name", "value"),     # JS:  const apiKey = "..."
    "assignment_expression": ("left", "right"),   # JS:  config.apiKey = "..."
    "pair": ("key", "value"),                     # JS {apiKey: "..."}  /  Python {"api_key": "..."}
    "public_field_definition": ("name", "value"), # TypeScript class field
    "field_definition": ("property", "value"),    # JavaScript class field
    "assignment": ("left", "right"),              # Python:  api_key = "..."
    "keyword_argument": ("name", "value"),        # Python:  connect(password="...")
}


def variable_name(node: Node) -> str | None:
    """The variable or key name a string is assigned to, if any.

    For `self.db_password = "x"` this returns "db_password".
    """
    parent = node.parent
    if parent is None or parent.type not in _NAME_FIELDS:
        return None
    name_field, value_field = _NAME_FIELDS[parent.type]  # unpack the pair into 2 variables
    if field(parent, value_field) != node:
        return None  # our string isn't the value (it might be the dict key)
    name_node = field(parent, name_field)
    if name_node is None:
        return None
    raw = text(name_node).strip("\"'`")
    # "self.config.api_key" -> "api_key". re.split breaks on . [ and ].
    pieces = [piece for piece in re.split(r"[.\[\]]", raw) if piece]
    return pieces[-1] if pieces else None


# ===========================================================================
# THE .env FILE
# ===========================================================================

ENV_HEADER = (
    "# Local secrets for this project. Never commit this file.\n"
    "# Created by DecalogueX: values here were moved out of your code.\n"
)


class EnvPlanner:
    """Decides the variable name for each secret moved to .env.

    One planner is shared by every file in a scan, so:
      * the same key found in two files gets the same variable name;
      * two DIFFERENT keys that want the same name get STRIPE_SECRET_KEY and
        STRIPE_SECRET_KEY_2;
      * a key that's already in .env isn't added again.

    JAVA COMPARISON: __init__ is the constructor, and `self` is Java's
    `this`, written out as the first parameter of every method.
    """

    def __init__(self, env_path: Path):
        self.env_path = env_path
        self.existing = read_env_file(env_path)  # what .env already contains
        self.planned: dict[str, str] = {}        # what this scan will add

    def reserve(self, base_name: str, value: str) -> tuple[str, bool]:
        """Pick a variable name for `value`.

        Returns (name, needs_append). needs_append is False when .env already
        holds this exact value under that name. A tuple is an easy way to
        return two things at once.
        """
        candidate = base_name
        number = 2
        while True:
            current = self.existing.get(candidate) or self.planned.get(candidate)
            if current is None:          # the name is free: take it
                self.planned[candidate] = value
                return candidate, True
            if current == value:         # same value already stored: reuse it
                return candidate, False
            candidate = f"{base_name}_{number}"  # taken by another value: try _2, _3...
            number += 1


def read_env_file(env_path: Path) -> dict[str, str]:
    """Read the KEY=VALUE lines of an existing .env file."""
    values = {}
    if not env_path.exists():
        return values
    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        # .partition splits on the FIRST "=" only, giving 3 parts:
        # ("KEY", "=", "value=with=equals"). _ means "ignore this one".
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values


def env_line(name: str, value: str) -> str:
    """Format one .env line, quoting the value only when it needs it."""
    if re.fullmatch(r"[A-Za-z0-9_\-./+=:@]+", value):
        return f"{name}={value}\n"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{name}="{escaped}"\n'
