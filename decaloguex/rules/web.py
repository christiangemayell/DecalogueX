"""
web.py: five common web-safety mistakes, in every language.

  DEBUG-001  Debug mode left on.
             Debug mode shows anyone who triggers an error a detailed page:
             code, settings, sometimes passwords. Fine on your own computer,
             dangerous online.
             FIX (Python): read it from .env, so it stays ON on your computer
             (where .env says DEBUG=1) and switches OFF online (where it doesn't).

  XSS-001    Raw HTML put into a web page ("cross-site scripting").
             If the HTML includes anything a visitor typed, they can type a
             script that runs in OTHER visitors' browsers and steals their
             logins. Examples: innerHTML =, dangerouslySetInnerHTML, v-html,
             {!! $x !!}, |safe, @Html.Raw(...).
             FIX (PHP): echo $_GET['name'] becomes
                        echo htmlspecialchars($_GET['name'], ...),
             which shows the text instead of running it. Everything else gets
             a card: only a person knows if the HTML comes from someone trusted.

  CORS-001   Any website allowed to call your server WITH the visitor's login.
             Browsers normally stop other websites from using your server on
             a visitor's behalf. A plain "allow any website" (*) is still
             safe: browsers then refuse to send the visitor's login. The
             danger is accepting any website AND allowing logins
             ("credentials"), so only that combination is reported.
             Card only: the fix needs your own website's address.

  TLS-001    Security certificate checks switched off (verify=False...).
             The certificate check proves you're talking to the real server.
             Without it, anyone on the same Wi-Fi can pretend to be it and
             read everything, passwords included. Card only.

  MASS-001   A whole form saved straight into the database (create(req.body)).
             A visitor can add extra fields the form never had, like
             "isAdmin": true, and the database saves them too. Card only:
             only you know which fields a visitor should be allowed to set.

HOW IT WORKS
    These mistakes look alike in every language, so most are found by
    searching the file's text for known patterns, rather than walking the
    code tree like the other rules. Two safety measures keep it accurate:
      * matches inside comments are ignored ("// don't use innerHTML");
      * a line that cleans its HTML first (DOMPurify, sanitize, escape...)
        isn't reported: that's the right way to do it.
    The few automatic fixes do use the code tree, like the other rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node

from decaloguex.languages import SourceFile, ancestors, field, line_of, text, walk
from decaloguex.models import AppendEdit, Finding, Fix, Severity, TextEdit
from decaloguex.project import ProjectInfo
from decaloguex.rules import secrets
from decaloguex.rules.common import python_import_edit, short

# Page-template files that have no code reader of their own: their text is
# still searched for the XSS patterns.
TEMPLATE_EXTENSIONS = {".ejs", ".hbs", ".handlebars", ".mustache", ".twig", ".jinja", ".jinja2", ".j2",
                       ".njk", ".liquid", ".pug"}


# ===========================================================================
# THE PATTERNS
# ===========================================================================

@dataclass(frozen=True)
class Pattern:
    rule: str
    regex: re.Pattern
    kinds: frozenset[str]        # which kinds of file it applies to (see kinds_of)
    unless: re.Pattern | None = None   # skip the line if this ALSO appears on it


def pattern(rule: str, regex: bytes, kinds: str, unless: bytes | None = None) -> Pattern:
    return Pattern(rule, re.compile(regex), frozenset(kinds.split()),
                   re.compile(unless) if unless else None)


# Cleaning HTML first is the right way to do it.
SANITIZED = rb"(?i)sanitiz|DOMPurify|purify|bleach|escape|htmlspecialchars|htmlentities|strip_tags|\bxss\(|\bclean\("
# A plain fixed string can't contain anything a visitor typed:  el.innerHTML = "";
LITERAL_ONLY = (rb"""(?:innerHTML|outerHTML)\s*=\s*(?:'[^'\\]*'|"[^"\\]*"|`[^`\\$]*`|null)\s*[);,]*\s*$""")
# Ruby: fixed text marked safe:  "".html_safe   "__FOREM_DATE__".html_safe  (nothing inserted with #{})
RUBY_LITERAL_SAFE = rb"""(?:'[^'\\]*'|"[^"#\\]*")\.html_safe"""
# Rails' to_json turns < > & into \u003c-style codes by default
# (escape_html_entities_in_json), so its output can't break out of a script.
# (An app that switches that off is checked for in check_text_file/check.)
RAILS_JSON = rb"\.to_json\s*(?:\)\s*)?(?:\.html_safe|%>)|raw\s*\(?\s*[@\w.\[\]'\"]+\.to_json"
# Code highlighters (Rouge, Shiki, Prism...) escape the code they colour.
HIGHLIGHTED = rb"\b[Hh]ighlight\w*"

PATTERNS = [
    # --- DEBUG-001 ------------------------------------------------------------
    pattern("DEBUG-001", rb"\bapp\.config\[\s*['\"]DEBUG['\"]\s*\]\s*=\s*True\b|\bFastAPI\([^)]*\bdebug\s*=\s*True",
            "python"),
    pattern("DEBUG-001", rb"""['"]debug['"]\s*=>\s*true\b|ini_set\(\s*['"]display_errors['"]\s*,\s*['"]?(?:1|on|true)""",
            "php"),
    pattern("DEBUG-001", rb"""app\.set\(\s*['"]env['"]\s*,\s*['"]development['"]""", "js"),
    pattern("DEBUG-001", rb"\.UseDeveloperExceptionPage\(\)", "csharp"),
    pattern("DEBUG-001", rb"gin\.SetMode\(\s*gin\.DebugMode\s*\)", "go"),
    pattern("DEBUG-001", rb"include-(?:stacktrace|message|exception)\s*[:=]\s*['\"]?always", "settings"),

    # --- XSS-001 --------------------------------------------------------------
    pattern("XSS-001", rb"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\binsertAdjacentHTML\(|\bdocument\.write(?:ln)?\(",
            "js", unless=SANITIZED + b"|" + LITERAL_ONLY),
    pattern("XSS-001", rb"\bdangerouslySetInnerHTML\s*=", "js", unless=SANITIZED),
    pattern("XSS-001", rb"\bv-html\s*=|\{@html\s", "markup", unless=SANITIZED),
    pattern("XSS-001", rb"\{!!.+?!!\}", "php markup", unless=SANITIZED),
    pattern("XSS-001", rb"@?Html\.Raw\(|\(MarkupString\)", "csharp markup", unless=SANITIZED),
    pattern("XSS-001", rb"\.html_safe\b|<%==|<%=\s*raw\b", "ruby markup",
            unless=SANITIZED + b"|" + RUBY_LITERAL_SAFE + b"|" + HIGHLIGHTED),
    pattern("XSS-001", rb"\|\s*safe\b|\{%-?\s*autoescape\s+(?:off|false)|\bmark_safe\(", "python markup",
            unless=SANITIZED),
    pattern("XSS-001", rb"<%-|\{\{\{|\|\s*raw\b", "template", unless=SANITIZED),
    pattern("XSS-001", rb"\btemplate\.HTML\(", "go", unless=SANITIZED),

    # --- CORS-001 -------------------------------------------------------------
    pattern("CORS-001", rb"""\bcors\(\s*\)|\borigin\s*:\s*(?:['"]\*['"]|true\b)|Access-Control-Allow-Origin['"]\s*,\s*['"]\*""",
            "js"),
    pattern("CORS-001", rb"""allow_origins\s*=\s*\[\s*['"]\*['"]|CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|\bCORS\(\s*app\s*\)|\borigins\s*=\s*['"]\*['"]""",
            "python"),
    pattern("CORS-001", rb"""header\(\s*['"]Access-Control-Allow-Origin:\s*\*|['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]""",
            "php"),
    pattern("CORS-001", rb"\.AllowAnyOrigin\(\)|SetIsOriginAllowed\(\s*_?\w*\s*=>\s*true\s*\)", "csharp"),
    pattern("CORS-001", rb"""AllowAllOrigins\s*:\s*true|AllowOrigins\s*:\s*\[\]string\{\s*"\*"|"Access-Control-Allow-Origin",\s*"\*\"""",
            "go"),
    pattern("CORS-001", rb"""@CrossOrigin\s*(?:\(\s*\)|\(\s*(?:origins\s*=\s*)?"\*"|$)|allowedOrigins?\(\s*"\*"|allowedOriginPatterns\(\s*"\*"|\banyHost\(\)""",
            "java kotlin"),
    pattern("CORS-001", rb"""\borigins\s+['"]\*['"]""", "ruby"),
    pattern("CORS-001", rb"allowedOrigin:\s*\.all\b", "swift"),
    pattern("CORS-001", rb"""allowed-origins\s*[:=]\s*['"]?\*""", "settings"),

    # --- TLS-001 --------------------------------------------------------------
    pattern("TLS-001", rb"\bverify\s*=\s*False\b|_create_unverified_context|\bCERT_NONE\b", "python"),
    pattern("TLS-001", rb"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=|strictSSL\s*:\s*false", "js"),
    pattern("TLS-001", rb"InsecureSkipVerify\s*:\s*true", "go"),
    pattern("TLS-001", rb"""CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b|['"]verify['"]\s*=>\s*false""", "php"),
    pattern("TLS-001", rb"ServerCertificateCustomValidationCallback\s*=.*=>\s*true|DangerousAcceptAnyServerCertificateValidator",
            "csharp"),
    pattern("TLS-001", rb"VERIFY_NONE", "ruby"),
    pattern("TLS-001", rb"(?i)trustAllCerts|InsecureTrustManagerFactory|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER",
            "java kotlin"),
    pattern("TLS-001", rb"""NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0""", "settings"),

    # --- MASS-001 -------------------------------------------------------------
    pattern("MASS-001", rb"""\.(?:create|insert|insertOne|insertMany|update|updateOne|build|upsert)\(\s*(?:\{\s*\.\.\.)?req\.body\s*[,)}]|\b(?:findByIdAndUpdate|findOneAndUpdate)\([^,()]+,\s*req\.body\s*[,)]|\bnew\s+[A-Z]\w*\(\s*req\.body\s*\)|Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)""",
            "js"),
    pattern("MASS-001", rb"""::(?:create|forceCreate|firstOrCreate|updateOrCreate)\(\s*\$request->all\(\)\s*\)|->(?:update|fill|forceFill)\(\s*\$request->all\(\)\s*\)|::create\(\s*\$_POST\s*\)|\$guarded\s*=\s*\[\s*\]""",
            "php"),
    pattern("MASS-001", rb"""\.objects\.(?:create|update)\(\s*\*\*request\.|\b[A-Z]\w*\(\s*\*\*request\.(?:get_json\(\)|json|form|data|POST)""",
            "python"),
    # (Rails itself refuses Model.new(params) unless fields are picked with permit(...),
    #  so the danger is permit!, which switches that protection off.)
    pattern("MASS-001", rb"\.permit!|\.(?:new|create|update|assign_attributes)\(\s*params\.to_unsafe_h", "ruby"),
]

# The plain-English "what to do", per rule. (The headline and explanation
# for the cards live in explain.py, like every other rule.)
NOTES = {
    "DEBUG-001": "Switch debug mode on only on your own computer: read it from a setting (for example an "
                 "environment variable) that's off unless you turn it on.",
    "XSS-001": "If any of this HTML can come from a visitor, show it as plain text instead (textContent, "
               "or your framework's normal {{ }} output), or clean it first with a library like DOMPurify. "
               "If it only ever comes from you, it's fine.",
    "CORS-001": "Your app logs visitors in with cookies, so allowing every website lets a bad site act as "
                "your visitors. 1) Only allow your own website's address, for example "
                "cors({ origin: \"https://myapp.com\" }). 2) Extra protection: set your login cookie to "
                "SameSite=Lax (or Strict), so browsers don't send it when another website asks. "
                "3) Or log in with tokens instead of cookies.",
    "TLS-001": "Turn the certificate check back on. If you're connecting to your own server with a "
               "self-made certificate, add that certificate to the trusted list instead of switching "
               "the check off.",
    "MASS-001": "Pick the fields a visitor is allowed to set, and save only those (for example "
                "{ name: req.body.name, email: req.body.email }), so extra fields like isAdmin are ignored.",
}
IMPACT = {
    "DEBUG-001": "Visitors no longer see your code, settings or passwords when something breaks.",
    "XSS-001": "Visitors can't sneak scripts into your pages that steal other people's logins.",
    "CORS-001": "Other websites can't use your server on your visitors' behalf.",
    "TLS-001": "Nobody can pretend to be the server you're talking to and read the data.",
    "MASS-001": "Visitors can't give themselves extra powers (like admin) by adding fields to a form.",
}
TITLES = {
    "DEBUG-001": "Debug mode left on",
    "XSS-001": "Raw HTML put into a web page",
    "CORS-001": "Any website allowed to call your server",
    "TLS-001": "Security certificate check switched off",
    "MASS-001": "Whole form saved without picking fields",
}
SEVERITY = {"DEBUG-001": Severity.CRITICAL, "TLS-001": Severity.CRITICAL}  # the rest are warnings


# ===========================================================================
# THE RULE
# ===========================================================================

def check(file: SourceFile, planner: secrets.EnvPlanner, info: ProjectInfo) -> list[Finding]:
    """Check one code file (JavaScript, Python, PHP, Vue...). Returns findings; writes nothing."""
    fixed = python_debug_fixes(file, planner, info) + php_echo_fixes(file) + json_script_fixes(file)
    skip = {(f.rule_id, f.line) for f in fixed}  # already reported, with a fix
    comments = comment_ranges(file)
    found = [f for f in search(file.path, file.source, kinds_of(file), comments) if (f.rule_id, f.line) not in skip]
    return fixed + [f for f in found if not (f.rule_id == "XSS-001" and (
        cleaned_elsewhere_in_file(file, f.line) or cleaned_in_page_loader(file, f.line)))]


def cleaned_in_page_loader(file: SourceFile, line: int) -> bool:
    """SvelteKit: {@html data.article.body} in +page.svelte.

    A page's `data` always comes from the loader file next to it
    (+page.server.js, +page.js...). If that file cleans HTML with a
    sanitizer, the page shows cleaned HTML.
    """
    if not file.path.name.startswith(("+page", "+layout")):
        return False
    match = HTML_VALUE.search(file.source.split(b"\n")[line - 1])
    value = next((g for g in match.groups() if g is not None), b"").strip() if match else b""
    if not value.startswith(b"data."):
        return False
    stem = file.path.name.split(".")[0]  # +page or +layout
    for loader in file.path.parent.glob(stem + ".*"):
        if loader.suffix in (".js", ".ts") and re.search(SANITIZED, loader.read_bytes()):
            return True
    return False


# The HTML being put in:  v-html="X"   {@html X}   __html: X   innerHTML = X
HTML_VALUE = re.compile(rb"""v-html\s*=\s*"([^"]+)"|v-html\s*=\s*'([^']+)'|\{@html\s+([^}]+)\}|__html\s*:\s*([^,}]+)|"""
                        rb"""(?:inner|outer)HTML\s*\+?=\s*([^;]+)|template\.HTML\((.+)\)""")

# HTML that's safe by its very shape:
#   icons bundled with the app      svg('octicon-copy')   item.FileIcon   octiconKebabHorizontal
#   html`...` templates             they escape every value put into them
#   a fixed piece of text           template.HTML("")
#   a copy of the page's own HTML   document.querySelector('#template').innerHTML
SAFE_HTML = re.compile(rb"""(?i)^(?:html`|[\w.$]*(?:icon|svg)\w*\s*(?:\(|$)|(["'`])[^"'`$]*\1$|.*\.innerHTML$|"""
                       rb"""[\w.$?]*highlight\w*(?:\s*\?\?\s*["']["'])?$)""")
ICON_CHOICE = re.compile(rb"(?i)^[\w.!()\s&|]+\?\s*[\w.]*icon\w*\s*:\s*[\w.]*icon\w*$")


# Translation functions return text the app's authors wrote:  $t('Previous'), __('Save'), i18n.t('x')
TRANSLATION = re.compile(rb"(?:\$t|\$tc|t|__|trans|i18n\.t|\$i18n\.t|I18n\.t|locale)\(\s*['\"]")


def cleaned_elsewhere_in_file(file: SourceFile, line: int) -> bool:
    """Is the HTML a variable this file makes with a sanitizer?

        <div v-html="description" />
        ...
        const description = computed(() => DOMPurify.sanitize(podcast.description))

    The cleaning happens on a different line from the v-html, so the
    same-line check (SANITIZED) doesn't see it. If the file uses a
    sanitizer AND creates that variable itself, it's treated as cleaned.
    """
    line_text = file.source.split(b"\n")[line - 1]
    match = HTML_VALUE.search(line_text)
    if match is None:
        return False
    value = next(g for g in match.groups() if g is not None).strip()
    if TRANSLATION.match(value):
        return True  # v-html="$t('Previous')": the app's own translated wording
    if SAFE_HTML.match(value) or ICON_CHOICE.match(value):
        return True  # an icon, an escaping html`` template, fixed text or a copy of the page's own HTML
    if not re.search(SANITIZED, file.source):
        return False
    name = re.match(rb"[A-Za-z_$][\w$]*", value)
    if name is None:
        return False
    word = re.escape(name.group(0))
    creates = rb"(?:const|let|var|function)\s+" + word + rb"\b|\b" + word + rb"(?:\.\w+)*\s*=[^=]"
    return re.search(creates, file.source) is not None


def check_text_file(path: Path, kind: str) -> list[Finding]:
    """Check a page template or settings file, which has no code tree."""
    try:
        source = path.read_bytes()
    except OSError:
        return []
    comments = [(m.start(), m.end()) for m in HTML_COMMENT.finditer(source)]
    return search(path, source, {kind, "markup"} if kind == "template" else {kind}, comments)


def kinds_of(file: SourceFile) -> set[str]:
    """Which groups of patterns apply to this file."""
    name = file.lang.name
    if file.lang.embedded:
        return {"markup", "js"}               # HTML, Vue, Svelte, Razor, ERB pages
    if name in ("javascript", "typescript", "tsx"):
        return {"js", "markup"} if file.path.suffix.lower() in (".jsx", ".tsx") else {"js"}
    if name == "php":
        return {"php", "markup"} if file.path.name.endswith(".blade.php") else {"php"}
    return {file.lang.family}


HTML_COMMENT = re.compile(rb"<!--.*?-->|\{\{!--.*?--\}\}|\{#.*?#\}|<%#.*?%>|@\*.*?\*@", re.DOTALL)


def comment_ranges(file: SourceFile) -> list[tuple[int, int]]:
    """Where the file's comments are, as (start, end) byte positions."""
    ranges = [(n.start_byte, n.end_byte) for n in file.nodes if "comment" in n.type]
    if file.lang.embedded:  # page markup isn't in the code tree, so find its comments by pattern
        ranges += [(m.start(), m.end()) for m in HTML_COMMENT.finditer(file.source)]
    return ranges


def search(path: Path, source: bytes, kinds: set[str], comments: list[tuple[int, int]]) -> list[Finding]:
    """Search the text for every pattern that applies, one finding per rule per line."""
    findings = []
    seen = set()
    lines = source.split(b"\n")
    for item in PATTERNS:
        if not item.kinds & kinds:
            continue
        for match in item.regex.finditer(source):
            start = match.start()
            if any(s <= start < e for s, e in comments):
                continue  # in a comment
            line = source.count(b"\n", 0, start) + 1
            line_text = lines[line - 1]
            if len(line_text) > 2_000:
                continue  # minified data, not code a person wrote
            if item.unless is not None and item.unless.search(line_text):
                continue  # e.g. the HTML is cleaned first: that's correct
            if item.rule in ("DEBUG-001", "TLS-001") and only_in_development(source, start):
                continue  # only switched on on the developer's own computer: that's fine
            if (item.rule, line) in seen:
                continue
            seen.add((item.rule, line))
            note = NOTES[item.rule]
            if item.rule == "CORS-001" and CREDENTIALS.search(b"\n".join(lines[max(0, line - 6):line + 5])):
                note = CREDENTIALS_NOTE
            if item.rule == "XSS-001" and re.search(RAILS_JSON, line_text):
                note = RAILS_JSON_NOTE
            findings.append(Finding(item.rule, TITLES[item.rule], path, line, IMPACT[item.rule],
                                    SEVERITY.get(item.rule, Severity.WARNING), note=note))
    return findings


# ===========================================================================
# CORS: only a risk with logins the browser sends by itself
# ===========================================================================

# Signs that an app logs visitors in with cookies (or sessions, which use a cookie).
COOKIE_LOGINS = re.compile(
    rb"express-session|cookie-session|cookie-parser|req\.session\b|res\.cookie\(|iron-session|next-auth|"
    rb"request\.session\b|login_user\(|flask_login|SessionMiddleware|django\.contrib\.sessions|"
    rb"SessionAuthentication|\.set_cookie\(|"
    rb"session_start\(|\$_SESSION\b|\bsetcookie\(|EnsureFrontendRequestsAreStateful|"
    rb"\bsession\[|\bcookies(?:\.signed|\.encrypted)?\[|\bdevise\s+:|"
    rb"\.AddCookie\(|CookieAuthenticationDefaults|\.AddIdentity\b|Response\.Cookies\.|"
    rb"http\.SetCookie\(|gorilla/sessions|gin-contrib/sessions|"
    rb"\bHttpSession\b|\.formLogin\(|\.addCookie\(|install\(Sessions\)|app\.sessions\.|SessionsMiddleware"
)

# CORS settings that let logins be sent along. With these, any-website CORS
# is dangerous whatever the app uses.
CREDENTIALS = re.compile(
    rb"(?i)credentials\s*[:=]\s*true|AllowCredentials|supports_credentials\s*=\s*True|"
    rb"CORS_ALLOW_CREDENTIALS\s*=\s*True|Access-Control-Allow-Credentials|'supports_credentials'\s*=>\s*true"
)
CREDENTIALS_NOTE = ("These settings let any website send your visitors' logins along, so a bad site can act as "
                    "them. 1) Only allow your own website's address, for example "
                    "cors({ origin: \"https://myapp.com\", credentials: true }). 2) Extra protection: set your "
                    "login cookie to SameSite=Lax (or Strict). 3) Or log in with tokens instead of cookies.")


def uses_cookie_logins(source: bytes) -> bool:
    return COOKIE_LOGINS.search(source) is not None


RAILS_JSON_NOTE = ("Rails' to_json normally makes this safe, but this app has switched that off "
                   "(escape_html_entities_in_json = false). Switch it back on, or use json_escape(...).")
# An app that switches Rails' JSON safety off.
RAILS_JSON_UNSAFE = re.compile(rb"escape_html_entities_in_json\s*=\s*false")


def without_safe_rails_json(findings: list[Finding], switched_off: bool) -> list[Finding]:
    """<%= data.to_json.html_safe %> is safe unless the app switched Rails' JSON escaping off."""
    if switched_off:
        return findings
    return [f for f in findings if not (f.rule_id == "XSS-001" and f.note == RAILS_JSON_NOTE)]


def only_risky_cors(findings: list[Finding]) -> list[Finding]:
    """Keep a CORS warning only when the settings let logins be sent along.

    "Any website" written as a plain * is safe on its own: browsers refuse
    to send a visitor's login (cookies included) to a server that allows
    every website. The danger is a server that accepts any website AND
    allows logins ("credentials"): then any website a visitor opens can act
    as them. So only that combination is reported.
    """
    return [f for f in findings if f.rule_id != "CORS-001" or f.note == CREDENTIALS_NOTE]


# "Only on the developer's own computer", in several frameworks:
#   if (env.IsDevelopment())          ASP.NET
#   if (App::environment('local'))    Laravel
#   if (app()->isLocal())             Laravel
#   if (process.env.NODE_ENV === 'development')
#   if Rails.env.development?
DEVELOPMENT_ONLY = re.compile(
    rb"IsDevelopment\(\)|IsEnvironment\(|environment\(\s*['\"](?:local|development|testing)|[iI]sLocal\w*\(|"
    rb"NODE_ENV\s*===?\s*['\"]development|NODE_ENV\s*!==?\s*['\"]production|Rails\.env\.(?:development|test)\?")


def only_in_development(source: bytes, position: int) -> bool:
    """Is this inside a check that it only runs on the developer's computer?

    That's the correct way to use debug pages, or to skip certificate checks
    for a local test server, so it isn't reported. The check looks at the
    few lines just above it.
    """
    before = source[max(0, position - 300):position]
    line_end = source.find(b"\n", position)
    rest_of_line = source[position:line_end if line_end != -1 else len(source)]  # Ruby: "... if Rails.env.development?"
    return DEVELOPMENT_ONLY.search(before) is not None or DEVELOPMENT_ONLY.search(rest_of_line) is not None


# ===========================================================================
# FIX: Python debug mode
# ===========================================================================

# Settings meant only for your own computer or for tests: debug mode on is fine there.
DEV_ONLY = re.compile(r"(?i)dev|local|test|debug")


def python_debug_fixes(file: SourceFile, planner: secrets.EnvPlanner, info: ProjectInfo) -> list[Finding]:
    """Django's DEBUG = True, and Flask's app.run(debug=True) / app.debug = True.

    The fix reads the setting from .env, and adds DEBUG=1 (or FLASK_DEBUG=1)
    to .env. So on your computer, debug mode stays ON. Online, where there's
    no .env with that line, it's OFF.
    """
    if not file.is_python or DEV_ONLY.search(file.path.stem):
        return []  # e.g. settings/dev.py or local_settings.py: debug on is the point
    findings = []
    for value in file.nodes_of("true"):
        holder = value.parent
        if holder is None or in_dev_class(value):
            continue
        if holder.type == "assignment" and field(holder, "right") == value:
            target = text(field(holder, "left"))
            if target == "DEBUG" and at_top_level(holder):
                findings.append(django_debug_finding(file, planner, value))
            elif target.endswith(".debug"):
                findings.append(debug_fix(file, planner, value, "FLASK_DEBUG"))
        elif holder.type == "keyword_argument" and text(field(holder, "name")) == "debug":
            call = holder.parent.parent if holder.parent is not None else None
            if call is not None and call.type == "call" and text(field(call, "function")).endswith(".run"):
                findings.append(debug_fix(file, planner, value, "FLASK_DEBUG"))
    return findings


def at_top_level(node: Node) -> bool:
    return node.parent is not None and node.parent.parent is not None and node.parent.parent.type == "module"


def in_dev_class(node: Node) -> bool:
    """Inside  class DevConfig:  or  class TestingConfig:  (Flask's usual setup)."""
    return any(a.type == "class_definition" and DEV_ONLY.search(text(field(a, "name")))
               for a in ancestors(node))


def django_debug_finding(file: SourceFile, planner: secrets.EnvPlanner, value: Node) -> Finding:
    """Django refuses visitors when debug is off and ALLOWED_HOSTS is empty.

    So the fix is only offered once ALLOWED_HOSTS lists the site's address.
    Otherwise, switching debug off online would make the site turn every
    visitor away.
    """
    allowed = re.search(rb"(?m)^ALLOWED_HOSTS\s*=\s*\[\s*\]", file.source)
    if allowed or b"ALLOWED_HOSTS" not in file.source:
        return Finding("DEBUG-001", TITLES["DEBUG-001"], file.path, line_of(value), IMPACT["DEBUG-001"],
                       Severity.CRITICAL,
                       note="Change it to  DEBUG = os.environ.get(\"DEBUG\") == \"1\"  and put DEBUG=1 in .env. "
                            "Also list your website's address in ALLOWED_HOSTS: Django turns visitors away "
                            "when debug is off and that list is empty.")
    return debug_fix(file, planner, value, "DEBUG")


def debug_fix(file: SourceFile, planner: secrets.EnvPlanner, value: Node, env_name: str) -> Finding:
    env_name, needs_append = planner.reserve(env_name, "1")
    replacement = f'os.environ.get("{env_name}") == "1"'
    edits = [TextEdit(file.path, value.start_byte, value.end_byte, replacement.encode())]
    import_edit = python_import_edit(file, "os")
    if import_edit is not None:
        edits.append(import_edit)
    appends = [AppendEdit(planner.env_path, f"{env_name}=1\n", header=secrets.ENV_HEADER)] if needs_append else []
    line = line_of(value)
    fix = Fix(edits=edits, appends=appends, preview_before=short(text(value.parent), 40),
              preview_after=short(text(value.parent).replace("True", replacement), 60))
    return Finding("DEBUG-001", TITLES["DEBUG-001"], file.path, line,
                   "Visitors no longer see your code and settings when something breaks. "
                   "Debug mode stays on for you, through .env.", Severity.CRITICAL, fix=fix)


# ===========================================================================
# FIX: data written into a <script> tag (React / Next.js)
# ===========================================================================

# In JavaScript text, "<" means "<". Python needs the backslash doubled.
ESCAPE_LESS_THAN = b'.replace(/</g, "\\\\u003c")'


def json_script_fixes(file: SourceFile) -> list[Finding]:
    """<script dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />

    Shops and blogs put hidden info for Google in a script like this. But
    JSON.stringify leaves "<" alone, so if the data ever contains
    "</script>" (a product name from a supplier's feed, say), the browser
    thinks the script ends there, and whatever follows RUNS as code.

    FIX: JSON.stringify(data).replace(/</g, "\\u003c")
    \\u003c means "<" to Google and to JavaScript, but the browser can't
    mistake it for the end of the script. Nothing else changes. (This is
    what the Next.js documentation recommends.)

    Only for <script> tags: anywhere else, \\u003c would show up on screen.
    """
    if file.lang.family != "js":
        return []
    findings = []
    for attribute in file.nodes_of("jsx_attribute"):
        if not attribute.named_children or text(attribute.named_children[0]) != "dangerouslySetInnerHTML":
            continue
        element = attribute.parent
        if element is None or text(field(element, "name")) != "script":
            continue
        edits = []
        for call in walk(attribute):
            if call.type != "call_expression" or text(field(call, "function")) != "JSON.stringify":
                continue
            if file.source[call.end_byte:call.end_byte + 20].lstrip().startswith(b".replace"):
                continue  # already escaped
            edits.append(TextEdit(file.path, call.end_byte, call.end_byte, ESCAPE_LESS_THAN))
        if edits:
            findings.append(Finding(
                "XSS-001", TITLES["XSS-001"], file.path, line_of(attribute),
                "Text in this script can't break out of it and run as code.", Severity.WARNING,
                fix=Fix(edits=edits, preview_before="JSON.stringify(data)",
                        preview_after='JSON.stringify(data).replace(/</g, "\\u003c")')))
    return findings


# ===========================================================================
# FIX: PHP echo of visitor input
# ===========================================================================

VISITOR_INPUT = {"_GET", "_POST", "_REQUEST", "_COOKIE"}


def php_echo_fixes(file: SourceFile) -> list[Finding]:
    """echo $_GET['name'];  ->  echo htmlspecialchars((string) $_GET['name'], ENT_QUOTES, 'UTF-8');

    htmlspecialchars turns < and > into &lt; and &gt;, so whatever the
    visitor typed is SHOWN as text instead of RUN as HTML.
    """
    if file.lang.family != "php":
        return []
    findings = []
    for statement in file.nodes_of("echo_statement", "print_intrinsic"):
        edits = []
        for node in statement.named_children:
            for value in visitor_values(node):
                code = text(value)
                edits.append(TextEdit(file.path, value.start_byte, value.end_byte,
                                      f"htmlspecialchars((string) {code}, ENT_QUOTES, 'UTF-8')".encode()))
        if edits:
            fix = Fix(edits=edits, preview_before=short(text(statement), 40),
                      preview_after="echo htmlspecialchars(…)")
            findings.append(Finding("XSS-001", TITLES["XSS-001"], file.path, line_of(statement),
                                    IMPACT["XSS-001"], Severity.WARNING, fix=fix))
    return findings


def visitor_values(node: Node) -> list[Node]:
    """The $_GET[...]-style values printed DIRECTLY: on their own, or joined with dots.

    Values passed through a function first (like intval($_GET['n'])) are
    left alone: the function may already make them safe.
    """
    if node.type == "subscript_expression":
        base = node.named_children[0] if node.named_children else None
        if base is not None and base.type == "variable_name" and text(base).lstrip("$") in VISITOR_INPUT:
            return [node]
        return []
    if node.type in ("binary_expression", "parenthesized_expression"):
        if node.type == "binary_expression" and text(field(node, "operator")) not in (".", ""):
            operator = next((c for c in node.children if not c.is_named), None)
            if operator is None or text(operator) != ".":
                return []
        return [value for child in node.named_children for value in visitor_values(child)]
    return []
