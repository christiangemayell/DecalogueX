"""
appsec.py: mistakes common in modern AI-built apps (found testing 10 AI-written apps).

  SEC-005     A secret given a PUBLIC name.  NEXT_PUBLIC_, VITE_, REACT_APP_,
              EXPO_PUBLIC_... names are BUILT INTO THE PAGE every visitor
              downloads. AI tools often add the prefix to "make it work",
              which hands the secret to anyone:  NEXT_PUBLIC_OPENAI_API_KEY
  JWT-001     Login tokens accepted without checking their signature:
              algorithms: ['none'], jwt.decode(..., verify=False), and friends.
              Anyone can then write their own token: "I'm the admin".
  UPLOAD-001  Uploaded files saved with no check on their type, so a visitor
              can upload a script or a huge file. ("Worth a look": the check
              may live somewhere else.)
  RAND-001    Math.random() / random.randint() used for something secret, like
              a reset code or a token. These numbers can be predicted.
  AI-001      An AI service's key used in the visitor's browser:
              new OpenAI({ dangerouslyAllowBrowser: true }). Anyone can copy the
              key and run up your bill.
  AI-002      What the AI wrote put straight into a page, a database query or
              eval(). A visitor can ask the AI to write an attack for them
              ("prompt injection" turning into a real hole).
  AI-003      An AI call with no rate limit anywhere in the project: one script
              can send thousands of requests and run up a huge bill (the
              "Bill Shock" problem). ("Worth a look".)

All are "What to do" cards: the right fix depends on the app.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from decaloguex.languages import SourceFile
from decaloguex.models import Finding, Severity
from decaloguex.rules import injection

# ===========================================================================
# SEC-005: secrets given public names
# ===========================================================================

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_"
# The rest of the name says it's a secret...
SECRET_WORDS = re.compile(
    r"SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|COHERE|"
    r"REPLICATE|HUGGING|HF_TOKEN|STRIPE_SK|SK_LIVE|DATABASE_URL|DB_URL|DB_PASS|JWT|ADMIN|AUTH_TOKEN|API_TOKEN|"
    r"RESEND|SENDGRID|TWILIO_AUTH|AWS_SECRET|WEBHOOK")
# ...unless it's one of the keys that are MEANT to be public.
PUBLIC_BY_DESIGN = re.compile(
    r"PUBLISHABLE|ANON_KEY|PUBLIC_KEY|SITE_KEY|CLIENT_ID|MEASUREMENT_ID|POSTHOG|SENTRY|MAPBOX|GOOGLE_MAPS|"
    r"FIREBASE|ALGOLIA|APP_ID|PROJECT_ID")
PUBLIC_NAME_IN_CODE = re.compile(r"(?:process\.env\.|import\.meta\.env\.|process\.env\[\s*['\"])(?P<name>" + PUBLIC_PREFIX + r"[A-Z0-9_]+)")
PUBLIC_NAME_IN_ENV = re.compile(r"(?m)^\s*(?:export\s+)?(?P<name>" + PUBLIC_PREFIX + r"[A-Z0-9_]+)\s*=")
SEC5_NOTE = ("Names starting with {prefix} are built into the page that every visitor downloads, so anyone "
             "can read this secret. Remove the prefix (call it {plain}) and only use it in server code, "
             "for example an API route that calls the service for the browser. If the key was ever "
             "published, cancel it and make a new one.")


def secretly_public(name: str) -> bool:
    rest = re.sub("^" + PUBLIC_PREFIX, "", name)
    return bool(SECRET_WORDS.search(rest)) and not PUBLIC_BY_DESIGN.search(rest)


def sec5_finding(path: Path, line: int, name: str) -> Finding:
    prefix = re.match(PUBLIC_PREFIX, name).group(0)
    plain = name[len(prefix):]
    return Finding("SEC-005", f"Secret with a public name: {name}", path, line,
                   "Visitors can't read your secret keys out of the page.", Severity.CRITICAL,
                   note=SEC5_NOTE.format(prefix=prefix, plain=plain))


def check_env_file(path: Path) -> list[Finding]:
    """SEC-005 in .env files (including .env.example: the NAME is the mistake)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = []
    for match in PUBLIC_NAME_IN_ENV.finditer(text):
        if secretly_public(match.group("name")):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(sec5_finding(path, line, match.group("name")))
    return findings


# ===========================================================================
# The code checks
# ===========================================================================

@dataclass(frozen=True)
class Pattern:
    rule: str
    families: frozenset
    regex: re.Pattern


def pattern(rule: str, families: str, regex: str) -> Pattern:
    return Pattern(rule, frozenset(families.split()), re.compile(regex))


PATTERNS = [
    # JWT-001: signature not checked
    pattern("JWT-001", "js", r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]"),
    pattern("JWT-001", "python", r"algorithms\s*=\s*\[[^\]]*['\"]none['\"]|jwt\.decode\([^)]*(?:verify\s*=\s*False|['\"]verify_signature['\"]\s*:\s*False)"),
    pattern("JWT-001", "java kotlin", r"\bparseUnsecuredClaims\(|\bparseClaimsJwt\("),
    pattern("JWT-001", "go", r"\bjwt\.ParseUnverified\(|\bSigningMethodNone\b|\bUnsafeAllowNoneSignatureType\b"),
    pattern("JWT-001", "ruby", r"\bJWT\.decode\([^)]*,\s*nil\s*,\s*false"),
    pattern("JWT-001", "csharp", r"\b(?:ValidateIssuerSigningKey|RequireSignedTokens|RequireSignature)\s*=\s*false"),
    # AI-001: an AI key used in the browser
    pattern("AI-001", "js", r"\bdangerouslyAllowBrowser\s*:\s*true"),
]

JWT_NOTE = ("This accepts login tokens without checking their signature, so anyone can write a token saying "
            "they're any user, admin included. Always verify with your secret and a fixed algorithm, for "
            "example jwt.verify(token, secret, { algorithms: ['HS256'] }).")
NOTES = {
    "JWT-001": JWT_NOTE,
    "AI-001": ("This makes the AI service's key visible to every visitor, who can copy it and run up your bill. "
               "Call the AI from your server (an API route) and keep the key in .env there."),
}
TITLES = {
    "JWT-001": "Login tokens accepted without checking them",
    "AI-001": "AI service key exposed in the browser",
    "UPLOAD-001": "Uploaded files saved without checking them",
    "RAND-001": "Guessable random numbers used for something secret",
    "AI-002": "What the AI wrote is used without checking",
    "AI-003": "AI calls with no limit on how often they can be used",
}
IMPACT = {
    "JWT-001": "Nobody can forge a login token.",
    "AI-001": "Your AI key stays private, so nobody else can spend your money.",
    "UPLOAD-001": "Visitors can't upload scripts or huge files to your server.",
    "RAND-001": "Reset codes and tokens can't be predicted.",
    "AI-002": "A visitor can't trick the AI into writing an attack that your app then runs.",
    "AI-003": "One person can't run up a huge AI bill by flooding your app.",
}

# Ruby: JWT.decode(token, key, true, ...) DOES check the signature.
RUBY_VERIFIED_DECODE = re.compile(r"JWT\.decode\(\s*\w+\s*,\s*[^,]+,\s*true\b")

# --- JWT-001 (JavaScript): jsonwebtoken's decode() doesn't check anything --------------
JS_DECODE = re.compile(r"\bjwt\.decode\s*\(")
JS_VERIFY = re.compile(r"\.verify\s*\(")

# --- UPLOAD-001 -------------------------------------------------------------------------
UPLOAD = {
    "js": (re.compile(r"\bmulter\s*\(\s*(?:\{|\))"), re.compile(r"fileFilter|mimetype|allowedTypes|limits\s*:")),
    "python": (re.compile(r"\.save\s*\("), re.compile(r"secure_filename|allowed_file|ALLOWED_EXTENSIONS|content_type|mimetype|imghdr|magic\.")),
    "php": (re.compile(r"\bmove_uploaded_file\s*\("), re.compile(r"(?i)mime|pathinfo|getimagesize|finfo_|exif_imagetype|allowed|in_array")),
    "java": (re.compile(r"\.transferTo\s*\(|getOriginalFilename\(\)"), re.compile(r"getContentType|allowed|Tika|MimeType|endsWith\(")),
    "kotlin": (re.compile(r"\.transferTo\s*\(|originalFilename"), re.compile(r"contentType|allowed|Tika|MimeType|endsWith\(")),
}
UPLOAD_SIGN = {"python": re.compile(r"request\.files|UploadFile|FileStorage")}
UPLOAD_NOTE = ("Check what's uploaded before saving it: allow only the file types you expect (for example "
               "images), set a size limit, give the file a new name you choose, and never save uploads where "
               "the server would run them as code. If this is already checked somewhere else, it's fine.")

# --- RAND-001 ---------------------------------------------------------------------------
WEAK_RANDOM = {
    "js": re.compile(r"\bMath\.random\s*\("),
    "python": re.compile(r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\("),
    "php": re.compile(r"(?<![\w>])(?:rand|mt_rand|uniqid|lcg_value)\s*\("),
    "java": re.compile(r"\bnew\s+Random\s*\(|\bMath\.random\s*\("),
    "kotlin": re.compile(r"\bRandom\.next\w*\(|\bMath\.random\s*\(|\(\d+\.\.\d+\)\.random\(\)"),
    "go": re.compile(r"\brand\.(?:Intn|Int\d*|Float\d+|Read|Perm)\s*\("),
    "ruby": re.compile(r"(?<![.\w])rand\s*\(|\.sample\b"),
    "csharp": re.compile(r"\bnew\s+Random\s*\("),
}
SECRET_THING = re.compile(
    r"(?i)token|secret|password|passwd|otp|nonce|salt|session|api_?key|reset|verif|coupon|gift|voucher|invite|"
    r"recovery|activation|confirm|one_?time|\bpin\b|captcha|csrf")
GO_SECURE_RAND = re.compile(r'"crypto/rand"')
RAND_NOTE = ("These random numbers can be predicted, so codes made with them can be guessed. Use the secure "
             "version: crypto.randomUUID() or crypto.getRandomValues() in JavaScript, secrets.token_urlsafe() "
             "in Python, random_bytes() in PHP, SecureRandom in Java/Ruby, crypto/rand in Go.")

# --- AI-002 and AI-003 ----------------------------------------------------------------------
AI_OUTPUT = re.compile(
    r"\.choices\s*\[\s*0\s*\]\s*\.\s*(?:message\s*\.\s*content|text)|\.content\s*\[\s*0\s*\]\s*\.\s*text|"
    r"\boutput_text\b|\.response\s*\.\s*text\s*\(|\bawait\s+(?:generateText|generateObject)\s*\(|\bgenerate_content\s*\(")
AI_SINK = re.compile(
    r"\.innerHTML\s*\+?=|dangerouslySetInnerHTML|(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\.query\s*\(|"
    r"\.execute\s*\(|\.raw\s*\(|\bexec\s*\(|\bmark_safe\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\(")
AI_CALL = re.compile(
    r"\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\.responses\.create\s*\(|"
    r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(|\.generate_?[Cc]ontent\s*\(|\.completions\.create\s*\(")
AI2_NOTE = ("What the AI writes can be steered by whoever wrote its input, so treat it like visitor input: show "
            "it as plain text (or clean it with DOMPurify), and never put it into a database query, eval() or a "
            "command. Ask the AI for structured data (JSON) and check it before using it.")
AI3_NOTE = ("Nothing in this project limits how often visitors can use the AI, so one script can send "
            "thousands of requests and run up your bill. Add a rate limit (for example express-rate-limit, "
            "@upstash/ratelimit, slowapi or flask-limiter) and a monthly spending cap in your AI account.")
# Anything that looks like rate limiting, anywhere in the project.
RATE_LIMIT = re.compile(rb"(?i)rate[-_ ]?limit|ratelimit|rateLimiter|slowapi|flask[-_]limiter|throttl|rack[-_]attack|limiter")


def check(file: SourceFile, comments: list[tuple[int, int]], runs_on_server: bool) -> list[Finding]:
    """Check one code file. Returns findings; writes nothing."""
    family = file.lang.family
    if file.lang.embedded:
        return []
    source = file.source.decode("utf-8", "replace")
    where = injection.Positions(source)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, position: int, note: str, severity: Severity = Severity.CRITICAL, title: str = "") -> None:
        line, byte = where.line_and_byte(position)
        if (rule, line) in seen or any(s <= byte < e for s, e in comments):
            return
        seen.add((rule, line))
        findings.append(Finding(rule, title or TITLES[rule], file.path, line, IMPACT.get(rule, ""), severity, note=note))

    # SEC-005 in code
    for match in PUBLIC_NAME_IN_CODE.finditer(source):
        if secretly_public(match.group("name")):
            line, byte = where.line_and_byte(match.start())
            if not any(s <= byte < e for s, e in comments) and ("SEC-005", line) not in seen:
                seen.add(("SEC-005", line))
                findings.append(sec5_finding(file.path, line, match.group("name")))

    for item in PATTERNS:
        if family in item.families:
            if item.rule == "JWT-001" and family == "ruby" and RUBY_VERIFIED_DECODE.search(source):
                continue  # header read first, then checked properly with JWT.decode(..., true, ...)
            for match in item.regex.finditer(source):
                add(item.rule, match.start(), NOTES[item.rule])

    # JWT-001 (JavaScript server code): jwt.decode() used, and nothing verifies tokens in this file
    if family == "js" and runs_on_server and not JS_VERIFY.search(source):
        for match in JS_DECODE.finditer(source):
            add("JWT-001", match.start(), JWT_NOTE)

    # UPLOAD-001
    if family in UPLOAD:
        save, checked = UPLOAD[family]
        sign = UPLOAD_SIGN.get(family)
        if (sign is None or sign.search(source)) and not checked.search(source):
            for match in save.finditer(source):
                add("UPLOAD-001", match.start(), UPLOAD_NOTE, Severity.WARNING)

    # RAND-001: weak random numbers on a line that's about something secret
    weak = WEAK_RANDOM.get(family)
    browser_only = family == "js" and not runs_on_server
    if weak is not None and not browser_only and not (family == "go" and GO_SECURE_RAND.search(source)):
        for match in weak.finditer(source):
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            line_text = source[line_start:line_end if line_end != -1 else len(source)]
            if SECRET_THING.search(line_text):
                add("RAND-001", match.start(), RAND_NOTE, Severity.WARNING)

    # AI-002: AI output reaching a page, a query or eval, in the same function
    if AI_OUTPUT.search(source):
        for scope_start, scope_text in function_texts(file, source):
            ai_names = names_from(scope_text, AI_OUTPUT)
            for match in AI_SINK.finditer(scope_text):
                rest = scope_text[match.start():scope_text.find("\n", match.start()) % (len(scope_text) + 1)]
                if AI_OUTPUT.search(rest) or any(re.search(rf"(?<![\w$.]){re.escape(n)}\b", rest) for n in ai_names):
                    add("AI-002", scope_start + match.start(), AI2_NOTE)

    # AI-003: an AI call in server code (dropped later if the project limits requests anywhere)
    if runs_on_server or family != "js":
        match = AI_CALL.search(source)
        if match:
            add("AI-003", match.start(), AI3_NOTE, Severity.WARNING)
    return findings


def function_texts(file: SourceFile, source: str) -> list[tuple[int, str]]:
    """(start position, text) of every function, or the whole file if it has none."""
    kinds = injection.FUNCTION_TYPES.get(file.lang.family)
    nodes = file.nodes_of(*kinds) if kinds else []
    if not nodes:
        return [(0, source)]
    raw = file.source
    texts = []
    for n in nodes:
        # The code tree counts bytes; the text counts characters (an emoji is 4 bytes, 1 character).
        start = len(raw[:n.start_byte].decode("utf-8", "replace"))
        texts.append((start, raw[n.start_byte:n.end_byte].decode("utf-8", "replace")))
    return texts


def names_from(scope: str, source: re.Pattern) -> set[str]:
    """Names assigned from AI output (and names built from those)."""
    names: set[str] = set()
    for _ in range(2):
        for line in scope.splitlines():
            match = injection.ASSIGNMENT.match(line)
            if match is None:
                continue
            rhs = match.group("rhs")
            if source.search(rhs) or any(re.search(rf"(?<![\w$]){re.escape(n)}\b", rhs) for n in names):
                for name in re.findall(r"\$?[A-Za-z_]\w*", match.group("lhs")):
                    if name not in injection.NOT_NAMES:
                        names.add(name)
    return names


def without_ai_cards_if_rate_limited(findings: list[Finding], rate_limited: bool) -> list[Finding]:
    """AI-003 only matters if NOTHING in the project limits requests."""
    if not rate_limited:
        return findings
    return [f for f in findings if f.rule_id != "AI-003"]
